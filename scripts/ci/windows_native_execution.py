#!/usr/bin/env python3
"""Strict consumer of native Windows facts; never substitutes a Python Core child.

The fixed source-built native producer owns token/cohort/job/loaded-module/wait
observations. Selection or a successful ordinary Cronet diagnostic grants no
authority. This adapter issues neither policy nor a privileged execution request.
"""
import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import subprocess
import threading
import stat
import time

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = 'polaris-windows-native-execution-proof-v1'
VARIANT = {'linkage':'shared-purego','libc':'','goarm':'','gomips':'','go386':'','legacy':False}
OUTPUT_LIMIT = 8 * 1024 * 1024
ERROR_LIMIT = 512 * 1024
PROCESS_SECONDS = 600
REAP_SECONDS = 15
COOPERATIVE_SECONDS = 90
POLL_SECONDS = 0.25
MAX_ERROR_RECORDS = 32
MAX_ERROR_EVENTS = 65535


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def integer(value, name, minimum=0, maximum=0xffffffff):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('Windows exact integer differs: ' + name)
    return value


def hex_identity(value, digits, name, nonzero=True):
    if type(value) is not str or not re.fullmatch('[a-f0-9]{' + str(digits) + '}', value) or (nonzero and int(value, 16) == 0):
        raise ValueError('Windows fixed hexadecimal identity differs: ' + name)
    return value


def strict_numbers(value):
    # Go emits integer DTO fields. JSON Schema's integer vocabulary also accepts
    # 1.0; Python equality aliases True/1. Neither is a wire identity here.
    if type(value) is float:
        raise ValueError('Windows proof contains a non-integer number')
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError('Windows JSON object key differs')
            strict_numbers(item)
    elif type(value) is list:
        for item in value:
            strict_numbers(item)
    elif value is not None and type(value) not in (str, bool, int):
        raise ValueError('Windows proof contains a non-JSON value')


def proof_shape(proof):
    import jsonschema
    strict_numbers(proof)
    if len(canonical(proof)) > OUTPUT_LIMIT:
        raise ValueError('Windows native proof byte bound')
    schema = json.loads((ROOT / 'release/ci/native-release-index.schema.json').read_text())
    jsonschema.Draft202012Validator(schema['$defs']['windowsExecution']).validate(proof)


def actor(value):
    for key, expected in [('sid', 'S-1-5-18'), ('tokenType', 'primary'), ('threadImpersonation', False)]:
        equal(value[key], expected, 'actual actor ' + key)
    integer(value['processId'], 'actor process ID', 1)
    hex_identity(value['creationTime'], 16, 'actor birth')


def protected_object(value):
    for key, expected in [('ownerSid', 'S-1-5-18'), ('protectedDacl', True),
                          ('systemOnlyDacl', True), ('reparsePoint', False)]:
        equal(value[key], expected, 'actual protection ' + key)
    hex_identity(value['volumeSerial'], 16, 'volume serial')
    hex_identity(value['fileId'], 32, 'file ID')


def exact_json(raw):
    if type(raw) is bytes:
        raw = raw.decode('utf-8', errors='strict')
    if type(raw) is not str or len(raw.encode('utf-8')) > OUTPUT_LIMIT or raw.startswith('\ufeff'):
        raise ValueError('native JSON encoding/byte bound')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate native JSON member')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite native JSON')))


def sha_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def sha_file(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(part)
    return result.hexdigest()


def equal(actual, expected, name):
    if type(actual) is not type(expected) or actual != expected:
        raise ValueError('Windows native binding differs: ' + name)


def native_path(value):
    if type(value) is not str or not value.lower().startswith('\\device\\') or any(ord(c) < 32 for c in value) or ':' in value or '/' in value or ntpath.normpath(value) != value:
        raise ValueError('Windows native object name differs')
    return ntpath.normcase(value)


def validate_facts(row, proof, source_root=ROOT):
    """Validate every source/data/control edge before derive_trusted_execution."""
    from tls_fingerprint_probe import (validate, validate_configuration_checks,
                                       configuration_cases, producer_module_identities)
    proof_shape(proof)
    strict_numbers(row)
    equal(row['target'], 'windows/amd64', 'modern target')
    equal(row['variant'], VARIANT, 'modern shared-purego variant')
    equal(row['variant']['legacy'], False, 'nonlegacy row')
    for key in ('sourceCommit', 'sourceTree'):
        hex_identity(row[key], 40, key)
    equal(row['tag'], 'v' + row['version'], 'product tag')
    expected_root = 'sing-box-' + row['version'] + '-windows-amd64'
    equal(row['id'], expected_root, 'native row ID')
    equal(row['archive']['root'], expected_root, 'archive root')
    equal(row['archive']['name'], expected_root + '.zip', 'archive filename')
    integer(row['archive']['bytes'], 'archive bytes', 1, 256 * 1024 * 1024)
    hex_identity(row['archive']['sha256'], 64, 'archive digest')
    members = row['archive']['members']
    if type(members) is not dict or not 2 <= len(members) <= 1024 or any(type(name) is not str for name in members) or len({name.casefold() for name in members}) != len(members):
        raise ValueError('Windows final archive member set differs')
    for name, digest in members.items():
        if type(name) is not str or not re.fullmatch(re.escape(expected_root) + r'/[A-Za-z0-9_+.-]+', name) or name.endswith('.'):
            raise ValueError('Windows final archive member namespace differs')
        hex_identity(digest, 64, 'archive member digest')
    for key in ('sourceCommit','sourceTree','version','target'):
        equal(proof[key], row[key], key)
    equal(proof['schema'], SCHEMA, 'schema')
    equal(proof['archiveSha256'], row['archive']['sha256'], 'archive')
    for key, member in [('core','sing-box.exe'), ('sidecar','libcronet.dll')]:
        if type(row[key]) is not dict or set(row[key]) != {'member', 'bytes', 'sha256'}:
            raise ValueError('Windows final member pin fields differ')
        integer(row[key]['bytes'], 'final member bytes', 1, 256 * 1024 * 1024)
        hex_identity(row[key]['sha256'], 64, 'final member digest')
        equal(row[key]['member'], member, 'selected member')
        equal(proof[key], row[key], key)
        equal(row['archive']['members'][row['archive']['root']+'/'+member], row[key]['sha256'], 'archive member')
    settings = row['buildGraph']['settings']
    for key,value in [('GOOS','windows'),('GOARCH','amd64'),('CGO_ENABLED','0')]:
        equal(settings.get(key), value, 'Go '+key)
    tags = row['tags'].split(',')
    if len(tags) != len(set(tags)) or set(settings.get('-tags','').split(',')) != set(tags) or not {'with_naive_outbound','with_utls','with_gvisor'} <= set(tags) or not {'with_purego','with_cronet_purego'} & set(tags):
        raise ValueError('Windows actual Go build tags differ')
    for key,value in [('vcs.revision',row['sourceCommit']),('vcs.modified','false')]:
        equal(settings.get(key),value,'mandatory Go clean source')
    receipt = proof['tlsProbe']
    equal(receipt['coreSHA256'],row['core']['sha256'],'TLS core hash')
    equal(receipt['coreBytes'],row['core']['bytes'],'TLS core bytes')
    equal(receipt['networkHandshakeValidated'],False,'local admission boundary')
    document = receipt['capabilities']
    validate(document,source=row['sourceCommit'],version=row['version'],go_version=row['goVersion'],
             target=row['target'],expected_modules=producer_module_identities(row['buildGraph']),source_root=source_root)
    if set(document['buildTags'].split(',')) != set(tags):
        raise ValueError('Windows running Core/Go tags differ')
    validate_configuration_checks(document,receipt['configurationChecks'])
    facts = proof['native']; cohort = facts['cohort']
    actor(facts['actor'])
    protected_object(cohort)
    equal(cohort['fileSystem'], 'NTFS', 'native filesystem')
    equal(cohort['createdNew'], True, 'born-private cohort')
    source_producer = facts['producer']
    for key in ('sourceCommit','sourceTree'):
        equal(source_producer[key],row[key],'native producer '+key)
    equal(source_producer['goVersion'],row['goVersion'],'native producer Go')
    hex_identity(source_producer['sha256'], 64, 'producer digest')
    integer(source_producer['bytes'], 'producer bytes', 1, 256 * 1024 * 1024)
    if not re.fullmatch(r'[A-Za-z]:\\.*',cohort['path']) or ntpath.basename(cohort['path']) != 'polaris-native-'+cohort['id'] or ntpath.basename(ntpath.dirname(cohort['path'])).lower() != 'systemtemp':
        raise ValueError('Windows fresh private cohort namespace differs')
    parent_native = native_path(cohort['nativePath'])
    if ntpath.basename(parent_native) != 'polaris-native-'+cohort['id'] or ntpath.basename(ntpath.dirname(parent_native)) != 'systemtemp':
        raise ValueError('Windows native cohort namespace differs')
    identities = []
    for key,member in [('coreObject','sing-box.exe'),('sidecarObject','libcronet.dll')]:
        obj = facts[key]; pin = row['core' if key=='coreObject' else 'sidecar']
        protected_object(obj)
        equal(obj['linkCount'], 1, 'held object link count')
        equal(obj['shareReadOnly'], True, 'held object sharing')
        equal(obj['path'],ntpath.join(cohort['path'],member),'cohort member path')
        equal(native_path(obj['nativePath']),ntpath.join(parent_native,member),'held native member')
        equal(obj['volumeSerial'],cohort['volumeSerial'],'held volume')
        equal(obj['bytes'],pin['bytes'],'held member bytes'); equal(obj['sha256'],pin['sha256'],'held member hash')
        identities.append(obj['fileId'])
    identities.append(cohort['fileId'])
    if len(set(identities)) != 3 or any(int(value,16)==0 for value in identities) or int(cohort['volumeSerial'],16)==0:
        raise ValueError('Windows object IDs alias or are empty')
    observed = proof['cronet']; library = observed['windowsLibrary']; side = facts['sidecarObject']
    pins=json.loads((Path(source_root)/'release/polaris-candidate-inputs.json').read_text())
    for key,value in {'os':'windows','arch':'amd64','go':row['goVersion'],'linkage':'shared-purego','gvisorCompiled':True,
                      'version':pins['cronetVersion'],'sha256':row['sidecar']['sha256'],'libraryBytes':row['sidecar']['bytes'],
                      'librarySelection':'captured-windows-module-v1','library':side['path']}.items():
        equal(observed[key],value,'actual Cronet '+key)
    for key,value in {'volumeSerial':cohort['volumeSerial'],'fileId':side['fileId'],'parentFileId':cohort['fileId'],
                      'parentVolumeSerial':cohort['volumeSerial'],'modulePath':side['path']}.items():
        equal(library[key],value,'selected module '+key)
    equal(native_path(library['nativePath']),native_path(side['nativePath']),'selected held native path')
    equal(native_path(library['mappedPath']),native_path(side['nativePath']),'actual mapped DLL')
    hex_identity(library['moduleBase'], 16, 'actual DLL base')
    for key,value in [('memoryType',16777216),('loadFlags',2304),('shareReadOnly',True)]:
        equal(library[key],value,'actual selected DLL '+key)
    controls = configuration_cases(document)
    expected = [('capabilities',['tools','tls-fingerprints'],b'')]
    expected += [('check-config-v1',['--disable-color','check','-c','stdin'],json.dumps(value,sort_keys=True,separators=(',',':')).encode()) for _,value,_ in controls]
    expected += [('cronet-observation',['tools','cronet','--expected-version',pins['cronetVersion'],'--sha256',side['sha256']],b'')]
    records = facts['executions']
    if len(records) != len(expected)+1:
        raise ValueError('Windows native phases are missing or extra')
    seen = set(); previous_birth = int(facts['actor']['creationTime'],16)
    for record in records:
        actor(record['actor'])
        integer(record['processId'], 'child process ID', 1)
        integer(record['stdinBytes'], 'child stdin bytes', 0, 8 * 1024 * 1024)
        integer(record['exitCode'], 'child exit code')
        hex_identity(record['creationTime'], 16, 'child birth')
        for key,value in [('imageLoadPolicy',7),('inheritedHandleCount',3),('jobAssignedAtCreation',True),
                          ('actualWait',True),('stdoutEOF',True),('stderrEOF',True),('outputTruncated',False),
                          ('timedOut',False),('forcedKill',False),('jobActiveAfterWait',0),('handlesClosed',True)]:
            equal(record[key],value,'native child completion '+key)
        for key in ('stdout', 'stderr'):
            if type(record[key]) is not str or len(record[key].encode('utf-8')) > 262144:
                raise ValueError('Windows child stream byte bound')
        equal(record['actor']['processId'],record['processId'],'child actor PID')
        equal(record['actor']['creationTime'],record['creationTime'],'child actor birth')
        birth=(record['processId'],record['creationTime'])
        # FILETIME resolution can give distinct sequential PIDs the same birth
        # timestamp. Identity is the pair; observed time must not go backwards.
        if birth in seen or int(birth[1],16) < previous_birth or record['processId']==facts['actor']['processId']:
            raise ValueError('Windows child incarnation aliases')
        previous_birth = int(birth[1],16)
        seen.add(birth)
        equal(native_path(record['imageNativePath']),native_path(facts['coreObject']['nativePath']),'actual child image')
    for record,(purpose,argv,input_bytes) in zip(records,expected):
        equal(record['purpose'],purpose,'ordered phase');equal(record['argv'],argv,'fixed phase argv')
        equal(record['stdinSHA256'],sha_bytes(input_bytes),'actual fixed stdin');equal(record['stdinBytes'],len(input_bytes),'actual stdin bytes')
    equal(exact_json(records[0]['stdout']),document,'actual child capability document')
    equal(records[0]['exitCode'],0,'capability child exit')
    for record,observation in zip(records[1:1+len(controls)],receipt['configurationChecks']):
        # A normal CLI configuration rejection exits 1 (main -> log.Fatal),
        # not a Windows NTSTATUS crash, loader failure or arbitrary nonzero.
        equal(record['exitCode'], 0 if observation['expectedPass'] else 1, 'normal CheckConfig outcome')
        equal(record['exitCode'],observation['exitCode'],'actual CheckConfig exit')
        equal(record['stdout']+record['stderr'],observation['output'],'actual CheckConfig output')
    equal(exact_json(records[-2]['stdout']),observed,'actual Cronet child document')
    equal(records[-2]['exitCode'],0,'Cronet child exit')
    main=records[-1]; run=facts['runMain']
    integer(run['port'], 'native loopback port', 1, 65535)
    integer(run['ownerPid'], 'kernel listener owner', 1)
    equal(run['listenAddress'], '127.0.0.1', 'loopback address')
    equal(run['ready'], True, 'native listener readiness')
    equal(run['dllModule']['memoryType'], 16777216, 'RunMain MEM_IMAGE')
    equal(main['purpose'],'run-main-v1','last phase');equal(main['argv'],['run','-c','stdin'],'fixed RunMain argv')
    equal(main['exitCode'],0,'RunMain actual exit');equal(run['ownerPid'],main['processId'],'kernel listener owner')
    config={'log':{'level':'error'},'inbounds':[{'type':'mixed','listen':'127.0.0.1','listen_port':run['port']}],
            'outbounds':[{'type':'direct','tag':'direct'},{'type':'naive','tag':'module-only','server':'127.0.0.1','server_port':9,'username':'native-proof','password':'native-proof','tls':{'enabled':True,'server_name':'tls.invalid'}}],
            'route':{'final':'direct'}}
    input_bytes=json.dumps(config,sort_keys=True,separators=(',',':')).encode()
    equal(main['stdinSHA256'],sha_bytes(input_bytes),'fixed RunMain stdin');equal(main['stdinBytes'],len(input_bytes),'RunMain stdin bytes')
    equal(native_path(run['dllModule']['nativePath']),native_path(side['nativePath']),'actual RunMain DLL mapping')
    hex_identity(run['dllModule']['moduleBase'], 16, 'RunMain actual DLL base')
    for key,value in [('allChildrenWaited',True),('readersJoined',True),('jobActiveProcesses',0),
                      ('heldObjectsClosed',True),('cohortRemoved',True),('configurationRetained',False),('forcedTermination',False)]:
        equal(facts['cleanup'][key],value,'native suite closure '+key)
    smoke=row['finalPackageCronetSmoke']
    equal([key for key in ('sealedExecution','macosExecution','windowsExecution') if key in smoke],
          ['windowsExecution'], 'retained proof kind')
    equal(smoke['windowsExecution'], proof, 'retained complete native proof')
    for key,value in {'status':'passed','os':'windows','arch':'amd64','go':row['goVersion'],'gvisorCompiled':True,'naiveOutbound':True,
                      'linkage':'shared-purego','version':observed['version'],'librarySha256':side['sha256'],'coreSha256':row['core']['sha256']}.items():
        equal(smoke[key],value,'final native smoke '+key)
    return {'schema':'polaris-trusted-execution-v1','sourceCommit':row['sourceCommit'],'sourceTree':row['sourceTree'],
            'loader':'windows-helper-private-cohort-v1','purposes':['check-config-v1','run-main-v1']}


def windows_host():
    return os.name == 'nt'


def plain_file(path):
    """Reject link/reparse namespaces rather than silently resolving them."""
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('fixed Windows native input must be absolute')
    for parent in [path, *path.parents]:
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('Windows native input has a reparse component')
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
        raise ValueError('Windows native input is not a nonempty regular file')
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def native_cleanup_observed(stdout):
    """A failed fixed native owner can report resource closure, never authority."""
    try:
        result=exact_json(stdout)
        if (type(result) is not dict or result.get('schema')!='polaris-windows-native-execution-diagnostic-v1'
                or result.get('publicationEligible') is not False or result.get('executionAuthority') is not False
                or result.get('custodyReconciled') is not True):
            return False
        native=result.get('native')
        if type(native) is not dict or type(native.get('cleanup')) is not dict:
            return False
        cleanup=native['cleanup']
        return (all(cleanup.get(key) is True for key in ('allChildrenWaited','readersJoined','heldObjectsClosed','cohortRemoved'))
                and type(cleanup.get('jobActiveProcesses')) is int and cleanup['jobActiveProcesses']==0
                and cleanup.get('configurationRetained') is False and type(cleanup.get('forcedTermination')) is bool)
    except (ValueError,TypeError,KeyError,UnicodeError,RecursionError):
        return False


def native_command(tool, archive, raw):
    """Cancel through the original owner; hard kill never certifies cleanup.

    The owner receives one canonical JSON/LF request, retains stdin until normal
    exit, and accepts only cancel/LF or EOF as cooperative cancellation. Its
    durable SYSTEM custody gate, rather than this adapter or a vanished PID,
    reconciles leftovers before any subsequent Core process can be created.
    """
    if type(raw) is not bytes or len(raw)>1024*1024 or b'\n' in raw:
        raise ValueError('Windows native request framing differs')
    deadline=time.monotonic()+PROCESS_SECONDS
    process = subprocess.Popen([str(tool), '--archive', str(archive)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT,
                               shell=False, close_fds=True)
    outputs=[bytearray(),bytearray()]
    errors=[]
    error_count=0
    lock=threading.Lock()
    cancelled=threading.Event()
    done=threading.Event()
    waited=False
    code=None
    hard_kill_attempted=False
    hard_killed=False
    cancel_sent=False

    def fail(error):
        nonlocal error_count
        # Output overflow and wait failures can repeat until teardown finishes.
        # Retain bounded type names, never exception messages or input secrets.
        with lock:
            error_count=min(MAX_ERROR_EVENTS,error_count+1)
            if len(errors)<MAX_ERROR_RECORDS:
                errors.append(type(error).__name__[:64])
        cancelled.set()

    def read(stream,index,limit):
        try:
            while True:
                chunk=stream.read(65536)
                if not chunk:break
                with lock:
                    room=limit-len(outputs[index]);outputs[index].extend(chunk[:room])
                if len(chunk)>room:
                    fail(ValueError('native output byte bound'))
                    # Drain after the retained-byte bound so the native owner
                    # can finish teardown without a broken output pipe.
        except BaseException as error:
            fail(error)
        finally:
            try:stream.close()
            except BaseException as error:fail(error)

    def write():
        nonlocal cancel_sent
        try:
            request=raw+b'\n'
            if process.stdin.write(request)!=len(request):
                raise ValueError('Windows native request short write')
            process.stdin.flush()
            while not done.is_set():
                if cancelled.wait(POLL_SECONDS):
                    if process.stdin.write(b'cancel\n')!=7:
                        raise ValueError('Windows native cancellation short write')
                    process.stdin.flush();cancel_sent=True
                    break
        except BaseException as error:
            fail(error)
        finally:
            # If writing the fixed frame failed, EOF still cancels the owner.
            # This pipe is never reused to send a path, argv or a cleanup command.
            try:process.stdin.close()
            except BaseException as error:fail(error)

    threads=[threading.Thread(target=read,args=(process.stdout,0,OUTPUT_LIMIT),daemon=True),
             threading.Thread(target=read,args=(process.stderr,1,ERROR_LIMIT),daemon=True),
             threading.Thread(target=write,daemon=True)]
    started=[]
    for thread,stream in zip(threads,(process.stdout,process.stderr,process.stdin)):
        try:
            thread.start();started.append(thread)
        except BaseException as error:
            fail(error)
            # No worker owns this pipe if creation failed. Closing an unwritten
            # stdin gives the native reader EOF instead of orphaning its owner.
            try:stream.close()
            except BaseException as close_error:fail(close_error)
    cancel_deadline=None
    while not waited:
        try:
            now=time.monotonic()
            if now>=deadline and not cancelled.is_set():fail(TimeoutError('native producer deadline'))
            if cancelled.is_set() and cancel_deadline is None:cancel_deadline=now+COOPERATIVE_SECONDS
            if cancel_deadline is not None and now>=cancel_deadline:
                hard_kill_attempted=True
                try:
                    process.kill();hard_killed=True
                except BaseException as error:fail(error)
                try:
                    status=process.wait(timeout=REAP_SECONDS)
                    if type(status) is int:code=status;waited=True
                    else:raise ValueError('native reap returned no exact exit status')
                except BaseException as error:fail(error)
                break
            status=process.wait(timeout=POLL_SECONDS)
            if type(status) is int:code=status;waited=True
            else:raise ValueError('native wait returned no exact exit status')
        except subprocess.TimeoutExpired:
            pass
        except BaseException as error:
            fail(error)
            # A persistent wait API failure must neither spin unbounded error
            # storage nor burn CPU during the fixed cooperative interval.
            try:time.sleep(POLL_SECONDS)
            except BaseException as pause_error:fail(pause_error)
    done.set()
    join_deadline=time.monotonic()+REAP_SECONDS
    joined_threads=[]
    for thread in started:
        try:
            thread.join(timeout=max(0,join_deadline-time.monotonic()))
            if not thread.is_alive():joined_threads.append(thread)
        except BaseException as error:fail(error)
    readers_joined=all(thread in joined_threads for thread in threads[:2])
    writer_joined=threads[2] in joined_threads
    joined=readers_joined and writer_joined
    with lock:
        stdout,stderr=map(bytes,outputs);failures=list(errors);count=error_count
    if not waited or not joined or failures or type(code) is not int or code!=0:
        closed=not hard_kill_attempted and waited and joined and native_cleanup_observed(stdout)
        diagnostic={'schema':'polaris-windows-native-adapter-diagnostic-v1',
                    'publicationEligible':False,'executionAuthority':False,
                    'actualWait':waited,'readersJoined':readers_joined,'writerJoined':writer_joined,'exitCode':code,
                    'cooperativeCancelRequested':cancelled.is_set(),'cooperativeFrameWritten':cancel_sent,
                    'hardKillAttempted':hard_kill_attempted,'hardKilled':hard_killed,'nativeCleanup':'complete' if closed else 'unknown',
                    'recoveryGate':'native-SYSTEM-custody-exact-reconciliation',
                    'cleanupDebt':'none-observed' if closed else 'unknown-native-custody-must-reconcile',
                    'errors':failures,'errorEvents':count,'errorEventsSaturated':count==MAX_ERROR_EVENTS,
                    'stdoutSHA256':sha_bytes(stdout),'stderrSHA256':sha_bytes(stderr),
                    'stdoutBytesRetained':len(stdout),'stderrBytesRetained':len(stderr),
                    'stdoutPrefixHex':stdout[:65536].hex(),'stderrPrefixHex':stderr[:65536].hex()}
        try:(tool.parent/'adapter-diagnostic.json').write_bytes(canonical(diagnostic)+b'\n')
        except OSError:pass
        raise ValueError('Windows native producer failed; exact native custody reconciliation is required before admission')
    return stdout


def produce(row, archive, *, context, source_root=ROOT):
    """Invoke only the workflow's fixed, source-built native fact producer."""
    if not windows_host() or os.environ.get('POLARIS_WINDOWS_NATIVE_PROOF_AUTHORIZED') != 'true':
        raise ValueError('explicit privileged Windows proof job required')
    if type(context) is not dict or set(context) != {'runId', 'runAttempt'}:
        raise ValueError('Windows formal execution context fields differ')
    for key in ('runId', 'runAttempt'):
        integer(context[key], 'formal ' + key, 1, 0xffffffffffffffff)
    expected_environment = {'GITHUB_ACTIONS':'true', 'GITHUB_EVENT_NAME':'workflow_dispatch',
                            'GITHUB_REPOSITORY':'polaris-arch/sing-box-polaris',
                            'GITHUB_REPOSITORY_ID':'1421657509', 'GITHUB_SHA':row['sourceCommit'],
                            'GITHUB_RUN_ID':str(context['runId']), 'GITHUB_RUN_ATTEMPT':str(context['runAttempt'])}
    if any(os.environ.get(key) != value for key, value in expected_environment.items()):
        raise ValueError('same-source formal Windows proof environment required')
    # This is only a source/run/job admission record. The native producer still
    # independently observes the actual SYSTEM token and every kernel object.
    from windows_native_admission import consume
    admission_raw = os.environ.get('POLARIS_WINDOWS_NATIVE_ADMISSION_RECEIPT', '')
    if len(admission_raw.encode('utf-8')) > 65536:
        raise ValueError('Windows formal admission input byte bound')
    admission = consume(exact_json(admission_raw))
    equal(admission['context']['sourceCommit'], row['sourceCommit'], 'admission source')
    for key in ('runId', 'runAttempt'):
        equal(admission['context'][key], context[key], 'admission ' + key)
    equal(row['target'], 'windows/amd64', 'adapter target')
    equal(row['variant'], VARIANT, 'adapter variant')
    equal(row['variant']['legacy'], False, 'adapter nonlegacy')
    tool = Path(os.environ['RUNNER_TEMP']) / 'polaris-windows-native-execution' / 'producer.exe'
    archive = Path(os.path.abspath(archive))
    tool_stamp, archive_stamp = plain_file(tool), plain_file(archive)
    tool_sha = sha_file(tool)
    if archive.stat().st_size != row['archive']['bytes'] or sha_file(archive) != row['archive']['sha256']:
        raise ValueError('Windows actual final archive differs before native custody')
    pins = json.loads((Path(source_root) / 'release/polaris-candidate-inputs.json').read_text())
    request = {'schema':'polaris-windows-native-execution-request-v1',
               **{key:row[key] for key in ('sourceCommit','sourceTree','version','target','goVersion','core','sidecar')},
               **context, 'cronetVersion':pins['cronetVersion'],
               'archive':{key:row['archive'][key] for key in ('root','bytes','sha256','members')}}
    strict_numbers(request)
    raw = canonical(request)
    if len(raw) > 1024 * 1024:
        raise ValueError('Windows native request byte bound')
    output = native_command(tool, archive, raw)
    proof = exact_json(output)
    proof_shape(proof)
    if plain_file(tool) != tool_stamp or sha_file(tool) != tool_sha or plain_file(archive) != archive_stamp or sha_file(archive) != row['archive']['sha256']:
        raise ValueError('Windows native producer/archive changed')
    equal(proof['native']['producer']['sha256'], tool_sha, 'actual native producer bytes')
    equal(proof['native']['producer']['bytes'], tool_stamp[2], 'actual native producer length')
    for key, value in context.items():
        equal(proof[key], value, 'actual native workflow ' + key)
    for key in ('sourceCommit', 'sourceTree', 'version', 'target', 'core', 'sidecar'):
        equal(proof[key], row[key], 'actual native request ' + key)
    equal(proof['archiveSha256'], row['archive']['sha256'], 'actual native request archive')
    return proof
