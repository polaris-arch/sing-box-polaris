"""Bounded QA for one already-produced native carrier; never a publisher."""
import hashlib
import ast
import datetime
import io
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

REPOSITORY = 'polaris-arch/sing-box-polaris'
REPOSITORY_ID = 1421657509
MODE = 'NativePeerDiagnostic'
PRODUCER = {
    'run': 40111722951, 'attempt': 1, 'job': 120924707929,
    'commit': '3847e0aba15555e31d9ea14038cac03699a8babd',
    'tree': '598a8e0e65f79f1812d91d891947888421c29f46',
    'artifact': 12566419819, 'artifactName': 'binary-linux_amd64-purego',
    'zipBytes': 34324242,
    'zipSHA256': '716e7a8265c37372b8b6cb5379b34ac24dd1c65502c7b7955c4441955ffb8863',
    'archiveName': 'sing-box-1.15.0-polaris-alpha.12.3-linux-amd64.tar.gz',
    'archiveBytes': 34370454,
    'archiveSHA256': 'c0bb6d0fbfd5e511ef4bdc1aa40b57c3876c54687c2244f7e848bcd0ebba01f0',
    'coreSHA256': '5c76005b899ad20a9da12012eafe7443c2c70ebf69ca6d0f150872b984316979',
    'coreBytes': 86982883,
    'sidecarBytes': 12370520,
    'sidecarSHA256': '99eb98eb47102c7418c7fed1e666d27e2bfb67c6b5517f7ae6b033748d657ed4',
    'rowName': 'native-row-sing-box-1.15.0-polaris-alpha.12.3-linux-amd64.json',
    'rowBytes': 44837, 'rowSHA256': 'de7f514aafcdfc6d911ad5364325ba0504150eef0daf2ee421e17e8d87e70ce1',
    'manifestName': 'polaris-candidate-manifest-build-build-0.json',
    'manifestBytes': 671, 'manifestSHA256': 'eb46745d10a96697e412061c15c3912df19d93e23ec9af88f9cd465403d90cee',
}
BRIDGE_PATHS = frozenset({'.github/workflows/build.yml', 'scripts/ci/protocol_peer.py',
    'scripts/ci/protocol_peer_diagnostic.py', 'scripts/ci/test_protocol_peer.py'})


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_dispatch(env=os.environ):
    if env.get('GITHUB_ACTIONS')!='true' or env.get('RUNNER_OS')!='Linux':
        raise ValueError('diagnostic requires its existing Linux Actions environment')
    if env.get('GITHUB_EVENT_NAME') != 'workflow_dispatch' or env.get('PEER_BUILD') != MODE:
        raise ValueError('diagnostic requires its explicit manual selector')
    if env.get('PEER_EVIDENCE_MODE') != 'staging' or env.get('PEER_SOURCE_GENERATE_ONLY') != 'false':
        raise ValueError('diagnostic cannot select final evidence or source generation')
    if env.get('PEER_VERSION') != '1.15.0-polaris-alpha.12.3':
        raise ValueError('diagnostic version differs from the frozen product')
    if env.get('GITHUB_REPOSITORY') != REPOSITORY or env.get('GITHUB_REPOSITORY_ID') != str(REPOSITORY_ID):
        raise ValueError('diagnostic repository differs')


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root).decode().strip()


def verify_runner_bridge(root, env=os.environ):
    validate_dispatch(env)
    head, tree = git(root, 'rev-parse', 'HEAD'), git(root, 'rev-parse', 'HEAD^{tree}')
    if head != env.get('GITHUB_SHA') or head != env.get('GITHUB_WORKFLOW_SHA'):
        raise ValueError('diagnostic runner checkout and workflow differ')
    if git(root, 'status', '--porcelain', '--untracked-files=no'):
        raise ValueError('diagnostic checkout is dirty')
    if git(root, 'rev-parse', PRODUCER['commit']+'^{tree}') != PRODUCER['tree']:
        raise ValueError('original product tree differs')
    subprocess.run(['git', 'merge-base', '--is-ancestor', PRODUCER['commit'], head], cwd=root, check=True)
    changed = set(git(root, 'diff', '--name-only', PRODUCER['commit'], head).splitlines())
    if not changed or not changed <= BRIDGE_PATHS:
        raise ValueError('diagnostic cannot reuse an old binary after product changes')
    for path in BRIDGE_PATHS:
        file = root/path
        if file.is_symlink() or not file.is_file(): raise ValueError('diagnostic source is not a regular file')
        original = subprocess.check_output(['git', 'show', 'HEAD:'+path], cwd=root)
        if file.read_bytes() != original: raise ValueError('diagnostic executing source bytes differ')
    for name in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
        if not re.fullmatch(r'[1-9][0-9]*', env.get(name, '')): raise ValueError('diagnostic run identity absent')
    return {'sourceCommit': head, 'sourceTree': tree, 'workflowCommit': env['GITHUB_WORKFLOW_SHA'],
            'runId': int(env['GITHUB_RUN_ID']), 'runAttempt': int(env['GITHUB_RUN_ATTEMPT']),
            'bridgeChangedPaths': sorted(changed)}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api(path, *, redirect=False):
    token = os.environ.get('GH_TOKEN')
    if not token: raise ValueError('fixed artifact download needs the existing read-only Actions token')
    request = urllib.request.Request('https://api.github.com/repos/'+REPOSITORY+'/'+path,
        headers={'Accept':'application/vnd.github+json','Authorization':'Bearer '+token,
                 'User-Agent':'polaris-fixed-native-peer-diagnostic'})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
            raw = response.read(2*1024*1024+1)
        if redirect: raise ValueError('artifact endpoint did not provide the expected redirect')
        if len(raw)>2*1024*1024: raise ValueError('bounded artifact metadata exceeded limit')
        return json.loads(raw)
    except urllib.error.HTTPError as error:
        if redirect and error.code == 302:
            location = error.headers.get('Location','')
            parsed = urllib.parse.urlsplit(location)
            if (parsed.scheme != 'https' or parsed.username or parsed.password or parsed.port not in (None,443)
                    or not parsed.hostname or not (parsed.hostname.endswith('.blob.core.windows.net')
                        or parsed.hostname.endswith('.actions.githubusercontent.com'))):
                raise ValueError('fixed artifact storage origin rejected') from None
            return location
        raise RuntimeError('fixed GitHub artifact API request failed') from None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        raise RuntimeError('fixed GitHub artifact metadata unavailable') from None


def validate_origin(run, jobs, artifact):
    if (run.get('id') != PRODUCER['run'] or run.get('run_attempt') != PRODUCER['attempt']
            or run.get('head_sha') != PRODUCER['commit'] or run.get('path') != '.github/workflows/build.yml'
            or run.get('event') != 'workflow_dispatch' or run.get('status') != 'completed'
            or run.get('repository',{}).get('id') != REPOSITORY_ID
            or run.get('repository',{}).get('full_name') != REPOSITORY):
        raise ValueError('fixed original producer run identity differs')
    matches = [j for j in jobs.get('jobs',[]) if j.get('id') == PRODUCER['job']]
    if (len(matches)!=1 or matches[0].get('conclusion')!='success' or matches[0].get('status')!='completed'
            or matches[0].get('head_sha')!=PRODUCER['commit'] or matches[0].get('run_id')!=PRODUCER['run']
            or matches[0].get('run_attempt')!=PRODUCER['attempt']):
        raise ValueError('fixed native producer job success absent')
    expected={'id':PRODUCER['artifact'],'name':PRODUCER['artifactName'],
              'size_in_bytes':PRODUCER['zipBytes'],'digest':'sha256:'+PRODUCER['zipSHA256'],'expired':False}
    if any(artifact.get(k)!=v for k,v in expected.items()): raise ValueError('fixed artifact metadata differs or expired')
    try: expires=datetime.datetime.fromisoformat(artifact['expires_at'].replace('Z','+00:00'))
    except (KeyError,ValueError,TypeError): raise ValueError('fixed artifact expiry evidence absent') from None
    if expires.tzinfo is None or expires<=datetime.datetime.now(datetime.timezone.utc):
        raise ValueError('fixed artifact expiry reached')
    origin=artifact.get('workflow_run',{})
    if (origin.get('id')!=PRODUCER['run'] or origin.get('head_sha')!=PRODUCER['commit']
            or origin.get('repository_id')!=REPOSITORY_ID or origin.get('head_repository_id')!=REPOSITORY_ID):
        raise ValueError('fixed artifact producer origin differs')


def validate_zip(raw):
    if not all(PRODUCER[x] for x in ('rowName','rowBytes','rowSHA256')):
        raise ValueError('original producer row not frozen; diagnostic disabled')
    if len(raw)!=PRODUCER['zipBytes'] or sha(raw)!=PRODUCER['zipSHA256']:
        raise ValueError('original artifact ZIP bytes differ')
    expected={PRODUCER['archiveName']:(PRODUCER['archiveBytes'],PRODUCER['archiveSHA256']),
              PRODUCER['rowName']:(PRODUCER['rowBytes'],PRODUCER['rowSHA256']),
              PRODUCER['manifestName']:(PRODUCER['manifestBytes'],PRODUCER['manifestSHA256'])}
    result={}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if len(archive.infolist())!=len(expected): raise ValueError('original ZIP inventory differs')
        for member in archive.infolist():
            if (member.filename not in expected or member.filename in result or member.is_dir()
                    or not re.fullmatch(r'[A-Za-z0-9_.-]+',member.filename) or member.filename in ('.','..')
                    or member.flag_bits & 1 or (member.external_attr>>16)&0o177777!=0o100644):
                raise ValueError('unsafe or unexpected original ZIP member')
            size, digest=expected[member.filename]
            if member.file_size!=size: raise ValueError('original ZIP member size differs')
            value=archive.read(member)
            if len(value)!=size or sha(value)!=digest: raise ValueError('original ZIP member bytes differ')
            result[member.filename]=value
    return result


def fetch_diagnostic(directory, root):
    runner=verify_runner_bridge(root)
    prefix=f"actions/runs/{PRODUCER['run']}/attempts/{PRODUCER['attempt']}"
    run=api(prefix); jobs=api(prefix+'/jobs?per_page=100')
    artifact=api(f"actions/artifacts/{PRODUCER['artifact']}")
    validate_origin(run,jobs,artifact)
    location=api(f"actions/artifacts/{PRODUCER['artifact']}/zip",redirect=True)
    try:
        # Never forward the GitHub authorization header to signed blob storage.
        request=urllib.request.Request(location,headers={'User-Agent':'polaris-fixed-native-peer-diagnostic'})
        with urllib.request.build_opener(NoRedirect()).open(request,timeout=60) as response:
            raw=response.read(PRODUCER['zipBytes']+1)
    except (urllib.error.HTTPError,urllib.error.URLError,TimeoutError):
        raise RuntimeError('fixed artifact bytes unavailable') from None
    members=validate_zip(raw)
    directory.mkdir(parents=True,exist_ok=False)
    for name,value in {**members,'original-artifact.zip':raw}.items():
        file=directory/name;file.write_bytes(value);file.chmod(0o444)
    evidence={'schema':'polaris-fixed-native-peer-acquisition-v1','producer':PRODUCER,'runner':runner,
              'artifact':artifact,'outerZipActualBytes':len(raw),'outerZipActualSHA256':sha(raw),
              'originalRowImmutable':True,'publicationEligible':False}
    (directory/'diagnostic-acquisition.json').write_text(json.dumps(evidence,indent=2)+'\n')
    return evidence


def verify_product_row(row, raw):
    if len(raw)!=PRODUCER['rowBytes'] or sha(raw)!=PRODUCER['rowSHA256']:
        raise ValueError('original producer row raw bytes differ')
    if (row.get('schema')!='polaris-upstream-native-receipt-v1' or row.get('sourceCommit')!=PRODUCER['commit']
            or row.get('sourceTree')!=PRODUCER['tree'] or row.get('version')!='1.15.0-polaris-alpha.12.3'
            or row.get('goVersion')!='go1.27.2' or row.get('target')!='linux/amd64'
            or row.get('variant',{}).get('linkage')!='shared-purego'
            or row.get('finalPackageCronetSmoke') is not None):
        raise ValueError('original producer profile differs')
    for fact, checks in [(row.get('archive',{}), {'name':PRODUCER['archiveName'],'sha256':PRODUCER['archiveSHA256'],'bytes':PRODUCER['archiveBytes']}),
                         (row.get('core',{}), {'member':'sing-box','sha256':PRODUCER['coreSHA256'],'bytes':PRODUCER['coreBytes']}),
                         (row.get('sidecar',{}), {'member':'libcronet.so','sha256':PRODUCER['sidecarSHA256'],'bytes':PRODUCER['sidecarBytes']})]:
        if any(fact.get(k)!=v for k,v in checks.items()): raise ValueError('original carrier member identity differs')


ERROR_CATEGORIES = {
    'go_nil_pointer': b'panic: runtime error: invalid memory address or nil pointer dereference',
    'go_index_bounds': b'panic: runtime error: index out of range',
    'go_slice_bounds': b'panic: runtime error: slice bounds out of range',
    'go_negative_waitgroup': b'panic: sync: negative WaitGroup counter',
    'go_concurrent_map': b'fatal error: concurrent map writes',
    'go_deadlock': b'fatal error: all goroutines are asleep - deadlock!',
    'native_close_incomplete': b'sing-box did not closed properly',
    'runtime_graph_cleanup_incomplete': b'runtime resource cleanup remains unconfirmed',
    'close_observer_deadline': b'context deadline exceeded',
    'close_context_canceled': b'context canceled',
    'runtime_reference_cleanup_incomplete': b'runtime reference observer cleanup incomplete',
    'runtime_owned_cleanup_incomplete': b'completion unknown',
    'runtime_device_close_incomplete': b'device shutdown did not complete',
    'runtime_scope_close_panic': b'panic during close:',
    'runtime_owner_close_panic': b'resource close panic:',
    'cleanup_snapshot_encoding_unavailable': b'runtime cleanup snapshot encoding unavailable',
    'native_close_timeout': b'sing-box did not close!',
    'tls_unknown_ca': b'certificate signed by unknown authority',
    'http_auth407': b'status: 407', 'http_auth401': b'unexpected status: 401',
    'http_path404': b'unexpected status: 404',
    'quic_idle_timeout': b'timeout: no recent network activity',
    'connection_refused': b'connection refused', 'connection_reset': b'connection reset by peer',
}
_SOURCE_SYMBOLS = None
_EXCEPTION_MESSAGES = None


def safe_exception(error):
    global _EXCEPTION_MESSAGES
    if _EXCEPTION_MESSAGES is None:
        allowed=set()
        for name in ('protocol_peer.py','protocol_peer_diagnostic.py'):
            tree=ast.parse(Path(__file__).with_name(name).read_text())
            for node in ast.walk(tree):
                if (isinstance(node,ast.Call) and isinstance(node.func,ast.Name)
                        and node.func.id in {'ValueError','RuntimeError','EOFError','TimeoutError','ConnectionError','IdentityFailure'}
                        and node.args and isinstance(node.args[0],ast.Constant) and isinstance(node.args[0].value,str)):
                    allowed.add(node.args[0].value)
        _EXCEPTION_MESSAGES=allowed
    message=str(error)
    return message if message in _EXCEPTION_MESSAGES else 'non-public exception details withheld'


def source_symbols(root):
    global _SOURCE_SYMBOLS
    if _SOURCE_SYMBOLS is None:
        modules={}
        for module in root.rglob('go.mod'):
            match=re.search(r'^module\s+([A-Za-z0-9_./-]+)',module.read_text(errors='replace'),re.M)
            if match:modules[module.parent]=match[1]
        names={}; files=set()
        for file in root.rglob('*.go'):
            if file.is_symlink(): continue
            parents=[p for p in file.parents if p in modules]
            if not parents: continue
            module_root=parents[0];relative=file.parent.relative_to(module_root).as_posix()
            package=modules[module_root]+('/'+relative if relative!='.' else '')
            for receiver,name in re.findall(r'^func\s+(?:\(([^\n)]*)\)\s+)?([A-Za-z_]\w*)',file.read_text(errors='replace'),re.M):
                if receiver:
                    typ=re.search(r'(\*?[A-Za-z_]\w*)(?:\[[^\]]*\])?\s*$',receiver)
                    if not typ:continue
                    symbol=package+'.('+typ[1]+').'+name
                else:symbol=package+'.'+name
                names.setdefault(symbol,set()).add(file.name)
            files.add(file.name)
        _SOURCE_SYMBOLS=(names,files)
    return _SOURCE_SYMBOLS


CLEANUP_COUNT_CAP = 1000000


def validate_cleanup_snapshot(value):
    """Exact finite schema; no arbitrary strings, extra keys or unbounded counts."""
    def obj(item, keys):
        return type(item) is dict and set(item) == set(keys.split())
    def count(item, maximum=CLEANUP_COUNT_CAP):
        return type(item) is int and 0 <= item <= maximum
    def flags(item, names):
        return all(type(item[name]) is bool for name in names.split())
    if not obj(value, 'schema atomic available preparing phase done failed truncated resourceCount resources connections reference'):
        return False
    if value['schema'] != 'runtime-cleanup-v1' or value['atomic'] is not False:
        return False
    if not flags(value, 'available preparing done failed truncated') or not count(value['phase'], 8) or not count(value['resourceCount']):
        return False
    resources = value['resources']
    if type(resources) is not list or len(resources) != 10:
        return False
    for item in resources:
        if not obj(item, 'owners unavailable states references dependencies endpointPhases endpointFailures ownerFailures'):
            return False
        if not all(count(item[key]) for key in ('owners', 'unavailable', 'references', 'dependencies', 'endpointFailures', 'ownerFailures')):
            return False
        for name, length in [('states', 4), ('endpointPhases', 8)]:
            if type(item[name]) is not list or len(item[name]) != length or not all(count(n) for n in item[name]):
                return False
    conn = value['connections']
    if not obj(conn, 'available closed tasks physical') or not flags(conn, 'available closed') or not count(conn['tasks']) or not count(conn['physical']):
        return False
    ref = value['reference']
    if not obj(ref, 'available started stopping busy pauses quarantined failed setupDone workerDone stoppedDone'):
        return False
    return (flags(ref, 'available started stopping busy failed setupDone workerDone stoppedDone')
            and count(ref['pauses']) and count(ref['quarantined']))


def cleanup_snapshot_observations(raw):
    observations, rejected = [], 0
    for line in raw.splitlines():
        marker = b'runtime cleanup snapshot: '
        if marker not in line:
            continue
        encoded = line.split(marker, 1)[1]
        # Generated fixtures disable color; reject anything outside exact JSON.
        if len(encoded) > 16384 or len(observations) >= 4:
            rejected += 1
            continue
        try:
            # Duplicate keys are not an exact source-generated snapshot.
            def unique_pairs(pairs):
                item = {}
                for key, value in pairs:
                    if key in item:
                        raise ValueError('duplicate cleanup snapshot key')
                    item[key] = value
                return item
            value = json.loads(encoded, object_pairs_hook=unique_pairs)
        except (ValueError, UnicodeError, RecursionError):
            rejected += 1
            continue
        if validate_cleanup_snapshot(value):
            observations.append(value)
        else:
            rejected += 1
    return observations, min(rejected, CLEANUP_COUNT_CAP)


def safe_log_observation(raw, root):
    """Emit enumerated source-derived classifications, never arbitrary log lines."""
    result={'sha256':sha(raw),'bytes':len(raw),'categories':[], 'goFrames':[],
            'panicMarker':bool(re.search(rb'^panic:',raw,re.M)),
            'fatalMarker':bool(re.search(rb'^fatal error:',raw,re.M))}
    for code, fixed in ERROR_CATEGORIES.items():
        position=raw.lower().find(fixed.lower())
        if position>=0: result['categories'].append({'category':code,'byteOffset':position})
    codes=root/'third_party/cronet-go/net_error_generated.go'
    if codes.is_file():
        for name,message in re.findall(r'\{NetError\w+, "(ERR_[A-Z0-9_]+)", "([a-z0-9 -]+)"',codes.read_text()):
            # Only fixed messages from the pinned source can become categories.
            for fixed in (name.encode(),message.encode()):
                if len(fixed)<8: continue
                found=re.search(rb'(?<![a-z0-9_])'+re.escape(fixed.lower())+rb'(?=$|[\r\n.,;:)]| \()',raw.lower())
                if found:
                    result['categories'].append({'category':name,'byteOffset':found.start()}); break
    if result['panicMarker'] or result['fatalMarker']:
        names,files=source_symbols(root); pending=None
        for line in raw.decode('utf-8',errors='replace').splitlines():
            # No arguments, pointer values or directory prefixes are emitted.
            match=re.match(r'^(github\.com/[A-Za-z0-9_./-]+\.(?:\(\*?[A-Za-z0-9_]+\)\.)?[A-Za-z_]\w*(?:\.func\d+)*)(?:\[[^\]]*\])?\(',line)
            if match and len(match[1])<=192:
                symbol=re.sub(r'(?:\.func\d+)+$','',match[1])
                if symbol in names:
                    pending=(match[1],names[symbol]);continue
            location=re.match(r'^\s+[^\r\n]*[/\\]([A-Za-z_][A-Za-z0-9_]*\.go):(\d+)(?:\s+\+0x[0-9a-f]+)?$',line)
            if pending and location and location[1] in pending[1]:
                result['goFrames'].append({'symbol':pending[0],'file':location[1],'line':int(location[2])})
                if len(result['goFrames'])>=48: break
            pending=None
    result['cleanupSnapshots'], result['cleanupSnapshotsRejected'] = cleanup_snapshot_observations(raw)
    result['unknownTextRetained']=False
    return result


def event(events, stage, **values):
    if not re.fullmatch(r'[a-z][a-z0-9_.-]{0,79}',stage): raise ValueError('invalid fixed diagnostic stage')
    item={'stage':stage,'monotonicSeconds':time.monotonic(),**values}
    if events is not None: events.append(item)
    return item


def safe_to_continue(case):
    if case.get('identityUncertain') or case.get('cleanupErrors') or not case.get('fixturesJoined'):
        return False
    if case.get('descendantRetirement') != {'remaining':[],'forcedKill':False,'retired':[]}:
        return False
    if not case.get('portsReleased') or not all(p.get('released') is True for p in case['portsReleased']):
        return False
    for child in case.get('cleanup',[]):
        if (not isinstance(child,dict) or child.get('exitCode')!=0 or child.get('forcedKill')
                or child.get('remainingGroup')!=[] or child.get('cleanupErrorLog') is not False): return False
        identity=child.get('startIdentity')
        if (not isinstance(identity,dict) or type(identity.get('startTicks')) is not int or identity['startTicks']<=0
                or type(child.get('pid')) is not int or child['pid']<=0 or identity.get('pid')!=child['pid']
                or identity.get('pgrp')!=child['pid'] or identity.get('session')!=child['pid']
                or child.get('boundCoreSHA256')!=case.get('expectedCoreSHA256')
                or not re.fullmatch(r'[0-9a-f]{64}',child.get('boundCoreSHA256') or '')):return False
    return True
