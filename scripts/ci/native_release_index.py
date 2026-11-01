#!/usr/bin/env python3
"""Collect actual native archives and assemble run-bound index; never invent smoke/release facts."""
import argparse,gzip,hashlib,io,json,os,platform,re,shlex,subprocess,sys,tarfile,tempfile,time,zipfile
from contextlib import contextmanager,ExitStack
from pathlib import Path,PurePosixPath
from polaris_version import validate as validate_version
from release_identity import verify_checkout, public_product_name
REPO='polaris-arch/sing-box-polaris';RID=1421657509

def sha(b):return hashlib.sha256(b).hexdigest()
def run(*args,cwd=None):return subprocess.check_output(args,text=True,cwd=cwd).strip()
def git(*args):return run('git',*args)
def identity():
 if os.environ.get('GITHUB_REPOSITORY')!=REPO or os.environ.get('GITHUB_REPOSITORY_ID')!=str(RID):raise ValueError('repository mismatch')
 if git('status','--porcelain','--untracked-files=no'):raise ValueError('tracked source is dirty')
 return git('rev-parse','HEAD'),git('rev-parse','HEAD^{tree}')
def read_archive(p):
 out={};roots=set();folded=set()
 def add(name,data):
  if '\\' in name or ':' in name or '\0' in name:raise ValueError('unsafe Windows archive member '+name)
  n=PurePosixPath(name)
  if n.is_absolute() or '..' in n.parts or len(n.parts)!=2 or not n.parts[0].startswith('sing-box-'):raise ValueError('unsafe/non-native archive member '+name)
  for part in n.parts:
   if not re.fullmatch(r'[A-Za-z0-9_+.-]+',part) or part in ('.','..') or part.endswith('.') or re.fullmatch(r'(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?',part):raise ValueError('unsafe portable member '+name)
  key=n.parts[1]
  if name.casefold() in folded:raise ValueError('case-insensitive archive collision')
  folded.add(name.casefold());roots.add(n.parts[0])
  if key in out:raise ValueError('duplicate archive member')
  out[key]=data
 if p.name.endswith('.zip'):
  with zipfile.ZipFile(p) as z:
   for f in z.infolist():
    if f.is_dir():continue
    if (f.external_attr>>16)&0o170000==0o120000:raise ValueError('archive symlink')
    add(f.filename,z.read(f))
 else:
  with tarfile.open(p,'r:gz') as t:
   for f in t:
    if f.isdir():continue
    if not f.isfile():raise ValueError('archive non-regular member')
    add(f.name,t.extractfile(f).read())
 if len(roots)!=1:raise ValueError('archive root count')
 return roots.pop(),out

def buildinfo(core):
 raw=subprocess.check_output(['go','version','-m',str(core)],text=True)
 go=raw.splitlines()[0].rsplit(': ',1)[-1]
 graph={'settings':{},'normalModules':[],'prebuiltAcquisitionModules':[],'localReplacements':[]};last=None
 for line in raw.splitlines()[1:]:
  f=line.strip().split('\t')
  if f[0]=='build':
   k,v=f[1].split('=',1)
   if v.startswith('"'):v=json.loads(v)
   graph['settings'][k]=v
  elif f[0]=='dep':
   last={'module':f[1],'version':f[2] if len(f)>2 else '', 'h1':f[3] if len(f)>3 else ''};graph['normalModules'].append(last)
  elif f[0]=='=>':
   if last is None:raise ValueError('replacement without module')
   graph['normalModules'].remove(last);last['replacement']={'module':f[1],'version':f[2] if len(f)>2 else '', 'h1':f[3] if len(f)>3 else ''};graph['localReplacements'].append(last)
 for x in list(graph['normalModules']):
  if x['module'].startswith('github.com/sagernet/cronet-go/lib/'):
   graph['normalModules'].remove(x);graph['prebuiltAcquisitionModules'].append(x)
 return go,raw,graph

def source_module_hashes():
 hashes={}
 for name,key in [('go.mod','goModSha256'),('go.sum','goSumSha256')]:
  actual=Path(name).read_bytes()
  committed=subprocess.check_output(['git','show','HEAD:'+name])
  if actual!=committed:raise ValueError(name+' working-tree bytes differ from HEAD blob')
  hashes[key]=sha(actual)
 return hashes

def validate_archived_source_identity(rows,source_tar,commit):
 expected=source_module_hashes();prefix='sing-box-polaris-source-'+commit+'/'
 with tarfile.open(fileobj=io.BytesIO(source_tar),mode='r:') as archive:
  archived={key:sha(archive.extractfile(prefix+name).read()) for name,key in [('go.mod','goModSha256'),('go.sum','goSumSha256')]}
 if archived!=expected:raise ValueError('archived module bytes differ from checked source')
 for row in rows:
  identity=row.get('sourceIdentity',{})
  if any(identity.get(key)!=value for key,value in archived.items()):raise ValueError('native row module identity differs from archived source: '+row['id'])

def source_identity():
 hashes=source_module_hashes()
 mod=json.loads(run('go','mod','edit','-json'));replacements=[]
 for r in mod.get('Replace',[]) or []:
  new=r['New']
  if new.get('Version'):continue
  path=new['Path']
  if not path.startswith('./') or '..' in PurePosixPath(path).parts:raise ValueError('non-repository local replacement')
  replacements.append({'module':r['Old']['Path'],'path':path,'tree':git('rev-parse','HEAD:'+path[2:])})
 return {'sourceOverlay':0,**hashes,'replacements':replacements}

def expected_native(version):
 validate_version(version)
 matrices=json.loads(Path('release/ci/upstream-matrices.json').read_text(encoding='utf-8'))['matrices']['build.yml']
 result={}
 for job in ['build','build_darwin','build_windows']:
  for matrix in matrices[job]['include']:
   m=dict(matrix);m['os']=m.get('os') or ('darwin' if job=='build_darwin' else 'windows')
   osname=m['os'];name=f"sing-box-{version}-{osname}-{m['arch']}"
   if m.get('goarm'):name+='v'+str(m['goarm'])
   elif m.get('go386') and m['go386']!='sse2':name+='-'+m['go386']
   elif m.get('gomips') and m['gomips']!='hardfloat':name+='-'+m['gomips']
   elif m.get('legacy_name'):name+='-legacy-'+m['legacy_name']
   if m.get('variant') in ('glibc','musl'):name+='-'+m['variant']
   naive=m.get('naive',False) or (osname=='darwin' and not m.get('legacy_osx'))
   linkage='shared-purego' if naive and (m.get('variant')=='purego' or osname=='windows') else ('static-cgo' if naive else 'other')
   variant={'linkage':linkage,'libc':m.get('variant','') if m.get('variant') in ('glibc','musl') else '', 'goarm':str(m.get('goarm','')),'gomips':str(m.get('gomips','')),'go386':str(m.get('go386','')),'legacy':bool(m.get('legacy_osx') or m.get('legacy_win7'))}
   if name in result:raise ValueError('duplicate expected archive identity')
   result[name]={'target':osname+'/'+m['arch'],'variant':variant,'matrix':m}
 if len(result)!=44:raise ValueError('baseline native matrix no longer has 44 unique rows')
 return result

ROOT = Path(__file__).resolve().parents[2]


def trusted_execution_definition():
 # The native schema owns the vocabulary; all producer/publisher calls use this validator.
 return json.loads((ROOT/'release/ci/native-release-index.schema.json').read_text())['$defs']['linuxTrustedExecution']


def execution_run():
 values = [os.environ.get('GITHUB_RUN_ID', ''), os.environ.get('GITHUB_RUN_ATTEMPT', '')]
 if any(not re.fullmatch('[1-9][0-9]*', value) for value in values):
  raise ValueError('sealed execution requires actual workflow run/attempt')
 return dict(zip(('runId', 'runAttempt'), map(int, values)))


def derive_trusted_execution(row, proof, producer, source_root=ROOT):
 """Formal workflow admission retains its original schema and run authority."""
 import jsonschema
 schema = json.loads((ROOT/'release/ci/native-release-index.schema.json').read_text())
 kind = 'macosExecution' if isinstance(proof,dict) and proof.get('schema') == 'polaris-macos-native-execution-proof-v1' else 'sealedExecution'
 jsonschema.Draft202012Validator(schema['$defs'][kind]).validate(proof)
 for key in ('runId', 'runAttempt'):
  if type(producer[key]) is not int or type(proof[key]) is not int or proof[key] != producer[key]:
   raise ValueError('sealed execution workflow run/attempt differs')
 return _derive_macos_execution_facts(row, proof, source_root) if kind == 'macosExecution' else _derive_execution_facts(row, proof, source_root)


def derive_local_trusted_execution(row, proof, context, source_root):
 """Private local producer entry. Never accepts or invents workflow identity.

 Developer compilation selects its lane; this closed context is provenance,
 not a signature, credential, or a replacement for the Formal wrapper above.
 """
 import jsonschema
 keys={'schema','coreSource','producerSource','host'}
 if type(context) is not dict or set(context)!=keys or context['schema']!='polaris-local-development-execution-context-v1':
  raise ValueError('local execution context differs')
 def source(value, path):
  if type(value) is not dict or set(value)!={'commit','tree'} or any(type(value[k]) is not str or not re.fullmatch('[0-9a-f]{40}',value[k]) for k in value):
   raise ValueError('local source identity differs')
  actual={'commit':run('git','-C',str(path),'rev-parse','HEAD'),'tree':run('git','-C',str(path),'rev-parse','HEAD^{tree}')}
  if value!=actual or run('git','-C',str(path),'status','--porcelain','--untracked-files=no'):
   raise ValueError('local source checkout differs or is dirty')
 source(context['coreSource'], source_root)
 source(context['producerSource'], ROOT)
 if context['host']!={'os':'linux','arch':'amd64'} or row['sourceCommit']!=context['coreSource']['commit'] or row['sourceTree']!=context['coreSource']['tree']:
  raise ValueError('local native host/Core source differs')
 # Reuse every existing fact property's exact schema. Run/attempt are not
 # defaulted, stripped from a Formal receipt, or fabricated for this lane.
 schema=json.loads((ROOT/'release/ci/native-release-index.schema.json').read_text())
 properties=schema['$defs']['sealedExecution']['properties']
 facts=set(properties)-{'runId','runAttempt'}
 if type(proof) is not dict or set(proof)!=facts:
  raise ValueError('local execution facts differ or contain workflow identity')
 for key in facts:
  jsonschema.Draft202012Validator({'$defs':schema['$defs'],**properties[key]}).validate(proof[key])
 return _derive_execution_facts(row, proof, source_root)


def _derive_execution_facts(row, proof, source_root):
 from tls_fingerprint_probe import validate, validate_configuration_checks, producer_module_identities
 for value in [proof.get('coreSeals'),proof.get('sidecarSeals'),proof.get('tlsProbe',{}).get('coreBytes'),proof.get('cronet',{}).get('libraryBytes')]:
  if type(value) is not int or value<=0:raise ValueError('sealed execution exact quantity type differs')
 for key in ('core','sidecar'):
  for obj in (row[key],proof[key]):
   if type(obj) is not dict or type(obj.get('bytes')) is not int or obj['bytes']<=0:
    raise ValueError('sealed execution exact member byte type differs')
 if row['target'] != 'linux/amd64' or row['variant']['linkage'] != 'shared-purego' or row['variant']['legacy'] or row['variant']['libc']:
  raise ValueError('trusted execution exact-object platform is unsupported')
 settings = row['buildGraph']['settings']
 tags = set(row['tags'].split(','))
 if (settings.get('GOOS'), settings.get('GOARCH'), settings.get('CGO_ENABLED')) != ('linux','amd64','0') or set(settings.get('-tags','').split(',')) != tags or not {'with_purego','with_naive_outbound','with_utls','with_gvisor'} <= tags:
  raise ValueError('sealed execution actual Go build settings differ')
 if settings.get('vcs.revision', row['sourceCommit']) != row['sourceCommit'] or settings.get('vcs.modified', 'false') != 'false':
  raise ValueError('sealed execution Go source identity differs')
 if row['core'].get('member') != 'sing-box' or not row['sidecar'] or row['sidecar'].get('member') != 'libcronet.so':
  raise ValueError('sealed execution requires the selected Linux core and sidecar')
 for key in ('sourceCommit', 'sourceTree', 'version', 'target'):
  if proof[key] != row[key]: raise ValueError('sealed execution source/target binding differs: '+key)
 if proof['archiveSha256'] != row['archive']['sha256'] or proof['core'] != row['core'] or proof['sidecar'] != row['sidecar']:
  raise ValueError('sealed execution final package bytes differ')
 for pin in (row['core'], row['sidecar']):
  if not pin or row['archive']['members'].get(row['archive']['root']+'/'+pin['member']) != pin['sha256']:
   raise ValueError('sealed execution archive member binding differs')
 receipt = proof['tlsProbe']
 if set(receipt['capabilities']['buildTags'].split(',')) != tags:
  raise ValueError('sealed execution capability/Go tags differ')
 if receipt['coreSHA256'] != row['core']['sha256'] or receipt['coreBytes'] != row['core']['bytes']:
  raise ValueError('sealed TLS core identity differs')
 validate(receipt['capabilities'], source=row['sourceCommit'], version=row['version'], go_version=row['goVersion'],
          target=row['target'], expected_modules=producer_module_identities(row['buildGraph']), source_root=source_root)
 validate_configuration_checks(receipt['capabilities'], receipt['configurationChecks'])
 observed = proof['cronet']
 expected = {'os':'linux', 'arch':'amd64', 'go':row['goVersion'], 'linkage':'shared-purego',
             'gvisorCompiled':True, 'sha256':row['sidecar']['sha256'], 'libraryBytes':row['sidecar']['bytes'],
             'librarySelection':'captured-sealed-fd'}
 if any(type(observed.get(k)) is not type(v) or observed[k] != v for k,v in expected.items()):
  raise ValueError('captured sealed Cronet observation differs')
 if not re.fullmatch('/proc/self/fd/[0-9]+', observed['library']):
  raise ValueError('captured Cronet object observation is not an owned FD')
 smoke = row['finalPackageCronetSmoke']
 if not smoke or any(smoke.get(k) != v for k,v in {
     'status':'passed','os':'linux','arch':'amd64','go':row['goVersion'],'gvisorCompiled':True,
     'naiveOutbound':True,'linkage':'shared-purego','version':observed['version'],
     'librarySha256':row['sidecar']['sha256'],'coreSha256':row['core']['sha256']}.items()):
  raise ValueError('sealed execution and native smoke differ')
 definition = trusted_execution_definition()['properties']
 return {'schema':definition['schema']['const'], 'sourceCommit':row['sourceCommit'], 'sourceTree':row['sourceTree'],
         'loader':definition['loader']['const'], 'purposes':list(definition['purposes']['items']['enum'])}



def macos_native_row(row):
    target = row['target']
    if target not in ('darwin/amd64', 'darwin/arm64') or type(row['variant'].get('legacy')) is not bool or row['variant'] != {
        'linkage':'static-cgo', 'libc':'', 'goarm':'', 'gomips':'', 'go386':'', 'legacy':False
    } or row['sidecar'] is not None or row['core']['member'] != 'sing-box':
        raise ValueError('Mac execution requires a modern thin static-CGO Core without sidecar')
    validate_version(row['version'])
    if type(row['archive']['bytes']) is not int or row['archive']['bytes'] <= 0: raise ValueError('Mac exact archive byte type differs')
    settings = row['buildGraph']['settings']; tags = row['tags'].split(',')
    if ((settings.get('GOOS'), settings.get('GOARCH'), settings.get('CGO_ENABLED')) !=
        ('darwin', target.split('/')[1], '1') or len(tags) != len(set(tags)) or
        set(settings.get('-tags','').split(',')) != set(tags) or
        not {'with_naive_outbound','with_utls','with_gvisor'} <= set(tags) or
        {'with_purego','with_cronet_purego'} & set(tags)):
        raise ValueError('Mac actual Go target/tags differ')
    tokens = shlex.split(settings.get('-ldflags','')); values = {}; i = 0
    while i < len(tokens):
        token = tokens[i]; i += 1
        if token == '-X':
            if i == len(tokens): raise ValueError('Mac truncated Go source flags')
            assignment = tokens[i]; i += 1
        elif token.startswith('-X='): assignment = token[3:]
        else: continue
        key, separator, value = assignment.partition('=')
        if not separator or key in values: raise ValueError('Mac ambiguous Go source flags')
        values[key] = value
    for key, value in [('SourceRevision',row['sourceCommit']), ('Version',row['version'])]:
        if values.get('github.com/sagernet/sing-box/constant.'+key) != value:
            raise ValueError('Mac compiled source/version binding differs: '+key)
    if settings.get('vcs.revision',row['sourceCommit']) != row['sourceCommit'] or settings.get('vcs.modified','false') != 'false':
        raise ValueError('Mac dirty or mismatched Go source')
    return target.split('/')[1]


def macos_loader_metadata(data, arch):
    """The closed thin-Mach-O profile also enforced by the Mac private factory.

    This is static loader acceptance, not proof of root birth, custody or wait.
    """
    import struct
    if len(data) < 32 or arch not in ('amd64','arm64'):
        raise ValueError('Mac truncated or unsupported native header')
    magic,cpu,_,kind,count,size,_,_ = struct.unpack_from('<8I',data)
    if magic != 0xfeedfacf or cpu != {'amd64':0x01000007,'arm64':0x0100000c}[arch] or kind != 2 or not 0 < count <= 4096 or size > 1024*1024 or 32+size > len(data):
        raise ValueError('Mac thin native execution graph differs')
    offset = 32; end = offset+size; signature = None; dyld = None; libraries = []
    def name(command, minimum):
        if len(command) < minimum: raise ValueError('Mac truncated loader command')
        start = struct.unpack_from('<I',command,8)[0]
        if start < minimum or start >= len(command): raise ValueError('Mac loader name offset differs')
        raw = command[start:]; zero = raw.find(b'\0')
        if zero < 0: raise ValueError('Mac unterminated loader name')
        value = raw[:zero].decode('utf-8',errors='strict')
        if not value.startswith('/') or any(part in ('','.', '..') for part in value[1:].split('/')):
            raise ValueError('Mac relative or ambiguous loader name')
        return value
    for _ in range(count):
        if offset+8 > end: raise ValueError('Mac truncated load command')
        command,length = struct.unpack_from('<II',data,offset)
        if length < 8 or length % 8 or offset+length > end: raise ValueError('Mac invalid load command size')
        payload = data[offset:offset+length]
        if command in (0xc,0x80000018,0x8000001f,0x80000023,0x20):
            library = name(payload,24)
            if not library.startswith(('/usr/lib/','/System/Library/')): raise ValueError('Mac non-system dependency needs its own proof')
            libraries.append(library)
        elif command == 0xe:
            if dyld is not None or name(payload,12) != '/usr/lib/dyld': raise ValueError('Mac ambiguous or unsupported dyld')
            dyld = '/usr/lib/dyld'
        elif command == 0x1d:
            if len(payload) != 16 or signature is not None: raise ValueError('Mac ambiguous signature command')
            start,amount = struct.unpack_from('<II',payload,8)
            if not amount or start < end or start+amount > len(data): raise ValueError('Mac invalid post-sign range')
            signature = {'signatureOffset':start,'signatureBytes':amount,'signatureSHA256':sha(data[start:start+amount])}
        elif command not in (0x19,0x2,0xb,0x1b,0x32,0x2a,0x80000028,0x26,0x29,0x80000022,0x80000033,0x80000034,0x24,0x4,0x5):
            raise ValueError('Mac unknown/search/environment/encrypted loader command')
        offset += length
    if offset != end or signature is None or dyld is None: raise ValueError('Mac incomplete signed loader graph')
    return {'arch':arch,'dyld':dyld,'libraries':sorted(set(libraries)),
            'commandsSHA256':sha(data[:end]), **signature}



def macos_native_process():
    # https://developer.apple.com/documentation/apple-silicon/about-the-rosetta-translation-environment
    # ENOENT means native; every other query error remains unsupported.
    import ctypes, errno
    try:
        function = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True).sysctlbyname
    except (OSError, AttributeError) as error:
        raise ValueError('Mac native translation state is unavailable') from error
    function.argtypes = [ctypes.c_char_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_size_t),ctypes.c_void_p,ctypes.c_size_t]
    function.restype = ctypes.c_int
    value = ctypes.c_int(); size = ctypes.c_size_t(ctypes.sizeof(value))
    result = function(b'sysctl.proc_translated',ctypes.byref(value),ctypes.byref(size),None,0)
    if result == -1 and ctypes.get_errno() == errno.ENOENT: return True
    if result != 0 or size.value != ctypes.sizeof(value) or value.value not in (0,1):
        raise ValueError('Mac native translation state is unknown')
    return value.value == 0

@contextmanager
def macos_postsign_observer(core, row):
    """Hold the original producer input across all native observations/probes.

    Held-FD/namespace checks detect producer-input drift; they are not a frozen
    execution object. Runtime root private-factory consumption is a separate gate.
    """
    import stat
    arch = macos_native_row(row)
    if platform.system() != 'Darwin' or {'arm64':'arm64','x86_64':'amd64'}.get(platform.machine()) != arch:
        raise ValueError('Mac post-sign proof requires the matching actual native host')
    if not macos_native_process(): raise ValueError('Mac translated execution cannot provide native proof')
    if any(key.startswith(('DYLD_','LD_')) for key in os.environ): raise ValueError('Mac ambient loader overrides are unsupported')
    fd = os.open(core,os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        def stamp(value): return (value.st_dev,value.st_ino,value.st_mode,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
        def current():
            if stamp(os.fstat(fd)) != stamp(before) or stamp(os.lstat(core)) != stamp(before):
                raise ValueError('Mac post-sign object/namespace changed')
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != row['core']['bytes']:
            raise ValueError('Mac final Core object differs')
        with os.fdopen(os.dup(fd),'rb') as stream: data = stream.read()
        if sha(data) != row['core']['sha256']: raise ValueError('Mac final post-sign digest differs')
        metadata = macos_loader_metadata(data, arch)
        def observe():
            current()
            go,_,graph = buildinfo(core)
            if go != row['goVersion'] or graph != row['buildGraph'] or run('go','tool','buildid',str(core)) != row['buildID']:
                raise ValueError('Mac actual post-sign Go metadata differs')
            current()
            verified = subprocess.run(['/usr/bin/codesign','--verify','--strict',str(core)],capture_output=True,text=True,timeout=30)
            displayed = subprocess.run(['/usr/bin/codesign','--display','--verbose=4',str(core)],capture_output=True,text=True,timeout=30)
            hashes = re.findall(r'^CDHash=([0-9a-f]{40})$',displayed.stderr,re.M)
            if verified.returncode != 0 or displayed.returncode != 0 or len(hashes) != 1:
                raise ValueError('Mac actual strict signature verification failed')
            expected = {'state':'signed','cdHash':hashes[0],'trustValidated':False}
            if row['signatureObservation'] != expected: raise ValueError('Mac collected signature differs from final bytes')
            current(); os.lseek(fd,0,os.SEEK_SET)
            with os.fdopen(os.dup(fd),'rb') as stream: after = stream.read()
            current()
            if after != data: raise ValueError('Mac post-sign bytes changed during observation')
            return {'coreSHA256':sha(after),'coreBytes':len(after),'cdHash':hashes[0],
                    'signatureVerified':True,'nativeLoader':metadata}
        yield observe
    finally:
        os.close(fd)


def observe_macos_postsign(core, row):
    with macos_postsign_observer(core, row) as observe:
        return observe()


def _derive_macos_execution_facts(row, proof, source_root):
    from tls_fingerprint_probe import validate, validate_configuration_checks, producer_module_identities
    arch = macos_native_row(row)
    for key in ('sourceCommit','sourceTree','version','target'):
        if proof[key] != row[key]: raise ValueError('Mac source/target binding differs: '+key)
    if proof['archiveSha256'] != row['archive']['sha256'] or proof['core'] != row['core']:
        raise ValueError('Mac final package bytes differ')
    for pin in (row['core'],proof['core']):
        if type(pin['bytes']) is not int or pin['bytes'] <= 0: raise ValueError('Mac exact Core byte type differs')
    if row['archive']['members'].get(row['archive']['root']+'/'+row['core']['member']) != row['core']['sha256']:
        raise ValueError('Mac archive member binding differs')
    post = proof['postSign']; native = post['nativeLoader']
    if post['coreSHA256'] != row['core']['sha256'] or type(post['coreBytes']) is not int or post['coreBytes'] != row['core']['bytes']:
        raise ValueError('Mac post-sign Core binding differs')
    if row['signatureObservation'] != {'state':'signed','cdHash':post['cdHash'],'trustValidated':False} or native['arch'] != arch:
        raise ValueError('Mac post-sign signature/native architecture differs')
    if any(type(native[k]) is not int or native[k] <= 0 for k in ('signatureOffset','signatureBytes')) or native['signatureOffset']+native['signatureBytes'] > post['coreBytes']:
        raise ValueError('Mac post-sign exact signature range differs')
    for library in native['libraries']:
        if any(part in ('','.', '..') for part in library[1:].split('/')) or not library.startswith(('/usr/lib/','/System/Library/')):
            raise ValueError('Mac dependency closure differs')
    receipt = proof['tlsProbe']
    if receipt['coreSHA256'] != row['core']['sha256'] or type(receipt['coreBytes']) is not int or receipt['coreBytes'] != row['core']['bytes'] or set(receipt['capabilities']['buildTags'].split(',')) != set(row['tags'].split(',')):
        raise ValueError('Mac capability/Core binding differs')
    validate(receipt['capabilities'],source=row['sourceCommit'],version=row['version'],go_version=row['goVersion'],
             target=row['target'],expected_modules=producer_module_identities(row['buildGraph']),source_root=source_root)
    validate_configuration_checks(receipt['capabilities'],receipt['configurationChecks'])
    cronet = proof['cronet']; smoke = row['finalPackageCronetSmoke']
    pins = json.loads((Path(source_root)/'release/polaris-candidate-inputs.json').read_text())
    if cronet['version'] != pins['cronetVersion']: raise ValueError('Mac source-owned Cronet version differs')
    expected = {'os':'darwin','arch':arch,'go':row['goVersion'],'linkage':'static-cgo','gvisorCompiled':True}
    if any(type(cronet.get(k)) is not type(v) or cronet[k] != v for k,v in expected.items()): raise ValueError('Mac native Cronet observation differs')
    expected.update(status='passed',naiveOutbound=True,version=cronet['version'],librarySha256=None,coreSha256=row['core']['sha256'])
    if not smoke or any(type(smoke.get(k)) is not type(v) or smoke[k] != v for k,v in expected.items()): raise ValueError('Mac native smoke and proof differ')
    return {'schema':'polaris-trusted-execution-v1','sourceCommit':row['sourceCommit'],'sourceTree':row['sourceTree'],
            'loader':'macos-root-private-v1','purposes':['check-config-v1','run-main-v1']}

def validate_trusted_execution(row, producer, source_root=ROOT):
 smoke = row.get('finalPackageCronetSmoke')
 keys = [key for key in ('sealedExecution','macosExecution') if isinstance(smoke,dict) and key in smoke]
 if len(keys) > 1: raise ValueError('ambiguous native execution proofs')
 proof = smoke[keys[0]] if keys else None
 present = 'trustedExecution' in row
 has_proof = bool(keys)
 if not has_proof and not present: return None # historical/unsupported rows never acquire authority
 if proof is None or not present: raise ValueError('trusted execution requires both policy and native sealed proof')
 expected = derive_trusted_execution(row, proof, producer, source_root)
 if row['trustedExecution'] != expected:
  raise ValueError('trusted execution policy differs from native proof')
 return expected


def collect(directory,matrix):
 commit,tree=identity();d=Path(directory);row_count=0
 for p in sorted(d.iterdir()):
  if not p.name.startswith('sing-box-') or not p.name.endswith(('.tar.gz','.zip')):continue
  root,members=read_archive(p);expected=expected_native(os.environ['VERSION']).get(root)
  if expected is None:raise ValueError('archive absent from exact upstream matrix')
  core_name='sing-box.exe' if 'sing-box.exe' in members else 'sing-box'
  core=members[core_name];side_name=next((x for x in ['libcronet.so','libcronet.dll'] if x in members),None)
  with tempfile.TemporaryDirectory() as td:
   cp=Path(td)/core_name;cp.write_bytes(core)
   go,raw,graph=buildinfo(cp);bid=run('go','tool','buildid',str(cp));sig=None
   if platform.system()=='Darwin' and graph['settings'].get('GOOS')=='darwin':
    o=subprocess.run(['codesign','-d','--verbose=4',str(cp)],capture_output=True,text=True);m=re.search(r'CDHash=([a-f0-9]{40})',o.stderr)
    sig={'state':'signed' if o.returncode==0 else 'unsigned','cdHash':m.group(1) if m else None,'trustValidated':False}
  settings=graph['settings'];tags=settings.get('-tags','');osname=settings['GOOS'];arch=settings['GOARCH']
  linkage='shared-purego' if side_name else ('static-cgo' if settings.get('CGO_ENABLED')=='1' and 'with_naive_outbound' in tags.split(',') else 'other')
  variant={'linkage':linkage,'libc':matrix.get('variant','') if osname=='linux' and matrix.get('variant') in ('glibc','musl') else '', 'goarm':str(matrix.get('goarm','')),'gomips':str(matrix.get('gomips','')),'go386':str(matrix.get('go386','')),'legacy':bool(matrix.get('legacy_win7') or matrix.get('legacy_osx'))}
  if osname!=os.environ['NATIVE_OS'] or arch!=matrix['arch']:raise ValueError('binary GOOS/GOARCH differs from matrix')
  if expected['target']!=osname+'/'+arch or expected['variant']!=variant:raise ValueError('native archive variant differs from exact upstream matrix')
  if variant['legacy']:
   from legacy_binary_version import minimum_version
   print('LEGACY_PLATFORM_HEADER '+json.dumps({'target':osname+'/'+arch,'coreSHA256':sha(core),'observation':minimum_version(core,osname),'oldOSRuntimeValidated':False}),flush=True)
  for key,value in [('GOARM',matrix.get('goarm')),('GO386',matrix.get('go386')),('GOMIPS64' if '64' in arch else 'GOMIPS',matrix.get('gomips'))]:
   if value is not None and settings.get(key,'').split(',')[0]!=str(value):raise ValueError('binary setting differs from matrix: '+key)
  def fact(name):return {'member':name,'bytes':len(members[name]),'sha256':sha(members[name])}
  row={'schema':'polaris-upstream-native-receipt-v1','id':p.name.removesuffix('.tar.gz').removesuffix('.zip'),'target':osname+'/'+arch,'variant':variant,'version':os.environ['VERSION'],'tag':'v'+os.environ['VERSION'],'sourceCommit':commit,'sourceTree':tree,'goVersion':go,'tags':tags,'buildID':bid,'rawBuildInfo':raw,'buildGraph':graph,'sourceIdentity':source_identity(),'archive':{'name':p.name,'bytes':p.stat().st_size,'sha256':sha(p.read_bytes()),'root':root,'members':{root+'/'+k:sha(v) for k,v in members.items()}},'core':fact(core_name),'sidecar':fact(side_name) if side_name else None,'signatureObservation':sig,'finalPackageCronetSmoke':None}
  validate_trusted_execution(row, {})
  (d/('native-row-'+row['id']+'.json')).write_text(json.dumps(row,indent=2)+'\n', encoding='utf-8', newline='\n');row_count+=1
 if row_count!=1:raise ValueError(f'expected one native archive, got {row_count}')
 for glob,expected in [('*.deb',int('debian' in matrix)),('*.rpm',int('rpm' in matrix)),('*.pkg.tar.zst',int('pacman' in matrix)),('*_linux_*.apk',int('alpine' in matrix)),('*.ipk',len(matrix.get('openwrt','').split())),('*_openwrt_*.apk',len(matrix.get('openwrt','').split()))]:
  if len(list(d.glob(glob)))!=expected:raise ValueError('package inventory mismatch '+glob)

def cleanup_smoke_directory(directory):
 """Retry only Windows sharing/lock violations, never turn failed cleanup into PASS."""
 started=time.monotonic();attempt=0
 while True:
  attempt+=1
  try:
   directory.cleanup()
   if os.path.lexists(directory.name):raise OSError('smoke temporary directory remains after cleanup')
   return
  except OSError as error:
   code=getattr(error,'winerror',None);elapsed=time.monotonic()-started
   retry=os.name=='nt' and code in (32,33) and elapsed<5.0
   print(f'smoke cleanup attempt={attempt} winerror={code} elapsed={elapsed:.3f}s retry={retry}',file=sys.stderr)
   if not retry:raise
   time.sleep(min(0.1*(2**min(attempt-1,2)),5.0-elapsed))

@contextmanager
def smoke_temp_directory():
 directory=tempfile.TemporaryDirectory()
 try:
  yield directory.name
 except BaseException as body_error:
  try:cleanup_smoke_directory(directory)
  except Exception as cleanup_error:
   # Preserve the original probe failure and its traceback; do not print paths.
   body_error.add_note(f'smoke cleanup also failed: {type(cleanup_error).__name__}, winerror={getattr(cleanup_error,"winerror",None)}')
  raise
 else:
  cleanup_smoke_directory(directory)

def smoke(directory):
 d=Path(directory);rows=list(d.glob('native-row-*.json'))
 if len(rows)!=1:raise ValueError('smoke requires exactly one native row')
 row=json.loads(rows[0].read_text(encoding='utf-8'));p=d/row['archive']['name'];root,members=read_archive(p)
 if sha(p.read_bytes())!=row['archive']['sha256']:raise ValueError('archive changed')
 pins=json.loads(Path('release/polaris-candidate-inputs.json').read_text(encoding='utf-8'))
 if Path('.github/CRONET_GO_VERSION').read_text(encoding='utf-8').strip()!=pins['wrapperCommit']:raise ValueError('Cronet smoke pin mismatch')
 # Never reuse a policy/proof from an earlier invocation or different final bytes.
 row.pop('trustedExecution', None)
 protected = platform.system() == 'Linux' and row['target'] == 'linux/amd64' and row['variant']['linkage'] == 'shared-purego' and not row['variant'].get('legacy') and not row['variant'].get('libc')
 protected_mac = platform.system() == 'Darwin' and row['target'] in ('darwin/amd64','darwin/arm64') and not row['variant'].get('legacy')
 with smoke_temp_directory() as td, ExitStack() as observers:
  if root!=row['archive']['root'] or {root+'/'+k for k in members}!=set(row['archive']['members']):raise ValueError('archive member inventory changed')
  for name,data in members.items():
   if sha(data)!=row['archive']['members'][root+'/'+name]:raise ValueError('member changed')
  for name,data in members.items():(Path(td)/name).write_bytes(data)
  core=Path(td)/row['core']['member'];core.chmod(0o755)
  from tls_fingerprint_probe import probe, producer_module_identities
  modules=producer_module_identities(row['buildGraph'])
  proof = None; mac_postsign = None
  if protected_mac:
   context = execution_run()
   if p.stat().st_size != row['archive']['bytes']: raise ValueError('Mac actual archive byte count differs')
   mac_observe = observers.enter_context(macos_postsign_observer(core,row))
   mac_postsign = mac_observe()
  if protected:
   from tls_fingerprint_probe import sealed_execution
   import fcntl
   context = execution_run()
   with sealed_execution(core, Path(td)/row['sidecar']['member'], row['core'], row['sidecar']) as execution:
    receipt = probe(core,source=row['sourceCommit'],version=row['version'],go_version=row['goVersion'],target=row['target'],expected_sha=row['core']['sha256'],expected_modules=modules,execution=execution)
    result = execution.run(['tools','cronet','--expected-version',pins['cronetVersion'],'--sha256',row['sidecar']['sha256']],cwd=td,text=True,capture_output=True,timeout=30)
    if result.returncode != 0: raise ValueError('sealed Cronet native smoke failed: '+result.stderr)
    observed = json.loads(result.stdout)
    proof = {**{key:row[key] for key in ('sourceCommit','sourceTree','version','target')}, **context,
             'archiveSha256':row['archive']['sha256'],'core':row['core'],'sidecar':row['sidecar'],
             'coreSeals':fcntl.fcntl(execution.core_fd, fcntl.F_GET_SEALS),
             'sidecarSeals':fcntl.fcntl(execution.library_fd, fcntl.F_GET_SEALS),
             'tlsProbe':receipt,'cronet':observed}
  else:
   receipt = probe(core,source=row['sourceCommit'],version=row['version'],go_version=row['goVersion'],target=row['target'],expected_sha=row['core']['sha256'],expected_modules=modules)
   args=[str(core),'tools','cronet','--expected-version',pins['cronetVersion']]
   if row['sidecar']:args+=['--library',str(Path(td)/row['sidecar']['member']),'--sha256',row['sidecar']['sha256']]
   observed=json.loads(run(*args,cwd=td))
  if protected_mac:
   after = mac_observe()
   if after != mac_postsign: raise ValueError('Mac post-sign observation changed during native smoke')
   proof = {**{key:row[key] for key in ('sourceCommit','sourceTree','version','target')}, **context,
            'schema':'polaris-macos-native-execution-proof-v1','archiveSha256':row['archive']['sha256'],
            'core':row['core'],'postSign':after,'tlsProbe':receipt,'cronet':observed}
  expected_os,expected_arch=row['target'].split('/')
  for k,v in [('os',expected_os),('arch',expected_arch),('go',row['goVersion']),('linkage',row['variant']['linkage']),('gvisorCompiled',True),('version',pins['cronetVersion'])]:
   if observed.get(k)!=v:raise ValueError('Cronet smoke mismatch '+k)
  if row['sidecar'] and observed.get('sha256')!=row['sidecar']['sha256']:raise ValueError('Cronet sidecar mismatch')
  if 'with_naive_outbound' not in row['tags'].split(','):raise ValueError('Naive tag missing')
  row['finalPackageCronetSmoke']={'status':'passed','os':expected_os,'arch':expected_arch,'go':observed['go'],'gvisorCompiled':True,'naiveOutbound':True,'linkage':observed['linkage'],'version':observed['version'],'librarySha256':row['sidecar']['sha256'] if row['sidecar'] else None,'coreSha256':row['core']['sha256']}
  if proof:
   row['finalPackageCronetSmoke']['macosExecution' if protected_mac else 'sealedExecution'] = proof
   row['trustedExecution'] = derive_trusted_execution(row, proof, context)
   validate_trusted_execution(row, context)
 # No result survives a changed final archive or failed cleanup.
 if sha(p.read_bytes()) != row['archive']['sha256']: raise ValueError('archive changed during native smoke')
 rows[0].write_text(json.dumps(row,indent=2)+'\n', encoding='utf-8', newline='\n')


def validate_distribution_assessment(catalog):
 if not isinstance(catalog,dict) or catalog.get('schema')!=1:
  raise ValueError('invalid current distribution assessment')
 if catalog.get('status') not in ('current-scope-review-required','reviewed-current-scope'):
  raise ValueError('invalid current distribution status')
 if not isinstance(catalog.get('openItems'),list):
  raise ValueError('current distribution assessment requires explicit openItems list')
 for item in catalog['openItems']:
  if not isinstance(item,dict) or not isinstance(item.get('id'),str) or not item['id'] or not isinstance(item.get('detail'),str) or not item['detail']:
   raise ValueError('invalid current distribution open item')
 return catalog['status']=='reviewed-current-scope' and catalog['openItems']==[]


def distribution_materials(index, root=Path('.')):
 """Bind existing shared source/legal assets to actual native bytes; never attest closure."""
 root=Path(root)
 from apple_package_overlays import definition as apple_package_definition
 apple_package_definition(root)
 inputs=['go.mod','go.sum','.gitmodules','.github/go-toolchains.json',
         'release/dependency-sources/sing-vmess-replacement.json',
         'release/dependency-sources/sing-vmess-vision.patch','scripts/ci/vision_source.py',
         'release/ci/client-overlays.json','release/ci/distribution-materials.json',
         'release/ci/apple-swift-package-overlays.json','scripts/ci/apple_package_overlays.py',
         'release/ci/current-module-sources.json','release/polaris-public-source-inputs.json',
         'release/ci/current44-notice-mappings.json','release/licenses/CURRENT44-NOTICE-CANDIDATE.txt',
         'release/dependency-sources/sing-usbip/source-tar-materials-manifest.json',
         'release/dependency-sources/sing-usbip/driver-source-notice-reconciliation.json',
         'release/dependency-sources/ACQUIRE-AND-BUILD-CURRENT.md',
         'release/dependency-sources/gomobile-v0.1.13.json','cmd/internal/build_libbox/main.go',
         'release/dependency-sources/oci/oci-source-notice-map.json',
         'release/dependency-sources/oci/source-acquisition.json',
         'release/dependency-sources/oci/reuse-reference.json','scripts/ci/github_release.py',
         'release/dependency-sources/clients/current-client-sources.json',
         'release/dependency-sources/clients/runtime/index.json',
         'release/dependency-sources/clients/runtime/recipe-index.json',
         'release/dependency-sources/clients/runtime/desugar-2.1.5-source.json',
         'release/dependency-sources/clients/runtime/ghostty-native/index.json',
         'release/dependency-sources/clients/runtime/header-scan/index.json',
         'release/dependency-sources/clients/runtime/notice-observation-scope.json',
         'release/dependency-sources/clients/runtime/android-resolved/source-notice-map.json',
         'release/dependency-sources/clients/runtime/android-resolved/reuse-reference.json',
         'release/dependency-sources/clients/actual-desktop-notice-proof.json',
         'release/dependency-sources/clients/actual-asar-notice-proof.json',
         'release/ci/current44-static-cronet-origin-bindings.json',
         'release/dependency-sources/windivert/current44-inclusion-proof.json',
         'release/dependency-sources/windivert/fixed-source-availability-proof.json',
         'release/dependency-sources/windivert/upstream-release-driver-proof.json',
         'release/polaris-cronet-materials.json','release/polaris-cronet-graph-kernel-materials.json',
         'scripts/ci/client_source.py','scripts/ci/native_release_index.py',
         'scripts/ci/android_runtime_materials.py','scripts/ci/android_runtime_materials.init.gradle',
         'scripts/ci/record_candidate.py','.github/workflows/android-runtime-materials.yml',
         '.github/workflows/build.yml','.github/workflows/linux.yml','.github/workflows/docker.yml']
 if any('trustedExecution' in row for row in index['platforms']):
  inputs += ['scripts/ci/tls_fingerprint_probe.py','release/ci/native-release-index.schema.json',
             'release/ci/native-release-contract.schema.json']
 toolchain=json.loads((root/'.github/go-toolchains.json').read_text(encoding='utf-8'))
 inputs += [x['patch'] for x in toolchain['legacy'].values()]+[toolchain['iosCPU']['patch']]
 catalog=json.loads((root/'release/ci/distribution-materials.json').read_text(encoding='utf-8'))
 eligible=validate_distribution_assessment(catalog)
 selection=json.loads((root/'release/ci/current44-notice-mappings.json').read_text(encoding='utf-8'))
 notice_bytes=(root/selection['noticeBundle']['path']).read_bytes()
 if sha(notice_bytes)!=selection['noticeBundle']['sha256']:raise ValueError('current notice bundle hash mismatch')
 for notice in selection['noticeRecords']:
  data=notice_bytes[notice['byteOffset']:notice['byteOffset']+notice['bytes']]
  if len(data)!=notice['bytes'] or sha(data)!=notice['sha256']:raise ValueError('current notice slice hash mismatch')
 runtime=json.loads((root/'release/dependency-sources/clients/runtime/index.json').read_text(encoding='utf-8'))
 recipes=json.loads((root/'release/dependency-sources/clients/runtime/recipe-index.json').read_text(encoding='utf-8'))
 ghostty=json.loads((root/'release/dependency-sources/clients/runtime/ghostty-native/index.json').read_text(encoding='utf-8'))
 android=json.loads((root/'release/dependency-sources/clients/runtime/android-resolved/source-notice-map.json').read_text(encoding='utf-8'))
 if android.get('concreteUnresolvedMaterials')!=[]:raise ValueError('unresolved actual Android source/notice materials')
 for record in runtime['noticeTexts']+recipes+ghostty['noticeFiles']+ghostty['recipeFiles']+android['noticeFiles']+android['materialFiles']:
  name=record['path']
  if not isinstance(name,str) or not name.startswith(('release/licenses/clients/runtime/','release/dependency-sources/clients/runtime/recipes/','release/dependency-sources/clients/runtime/ghostty-native/recipes/','release/dependency-sources/clients/runtime/android-resolved/')) or '..' in Path(name).parts:
   raise ValueError('invalid shared client material path')
  data=(root/name).read_bytes()
  if ('bytes' in record and len(data)!=record['bytes']) or sha(data)!=record['sha256']:
   raise ValueError('shared client runtime material identity mismatch')
 old_sources=json.loads((root/'release/polaris-public-source-inputs.json').read_text(encoding='utf-8'))['modules']
 current_sources=json.loads((root/'release/ci/current-module-sources.json').read_text(encoding='utf-8'))['delta']
 source_key=lambda x:(x['module'],x['version'],x.get('h1',''))
 pinned_sources={source_key(x):x for x in old_sources}
 current_sources={source_key(x):x for x in current_sources}
 modules={}; native=[]; missing_materials=[]
 notice_components={(x['module'],x.get('version'),x.get('h1')):x for x in selection['components'] if 'version' in x}
 def module_id(item):
  return sha(json.dumps(item,sort_keys=True,separators=(',',':')).encode())
 def module_record(item):
  # Go BuildInfo labels both local and remote replacements as localReplacements.
  actual=item.get('replacement',item)
  m=dict(actual)
  if m['module'].startswith('./'):
   m['delivery']='tracked-source-archive'
  else:
   if not m.get('version') or not m.get('h1'):raise ValueError('unbound external module source')
   escape=lambda x: ''.join('!'+c.lower() if c.isupper() else c for c in x)
   m['sourceURL']='https://proxy.golang.org/'+escape(m['module'])+'/@v/'+escape(m['version'])+'.zip'
   m['delivery']='fixed-module-source-location'
   m['availabilityVerified']=False
   key=source_key(m)
   if key not in pinned_sources and key not in current_sources:
    missing_materials.append({'module':m['module'],'version':m['version'],'h1':m['h1'],'reason':'no exact source acquisition input'})
   if key in notice_components:
    m['noticeRecordIndexes']=notice_components[key].get('noticeRecordIndexes',[])
   else:
    missing_materials.append({'module':m['module'],'version':m['version'],'h1':m['h1'],'reason':'no exact notice component mapping'})
   if key in pinned_sources:
    source=pinned_sources[key]
    m['sourceArchive']={k:source[k] for k in ('zipUrl','zipBytes','zipSha256')}
    m['sourceEvidence']='release/polaris-public-source-inputs.json (exact module/version/h1 match; historical acquisition)'
   if key in current_sources:
    source=current_sources[key]
    m['sourceEvidence']='release/ci/current-module-sources.json'
    m['availabilityVerified']=source.get('verifiedH1')==m['h1']
    m['publicMetadataAvailable']=source.get('publicInfo',{}).get('fullGetVerified',False)
    if source.get('verifiedH1')==m['h1']:
     m['sourceArchive']={k:source[k] for k in ('zipUrl','zipBytes','zipSha256')}
     m['noticeFiles']=source.get('noticeFiles',[])
  if 'replacement' in item:m['replaces']={k:v for k,v in item.items() if k!='replacement'}
  key=module_id(m);modules[key]=m;return key
 for row in sorted(index['platforms'],key=lambda x:x['id']):
  if row['sourceCommit']!=index['sourceCommit'] or row['sourceTree']!=index['sourceTree']:
   raise ValueError('mixed source material binding')
  if row['goVersion']!='go'+toolchain['version']:
   missing_materials.append({'toolchain':row['goVersion'],'reason':'actual toolchain differs from source-owned current material version'})
  graph=row['buildGraph']
  ids=sorted({module_record(m) for kind in ['normalModules','prebuiltAcquisitionModules','localReplacements'] for m in graph[kind]})
  native.append({'archive':row['archive']['name'],'archiveSHA256':row['archive']['sha256'],
                 'coreSHA256':row['core']['sha256'],'goVersion':row['goVersion'],
                 'modules':ids,'localSourceIdentity':row['sourceIdentity'],
                 'cronetSidecar':row['sidecar'],
                 'windivertSourceEvidence':'release/dependency-sources/windivert/' if row['target'] in ('windows/386','windows/amd64') and 'with_external_windivert' not in row['tags'].split(',') else None,
                 'repositoryNoticePaths':['licenses/repository-components/JA3-LICENSE'] +
                     (['licenses/repository-components/WINDIVERT-LICENSE.txt'] if row['target'] in ('windows/386','windows/amd64') and 'with_external_windivert' not in row['tags'].split(',') else [])})
  if 'trustedExecution' in row:
   native[-1]['trustedExecutionSHA256']=sha(json.dumps(row['trustedExecution'],sort_keys=True,separators=(',', ':')).encode())
   proof_key='macosExecution' if 'macosExecution' in row['finalPackageCronetSmoke'] else 'sealedExecution'
   native[-1][proof_key+'SHA256']=sha(json.dumps(row['finalPackageCronetSmoke'][proof_key],sort_keys=True,separators=(',', ':')).encode())
 return {'schema':'polaris-distribution-materials-v1','sourceCommit':index['sourceCommit'],
         'sourceTree':index['sourceTree'],'sourceArchive':index['sourceArchive'],
         'sourceURL':'https://github.com/'+REPO+'/tree/'+index['sourceCommit'],
         'toolchain':toolchain,'inputs':{p:sha((root/p).read_bytes()) for p in sorted(set(inputs))},
         'legalFiles':{x['path']:x['sha256'] for x in index['legalFiles']},
         'modules':dict(sorted(modules.items())),'nativeArchives':native,
         'noticeSelection':{'path':'release/ci/current44-notice-mappings.json','sha256':sha((root/'release/ci/current44-notice-mappings.json').read_bytes()),'bundle':selection['noticeBundle']},
         'assessment':catalog,'unmappedMaterialIdentities':[json.loads(x) for x in sorted({json.dumps(x,sort_keys=True) for x in missing_materials})],
         'publicationEligible':eligible and not missing_materials,
         'limitations':['This binding proves identity and association, not license/source closure.',
                        'The kernel source archive does not expand client gitlinks.',
                        'Module h1 is a Go directory checksum, not a downloaded ZIP SHA256.',
                        'Historical source/notice evidence remains historical.']}


def assemble(directory):
 commit,tree=identity();d=Path(directory);v=os.environ['VERSION'];tag='v'+v
 final=os.environ.get('REQUIRE_RELEASE_TAG')=='true'
 tag_object=None
 if final:
  expected_object=os.environ.get('EXPECTED_RELEASE_TAG_OBJECT')
  if not expected_object or not re.fullmatch(r'[0-9a-f]{40}',expected_object):raise ValueError('final index requires preflight tag object')
  tag_object=verify_checkout(tag,commit,expected_object)
 context=execution_run()
 rows={}
 for p in d.rglob('native-row-*.json'):
  r=json.loads(p.read_text(encoding='utf-8'));validate_trusted_execution(r, context);old=rows.get(r['id'])
  if old:
   plain=lambda row:{k:v for k,v in row.items() if k not in ('trustedExecution','finalPackageCronetSmoke')}
   if plain(r)!=plain(old):raise ValueError('conflicting native receipt')
   if r['finalPackageCronetSmoke'] is None:continue
   if old['finalPackageCronetSmoke'] is not None and r != old:raise ValueError('conflicting native smoke receipt')
  rows[r['id']]=r
 expected=expected_native(v)
 if set(rows)!=set(expected):raise ValueError('full upstream native index differs from exact 44 expected archive identities')
 for key,r in rows.items():
  if r['target']!=expected[key]['target'] or r['variant']!=expected[key]['variant'] or r['archive']['root']!=key:raise ValueError('assembled native row variant differs from pinned matrix')
 for r in rows.values():
  if (r['sourceCommit'],r['sourceTree'],r['version'])!=(commit,tree,v):raise ValueError('mixed source native receipts')
  matches=list(d.rglob(r['archive']['name']))
  if not matches or any(sha(x.read_bytes())!=r['archive']['sha256'] for x in matches):raise ValueError('native archive hash mismatch')
 # Source archive is the exact committed kernel tree, including tracked replacements/materials.
 source_name=f'sing-box-polaris-source-{commit}.tar.gz';source=d/source_name
 tar=subprocess.check_output(['git','archive','--format=tar','--prefix',f'sing-box-polaris-source-{commit}/',commit])
 validate_archived_source_identity(rows.values(),tar,commit)
 with source.open('wb') as out:
  with gzip.GzipFile(filename='',mode='wb',fileobj=out,mtime=0) as gz:gz.write(tar)
 legal=[]
 for src,dest in [('LICENSE','licenses/LICENSE'),('release/licenses/NOTICE','licenses/NOTICE')]:
  data=Path(src).read_bytes();legal.append({'path':dest,'content':data.decode(),'bytes':len(data),'sha256':sha(data)})
 for p in sorted(Path('release/licenses').rglob('*')):
  if p.is_file() and p.name!='NOTICE':
   data=p.read_bytes();legal.append({'path':'licenses/'+p.relative_to('release/licenses').as_posix(),'content':data.decode(),'bytes':len(data),'sha256':sha(data)})
 dedup={}
 for item in legal:
  old=dedup.get(item['path'])
  if old and old!=item:raise ValueError('conflicting legal file path')
  dedup[item['path']]=item
 legal=list(dedup.values())
 workflow=os.environ['GITHUB_WORKFLOW_REF'].split(REPO+'/',1)[1].split('@',1)[0]
 run_id=os.environ['GITHUB_RUN_ID'];attempt=os.environ['GITHUB_RUN_ATTEMPT']
 pages=json.loads(run('gh','api','--paginate','--slurp',f'repos/{REPO}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100'))
 jobs=[j for page in pages for j in page['jobs']];native_jobs={}
 for key,ident in [('linux','linux-amd64-purego'),('win','windows-amd64'),('mac-x64','darwin-amd64'),('mac-arm64','darwin-arm64')]:
  name=f'Native final-package Cronet and gVisor smoke ({ident})'
  matches=[j for j in jobs if j['name']==name and j.get('conclusion')=='success' and j.get('status')=='completed' and j.get('head_sha')==commit and str(j.get('run_id'))==run_id and str(j.get('run_attempt'))==attempt]
  if len(matches)!=1:raise ValueError('missing unique successful native smoke API evidence: '+name)
  native_jobs[key]={'id':matches[0]['id'],'name':name}
 # Preserve actual candidate names/root/member hashes; publish explicit derivative basenames.
 for row in rows.values():
  validate_trusted_execution(row, context)
  row['archive']['releaseName']=public_product_name(row['archive']['name'])
 index={'schema':'polaris-upstream-native-assets-v1' if final else 'polaris-upstream-native-staging-v1','repository':REPO,'repositoryId':RID,'version':v,'tag':tag,'tagObject':tag_object,'sourceCommit':commit,'sourceTree':tree,'producer':{'repository':REPO,'repositoryId':RID,'workflow':workflow,'workflowCommit':os.environ['GITHUB_WORKFLOW_SHA'],'runId':int(os.environ['GITHUB_RUN_ID']),'runAttempt':int(os.environ['GITHUB_RUN_ATTEMPT']),'nativeJobs':native_jobs},'legalFiles':legal,'sourceArchive':{'name':source.name,'bytes':source.stat().st_size,'sha256':sha(source.read_bytes())},'platforms':sorted(rows.values(),key=lambda r:r['id'])}
 index['distributionMaterials']=distribution_materials(index)
 if final:
  verify_checkout(tag,commit,tag_object)
  import jsonschema
  jsonschema.Draft202012Validator(json.loads(Path('release/ci/native-release-index.schema.json').read_text(encoding='utf-8'))).validate(index)
 (d/'polaris-upstream-native-assets.json').write_text(json.dumps(index,indent=2)+'\n', encoding='utf-8', newline='\n')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('mode',choices=['collect','smoke','assemble']);p.add_argument('directory');a=p.parse_args()
 if a.mode=='collect':collect(a.directory,json.loads(os.environ['NATIVE_MATRIX']))
 elif a.mode=='smoke':smoke(a.directory)
 else:assemble(a.directory)
