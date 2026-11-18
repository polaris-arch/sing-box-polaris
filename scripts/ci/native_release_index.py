#!/usr/bin/env python3
"""Native archive helpers for the controlled peer and private local producer."""
import json,os,re,subprocess,sys,tarfile,tempfile,time,zipfile
from contextlib import contextmanager
from pathlib import Path,PurePosixPath

def run(*args,cwd=None):return subprocess.check_output(args,text=True,cwd=cwd).strip()
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

ROOT = Path(__file__).resolve().parents[2]


def trusted_execution_definition():
 # The native schema owns the vocabulary shared with the private local lane.
 return json.loads((ROOT/'release/ci/native-release-index.schema.json').read_text(encoding='utf-8'))['$defs']['linuxTrustedExecution']


def derive_local_trusted_execution(row, proof, context, source_root):
 """Private local producer entry. Never accepts or invents workflow identity.

 Developer compilation selects its lane; this closed context is provenance,
 not a signature, credential, or a replacement for Formal workflow admission.
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
 schema=json.loads((ROOT/'release/ci/native-release-index.schema.json').read_text(encoding='utf-8'))
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
