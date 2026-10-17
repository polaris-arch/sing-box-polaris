#!/usr/bin/env python3
"""Collect actual native archives and assemble run-bound index; never invent smoke/release facts."""
import argparse,gzip,hashlib,io,json,os,platform,re,shlex,subprocess,tarfile,tempfile,zipfile
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
 matrices=json.loads(Path('release/ci/upstream-matrices.json').read_text())['matrices']['build.yml']
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
  (d/('native-row-'+row['id']+'.json')).write_text(json.dumps(row,indent=2)+'\n');row_count+=1
 if row_count!=1:raise ValueError(f'expected one native archive, got {row_count}')
 for glob,expected in [('*.deb',int('debian' in matrix)),('*.rpm',int('rpm' in matrix)),('*.pkg.tar.zst',int('pacman' in matrix)),('*_linux_*.apk',int('alpine' in matrix)),('*.ipk',len(matrix.get('openwrt','').split())),('*_openwrt_*.apk',len(matrix.get('openwrt','').split()))]:
  if len(list(d.glob(glob)))!=expected:raise ValueError('package inventory mismatch '+glob)

def smoke(directory):
 d=Path(directory);rows=list(d.glob('native-row-*.json'))
 if len(rows)!=1:raise ValueError('smoke requires exactly one native row')
 row=json.loads(rows[0].read_text());p=d/row['archive']['name'];root,members=read_archive(p)
 if sha(p.read_bytes())!=row['archive']['sha256']:raise ValueError('archive changed')
 pins=json.loads(Path('release/polaris-candidate-inputs.json').read_text())
 if Path('.github/CRONET_GO_VERSION').read_text().strip()!=pins['wrapperCommit']:raise ValueError('Cronet smoke pin mismatch')
 with tempfile.TemporaryDirectory() as td:
  if root!=row['archive']['root'] or {root+'/'+k for k in members}!=set(row['archive']['members']):raise ValueError('archive member inventory changed')
  for name,data in members.items():
   if sha(data)!=row['archive']['members'][root+'/'+name]:raise ValueError('member changed')
  for name,data in members.items():(Path(td)/name).write_bytes(data)
  core=Path(td)/row['core']['member'];core.chmod(0o755)
  from tls_fingerprint_probe import probe, producer_module_identities
  modules=producer_module_identities(row['buildGraph'])
  probe(core,source=row['sourceCommit'],version=row['version'],go_version=row['goVersion'],target=row['target'],expected_sha=row['core']['sha256'],expected_modules=modules)
  args=[str(core),'tools','cronet','--expected-version',pins['cronetVersion']]
  if row['sidecar']:args+=['--library',str(Path(td)/row['sidecar']['member']),'--sha256',row['sidecar']['sha256']]
  observed=json.loads(run(*args,cwd=td))
  expected_os,expected_arch=row['target'].split('/')
  for k,v in [('os',expected_os),('arch',expected_arch),('go',row['goVersion']),('linkage',row['variant']['linkage']),('gvisorCompiled',True),('version',pins['cronetVersion'])]:
   if observed.get(k)!=v:raise ValueError('Cronet smoke mismatch '+k)
  if row['sidecar'] and observed.get('sha256')!=row['sidecar']['sha256']:raise ValueError('Cronet sidecar mismatch')
  if 'with_naive_outbound' not in row['tags'].split(','):raise ValueError('Naive tag missing')
  row['finalPackageCronetSmoke']={'status':'passed','os':expected_os,'arch':expected_arch,'go':observed['go'],'gvisorCompiled':True,'naiveOutbound':True,'linkage':observed['linkage'],'version':observed['version'],'librarySha256':row['sidecar']['sha256'] if row['sidecar'] else None,'coreSha256':row['core']['sha256']}
 rows[0].write_text(json.dumps(row,indent=2)+'\n')

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
 inputs=['go.mod','go.sum','.gitmodules','.github/go-toolchains.json',
         'release/ci/client-overlays.json','release/ci/distribution-materials.json',
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
 toolchain=json.loads((root/'.github/go-toolchains.json').read_text())
 inputs += [x['patch'] for x in toolchain['legacy'].values()]+[toolchain['iosCPU']['patch']]
 catalog=json.loads((root/'release/ci/distribution-materials.json').read_text())
 eligible=validate_distribution_assessment(catalog)
 selection=json.loads((root/'release/ci/current44-notice-mappings.json').read_text())
 notice_bytes=(root/selection['noticeBundle']['path']).read_bytes()
 if sha(notice_bytes)!=selection['noticeBundle']['sha256']:raise ValueError('current notice bundle hash mismatch')
 for notice in selection['noticeRecords']:
  data=notice_bytes[notice['byteOffset']:notice['byteOffset']+notice['bytes']]
  if len(data)!=notice['bytes'] or sha(data)!=notice['sha256']:raise ValueError('current notice slice hash mismatch')
 runtime=json.loads((root/'release/dependency-sources/clients/runtime/index.json').read_text())
 recipes=json.loads((root/'release/dependency-sources/clients/runtime/recipe-index.json').read_text())
 ghostty=json.loads((root/'release/dependency-sources/clients/runtime/ghostty-native/index.json').read_text())
 android=json.loads((root/'release/dependency-sources/clients/runtime/android-resolved/source-notice-map.json').read_text())
 if android.get('concreteUnresolvedMaterials')!=[]:raise ValueError('unresolved actual Android source/notice materials')
 for record in runtime['noticeTexts']+recipes+ghostty['noticeFiles']+ghostty['recipeFiles']+android['noticeFiles']+android['materialFiles']:
  name=record['path']
  if not isinstance(name,str) or not name.startswith(('release/licenses/clients/runtime/','release/dependency-sources/clients/runtime/recipes/','release/dependency-sources/clients/runtime/ghostty-native/recipes/','release/dependency-sources/clients/runtime/android-resolved/')) or '..' in Path(name).parts:
   raise ValueError('invalid shared client material path')
  data=(root/name).read_bytes()
  if ('bytes' in record and len(data)!=record['bytes']) or sha(data)!=record['sha256']:
   raise ValueError('shared client runtime material identity mismatch')
 old_sources=json.loads((root/'release/polaris-public-source-inputs.json').read_text())['modules']
 current_sources=json.loads((root/'release/ci/current-module-sources.json').read_text())['delta']
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
 rows={}
 for p in d.rglob('native-row-*.json'):
  r=json.loads(p.read_text());old=rows.get(r['id'])
  if old:
   copy=dict(r);copy['finalPackageCronetSmoke']=old['finalPackageCronetSmoke']
   if copy!=old:raise ValueError('conflicting native receipt')
   if r['finalPackageCronetSmoke'] is None:continue
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
 for row in rows.values():row['archive']['releaseName']=public_product_name(row['archive']['name'])
 index={'schema':'polaris-upstream-native-assets-v1' if final else 'polaris-upstream-native-staging-v1','repository':REPO,'repositoryId':RID,'version':v,'tag':tag,'tagObject':tag_object,'sourceCommit':commit,'sourceTree':tree,'producer':{'repository':REPO,'repositoryId':RID,'workflow':workflow,'workflowCommit':os.environ['GITHUB_WORKFLOW_SHA'],'runId':int(os.environ['GITHUB_RUN_ID']),'runAttempt':int(os.environ['GITHUB_RUN_ATTEMPT']),'nativeJobs':native_jobs},'legalFiles':legal,'sourceArchive':{'name':source.name,'bytes':source.stat().st_size,'sha256':sha(source.read_bytes())},'platforms':sorted(rows.values(),key=lambda r:r['id'])}
 index['distributionMaterials']=distribution_materials(index)
 if final:
  verify_checkout(tag,commit,tag_object)
  import jsonschema
  jsonschema.Draft202012Validator(json.loads(Path('release/ci/native-release-index.schema.json').read_text())).validate(index)
 (d/'polaris-upstream-native-assets.json').write_text(json.dumps(index,indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('mode',choices=['collect','smoke','assemble']);p.add_argument('directory');a=p.parse_args()
 if a.mode=='collect':collect(a.directory,json.loads(os.environ['NATIVE_MATRIX']))
 elif a.mode=='smoke':smoke(a.directory)
 else:assemble(a.directory)
