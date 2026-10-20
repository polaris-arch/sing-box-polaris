#!/usr/bin/env python3
"""Fail-closed owned distribution gate; configuration contains public identities only."""
import hashlib,json,os,re,subprocess,sys
from pathlib import Path
from release_identity import validate_publication_index, require
REPO='polaris-arch/sing-box-polaris'; REPO_ID='1421657509'
def run(*a):return subprocess.check_output(a,text=True).strip()
def config():
 if os.environ.get('GITHUB_REPOSITORY')!=REPO or os.environ.get('GITHUB_REPOSITORY_ID')!=REPO_ID:raise SystemExit('wrong repository identity')
 p=Path('release/ci/owned-distribution.json')
 if not p.exists():raise SystemExit('BLOCKED: reviewed owned-distribution.json and owned signing identities have not been configured')
 d=json.loads(p.read_text(encoding='utf-8'))
 if d.get('repository')!=REPO or d.get('repositoryId')!=int(REPO_ID) or d.get('reviewed') is not True:raise SystemExit('owned distribution identity configuration is not reviewed')
 return d

def verify_tag():
 config();v=os.environ['VERSION'].removeprefix('v')
 if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?',v):raise SystemExit('invalid version')
 tag='v'+v
 if run('git','cat-file','-t','refs/tags/'+tag)!='tag':raise SystemExit('existing annotated tag required')
 if run('git','rev-parse','refs/tags/'+tag+'^{commit}')!=run('git','rev-parse','HEAD'):raise SystemExit('tag must identify exact built source')
 return tag

def apply(platform):
 d=config();entry=d.get('clientIdentityPatches',{}).get(platform)
 if not entry:raise SystemExit(f'BLOCKED: reviewed owned {platform} client identity patch is required')
 # Replay source-owned compatibility first, then the reviewed identity patch.
 # The same descriptor is consumed by the final client source receipt.
 from client_source import apply as apply_source
 if platform=='desktop':
  job=os.environ.get('GITHUB_JOB')
  if job not in ('build_windows_client','build_linux_client'):raise SystemExit('desktop identity needs an explicit client producer')
  platform='windows' if job=='build_windows_client' else 'linux'
 apply_source(platform,unsigned=False)

def verify_apple():
 d=config();apple=d.get('apple',{})
 if apple.get('credentialMode')!='team':raise SystemExit('this workflow requires an explicitly reviewed owned Apple team API key')
 for name,key in [('POLARIS_ASC_APP_ID','appId'),('POLARIS_ASC_GROUP_ID','groupId'),('POLARIS_ASC_ISSUER_ID','issuerId'),('POLARIS_ASC_KEY_ID','keyId'),('POLARIS_APPLE_APPLICATION_SIGN_IDENTITY','applicationSignIdentity'),('POLARIS_APPLE_INSTALLER_SIGN_IDENTITY','installerSignIdentity')]:
  value=os.environ.get(name,'')
  if not value or value!=apple.get(key):raise SystemExit('reviewed owned Apple identity mismatch: '+key)
 if not re.fullmatch(r'[A-Z0-9]{10}',apple['keyId']):raise SystemExit('owned Apple key ID required')
 for key in ['applicationSignIdentity','installerSignIdentity']:
  if not re.fullmatch(r'[a-fA-F0-9]{40}',apple[key]) or apple[key].upper() in ['34EED4C8F8E609CD5D253D88202A071521D1BE74','21E03A44ACC2B48753BABB3DAE9B5F9A9CFF0480']:raise SystemExit('owned Apple signing certificate fingerprint required')
 if not re.fullmatch(r'[0-9]+',apple['appId']) or apple['appId']=='6785326793':raise SystemExit('owned App Store app ID required')
 for key in ['groupId','issuerId']:
  if not re.fullmatch(r'[a-fA-F0-9-]{36}',apple[key]) or apple[key] in ['00000000-0000-0000-0000-000000000000','39f9ebdc-05d4-421f-9595-dae71df227c4']:raise SystemExit('owned Apple UUID required')

def verify_registry():
 d=config()
 if d.get('registryImage')!='ghcr.io/polaris-arch/sing-box-polaris' or d.get('registryExclusiveWriterReviewed') is not True:raise SystemExit('BLOCKED: reviewed exclusive registry writer policy required; GHCR tag updates are not atomic create-only')

def publish_packages():
 d=config();account=d.get('furyAccount','')
 if not re.fullmatch(r'[a-z0-9][a-z0-9-]{1,63}',account) or account=='sagernet':raise SystemExit('reviewed owned Gemfury account required')
 token=os.environ.get('FURY_TOKEN','')
 if not token:raise SystemExit('owned Gemfury credential is missing')
 files=sorted(Path('dist').glob('*'))
 if not files:raise SystemExit('no signed packages')
 for p in files:
  if p.suffix not in ('.deb','.rpm'):raise SystemExit('unexpected package type')
  subprocess.run(['curl','--fail-with-body','--silent','--show-error','--user',token+':','-F','package=@'+str(p),'https://push.fury.io/'+account+'/'],check=True)

def verify_publication_materials(tag):
 source=run('git','rev-parse','HEAD');tree=run('git','rev-parse','HEAD^{tree}')
 tag_object=run('git','rev-parse','refs/tags/'+tag)
 index=json.loads(Path('dist/polaris-upstream-native-assets.json').read_text(encoding='utf-8'))
 validate_publication_index(index,source,tag,tag_object,tree)
 require((index.get('repository'),index.get('repositoryId'),index.get('version'))==(REPO,int(REPO_ID),tag.removeprefix('v')),'final index repository/version differs')
 materials=index['distributionMaterials'];archive=index.get('sourceArchive')
 require(isinstance(archive,dict) and archive.get('name')=='sing-box-polaris-source-'+source+'.tar.gz','immutable source archive basename required')
 require((materials.get('sourceCommit'),materials.get('sourceTree'),materials.get('sourceArchive'))==(source,tree,archive),'source material binding differs')
 content=(Path('dist')/archive['name']).read_bytes()
 require(archive.get('bytes')==len(content) and archive.get('sha256')==hashlib.sha256(content).hexdigest(),'source archive bytes differ from final index')

def publish():
 tag=verify_tag();verify_publication_materials(tag);env=dict(os.environ,GH_REPO=REPO)
 # An existing release is never changed, including draft releases. A network error also blocks.
 existing=subprocess.run(['gh','api',f'repos/{REPO}/releases/tags/{tag}'],capture_output=True,text=True,env=env)
 if existing.returncode==0:raise SystemExit('release already exists; replacement is forbidden')
 if 'HTTP 404' not in existing.stderr:raise SystemExit('unable to establish that release is absent')
 files=sorted(str(p) for p in Path('dist').iterdir() if p.is_file())
 if not files:raise SystemExit('no artifacts to publish')
 args=['gh','release','create',tag,'--verify-tag','--draft','--title',tag,'--notes','Polaris build from '+run('git','rev-parse','HEAD')]
 if '-' in tag:args+=['--prerelease']
 subprocess.run(args+files,check=True,env=env)
 # Verify remote file identity before making the draft public.
 release=json.loads(subprocess.check_output(['gh','api',f'repos/{REPO}/releases/tags/{tag}'],text=True,env=env))
 expected={Path(f).name:(Path(f).stat().st_size,hashlib.sha256(Path(f).read_bytes()).hexdigest()) for f in files}
 if len(release['assets'])!=len(expected):raise SystemExit('draft asset count mismatch; retained as draft')
 for asset in release['assets']:
  size,digest=expected.get(asset['name'],(None,None))
  if asset['size']!=size or asset.get('digest')!='sha256:'+str(digest):raise SystemExit('draft asset checksum mismatch; retained as draft')
 subprocess.run(['gh','release','edit',tag,'--draft=false'],check=True,env=env)
if __name__=='__main__':
 mode=sys.argv[1]
 if mode=='verify':config()
 elif mode=='verify-tag':verify_tag()
 elif mode=='verify-apple':verify_apple()
 elif mode=='verify-registry':verify_registry()
 elif mode=='apply':apply(sys.argv[2])
 elif mode=='publish':publish()
 elif mode=='publish-packages':publish_packages()
 else:raise SystemExit('unknown operation')
