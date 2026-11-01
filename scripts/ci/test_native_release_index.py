import importlib.util,io,json,tarfile,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
R=Path(__file__).parent
spec=importlib.util.spec_from_file_location('n',R/'native_release_index.py');n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
class TestNative(unittest.TestCase):
 def test_shared_materials_bind_apple_contract_helper_and_original_recipes(self):
  root=R.parent.parent
  index={'sourceCommit':'a'*40,'sourceTree':'b'*40,'sourceArchive':{'name':'synthetic-source'},'platforms':[],'legalFiles':[]}
  material=n.distribution_materials(index,root)
  self.assertNotIn('scripts/ci/tls_fingerprint_probe.py',material['inputs'])
  for path in ('release/ci/apple-swift-package-overlays.json','scripts/ci/apple_package_overlays.py',
               'scripts/ci/client_source.py','release/dependency-sources/clients/runtime/recipe-index.json'):
   self.assertEqual(material['inputs'][path],n.sha((root/path).read_bytes()))
  spec=json.loads((root/'release/ci/apple-swift-package-overlays.json').read_text())
  recipes={r['path']:r for r in json.loads((root/'release/dependency-sources/clients/runtime/recipe-index.json').read_text())}
  for package in spec['packages']:
   self.assertEqual(recipes[package['originalRecipe']]['sha256'],package['beforeSHA256'])
   self.assertNotEqual(package['beforeSHA256'],package['afterSHA256'])
 def archive(self,path,entries):
  with tarfile.open(path,'w:gz') as t:
   for name,data in entries:
    info=tarfile.TarInfo(name);info.size=len(data);t.addfile(info,io.BytesIO(data))
 def test_archive_hashable_members(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'a.tar.gz';self.archive(p,[('sing-box-1.0.0-linux-amd64/LICENSE',b'license'),('sing-box-1.0.0-linux-amd64/sing-box',b'core')]);root,m=n.read_archive(p);self.assertEqual(root,'sing-box-1.0.0-linux-amd64');self.assertEqual(m['sing-box'],b'core')
 def test_traversal_rejected(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'a.tar.gz';self.archive(p,[('sing-box-1/../evil',b'bad')]);self.assertRaises(ValueError,n.read_archive,p)
 def test_duplicate_rejected(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'a.tar.gz';self.archive(p,[('sing-box-1/sing-box',b'a'),('sing-box-1/sing-box',b'b')]);self.assertRaises(ValueError,n.read_archive,p)
 def test_zip_symlink_rejected(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'a.zip'
   with zipfile.ZipFile(p,'w') as z:
    i=zipfile.ZipInfo('sing-box-1/sing-box');i.external_attr=(0o120777<<16);z.writestr(i,'elsewhere')
   self.assertRaises(ValueError,n.read_archive,p)
 def test_windows_paths_rejected(self):
  for member in ['..\\evil','C:\\evil','CON','NUL.txt','endsdot.']:
   with self.subTest(member=member),tempfile.TemporaryDirectory() as td:
    p=Path(td)/'a.tar.gz';self.archive(p,[('sing-box-1/'+member,b'bad')]);self.assertRaises(ValueError,n.read_archive,p)
 def test_casefold_collision_rejected(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'a.tar.gz';self.archive(p,[('sing-box-1/LICENSE',b'a'),('sing-box-1/license',b'b')]);self.assertRaises(ValueError,n.read_archive,p)
 def test_exact_native_matrix(self):
  contract=R.parent.parent/'release/ci/upstream-matrices.json'
  with patch.object(n.Path,'read_text',return_value=contract.read_text()):rows=n.expected_native('1.15.0-polaris-alpha.12')
  self.assertEqual(len(rows),44)
  self.assertEqual(rows['sing-box-1.15.0-polaris-alpha.12-linux-amd64']['variant']['libc'],'')
  self.assertEqual(rows['sing-box-1.15.0-polaris-alpha.12-linux-amd64']['variant']['linkage'],'shared-purego')
  self.assertIn('sing-box-1.15.0-polaris-alpha.12-linux-amd64-musl',rows)
  self.assertIn('sing-box-1.15.0-polaris-alpha.12-windows-amd64-legacy-windows-7',rows)
 def test_buildinfo_multiple_local_replacements(self):
  raw='/tmp/core: go1.26.8\n\tpath\tgithub.com/sagernet/sing-box/cmd/sing-box\n\tdep\tmodule/a\tv1\th1:a\n\t=>\t./third_party/a\t(devel)\t\n\tdep\tmodule/b\tv2\th1:b\n\t=>\t./third_party/b\t(devel)\t\n\tdep\tgithub.com/sagernet/cronet-go/lib/linux_amd64\tv3\th1:c\n\tbuild\tCGO_ENABLED=0\n\tbuild\t-tags=with_gvisor,with_naive_outbound\n'
  with patch.object(n.subprocess,'check_output',return_value=raw):
   go,out,g=n.buildinfo(Path('/tmp/core'))
  self.assertEqual(go,'go1.26.8');self.assertEqual(out,raw);self.assertEqual(len(g['localReplacements']),2);self.assertEqual(len(g['prebuiltAcquisitionModules']),1);self.assertEqual(g['settings']['CGO_ENABLED'],'0')
 def test_branded_version(self):
  self.assertEqual(n.validate_version("1.15.0-polaris-alpha.12"),"1.15.0-polaris-alpha.12")
  for value in ["1.15.0-alpha.12","1.15.0-polaris-alpha12","1.15.0-polaris-alpha.012","../bad"]:
   self.assertRaises(ValueError,n.validate_version,value)
 def test_wrong_repository_rejected(self):
  with patch.dict(n.os.environ,{'GITHUB_REPOSITORY':'other/repo','GITHUB_REPOSITORY_ID':'1421657509'}):self.assertRaises(ValueError,n.identity)
 def module_bytes(self):
  return {'go.mod':b'module example.org/kernel\n\ngo 1.27.2\n','go.sum':b'example.org/dependency v1.0.0 h1:baseline\n'}
 def module_mocks(self,working=None):
  committed=self.module_bytes();actual=committed if working is None else working
  def read(path):return actual[path.name]
  def blob(*args,**kwargs):
   command=args[0]
   self.assertIn(command,[['git','show','HEAD:go.mod'],['git','show','HEAD:go.sum']])
   self.assertNotIn('text',kwargs)
   return committed[command[2][5:]]
  return patch.object(n.Path,'read_bytes',read),patch.object(n.subprocess,'check_output',side_effect=blob)
 def test_module_identity_preserves_exact_lf_blob_bytes(self):
  reads,blobs=self.module_mocks()
  with reads,blobs:self.assertEqual(n.source_module_hashes(),{'goModSha256':n.sha(self.module_bytes()['go.mod']),'goSumSha256':n.sha(self.module_bytes()['go.sum'])})
 def test_module_identity_rejects_crlf_worktree_in_each_file(self):
  for name in self.module_bytes():
   with self.subTest(name=name):
    actual=self.module_bytes();actual[name]=actual[name].replace(b'\n',b'\r\n');reads,blobs=self.module_mocks(actual)
    with reads,blobs:self.assertRaisesRegex(ValueError,name+' working-tree bytes differ',n.source_module_hashes)
 def test_module_identity_rejects_arbitrary_byte_changes_in_each_file(self):
  for name in self.module_bytes():
   for mutation in [lambda data:data+b'\x00',lambda data:data[:-1],lambda data:b'X'+data[1:]]:
    with self.subTest(name=name,mutation=mutation):
     actual=self.module_bytes();actual[name]=mutation(actual[name]);reads,blobs=self.module_mocks(actual)
     with reads,blobs:self.assertRaisesRegex(ValueError,name+' working-tree bytes differ',n.source_module_hashes)
 def test_collector_rejects_changed_module_before_go_parser(self):
  with patch.object(n,'source_module_hashes',side_effect=ValueError('changed module bytes')),patch.object(n,'run') as runner:
   self.assertRaisesRegex(ValueError,'changed module bytes',n.source_identity);runner.assert_not_called()
 def archived_module_fixture(self,overrides=None):
  files=self.module_bytes();files.update(overrides or {});output=io.BytesIO()
  with tarfile.open(fileobj=output,mode='w') as archive:
   for name,data in files.items():
    member=tarfile.TarInfo('sing-box-polaris-source-'+'a'*40+'/'+name);member.size=len(data);archive.addfile(member,io.BytesIO(data))
  hashes={'goModSha256':n.sha(self.module_bytes()['go.mod']),'goSumSha256':n.sha(self.module_bytes()['go.sum'])}
  rows=[{'id':'native-'+str(i),'sourceIdentity':dict(hashes,sourceOverlay=0)} for i in range(44)]
  return rows,output.getvalue()
 def test_assembled_all_44_rows_match_actual_source_tar(self):
  rows,archive=self.archived_module_fixture();reads,blobs=self.module_mocks()
  with reads,blobs:n.validate_archived_source_identity(rows,archive,'a'*40)
 def test_assembled_each_row_rejects_either_module_hash_mismatch(self):
  for position in range(44):
   for key in ['goModSha256','goSumSha256']:
    with self.subTest(position=position,key=key):
     rows,archive=self.archived_module_fixture();rows[position]['sourceIdentity'][key]='f'*64;reads,blobs=self.module_mocks()
     with reads,blobs:self.assertRaisesRegex(ValueError,'native row module identity differs from archived source',n.validate_archived_source_identity,rows,archive,'a'*40)
 def test_assembled_source_tar_rejects_changed_or_crlf_module_bytes(self):
  for name,data in self.module_bytes().items():
   for changed in [data.replace(b'\n',b'\r\n'),data+b'\x00']:
    with self.subTest(name=name,changed=changed):
     rows,archive=self.archived_module_fixture({name:changed});reads,blobs=self.module_mocks()
     with reads,blobs:self.assertRaisesRegex(ValueError,'archived module bytes differ from checked source',n.validate_archived_source_identity,rows,archive,'a'*40)
 def test_assembled_rejects_missing_row_source_identity(self):
  rows,archive=self.archived_module_fixture();del rows[-1]['sourceIdentity'];reads,blobs=self.module_mocks()
  with reads,blobs:self.assertRaisesRegex(ValueError,'native row module identity differs',n.validate_archived_source_identity,rows,archive,'a'*40)
 def test_shared_notice_files_are_text_not_compiled_payloads(self):
  for path in (R.parents[1]/'release/licenses').rglob('*'):
   if path.is_file():
    with self.subTest(path=path):
     path.read_bytes().decode('utf-8')
     self.assertNotEqual(path.suffix.lower(),'.class')
 def test_ghostty_logf_retains_all_original_notice_blocks(self):
  root=R.parents[1]
  index=json.loads((root/'release/dependency-sources/clients/runtime/ghostty-native/index.json').read_text())
  rows=[row for row in index['noticeFiles'] if row['path'].endswith('-logf.c.original-header.txt')]
  self.assertEqual(len(rows),1)
  row=rows[0];data=(root/row['path']).read_bytes()
  self.assertEqual(len(data),515)
  self.assertEqual(n.sha(data),'8321493840d6ffec09121148a782785c0591b42a3a270dfda01b4ce4d5c7aa6b')
  self.assertIn(b'Ian Lance Taylor',data)
  self.assertIn(b'Copyright (C) 1993 by Sun Microsystems',data)
  self.assertIn(b'is preserved.',data)
  self.assertEqual(row['mappings'][0]['byteStart'],0)
  self.assertEqual(row['mappings'][0]['byteEnd'],515)
class TestSmokeCleanup(unittest.TestCase):
 def lock_error(self,code):
  error=PermissionError('locked');error.winerror=code;return error
 def test_windows_sharing_and_lock_violations_retry(self):
  from types import SimpleNamespace
  from unittest.mock import Mock
  for code in (32,33):
   with self.subTest(code=code):
    directory=SimpleNamespace(name='unused',cleanup=Mock(side_effect=[self.lock_error(code),None]))
    with patch.object(n.os,'name','nt'),patch.object(n.os.path,'lexists',return_value=False),patch.object(n.time,'monotonic',side_effect=[0,0.1]),patch.object(n.time,'sleep') as sleep:
     n.cleanup_smoke_directory(directory)
    self.assertEqual(directory.cleanup.call_count,2);sleep.assert_called_once()
 def test_persistent_lock_fails_at_deadline(self):
  from types import SimpleNamespace
  from unittest.mock import Mock
  error=self.lock_error(32);directory=SimpleNamespace(name='unused',cleanup=Mock(side_effect=error))
  with patch.object(n.os,'name','nt'),patch.object(n.time,'monotonic',side_effect=[0,0,5]),patch.object(n.time,'sleep') as sleep:
   with self.assertRaises(PermissionError) as result:n.cleanup_smoke_directory(directory)
  self.assertIs(result.exception,error);self.assertEqual(directory.cleanup.call_count,2);sleep.assert_called_once()
 def test_other_errors_and_non_windows_fail_without_retry(self):
  from types import SimpleNamespace
  from unittest.mock import Mock
  for host,code in [('nt',5),('posix',32),('nt',None)]:
   error=self.lock_error(code);directory=SimpleNamespace(name='unused',cleanup=Mock(side_effect=error))
   with self.subTest(host=host,code=code),patch.object(n.os,'name',host),patch.object(n.time,'sleep') as sleep:
    with self.assertRaises(PermissionError) as result:n.cleanup_smoke_directory(directory)
   self.assertIs(result.exception,error);sleep.assert_not_called()
 def test_body_error_preserved_when_cleanup_also_fails(self):
  body=ValueError('probe failed');cleanup=self.lock_error(32)
  with tempfile.TemporaryDirectory() as name:
   from types import SimpleNamespace
   directory=SimpleNamespace(name=name)
   with patch.object(n.tempfile,'TemporaryDirectory',return_value=directory),patch.object(n,'cleanup_smoke_directory',side_effect=cleanup):
    with self.assertRaises(ValueError) as result:
     with n.smoke_temp_directory():raise body
  self.assertIs(result.exception,body);self.assertIn('winerror=32',body.__notes__[0])
 def test_success_requires_actual_removal(self):
  with n.smoke_temp_directory() as name:
   path=Path(name);(path/'payload').write_text('data');self.assertTrue(path.exists())
  self.assertFalse(path.exists())
 def test_cleanup_return_without_removal_fails(self):
  from types import SimpleNamespace
  from unittest.mock import Mock
  with patch.object(n.os.path,'lexists',return_value=True):
   self.assertRaises(OSError,n.cleanup_smoke_directory,SimpleNamespace(name='unused',cleanup=Mock()))
 def test_smoke_cleanup_failure_does_not_publish_pass_row(self):
  from contextlib import contextmanager
  from types import SimpleNamespace
  with tempfile.TemporaryDirectory() as root,tempfile.TemporaryDirectory() as work:
   d=Path(root);archive=d/'native.zip';archive.write_bytes(b'archive')
   row={'archive':{'name':archive.name,'sha256':n.sha(b'archive'),'root':'sing-box-v','members':{'sing-box-v/sing-box.exe':n.sha(b'core')}},'core':{'member':'sing-box.exe','sha256':n.sha(b'core')},'buildGraph':{},'sourceCommit':'source','version':'version','goVersion':'go1.27.2','target':'windows/amd64','sidecar':None,'variant':{'linkage':'shared-purego'},'tags':'with_naive_outbound','finalPackageCronetSmoke':None}
   row_path=d/'native-row-test.json';original=json.dumps(row);row_path.write_text(original)
   observed={'os':'windows','arch':'amd64','go':'go1.27.2','linkage':'shared-purego','gvisorCompiled':True,'version':'cronet'}
   original_read=Path.read_text
   def read(path,*args,**kwargs):
    if str(path)=='release/polaris-candidate-inputs.json':return json.dumps({'wrapperCommit':'wrapper','cronetVersion':'cronet'})
    if str(path)=='.github/CRONET_GO_VERSION':return 'wrapper'
    return original_read(path,*args,**kwargs)
   @contextmanager
   def failing_cleanup():
    yield work
    raise self.lock_error(32)
   probe=SimpleNamespace(probe=lambda *a,**kw:None,producer_module_identities=lambda graph:{})
   with patch.object(n.Path,'read_text',read),patch.object(n,'read_archive',return_value=('sing-box-v',{'sing-box.exe':b'core'})),patch.object(n,'smoke_temp_directory',failing_cleanup),patch.object(n,'run',return_value=json.dumps(observed)),patch.dict('sys.modules',{'tls_fingerprint_probe':probe}):
    self.assertRaises(PermissionError,n.smoke,str(d))
   self.assertEqual(row_path.read_text(),original)

if __name__=='__main__':unittest.main()

class TestWin7ReceiptMatrix(unittest.TestCase):
 def test_actual_legacy_rows_keep_absent_settings_and_package_inventory(self):
  import os,yaml
  from contextlib import ExitStack
  root=R.parents[1];version=json.loads((root/'release/ci/github-release.json').read_text())['version']
  for workflow in ['build','signed-release']:
   rows=yaml.safe_load((root/'.github/workflows'/f'{workflow}.yml').read_text())['jobs']['build_windows7']['strategy']['matrix']['include']
   for matrix in rows:
    with self.subTest(workflow=workflow,arch=matrix['arch']):
     self.assertEqual(set(matrix),{'os','arch','legacy_win7','legacy_name'})
     name=f"sing-box-{version}-windows-{matrix['arch']}-legacy-windows-7"
     settings={'GOOS':'windows','GOARCH':matrix['arch'],'CGO_ENABLED':'0'}
     if matrix['arch']=='386':settings['GO386']='sse2'
     with tempfile.TemporaryDirectory() as td,ExitStack() as stack:
      with zipfile.ZipFile(Path(td)/(name+'.zip'),'w') as archive:
       archive.writestr(name+'/sing-box.exe',b'fixture-core');archive.writestr(name+'/LICENSE',b'fixture-license')
      stack.enter_context(patch.dict(os.environ,{'VERSION':version,'NATIVE_OS':'windows'}))
      stack.enter_context(patch.object(n,'identity',return_value=('a'*40,'b'*40)))
      stack.enter_context(patch.object(n,'buildinfo',return_value=('go1.27.2','fixture-buildinfo',{'settings':settings})))
      stack.enter_context(patch.object(n,'run',return_value='fixture-buildid'))
      stack.enter_context(patch.object(n,'source_identity',return_value={}))
      stack.enter_context(patch('legacy_binary_version.minimum_version',return_value={'fixture':True}))
      n.collect(td,matrix)
      receipt=json.loads((Path(td)/('native-row-'+name+'.json')).read_text())
      self.assertEqual(receipt['target'],'windows/'+matrix['arch']);self.assertTrue(receipt['variant']['legacy'])
      # These are the exact old failure modes. Exercise the collector, without Go.
      for key in ['debian','rpm','pacman','alpine']:
       with self.assertRaisesRegex(ValueError,'package inventory mismatch'):
        n.collect(td,{**matrix,key:''})
      if matrix['arch']=='386':
       with self.assertRaisesRegex(ValueError,'binary setting differs from matrix: GO386'):
        n.collect(td,{**matrix,'go386':''})


def sealed_row_fixture(source='a'*40, tree='b'*40, version=None):
 """Synthetic source-control receipt, never native acceptance evidence."""
 import tls_fingerprint_probe as tls
 import test_tls_fingerprint_probe as controls
 version=version or json.loads((R.parents[1]/'release/ci/github-release.json').read_text())['version']
 ident='sing-box-'+version+'-linux-amd64'
 graph={'settings':{},'normalModules':[],'prebuiltAcquisitionModules':[],'localReplacements':[]}
 for item in tls.linked_module_pins().values():
  row={'module':item['path'],'version':item['version'],'h1':item['sum']}
  if 'replace' in item:
   r=item['replace'];row['replacement']={'module':r['path'],'version':r['version'],'h1':r['sum']};graph['localReplacements'].append(row)
  else:graph['normalModules'].append(row)
 document=controls.FingerprintProbeControls().fixture();document.update(sourceCommit=source,coreVersion=version)
 checks=[dict(descriptor,exitCode=0 if descriptor['expectedPass'] else 1,output=error or '') for descriptor,_,error in tls.configuration_cases(document)]
 row={'schema':'polaris-upstream-native-receipt-v1','id':ident,'target':'linux/amd64',
      'variant':{'linkage':'shared-purego','libc':'','goarm':'','gomips':'','go386':'','legacy':False},
      'version':version,'tag':'v'+version,'sourceCommit':source,'sourceTree':tree,'goVersion':'go1.27.2',
      'tags':'with_naive_outbound,with_utls,with_gvisor,with_purego','buildID':'synthetic','rawBuildInfo':'synthetic',
      'buildGraph':graph,'sourceIdentity':{'sourceOverlay':0,'goModSha256':'0'*64,'goSumSha256':'1'*64,'replacements':[]},
      'archive':{'name':ident+'.tar.gz','releaseName':n.public_product_name(ident+'.tar.gz'),'bytes':1,'sha256':'2'*64,'root':ident,
                 'members':{ident+'/sing-box':'3'*64,ident+'/libcronet.so':'4'*64}},
      'core':{'member':'sing-box','bytes':7,'sha256':'3'*64},'sidecar':{'member':'libcronet.so','bytes':11,'sha256':'4'*64},'signatureObservation':None}
 graph['settings'].update(GOOS='linux',GOARCH='amd64',CGO_ENABLED='0',**{'-tags':row['tags']})
 document['buildTags']=row['tags']
 cronet_version=json.loads((R.parents[1]/'release/polaris-candidate-inputs.json').read_text())['cronetVersion']
 row['finalPackageCronetSmoke']={'status':'passed','os':'linux','arch':'amd64','go':row['goVersion'],'gvisorCompiled':True,'naiveOutbound':True,
                               'linkage':'shared-purego','version':cronet_version,'librarySha256':'4'*64,'coreSha256':'3'*64}
 proof={**{key:row[key] for key in ('sourceCommit','sourceTree','version','target')},'runId':42,'runAttempt':1,
        'archiveSha256':'2'*64,'core':dict(row['core']),'sidecar':dict(row['sidecar']),'coreSeals':15,'sidecarSeals':15,
        'tlsProbe':{'schema':'polaris-tls-fingerprint-runtime-probe-v1','coreSHA256':'3'*64,'coreBytes':7,'capabilities':document,
                    'configurationChecks':checks,'networkHandshakeValidated':False},
        'cronet':{'os':'linux','arch':'amd64','go':row['goVersion'],'linkage':'shared-purego','library':'/proc/self/fd/17',
                  'sha256':'4'*64,'libraryBytes':11,'librarySelection':'captured-sealed-fd','version':cronet_version,'gvisorCompiled':True}}
 row['finalPackageCronetSmoke']['sealedExecution']=proof
 row['trustedExecution']=n.derive_trusted_execution(row,proof,{'runId':42,'runAttempt':1})
 return row


class TrustedExecutionControls(unittest.TestCase):
 def check(self,row,producer=None):
  return n.validate_trusted_execution(row,producer or {'runId':42,'runAttempt':1})
 def test_native_observation_is_the_only_policy_source(self):
  row=sealed_row_fixture();self.assertEqual(self.check(row),row['trustedExecution'])
  self.assertEqual(set(row['trustedExecution']),{'schema','sourceCommit','sourceTree','loader','purposes'})
  self.assertEqual(len(row['trustedExecution']['purposes']),5)
  del row['trustedExecution'];del row['finalPackageCronetSmoke']['sealedExecution']
  self.assertIsNone(self.check(row))
 def test_policy_and_proof_are_both_required_in_existing_validator(self):
  for missing in ('policy','proof'):
   row=sealed_row_fixture()
   if missing=='policy':del row['trustedExecution']
   else:del row['finalPackageCronetSmoke']['sealedExecution']
   with self.subTest(missing=missing),self.assertRaisesRegex(ValueError,'both policy and native sealed proof'):self.check(row)
 def test_exact_policy_rejects_injection_malformed_source_loader_and_purposes(self):
  mutations=[lambda p:p.update(extra=True),lambda p:p.pop('sourceTree'),lambda p:p.update(sourceCommit='c'*40),
             lambda p:p.update(sourceTree='c'*40),lambda p:p.update(loader='path-loader'),lambda p:p['purposes'].pop(),
             lambda p:p['purposes'].append(p['purposes'][0]),lambda p:p['purposes'].append('invented'),lambda p:p.update(purposes=[])]
  for mutate in mutations:
   row=sealed_row_fixture();mutate(row['trustedExecution'])
   with self.subTest(mutate=mutate),self.assertRaises(ValueError):self.check(row)
 def test_source_run_attempt_and_all_final_object_identities_are_bound(self):
  import copy,jsonschema
  row=sealed_row_fixture()
  mutations=[lambda p:p.update(sourceCommit='c'*40),lambda p:p.update(sourceTree='c'*40),lambda p:p.update(version='other'),
             lambda p:p.update(target='windows/amd64'),lambda p:p.update(runId=43),lambda p:p.update(runAttempt=2),
             lambda p:p.update(archiveSha256='f'*64),lambda p:p['core'].update(sha256='f'*64),lambda p:p['sidecar'].update(sha256='f'*64),
             lambda p:p.update(coreSeals=0),lambda p:p.update(sidecarSeals=0),lambda p:p['tlsProbe'].update(coreBytes=8),
             lambda p:p['tlsProbe']['capabilities'].update(sourceCommit='c'*40),lambda p:p['tlsProbe']['configurationChecks'].pop(),
             lambda p:p['cronet'].update(librarySelection='standalone-path'),lambda p:p['cronet'].update(libraryBytes=12),
             lambda p:p['cronet'].update(sha256='f'*64),lambda p:p['cronet'].update(library='/tmp/original.so')]
  for mutate in mutations:
   candidate=copy.deepcopy(row);mutate(candidate['finalPackageCronetSmoke']['sealedExecution'])
   with self.subTest(mutate=mutate),self.assertRaises((ValueError,jsonschema.ValidationError)):self.check(candidate)
  for key in ('runId','runAttempt'):
   with self.subTest(key=key),self.assertRaises(ValueError):self.check(row,{**{'runId':42,'runAttempt':1},key:True})
 def test_go_graph_tags_and_vcs_identity_cannot_relabel_the_sealed_receipt(self):
  mutations=[lambda r:r['buildGraph']['settings'].update(CG0_ENABLED='1',CGO_ENABLED='1'),
             lambda r:r['buildGraph']['settings'].update(GOOS='darwin'),
             lambda r:r['buildGraph']['settings'].update(**{'-tags':'with_utls'}),
             lambda r:r['buildGraph']['settings'].update(**{'vcs.revision':'f'*40}),
             lambda r:r['buildGraph']['settings'].update(**{'vcs.modified':'true'}),
             lambda r:r['finalPackageCronetSmoke']['sealedExecution']['tlsProbe']['capabilities'].update(buildTags='with_utls')]
  for mutate in mutations:
   row=sealed_row_fixture();mutate(row)
   with self.subTest(mutate=mutate),self.assertRaisesRegex(ValueError,'sealed execution'):self.check(row)
 def test_platform_and_archive_member_mutations_cannot_reuse_proof(self):
  import jsonschema
  for platform in ('darwin/amd64','windows/amd64','linux/arm64'):
   row=sealed_row_fixture();row['target']=platform;row['finalPackageCronetSmoke']['sealedExecution']['target']=platform
   with self.subTest(platform=platform),self.assertRaises((ValueError,jsonschema.ValidationError)):self.check(row)
  row=sealed_row_fixture();row['archive']['members'][row['id']+'/libcronet.so']='f'*64
  self.assertRaisesRegex(ValueError,'archive member binding',self.check,row)
 def test_closed_native_and_consumer_schemas_preserve_five_field_policy(self):
  import copy,jsonschema
  native=json.loads((R.parents[1]/'release/ci/native-release-index.schema.json').read_text())
  consumer=json.loads((R.parents[1]/'release/ci/native-release-contract.schema.json').read_text())
  for name in ('trustedExecution','sealedExecution'):self.assertEqual(native['$defs'][name],consumer['$defs'][name])
  row=sealed_row_fixture()
  for schema,shape in [(native,native['properties']['platforms']['items']), (consumer,consumer['properties']['platforms']['properties']['linux'])]:
   # Existing consumer adds releaseAsset, so exercise its exact shared policy/proof definitions and closed smoke.
   jsonschema.Draft202012Validator({'$defs':schema['$defs'],**schema['$defs']['trustedExecution']}).validate(row['trustedExecution'])
   jsonschema.Draft202012Validator({'$defs':schema['$defs'],**schema['$defs']['sealedExecution']}).validate(row['finalPackageCronetSmoke']['sealedExecution'])
   self.assertFalse(shape['additionalProperties'])
  validator=jsonschema.Draft202012Validator({'$defs':native['$defs'],**native['properties']['platforms']['items']})
  validator.validate(row)
  for missing in ('policy','proof'):
   bad=copy.deepcopy(row)
   if missing=='policy':del bad['trustedExecution']
   else:del bad['finalPackageCronetSmoke']['sealedExecution']
   with self.subTest(missing=missing),self.assertRaises(jsonschema.ValidationError):validator.validate(bad)
 def test_distribution_materials_bind_policy_and_sealed_observation(self):
  row=sealed_row_fixture();index={'sourceCommit':row['sourceCommit'],'sourceTree':row['sourceTree'],
      'sourceArchive':{'name':'synthetic-source'},'platforms':[row],'legalFiles':[]}
  material=n.distribution_materials(index,R.parents[1]);record=material['nativeArchives'][0]
  self.assertEqual(material['inputs']['scripts/ci/tls_fingerprint_probe.py'],n.sha((R.parents[1]/'scripts/ci/tls_fingerprint_probe.py').read_bytes()))
  for field,value in [('trustedExecutionSHA256',row['trustedExecution']),('sealedExecutionSHA256',row['finalPackageCronetSmoke']['sealedExecution'])]:
   self.assertEqual(record[field],n.sha(json.dumps(value,sort_keys=True,separators=(',',':')).encode()))
 def test_real_smoke_entry_uses_two_held_sealed_objects_and_emits_only_after_success(self):
  import copy,os
  import tls_fingerprint_probe as tls
  from types import SimpleNamespace
  row=sealed_row_fixture();data={'sing-box':b'core','libcronet.so':b'library'}
  row['archive']['members']={row['id']+'/'+k:n.sha(v) for k,v in data.items()}
  for pin in (row['core'],row['sidecar']):pin.update(bytes=len(data[pin['member']]),sha256=n.sha(data[pin['member']]))
  proof=row['finalPackageCronetSmoke']['sealedExecution'];receipt=copy.deepcopy(proof['tlsProbe']);receipt.update(coreBytes=row['core']['bytes'],coreSHA256=row['core']['sha256'])
  observed=copy.deepcopy(proof['cronet']);observed.update(sha256=row['sidecar']['sha256'],libraryBytes=row['sidecar']['bytes'])
  row['finalPackageCronetSmoke']=None;row.pop('trustedExecution')
  for fail in (False,True):
   with self.subTest(fail=fail),tempfile.TemporaryDirectory() as directory:
    d=Path(directory);archive=d/row['archive']['name'];archive.write_bytes(b'archive');row['archive']['sha256']=n.sha(b'archive')
    target=d/'native-row-synthetic.json';target.write_text(json.dumps(row));original=target.read_bytes()
    def probe(core,**kwargs):
     execution=kwargs['execution'];self.assertTrue(Path(core).is_file())
     self.assertEqual(os.pread(execution.core_fd,4,0),b'core');self.assertEqual(os.pread(execution.library_fd,7,0),b'library')
     return receipt
    def child(execution,args,**kwargs):
     self.assertNotIn('--library',args);self.assertIn('--sha256',args)
     self.assertTrue(os.fstat(execution.core_fd).st_size);self.assertTrue(os.fstat(execution.library_fd).st_size)
     return SimpleNamespace(returncode=1 if fail else 0,stdout=json.dumps(observed),stderr='synthetic failure')
    # Linux retains actual memfd/seal coverage. Other hosts exercise the same
    # producer entry using explicitly controlled FD/seal observations, not a
    # claim that their kernel implements Linux sealed execution.
    from contextlib import ExitStack, contextmanager
    import fcntl
    with ExitStack() as kernel:
     if not hasattr(os,'memfd_create'):
      @contextmanager
      def controlled_descriptors(core,library,core_pin,library_pin):
       with open(core,'rb') as first,open(library,'rb') as second:
        for stream,pin in [(first,core_pin),(second,library_pin)]:
         payload=stream.read();self.assertEqual(len(payload),pin['bytes']);self.assertEqual(n.sha(payload),pin['sha256']);stream.seek(0)
        yield tls.SealedExecution(first.fileno(),second.fileno())
      kernel.enter_context(patch.object(tls,'sealed_execution',side_effect=controlled_descriptors))
      kernel.enter_context(patch.object(fcntl,'F_GET_SEALS',0x53544,create=True))
      original_fcntl=fcntl.fcntl
      def controlled_seals(fd,operation,*args):
       return 15 if operation==fcntl.F_GET_SEALS else original_fcntl(fd,operation,*args)
      kernel.enter_context(patch.object(fcntl,'fcntl',side_effect=controlled_seals))
     with patch.object(n,'read_archive',return_value=(row['id'],data)),patch.object(n.platform,'system',return_value='Linux'), \
          patch.dict(os.environ,{'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':'1'}),patch.object(tls,'probe',side_effect=probe), \
          patch.object(tls.SealedExecution,'run',autospec=True,side_effect=child):
      if fail:self.assertRaisesRegex(ValueError,'sealed Cronet native smoke failed',n.smoke,d)
      else:n.smoke(d)
    if fail:self.assertEqual(target.read_bytes(),original)
    else:self.check(json.loads(target.read_text()))

class LocalDevelopmentExecutionControls(unittest.TestCase):
 """Source controls only; these synthetic objects are not native evidence."""
 def setUp(self):
  import shutil
  directory=tempfile.TemporaryDirectory(prefix='polaris-local-core-fixture-')
  self.addCleanup(directory.cleanup)
  self.source=Path(directory.name)
  self.assertNotEqual(self.source.resolve(),n.ROOT.resolve())
  def copy(relative):
   relative=Path(relative)
   self.assertFalse(relative.is_absolute())
   self.assertNotIn('..',relative.parts)
   original=n.ROOT/relative;target=self.source/relative
   self.assertTrue(original.is_file())
   self.assertFalse(original.is_symlink())
   target.parent.mkdir(parents=True,exist_ok=True)
   shutil.copyfile(original,target)
  # The real validator reads these files from the selected Core, including
  # the complete source-owned replacement inventory and its original delta.
  manifest_path='release/dependency-sources/metacubex-utls-replacement.json'
  for relative in ['release/ci/tls-fingerprint-capabilities.schema.json',
                   'release/GO_VERSION','option/tls.go','go.mod','go.sum',manifest_path]:
   copy(relative)
  manifest=json.loads((self.source/manifest_path).read_text())
  copy(manifest['patch'])
  for relative in manifest['files']:
   copy(Path(manifest['replacementPath'])/relative)
  self.replacement_patch=self.source/manifest['patch']
 def fixture(self):
  import copy
  row=sealed_row_fixture()
  proof=copy.deepcopy(row['finalPackageCronetSmoke']['sealedExecution'])
  proof.pop('runId');proof.pop('runAttempt')
  context={'schema':'polaris-local-development-execution-context-v1',
           'coreSource':{'commit':'a'*40,'tree':'b'*40},
           'producerSource':{'commit':'c'*40,'tree':'d'*40},'host':{'os':'linux','arch':'amd64'}}
  return row,proof,context
 def derive(self,row,proof,context,dirty=False):
  from unittest.mock import patch
  def git(*args,**kwargs):
   self.assertEqual(args[:2],('git','-C'))
   self.assertIn(Path(args[2]),(self.source,n.ROOT))
   if 'status' in args:return ' M go.mod' if dirty else ''
   identity=context['coreSource'] if args[2]==str(self.source) else context['producerSource']
   return identity['tree' if args[-1]=='HEAD^{tree}' else 'commit']
  with patch.object(n,'run',side_effect=git):return n.derive_local_trusted_execution(row,proof,context,self.source)
 def test_distinct_local_context_reuses_all_exact_facts(self):
  row,proof,context=self.fixture()
  self.assertEqual(self.derive(row,proof,context),row['trustedExecution'])
  self.assertNotEqual(context['coreSource'],context['producerSource'])
  # Prove the independent Core's real material is read, rather than silently
  # validating against producer ROOT or bypassing the replacement validator.
  original=self.replacement_patch.read_bytes()
  try:
   self.replacement_patch.write_bytes(original+b'\n')
   with self.assertRaisesRegex(ValueError,'^source-owned Meta delta digest differs$'):
    self.derive(row,proof,context)
  finally:self.replacement_patch.write_bytes(original)
  import jsonschema
  with self.assertRaises(jsonschema.ValidationError) as rejected:
   n.derive_trusted_execution(row,proof,{'runId':42,'runAttempt':1})
  self.assertEqual(rejected.exception.validator,'required')
  self.assertIn(rejected.exception.message,("'runId' is a required property","'runAttempt' is a required property"))
  print('local source control: independent Core baseline returned exact policy; owned patch tampering rejected; Formal missing-workflow rejection reached')
 def test_workflow_identity_cannot_default_or_enter_local_context(self):
  import copy
  for key in ['runId','runAttempt','validationOnly','publicationEligible']:
   row,proof,context=self.fixture();proof[key]=1
   with self.subTest(key=key),self.assertRaises(ValueError):self.derive(row,proof,context)
  for key in ['runId','validationOnly','path','lane']:
   row,proof,context=self.fixture();context[key]=True
   with self.subTest(key=key),self.assertRaises(ValueError):self.derive(row,proof,context)
  row,proof,context=self.fixture()
  with self.assertRaises(ValueError):self.derive(row,proof,context,dirty=True)
 def test_local_checks_exact_types_source_seals_caps_and_actual_loader(self):
  import copy,jsonschema
  row,baseline,context=self.fixture()
  self.assertEqual(self.derive(row,baseline,context),row['trustedExecution'])
  mutations=[
   ('core bool',lambda p:p['core'].update(bytes=True),jsonschema.ValidationError,'type',['bytes']),
   ('core float',lambda p:p['core'].update(bytes=7.0),ValueError,'sealed execution exact member byte type differs',None),
   ('sidecar float',lambda p:p['sidecar'].update(bytes=11.0),ValueError,'sealed execution exact member byte type differs',None),
   ('core seals',lambda p:p.update(coreSeals=0),jsonschema.ValidationError,'const',[]),
   ('proof source',lambda p:p.update(sourceCommit='e'*40),ValueError,'sealed execution source/target binding differs: sourceCommit',None),
   # This is a schema const refusal, not evidence of the later Cronet guard.
   ('standalone schema',lambda p:p['cronet'].update(librarySelection='standalone-path'),jsonschema.ValidationError,'const',['librarySelection']),
   ('Cronet library bytes',lambda p:p['cronet'].update(libraryBytes=12),ValueError,'captured sealed Cronet observation differs',None),
   ('configuration coverage',lambda p:p['tlsProbe']['configurationChecks'].pop(),ValueError,'incomplete sealed configuration controls',None),
   ('capability source',lambda p:p['tlsProbe']['capabilities'].update(sourceCommit='e'*40),ValueError,'selected-core capability binding mismatch: sourceCommit',None)]
  for name,mutation,error,reason,path in mutations:
   proof=copy.deepcopy(baseline);mutation(proof)
   with self.subTest(control=name):
    with self.assertRaises(error) as rejected:self.derive(row,proof,context)
    if error is jsonschema.ValidationError:
     self.assertEqual(rejected.exception.validator,reason)
     self.assertEqual(list(rejected.exception.absolute_path),path)
    else:self.assertEqual(str(rejected.exception),reason)
    print('local source control '+name+': '+str(rejected.exception))


class MacNativeExecutionControls(unittest.TestCase):
 """Inert byte fixtures/mock native tools: source controls, never signed/root evidence."""
 def macho(self, arch='arm64', extra=None, library='/usr/lib/libSystem.B.dylib', dyld='/usr/lib/dyld'):
  import struct
  def string_command(code, value, minimum):
   raw=value.encode()+b'\0';length=(minimum+len(raw)+7)//8*8
   return struct.pack('<III',code,length,minimum)+b'\0'*(minimum-12)+raw+b'\0'*(length-minimum-len(raw))
  commands=[string_command(0xe,dyld,12),string_command(0xc,library,24)]
  if extra is not None:commands.append(extra)
  end=32+sum(map(len,commands))+16;signature=b'controlled-non-executable-signature'
  commands.append(struct.pack('<IIII',0x1d,16,end,len(signature)))
  return struct.pack('<8I',0xfeedfacf,{'arm64':0x0100000c,'amd64':0x01000007}[arch],0,2,len(commands),sum(map(len,commands)),0,0)+b''.join(commands)+signature
 def fixture(self, arch='arm64'):
  import copy
  row=sealed_row_fixture();old=copy.deepcopy(row['finalPackageCronetSmoke']['sealedExecution']);data=self.macho(arch)
  row['target']='darwin/'+arch;row['id']='sing-box-'+row['version']+'-darwin-'+arch
  row['variant'].update(linkage='static-cgo');row['sidecar']=None
  row['tags']='with_naive_outbound,with_utls,with_gvisor'
  row['buildGraph']['settings'].update(GOOS='darwin',GOARCH=arch,CGO_ENABLED='1',**{'-tags':row['tags'],'-ldflags':'-X github.com/sagernet/sing-box/constant.SourceRevision='+row['sourceCommit']+' -X github.com/sagernet/sing-box/constant.Version='+row['version']})
  row['core']={'member':'sing-box','bytes':len(data),'sha256':n.sha(data)}
  row['signatureObservation']={'state':'signed','cdHash':'e'*40,'trustValidated':False}
  row['archive'].update(name=row['id']+'.tar.gz',releaseName=n.public_product_name(row['id']+'.tar.gz'),root=row['id'],members={row['id']+'/sing-box':n.sha(data)})
  native=n.macos_loader_metadata(data,arch)
  post={'coreSHA256':n.sha(data),'coreBytes':len(data),'cdHash':'e'*40,'signatureVerified':True,'nativeLoader':native}
  receipt=old['tlsProbe'];receipt.update(coreSHA256=n.sha(data),coreBytes=len(data));receipt['capabilities'].update(os='darwin',arch=arch,buildTags=row['tags'])
  cronet={k:old['cronet'][k]for k in ['os','arch','go','linkage','version','gvisorCompiled']};cronet.update(os='darwin',arch=arch,linkage='static-cgo')
  proof={k:old[k]for k in ['sourceCommit','sourceTree','version','runId','runAttempt','archiveSha256']}
  proof.update(schema='polaris-macos-native-execution-proof-v1',target=row['target'],core=row['core'].copy(),postSign=post,tlsProbe=receipt,cronet=cronet)
  row['finalPackageCronetSmoke'].update(os='darwin',arch=arch,linkage='static-cgo',librarySha256=None,coreSha256=n.sha(data))
  row['finalPackageCronetSmoke'].pop('sealedExecution');row['finalPackageCronetSmoke']['macosExecution']=proof
  row['trustedExecution']={'schema':'polaris-trusted-execution-v1','sourceCommit':row['sourceCommit'],'sourceTree':row['sourceTree'],'loader':'macos-root-private-v1','purposes':['check-config-v1','run-main-v1']}
  return row,data
 def check(self,row):return n.validate_trusted_execution(row,{'runId':42,'runAttempt':1})
 def test_two_native_targets_derive_only_exact_five_fields_and_two_purposes(self):
  for arch in ['arm64','amd64']:
   row,_=self.fixture(arch)
   with self.subTest(arch=arch):
    self.assertEqual(self.check(row),row['trustedExecution']);self.assertEqual(len(row['trustedExecution']),5)
    material=n.distribution_materials({'sourceCommit':row['sourceCommit'],'sourceTree':row['sourceTree'],'sourceArchive':{'name':'synthetic'},'platforms':[row],'legalFiles':[]},n.ROOT)
    expected=n.sha(json.dumps(row['finalPackageCronetSmoke']['macosExecution'],sort_keys=True,separators=(',',':')).encode())
    self.assertEqual(material['nativeArchives'][0]['macosExecutionSHA256'],expected)
    self.assertNotIn('sealedExecutionSHA256',material['nativeArchives'][0])
 def test_linux_original_canonical_policy_bytes_unchanged(self):
  row=sealed_row_fixture()
  expected={'schema':'polaris-trusted-execution-v1','sourceCommit':'a'*40,'sourceTree':'b'*40,'loader':'linux-sealed-fd-v1','purposes':['check-config-v1','tls-inventory-v1','run-main-v1','run-login-v1','run-speedtest-v1']}
  canonical=lambda v:json.dumps(v,sort_keys=True,separators=(',',':')).encode()
  self.assertEqual(canonical(n.validate_trusted_execution(row,{'runId':42,'runAttempt':1})),canonical(expected))
 def test_no_native_proof_or_signature_string_alone_can_grant(self):
  import copy
  row,_=self.fixture();plain=copy.deepcopy(row);plain.pop('trustedExecution');plain['finalPackageCronetSmoke'].pop('macosExecution');self.assertIsNone(self.check(plain))
  for which in ['policy','proof']:
   bad=copy.deepcopy(row)
   if which=='policy':bad.pop('trustedExecution')
   else:bad['finalPackageCronetSmoke'].pop('macosExecution')
   with self.subTest(which=which),self.assertRaisesRegex(ValueError,'both policy and native sealed proof'):self.check(bad)
  bad=copy.deepcopy(row);bad['finalPackageCronetSmoke']['sealedExecution']=sealed_row_fixture()['finalPackageCronetSmoke']['sealedExecution']
  with self.assertRaisesRegex(ValueError,'ambiguous'):self.check(bad)
 def test_closed_mac_policy_schemas_reject_unknown_fields_and_purposes(self):
  import copy,jsonschema
  for filename in ['native-release-index','native-release-contract']:
   schema=json.loads((n.ROOT/'release/ci'/f'{filename}.schema.json').read_text());validator=jsonschema.Draft202012Validator({'$defs':schema['$defs'],**schema['$defs']['trustedExecution']})
   row,_=self.fixture();validator.validate(row['trustedExecution'])
   for mutation in [lambda p:p.update(owner='root'),lambda p:p.update(loader='linux-sealed-fd-v1'),lambda p:p['purposes'].append('tls-inventory-v1'),lambda p:p['purposes'].pop(),lambda p:p['purposes'].reverse(),lambda p:p['purposes'].append('check-config-v1'),lambda p:p.update(purposes=['invented'])]:
    bad=copy.deepcopy(row);mutation(bad['trustedExecution'])
    # A Linux-looking policy still fails the row's platform/proof binding and derivation.
    if bad['trustedExecution']['loader']=='linux-sealed-fd-v1':self.assertRaises(ValueError,self.check,bad)
    else:self.assertRaises(jsonschema.ValidationError,validator.validate,bad['trustedExecution'])
 def test_source_target_build_metadata_and_final_byte_mismatches_fail(self):
  import copy,jsonschema
  row,_=self.fixture()
  mutations=[lambda r:r.update(target='windows/arm64'),lambda r:r.update(target='darwin/universal'),lambda r:r['variant'].update(linkage='shared-purego'),lambda r:r['variant'].update(legacy=True),lambda r:r['buildGraph']['settings'].update(CGO_ENABLED='0'),lambda r:r['buildGraph']['settings'].update(GOARCH='amd64'),lambda r:r['buildGraph']['settings'].update(**{'vcs.modified':'true'}),lambda r:r['buildGraph']['settings'].update(**{'vcs.revision':'f'*40}),lambda r:r['buildGraph']['settings'].update(**{'-ldflags':''}),lambda r:r.update(sourceTree='f'*40),lambda r:r['archive'].update(sha256='f'*64),lambda r:r['archive'].update(bytes=1.0),lambda r:r['variant'].update(legacy=0),lambda r:r['core'].update(bytes=7.0),lambda r:r['signatureObservation'].update(cdHash='f'*40),lambda r:r['archive']['members'].update({r['id']+'/sing-box':'f'*64}),lambda r:r['finalPackageCronetSmoke']['macosExecution'].update(runAttempt=2),lambda r:r['finalPackageCronetSmoke']['macosExecution']['postSign'].update(signatureVerified=False),lambda r:r['finalPackageCronetSmoke']['macosExecution']['postSign'].update(coreBytes=float(r['core']['bytes'])),lambda r:r['finalPackageCronetSmoke']['macosExecution']['postSign']['nativeLoader'].update(signatureOffset=999999),lambda r:r['finalPackageCronetSmoke']['macosExecution']['postSign']['nativeLoader'].update(libraries=['/usr/lib/../local/evil.dylib']),lambda r:r['finalPackageCronetSmoke']['macosExecution']['tlsProbe']['capabilities'].update(sourceCommit='f'*40),lambda r:r['finalPackageCronetSmoke']['macosExecution']['tlsProbe']['configurationChecks'].pop(),lambda r:r['finalPackageCronetSmoke']['macosExecution']['cronet'].update(linkage='shared-purego')]
  for index,mutate in enumerate(mutations):
   bad=copy.deepcopy(row);mutate(bad)
   with self.subTest(index=index),self.assertRaises((ValueError,jsonschema.ValidationError)):self.check(bad)
  bad=copy.deepcopy(row);bad['tags']+=',with_purego';bad['buildGraph']['settings']['-tags']=bad['tags'];self.assertRaises(ValueError,self.check,bad)
  with self.assertRaises(ValueError):n.derive_trusted_execution(row,row['finalPackageCronetSmoke']['macosExecution'],{'runId':True,'runAttempt':1})
 def test_both_schemas_bind_proof_to_platform_and_original_linux_definition(self):
  import copy,jsonschema
  native=json.loads((n.ROOT/'release/ci/native-release-index.schema.json').read_text());consumer=json.loads((n.ROOT/'release/ci/native-release-contract.schema.json').read_text())
  for key in ['trustedExecution','linuxTrustedExecution','macosTrustedExecution','sealedExecution','macosExecution']:self.assertEqual(native['$defs'][key],consumer['$defs'][key])
  schema={'$defs':native['$defs'],**native['properties']['platforms']['items']};validator=jsonschema.Draft202012Validator(schema);row,_=self.fixture();validator.validate(row)
  for mutation in [lambda r:r.update(target='windows/amd64'),lambda r:r.update(target='linux/amd64'),lambda r:r['variant'].update(linkage='shared-purego'),lambda r:r.pop('trustedExecution'),lambda r:r['finalPackageCronetSmoke'].pop('macosExecution')]:
   bad=copy.deepcopy(row);mutation(bad)
   with self.assertRaises(jsonschema.ValidationError):validator.validate(bad)
 def test_loader_rejects_universal_unknown_search_environment_encryption_and_bad_names(self):
  import struct
  for arch in ['arm64','amd64']:self.assertEqual(n.macos_loader_metadata(self.macho(arch),arch)['arch'],arch)
  for command in [0x8000001c,0x27,0x10,0x21,0x2c,0xdeadbeef]:
   with self.subTest(command=command),self.assertRaises(ValueError):n.macos_loader_metadata(self.macho(extra=struct.pack('<II',command,8)),'arm64')
  for name in ['@rpath/evil.dylib','/tmp/evil.dylib','/usr/lib/../evil','/usr/lib//libX.dylib']:
   with self.subTest(library=name),self.assertRaises(ValueError):n.macos_loader_metadata(self.macho(library=name),'arm64')
  for change in [lambda d:d.__setitem__(slice(0,4),b'\xca\xfe\xba\xbe'),lambda d:d.__setitem__(slice(4,8),struct.pack('<I',0x01000007)),lambda d:d.__setitem__(slice(12,16),struct.pack('<I',6)),lambda d:d.__setitem__(slice(16,20),struct.pack('<I',0)),lambda d:d.__setitem__(slice(20,24),struct.pack('<I',2**20+1)),lambda d:d.__setitem__(slice(36,40),struct.pack('<I',7)),lambda d:d.__setitem__(slice(36,40),struct.pack('<I',40))]:
   bad=bytearray(self.macho());change(bad)
   with self.subTest(change=change),self.assertRaises(ValueError):n.macos_loader_metadata(bad,'arm64')
  with self.assertRaises(ValueError):n.macos_loader_metadata(self.macho(dyld='/tmp/dyld'),'arm64')
  with self.assertRaises(ValueError):n.macos_loader_metadata(self.macho(extra=struct.pack('<IIII',0x1d,16,150,3)),'arm64')
  with self.assertRaises(ValueError):n.macos_loader_metadata(self.macho()[:-1],'arm64')
 def observe(self,path,row,commands=None):
  from contextlib import ExitStack
  from types import SimpleNamespace
  def code(*args,**kwargs):
   if commands is not None:commands.append(args[0])
   return SimpleNamespace(returncode=0,stderr='CDHash='+'e'*40+'\n')
  with ExitStack() as stack:
   stack.enter_context(patch.object(n,'macos_native_process',return_value=True));stack.enter_context(patch.object(n.platform,'system',return_value='Darwin'));stack.enter_context(patch.object(n.platform,'machine',return_value='arm64'))
   stack.enter_context(patch.object(n,'buildinfo',return_value=(row['goVersion'],'fixture',row['buildGraph'])));stack.enter_context(patch.object(n,'run',return_value=row['buildID']));stack.enter_context(patch.object(n.subprocess,'run',side_effect=code))
   return n.observe_macos_postsign(path,row)
 def test_postsign_observer_reads_actual_bytes_and_requires_real_native_tools(self):
  row,data=self.fixture()
  with tempfile.TemporaryDirectory() as td:
   core=Path(td)/'inert-core';core.write_bytes(data);commands=[]
   self.assertEqual(self.observe(core,row,commands),row['finalPackageCronetSmoke']['macosExecution']['postSign'])
   self.assertEqual(commands,[['/usr/bin/codesign','--verify','--strict',str(core)],['/usr/bin/codesign','--display','--verbose=4',str(core)]])
   core.write_bytes(data[:-1]+b'X');self.assertRaisesRegex(ValueError,'digest differs',self.observe,core,row)
 def test_postsign_refuses_host_override_links_and_native_signature_failure(self):
  import os
  from types import SimpleNamespace
  row,data=self.fixture()
  with tempfile.TemporaryDirectory() as td:
   core=Path(td)/'inert-core';core.write_bytes(data)
   with patch.object(n.platform,'system',return_value='Linux'):self.assertRaisesRegex(ValueError,'actual native host',n.observe_macos_postsign,core,row)
   with patch.dict(os.environ,{'DYLD_INSERT_LIBRARIES':'fixture-only'}):self.assertRaisesRegex(ValueError,'ambient loader',self.observe,core,row)
   link=Path(td)/'link';link.symlink_to(core);self.assertRaises(OSError,self.observe,link,row);link.unlink();os.link(core,link);self.assertRaisesRegex(ValueError,'final Core object',self.observe,core,row);link.unlink()
   with patch.object(n,'macos_native_process',return_value=True),patch.object(n.platform,'system',return_value='Darwin'),patch.object(n.platform,'machine',return_value='arm64'),patch.object(n,'buildinfo',return_value=(row['goVersion'],'fixture',row['buildGraph'])),patch.object(n,'run',return_value=row['buildID']),patch.object(n.subprocess,'run',return_value=SimpleNamespace(returncode=1,stderr='CDHash='+'e'*40)):
    self.assertRaisesRegex(ValueError,'strict signature verification',n.observe_macos_postsign,core,row)
 def test_postsign_detects_namespace_swap_during_tool_observation(self):
  import os
  from types import SimpleNamespace
  row,data=self.fixture()
  with tempfile.TemporaryDirectory() as td:
   core=Path(td)/'inert-core';core.write_bytes(data);replacement=Path(td)/'replacement';replacement.write_bytes(data)
   def code(*args,**kwargs):
    if replacement.exists():os.replace(replacement,core)
    return SimpleNamespace(returncode=0,stderr='CDHash='+'e'*40+'\n')
   with patch.object(n,'macos_native_process',return_value=True),patch.object(n.platform,'system',return_value='Darwin'),patch.object(n.platform,'machine',return_value='arm64'),patch.object(n,'buildinfo',return_value=(row['goVersion'],'fixture',row['buildGraph'])),patch.object(n,'run',return_value=row['buildID']),patch.object(n.subprocess,'run',side_effect=code):self.assertRaisesRegex(ValueError,'namespace changed',n.observe_macos_postsign,core,row)
 def smoke_actual_observer(self, failure, arch='arm64'):
  import copy,errno,os,tls_fingerprint_probe as tls
  from contextlib import ExitStack
  from types import SimpleNamespace
  row,data=self.fixture(arch);proof=copy.deepcopy(row['finalPackageCronetSmoke']['macosExecution'])
  row.pop('trustedExecution');row['finalPackageCronetSmoke']=None
  with tempfile.TemporaryDirectory() as td:
   directory=Path(td);archive=directory/row['archive']['name']
   TestNative().archive(archive,[(row['archive']['root']+'/sing-box',data)])
   row['archive'].update(sha256=n.sha(archive.read_bytes()),bytes=archive.stat().st_size)
   file=directory/'native-row-synthetic.json';file.write_text(json.dumps(row));original=file.read_bytes()
   opened=[];duplicated=[];calls=[];config_index=0;mutated=False
   original_open=os.open;original_dup=os.dup
   def open_input(path,flags,*args,**kwargs):
    fd=original_open(path,flags,*args,**kwargs)
    if Path(path).name=='sing-box':
     self.assertTrue(flags & os.O_NOFOLLOW);self.assertTrue(flags & os.O_CLOEXEC)
     opened.append((fd,os.fstat(fd)))
    return fd
   def duplicate(fd):
    result=original_dup(fd)
    if any(fd==held for held,_ in opened):duplicated.append(result)
    return result
   def native_phase(core,phase):
    nonlocal mutated
    # Check the original no-follow descriptor really spans every native probe.
    self.assertEqual(len(opened),1)
    fd,before=opened[0];held=os.fstat(fd)
    self.assertEqual((held.st_dev,held.st_ino),(before.st_dev,before.st_ino))
    if failure=='swap-'+phase and not mutated:
     replacement=core.with_name('replacement');replacement.write_bytes(data);replacement.chmod(core.stat().st_mode & 0o777)
     self.assertNotEqual(replacement.stat().st_ino,before.st_ino)
     os.replace(replacement,core);self.assertEqual(core.read_bytes(),data);mutated=True
    if phase=='cronet':
     if failure=='runtime':raise ValueError('fixture native failure')
     if failure=='archive-drift':archive.write_bytes(b'changed archive')
     if failure=='postsign-bytes':core.write_bytes(data[:-1]+b'X')
     if failure=='postsign-metadata':core.chmod(0o700)
   def output(argv,**kwargs):
    argv=list(argv);calls.append(tuple(argv))
    if argv[:3]==['go','version','-m']:
     graph=row['buildGraph'];lines=[str(argv[3])+': '+row['goVersion']]
     for kind in ['normalModules','prebuiltAcquisitionModules','localReplacements']:
      for item in graph[kind]:
       lines.append('\tdep\t'+item['module']+'\t'+item['version']+'\t'+item['h1'])
       if 'replacement' in item:
        value=item['replacement'];lines.append('\t=>\t'+value['module']+'\t'+value['version']+'\t'+value['h1'])
     lines += ['\tbuild\t'+key+'='+json.dumps(value) for key,value in graph['settings'].items()]
     return '\n'.join(lines)
    if argv[:3]==['go','tool','buildid']:return row['buildID']
    self.assertEqual(argv[1:3],['tools','cronet']);self.assertNotIn('--library',argv)
    native_phase(Path(argv[0]),'cronet');return json.dumps(proof['cronet'])
   def native(argv,**kwargs):
    nonlocal config_index
    calls.append(tuple(argv))
    if argv[0]=='/usr/bin/codesign':
     second=sum(command[0]=='/usr/bin/codesign' and '--verify' in command for command in calls)==2
     signature='f'*40 if failure=='postsign-drift' and second else 'e'*40
     return SimpleNamespace(returncode=1 if failure=='signature' else 0,stderr='CDHash='+signature+'\n')
    core=Path(argv[0])
    if argv[1:]==['tools','tls-fingerprints']:
     native_phase(core,'capability')
     return SimpleNamespace(returncode=0,stdout=json.dumps(proof['tlsProbe']['capabilities']),stderr='')
    self.assertEqual(argv[1:3],['check','-c']);native_phase(core,'config')
    descriptor,config,error=tls.configuration_cases(proof['tlsProbe']['capabilities'])[config_index];config_index+=1
    self.assertEqual(json.loads(Path(argv[3]).read_text()),config)
    return SimpleNamespace(returncode=0 if descriptor['expectedPass'] else 1,stdout=error or '',stderr='')
   with ExitStack() as stack:
    stack.enter_context(patch.object(n.platform,'system',return_value='Darwin'))
    stack.enter_context(patch.object(n.platform,'machine',return_value={'arm64':'arm64','amd64':'x86_64'}[arch]))
    stack.enter_context(patch.object(n,'macos_native_process',return_value=True))
    stack.enter_context(patch.dict(os.environ,{'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':'1'}))
    stack.enter_context(patch.object(n.os,'open',side_effect=open_input));stack.enter_context(patch.object(n.os,'dup',side_effect=duplicate))
    stack.enter_context(patch.object(n.subprocess,'check_output',side_effect=output));stack.enter_context(patch.object(n.subprocess,'run',side_effect=native))
    if failure=='none':n.smoke(directory)
    else:
     with self.assertRaises(ValueError) as rejected:n.smoke(directory)
     if failure.startswith('swap-') or failure in ('postsign-bytes','postsign-metadata'):
      self.assertIn('object/namespace changed',str(rejected.exception))
   self.assertEqual(len(opened),1);self.assertTrue(duplicated)
   for fd in set([held for held,_ in opened]+duplicated):
    with self.assertRaises(OSError) as closed:os.fstat(fd)
    self.assertEqual(closed.exception.errno,errno.EBADF)
   if failure.startswith('swap-'):self.assertTrue(mutated)
   if failure!='none':self.assertEqual(file.read_bytes(),original)
   else:
    self.assertEqual(config_index,len(tls.configuration_cases(proof['tlsProbe']['capabilities'])))
    self.assertEqual(sum(command[0]=='/usr/bin/codesign' and '--verify' in command for command in calls),2)
    result=json.loads(file.read_text());self.assertEqual(self.check(result),result['trustedExecution'])
    self.assertEqual(result['finalPackageCronetSmoke']['macosExecution']['postSign'],proof['postSign'])
    self.assertNotIn('sealedExecution',result['finalPackageCronetSmoke'])
 def test_smoke_wires_actual_postsign_twice_and_emits_only_after_native_success(self):
  for failure in ['none','signature','runtime','postsign-drift','archive-drift']:
   with self.subTest(failure=failure):self.smoke_actual_observer(failure)
  with self.subTest(arch='amd64'):self.smoke_actual_observer('none','amd64')
 def test_smoke_rejects_same_bytes_new_inode_during_actual_native_probes(self):
  for phase in ['capability','config','cronet']:
   with self.subTest(phase=phase):self.smoke_actual_observer('swap-'+phase)
 def test_smoke_rechecks_original_held_object_bytes_and_metadata_after_probes(self):
  for failure in ['postsign-bytes','postsign-metadata']:
   with self.subTest(failure=failure):self.smoke_actual_observer(failure)

 def test_shared_publisher_accepts_mac_only_with_bound_native_materials(self):
  import copy,jsonschema,test_github_release as publishing
  publisher=publishing.TrustedExecutionPublisherTests();index=publisher.index();row,_=self.fixture()
  self.assertEqual(sum(old['id']==row['id']for old in index['platforms']),1)
  index['platforms']=[row if old['id']==row['id']else old for old in index['platforms']]
  index['distributionMaterials']=n.distribution_materials(index,n.ROOT);publisher.check(index)
  for mutation in ['proof','material','purpose']:
   bad=copy.deepcopy(index);selected=next(item for item in bad['platforms']if item['id']==row['id'])
   if mutation=='proof':selected['finalPackageCronetSmoke']['macosExecution']['postSign']['cdHash']='f'*40
   elif mutation=='purpose':selected['trustedExecution']['purposes'].append('run-login-v1')
   else:next(item for item in bad['distributionMaterials']['nativeArchives']if item['archive']==row['archive']['name']).pop('macosExecutionSHA256')
   with self.subTest(mutation=mutation),self.assertRaises((ValueError,jsonschema.ValidationError)):publisher.check(bad)

 def test_native_translation_query_rejects_rosetta_and_unknown_without_arch_guessing(self):
  import ctypes,errno
  from unittest.mock import Mock
  original_errno=ctypes.get_errno()
  try:
   for result,value,error,size,expected in [(0,0,0,4,True),(0,1,0,4,False),(-1,0,errno.ENOENT,4,True),(-1,0,errno.EACCES,4,None),(0,2,0,4,None),(0,0,0,8,None)]:
    def query(name,returned,amount,new,new_amount):
     self.assertEqual(name,b'sysctl.proc_translated');self.assertIsNone(new);self.assertEqual(new_amount,0)
     returned._obj.value=value;amount._obj.value=size;ctypes.set_errno(error);return result
    function=Mock(side_effect=query);library=Mock(sysctlbyname=function)
    with self.subTest(result=result,value=value,error=error,size=size),patch.object(ctypes,'CDLL',return_value=library) as load:
     if expected is None:self.assertRaisesRegex(ValueError,'unknown',n.macos_native_process)
     else:self.assertIs(n.macos_native_process(),expected)
     load.assert_called_once_with('/usr/lib/libSystem.B.dylib',use_errno=True)
   with patch.object(ctypes,'CDLL',side_effect=OSError('controlled missing API')):self.assertRaisesRegex(ValueError,'unavailable',n.macos_native_process)
  finally:ctypes.set_errno(original_errno)
  row,data=self.fixture()
  with tempfile.TemporaryDirectory() as td:
   core=Path(td)/'inert-core';core.write_bytes(data)
   with patch.object(n.platform,'system',return_value='Darwin'),patch.object(n.platform,'machine',return_value='arm64'),patch.object(n,'macos_native_process',return_value=False),patch.object(n.subprocess,'run') as commands:
    self.assertRaisesRegex(ValueError,'translated execution',n.observe_macos_postsign,core,row);commands.assert_not_called()
