import importlib.util,io,json,tarfile,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
R=Path(__file__).parent
spec=importlib.util.spec_from_file_location('n',R/'native_release_index.py');n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
class TestNative(unittest.TestCase):
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
