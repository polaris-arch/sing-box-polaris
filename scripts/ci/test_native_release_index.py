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
  self.assertEqual(rows['sing-box-1.15.0-polaris-alpha.12-linux-amd64']['variant']['libc'],'')
  self.assertEqual(rows['sing-box-1.15.0-polaris-alpha.12-linux-amd64']['variant']['linkage'],'shared-purego')
  self.assertIn('sing-box-1.15.0-polaris-alpha.12-linux-arm64',rows)
  self.assertEqual(rows['sing-box-1.15.0-polaris-alpha.12-darwin-arm64']['variant']['linkage'],'static-cgo')
 def test_buildinfo_multiple_local_replacements(self):
  raw='/tmp/core: go1.26.8\n\tpath\tgithub.com/sagernet/sing-box/cmd/sing-box\n\tdep\tmodule/a\tv1\th1:a\n\t=>\t./third_party/a\t(devel)\t\n\tdep\tmodule/b\tv2\th1:b\n\t=>\t./third_party/b\t(devel)\t\n\tdep\tgithub.com/sagernet/cronet-go/lib/linux_amd64\tv3\th1:c\n\tbuild\tCGO_ENABLED=0\n\tbuild\t-tags=with_gvisor,with_naive_outbound\n'
  with patch.object(n.subprocess,'check_output',return_value=raw):
   go,out,g=n.buildinfo(Path('/tmp/core'))
  self.assertEqual(go,'go1.26.8');self.assertEqual(out,raw);self.assertEqual(len(g['localReplacements']),2);self.assertEqual(len(g['prebuiltAcquisitionModules']),1);self.assertEqual(g['settings']['CGO_ENABLED'],'0')
 def test_shared_notice_files_are_text_not_compiled_payloads(self):
  for path in (R.parents[1]/'release/licenses').rglob('*'):
   if path.is_file():
    with self.subTest(path=path):
     path.read_bytes().decode('utf-8')
     self.assertNotEqual(path.suffix.lower(),'.class')


class OverlayProductionBoundaryControls(unittest.TestCase):
 def test_smoke_rejects_bad_overlay_before_product_work(self):
  for operation,args in ((n.smoke,('unused',)),):
   with self.subTest(operation=operation.__name__), \
        patch.object(n,'validate_overlay',side_effect=ValueError('bad overlay')) as check, \
        patch.object(n,'read_archive') as archive,patch.object(n.subprocess,'check_output') as command:
    self.assertRaisesRegex(ValueError,'bad overlay',operation,*args)
    check.assert_called_once_with(Path.cwd());archive.assert_not_called();command.assert_not_called()


if __name__=='__main__':unittest.main()
