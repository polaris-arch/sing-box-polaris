import io
import json
from pathlib import Path
import tempfile
import unittest
import polaris_native_distribution as pack

class ArchiveTests(unittest.TestCase):
    def fixture(self, directory, suffix='.tar.gz'):
        path = Path(directory)/('candidate'+suffix)
        provenance = {'sourceCommit': pack.SOURCE, 'sourceTree': pack.TREE, 'sourceOverlay':0,
                      'workflowCommit':'producer','workflowRun':'123','workflowAttempt':'1'}
        members = {'candidate/sing-box':(b'unchanged core bytes',0o755),
                   'candidate/provenance.json':(pack.encode(provenance),0o644),
                   'candidate/SHA256SUMS':(b'historical sums',0o644)}
        pack.write_archive(path,members)
        expected = {**pack.file_info(path), 'members':{n:pack.sha(d) for n,(d,_) in members.items()}}
        return path,members,expected
    def test_snapshot_modes_tar_and_zip(self):
        with tempfile.TemporaryDirectory() as d:
            for suffix in ['.tar.gz','.zip']:
                path,members,expected=self.fixture(d,suffix)
                self.assertEqual(pack.read_archive(path,expected),members)
    def test_outer_and_member_drift_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path,members,expected=self.fixture(d)
            with self.assertRaises(ValueError):pack.read_archive(path,dict(expected,sha256='0'*64))
            members['candidate/sing-box']=(b'changed core bytes',0o755);pack.write_archive(path,members)
            expected.update(pack.file_info(path))
            with self.assertRaises(ValueError):pack.read_archive(path,expected)
    def test_unsafe_member_rejected(self):
        for name in ['/a','a/../b','a//b','a/./b','a\\b','']:
            with self.assertRaises(ValueError):pack.safe_name(name)
    def test_duplicate_and_link_rejected(self):
        import tarfile,zipfile
        with tempfile.TemporaryDirectory() as d:
            for kind in ['duplicate','link']:
                path=Path(d)/(kind+'.tar.gz')
                with tarfile.open(path,'w:gz') as t:
                    if kind=='link':
                        i=tarfile.TarInfo('candidate/sing-box');i.type=tarfile.SYMTYPE;i.linkname='/tmp/other';t.addfile(i)
                    else:
                        for _ in range(2):
                            i=tarfile.TarInfo('candidate/sing-box');i.size=1;t.addfile(i,io.BytesIO(b'x'))
                with self.assertRaises(ValueError):pack.read_archive(path,dict(pack.file_info(path),members={}))
    def test_repack_preserves_originals_and_recalculates_sums(self):
        with tempfile.TemporaryDirectory() as d:
            path,members,expected=self.fixture(d);out=Path(d)/'out';out.mkdir()
            item={'archive':expected,'platform':'linux/amd64','producerCommit':'producer','run':123,'coreSha256':pack.sha(b'unchanged core bytes'),'artifactId':1,'signatureObservation':{}}
            inputs={'proposedTag':'tag','compiledVersion':'candidate','materialCommit':'material','noticeRecords':268,'noticeSha256':'notice','sourceAsset':{'sha256':'source'}}
            receipt=pack.repack_one(path,out,item,inputs,{'licenses/WHOLE-NOTICE':b'whole bundle'})
            actual=pack.read_archive(out/path.name,receipt['archive'])
            for n,v in members.items():
                if not n.endswith('/SHA256SUMS'):self.assertEqual(actual[n],v)
            self.assertEqual(actual['candidate/licenses/WHOLE-NOTICE'][0],b'whole bundle')
            self.assertIn(b'  licenses/WHOLE-NOTICE\n',actual['candidate/SHA256SUMS'][0])
            self.assertEqual(receipt['signatureChanges'],[])
    def test_wrong_producer_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path,members,expected=self.fixture(d);out=Path(d)/'out';out.mkdir()
            item={'archive':expected,'platform':'linux/amd64','producerCommit':'wrong','run':123}
            with self.assertRaises(ValueError):pack.repack_one(path,out,item,{}, {})
    def test_notice_materials_are_whole_controlled_bundle(self):
        repo=Path(__file__).resolve().parents[1]
        inputs=json.loads((repo/'release/native-publication/inputs.json').read_text())
        additions=pack.material_inputs(repo,inputs)
        self.assertEqual(len(additions['licenses/DESKTOP-SOURCE-NOTICE-SUPERSET.txt']),976474)
        index=json.loads(additions['source/SOURCE-INDEX.json'])
        self.assertEqual(len(index['noticeRecords']),268)
        self.assertTrue(any('Go' in r['source'] or 'golang.org/toolchain' in r['source'] for r in index['noticeRecords']))
        self.assertTrue(any('naive' in r['source'].lower() for r in index['noticeRecords']))

if __name__=='__main__':unittest.main()
