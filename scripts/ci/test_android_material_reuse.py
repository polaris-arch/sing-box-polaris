import copy, json, tempfile, unittest
from pathlib import Path
import github_release as g
import test_android_runtime_materials as fixtures

class AndroidMaterialReuseTests(unittest.TestCase):
    def fixture(self, root):
        record=fixtures.AndroidRuntimeMaterialsTests().fixture()
        client={'repository':'SagerNet/sing-box-for-android','baseCommit':'a'*40,'baseTree':'b'*40,'overlayManifestSHA256':'c'*64,'platform':'android','unsigned':True}
        directory=root/'release/dependency-sources/clients/runtime/android-resolved';directory.mkdir(parents=True)
        (directory/'source-notice-map.json').write_text(json.dumps({'concreteUnresolvedMaterials':[], 'components':[{'artifact':copy.deepcopy(record['artifacts'][0])}]}))
        reference={'schema':'polaris-android-material-reuse-v1','materialMapSHA256':g.sha(directory/'source-notice-map.json'),'clientSource':client,'variants':{record['configuration']:{'artifacts':copy.deepcopy(record['artifacts'])}}}
        (directory/'reuse-reference.json').write_text(json.dumps(reference))
        return record,client
    def test_exact_actual_and_duplicate_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);record,client=self.fixture(root);record['artifacts']*=2
            result=g.validate_android_material_reuse(record,record['configuration'],client,root)
            self.assertTrue(result['sourceMaterialsReusable']);self.assertEqual(result['actualArtifactCount'],1)
    def test_artifact_identity_and_byte_drift_rejected(self):
        for field,value in [('name','other.aar'),('artifactIdentity','changed'),('type','jar'),('classifier','other'),('bytes',43),('sha256','b'*64)]:
            with self.subTest(field=field),tempfile.TemporaryDirectory() as d:
                root=Path(d);record,client=self.fixture(root);record['artifacts'][0][field]=value
                with self.assertRaisesRegex(ValueError,'drift'):g.validate_android_material_reuse(record,record['configuration'],client,root)
    def test_client_identity_drift_rejected(self):
        for field in ('repository','baseCommit','baseTree','overlayManifestSHA256','platform','unsigned'):
            with self.subTest(field=field),tempfile.TemporaryDirectory() as d:
                root=Path(d);record,client=self.fixture(root);client[field]='changed'
                with self.assertRaisesRegex(ValueError,'drift'):g.validate_android_material_reuse(record,record['configuration'],client,root)
    def test_map_drift_and_missing_reference_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);record,client=self.fixture(root);p=root/'release/dependency-sources/clients/runtime/android-resolved/source-notice-map.json';p.write_text('changed')
            with self.assertRaisesRegex(ValueError,'map changed'):g.validate_android_material_reuse(record,record['configuration'],client,root)
    def test_unresolved_or_missing_material_mapping_rejected(self):
        for missing in (True, False):
            with tempfile.TemporaryDirectory() as d:
                root=Path(d);record,client=self.fixture(root)
                directory=root/'release/dependency-sources/clients/runtime/android-resolved'
                p=directory/'source-notice-map.json';material=json.loads(p.read_text())
                if missing:material['components']=[]
                else:material['concreteUnresolvedMaterials']=['actual missing notice']
                p.write_text(json.dumps(material));q=directory/'reuse-reference.json';reference=json.loads(q.read_text());reference['materialMapSHA256']=g.sha(p);q.write_text(json.dumps(reference))
                with self.assertRaises(ValueError):g.validate_android_material_reuse(record,record['configuration'],client,root)
    def test_new_source_commit_may_change_without_reusing_old_identity(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);record,client=self.fixture(root);client['coreSourceCommit']='d'*40
            self.assertTrue(g.validate_android_material_reuse(record,record['configuration'],client,root)['sourceMaterialsReusable'])

if __name__=='__main__':unittest.main()
