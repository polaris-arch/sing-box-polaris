import copy, hashlib, json, tempfile, unittest
from pathlib import Path
from unittest import mock
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
        # Production always carries the overlay manifest that actual identities are compared against.
        (root/'release/ci').mkdir(parents=True);(root/'release/ci/client-overlays.json').write_text(json.dumps({'platforms':{}}))
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

    def transition_fixture(self, root):
        record,previous=self.fixture(root)
        directory=root/'release/ci'
        android={'repository':previous['repository'],'baseCommit':previous['baseCommit'],
                 'files':[{'path':'app/build.gradle.kts','edits':[{'old':'ndkVersion = "old"','new':'ndkVersion = "30.0.16248370"'}]}],
                 'toolchain':{'jdk':'21'},'versionMetadata':['app/build.gradle.kts']}
        manifest=directory/'client-overlays.json'
        manifest.write_text(json.dumps({'platforms':{'android':android,'apple':{'patchVersion':True}}}))
        client=dict(previous,overlayManifestSHA256=g.sha(manifest))
        return record,client,hashlib.sha256(json.dumps(android,sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def fixture_transition_check(self, root, record, client, android_sha):
        # Only temporary fixtures may replace the production-pinned Android definition hash.
        self.assertNotEqual(root.resolve(),g.ROOT.resolve())
        with mock.patch.object(g,'ANDROID_DEFINITION_SHA256',android_sha):
            return g.validate_android_material_reuse(record,record['configuration'] if record else 'otherReleaseRuntimeClasspath',client,root)

    def test_apple_only_transition_keeps_actual_runtime_and_reference_identity(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);record,client,path=self.transition_fixture(root)
            reference=root/'release/dependency-sources/clients/runtime/android-resolved/reuse-reference.json'
            original=reference.read_bytes();record['artifacts']*=2
            result=self.fixture_transition_check(root,record,client,path)
            self.assertTrue(result['sourceMaterialsReusable']);self.assertFalse(result['legalConclusion'])
            self.assertEqual(result['actualArtifactCount'],1)
            self.assertEqual(result['referenceSHA256'],g.sha(reference))
            self.assertNotIn('overlayTransitionSHA256',result)
            self.assertEqual(reference.read_bytes(),original)
            with self.assertRaises(ValueError):self.fixture_transition_check(root,None,client,path)

    def test_transition_cannot_change_other_client_identity_fields(self):
        for field,value in [('repository','other/repo'),('baseCommit','e'*40),('baseTree','f'*40),('platform','apple'),('unsigned',False)]:
            with self.subTest(field=field),tempfile.TemporaryDirectory() as d:
                root=Path(d);record,client,path=self.transition_fixture(root);client[field]=value
                with self.assertRaisesRegex(ValueError,'reference drift'):self.fixture_transition_check(root,record,client,path)

    def test_transition_rejects_arbitrary_new_manifest(self):
        for field in ['android','unbound']:
            with self.subTest(platform=field),tempfile.TemporaryDirectory() as d:
                root=Path(d);record,client,path=self.transition_fixture(root)
                manifest=root/'release/ci/client-overlays.json';data=json.loads(manifest.read_text())
                data['platforms']['android' if field=='android' else 'apple']={'unreviewed':True};manifest.write_text(json.dumps(data))
                if field=='android':client['overlayManifestSHA256']=g.sha(manifest)
                with self.assertRaisesRegex(ValueError,'Android definition changed|overlay manifest differs'):self.fixture_transition_check(root,record,client,path)

    def test_transition_rechecks_android_source_ndk_and_toolchain_definition(self):
        for field in ['baseCommit','ndk','toolchain']:
            with self.subTest(field=field),tempfile.TemporaryDirectory() as d:
                root=Path(d);record,client,path=self.transition_fixture(root)
                manifest=root/'release/ci/client-overlays.json';data=json.loads(manifest.read_text());android=data['platforms']['android']
                if field=='ndk':android['files'][0]['edits'][0]['new']='ndkVersion = "unreviewed"'
                elif field=='toolchain':android['toolchain']['jdk']='unreviewed'
                else:android[field]='e'*40
                manifest.write_text(json.dumps(data));client['overlayManifestSHA256']=g.sha(manifest)
                # Even a fixture with an accepted outer manifest hash must retain
                # the separately pinned Android definition, including toolchains.
                with self.assertRaisesRegex(ValueError,'Android definition changed'):self.fixture_transition_check(root,record,client,path)

    def test_transition_rejects_actual_runtime_identity_or_byte_drift(self):
        cases=[('name','other.aar'),('artifactIdentity','changed'),('artifactName','other'),
               ('type','jar'),('extension','jar'),('classifier','other'),('bytes',43),('sha256','b'*64),
               ('componentSelectedVariants',[{'owner':'g:a:1','name':'other','attributes':{},'capabilities':[]}])]
        for field,value in cases:
            with self.subTest(field=field),tempfile.TemporaryDirectory() as d:
                root=Path(d);record,client,path=self.transition_fixture(root);record['artifacts'][0][field]=value
                with self.assertRaisesRegex(ValueError,'drift'):self.fixture_transition_check(root,record,client,path)

    def test_transition_rejects_changed_source_notice_map(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);record,client,path=self.transition_fixture(root)
            material=root/'release/dependency-sources/clients/runtime/android-resolved/source-notice-map.json'
            material.write_bytes(material.read_bytes()+b'\n')
            with self.assertRaisesRegex(ValueError,'map changed'):self.fixture_transition_check(root,record,client,path)

if __name__=='__main__':unittest.main()
