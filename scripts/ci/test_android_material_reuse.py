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
        directory=root/'release/ci';directory.mkdir(parents=True)
        android={'repository':previous['repository'],'baseCommit':previous['baseCommit'],
                 'files':[{'path':'app/build.gradle.kts','edits':[{'old':'ndkVersion = "old"','new':'ndkVersion = "30.0.16248370"'}]}],
                 'toolchain':{'jdk':'21'},'versionMetadata':['app/build.gradle.kts']}
        manifest=directory/'client-overlays.json'
        manifest.write_text(json.dumps({'platforms':{'android':android,'apple':{'patchVersion':True}}}))
        client=dict(previous,overlayManifestSHA256=g.sha(manifest))
        reference=root/'release/dependency-sources/clients/runtime/android-resolved/reuse-reference.json'
        transition={'schema':'polaris-android-material-overlay-transition-v1',
            'referenceSHA256':g.sha(reference),'previousSourceCommit':'d'*40,
            'previousOverlayManifestSHA256':previous['overlayManifestSHA256'],
            'currentOverlayManifestSHA256':client['overlayManifestSHA256'],
            'unchangedAndroidDefinitionSHA256':hashlib.sha256(json.dumps(android,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'changedPlatforms':['apple'],'requiresActualRuntimeArtifactComparison':True}
        path=directory/'android-material-overlay-transition.json';path.write_text(json.dumps(transition))
        return record,client,path

    def fixture_transition_check(self, root, record, client, transition):
        # Only temporary fixtures may replace the production-pinned contract hash.
        self.assertNotEqual(root.resolve(),g.ROOT.resolve())
        with mock.patch.object(g,'ANDROID_OVERLAY_TRANSITION_SHA256',g.sha(transition)):
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
            self.assertEqual(result['overlayTransitionSHA256'],g.sha(path))
            self.assertEqual(reference.read_bytes(),original)
            with self.assertRaises(ValueError):self.fixture_transition_check(root,None,client,path)

    def test_transition_cannot_change_other_client_identity_fields(self):
        for field,value in [('repository','other/repo'),('baseCommit','e'*40),('baseTree','f'*40),('platform','apple'),('unsigned',False)]:
            with self.subTest(field=field),tempfile.TemporaryDirectory() as d:
                root=Path(d);record,client,path=self.transition_fixture(root);client[field]=value
                with self.assertRaisesRegex(ValueError,'reference drift'):self.fixture_transition_check(root,record,client,path)

    def test_transition_rejects_arbitrary_new_manifest(self):
        for field in ['apple','android','new-platform']:
            with self.subTest(platform=field),tempfile.TemporaryDirectory() as d:
                root=Path(d);record,client,path=self.transition_fixture(root)
                manifest=root/'release/ci/client-overlays.json';data=json.loads(manifest.read_text())
                data['platforms'][field]={'unreviewed':True};manifest.write_text(json.dumps(data))
                client['overlayManifestSHA256']=g.sha(manifest)
                with self.assertRaisesRegex(ValueError,'transition identity changed'):self.fixture_transition_check(root,record,client,path)

    def test_transition_rechecks_android_source_ndk_and_toolchain_definition(self):
        for field in ['baseCommit','ndk','toolchain']:
            with self.subTest(field=field),tempfile.TemporaryDirectory() as d:
                root=Path(d);record,client,path=self.transition_fixture(root)
                manifest=root/'release/ci/client-overlays.json';data=json.loads(manifest.read_text());android=data['platforms']['android']
                if field=='ndk':android['files'][0]['edits'][0]['new']='ndkVersion = "unreviewed"'
                elif field=='toolchain':android['toolchain']['jdk']='unreviewed'
                else:android[field]='e'*40
                manifest.write_text(json.dumps(data));client['overlayManifestSHA256']=g.sha(manifest)
                transition=json.loads(path.read_text());transition['currentOverlayManifestSHA256']=client['overlayManifestSHA256'];path.write_text(json.dumps(transition))
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

    def test_transition_rejects_changed_reference_or_source_notice_map(self):
        for changed in ['reference','map','map-and-reference']:
            with self.subTest(changed=changed),tempfile.TemporaryDirectory() as d:
                root=Path(d);record,client,path=self.transition_fixture(root)
                directory=root/'release/dependency-sources/clients/runtime/android-resolved'
                reference=directory/'reuse-reference.json';material=directory/'source-notice-map.json'
                if changed=='reference':reference.write_bytes(reference.read_bytes()+b'\n')
                else:
                    material.write_bytes(material.read_bytes()+b'\n')
                    if changed=='map-and-reference':
                        data=json.loads(reference.read_text());data['materialMapSHA256']=g.sha(material);reference.write_text(json.dumps(data))
                with self.assertRaisesRegex(ValueError,'map changed|transition identity changed'):self.fixture_transition_check(root,record,client,path)

    def test_transition_file_hash_is_not_self_authorizing(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);record,client,path=self.transition_fixture(root);approved_sha=g.sha(path)
            path.write_bytes(path.read_bytes()+b'\n')
            with mock.patch.object(g,'ANDROID_OVERLAY_TRANSITION_SHA256',approved_sha):
                with self.assertRaisesRegex(ValueError,'transition changed'):g.validate_android_material_reuse(record,record['configuration'],client,root)

    def test_transition_metadata_must_match_all_identity_guards(self):
        cases=[('schema','wrong'),('referenceSHA256','0'*64),('previousOverlayManifestSHA256','0'*64),
               ('currentOverlayManifestSHA256','0'*64),('unchangedAndroidDefinitionSHA256','0'*64),
               ('changedPlatforms',['apple','android']),('requiresActualRuntimeArtifactComparison',False)]
        for field,value in cases:
            with self.subTest(field=field),tempfile.TemporaryDirectory() as d:
                root=Path(d);record,client,path=self.transition_fixture(root)
                data=json.loads(path.read_text());data[field]=value;path.write_text(json.dumps(data))
                with self.assertRaisesRegex(ValueError,'transition identity changed|Android definition changed'):self.fixture_transition_check(root,record,client,path)

    def test_real_contract_pins_current_overlay_and_untouched_historical_reference(self):
        # No patching and no fabricated new runtime evidence in this production check.
        root=Path(__file__).resolve().parents[2]
        path=root/'release/ci/android-material-overlay-transition.json';transition=json.loads(path.read_text())
        reference=root/'release/dependency-sources/clients/runtime/android-resolved/reuse-reference.json'
        manifest=root/'release/ci/client-overlays.json'
        self.assertEqual(g.ANDROID_OVERLAY_TRANSITION_SHA256,'68a5b52a4768ecf1534cb48b99285c21b365b815fcf985d7303994b1664b3b11')
        self.assertEqual(g.sha(path),g.ANDROID_OVERLAY_TRANSITION_SHA256)
        self.assertEqual(g.sha(reference),'6267fd43a2e4167b6f015303d13090d4e8286843c58cdc89ad1be5186008a8a3')
        self.assertEqual(transition['referenceSHA256'],g.sha(reference))
        historical=json.loads(reference.read_text())
        self.assertEqual(historical['referenceDiagnostic']['runId'],'39031988065')
        self.assertEqual(historical['clientSource']['overlayManifestSHA256'],'6565ccd48a4392dcc6f0172353f0faba0dad221e0c25ed2803fc79a0e0dd8093')
        self.assertEqual(transition['previousOverlayManifestSHA256'],historical['clientSource']['overlayManifestSHA256'])
        self.assertEqual(transition['previousSourceCommit'],'9031509c75ade460fd631437decbc9045eccee2a')
        self.assertEqual(transition['currentOverlayManifestSHA256'],g.sha(manifest))
        self.assertNotEqual(transition['previousOverlayManifestSHA256'],transition['currentOverlayManifestSHA256'])
        android=json.loads(manifest.read_text())['platforms']['android']
        self.assertEqual(hashlib.sha256(json.dumps(android,sort_keys=True,separators=(',',':')).encode()).hexdigest(),transition['unchangedAndroidDefinitionSHA256'])
        self.assertEqual(transition['changedPlatforms'],['apple'])
        self.assertIs(transition['requiresActualRuntimeArtifactComparison'],True)
        current=dict(historical['clientSource'],overlayManifestSHA256=g.sha(manifest))
        with self.assertRaisesRegex(ValueError,'missing Android runtime|invalid Android runtime'):
            g.validate_android_material_reuse(None,'otherReleaseRuntimeClasspath',current,root)

if __name__=='__main__':unittest.main()
