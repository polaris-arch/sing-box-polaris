import copy, json, tempfile, unittest
from pathlib import Path
from android_runtime_materials import validate, write_diagnostic

class AndroidRuntimeMaterialsTests(unittest.TestCase):
    def fixture(self):
        return {'schema':'polaris-android-runtime-materials-v2','configuration':'otherReleaseRuntimeClasspath',
            'components':[{'id':'g:a:1','module':'g:a:1'}],
            'artifacts':[{'module':'g:a:1','name':'a-1.aar','artifactIdentity':'a-1.aar (g:a:1)',
                'artifactName':'a','type':'aar','extension':'aar','classifier':None,
                'componentSelectedVariants':[{'owner':'g:a:1','name':'runtime','attributes':{'usage':'java-runtime'},'capabilities':['g:a:1']}],
                'bytes':42,'sha256':'a'*64}]}
    def check(self, record):
        return validate(record,'otherReleaseRuntimeClasspath')
    def test_valid(self):
        record=self.fixture(); self.assertEqual(self.check(record),dict(record,deduplicatedArtifactCount=0))
    def test_missing_and_wrong_configuration(self):
        for record in [None,{},dict(self.fixture(),configuration='playReleaseRuntimeClasspath'),dict(self.fixture(),schema='polaris-android-runtime-materials-v1')]:
            with self.assertRaises(ValueError):self.check(record)
    def test_rejects_unbound_and_invalid_bytes(self):
        for key,value in [('module','g:b:1'),('name','../a.aar'),('bytes',True),('sha256','z'*64)]:
            record=self.fixture();record['artifacts'][0][key]=value
            with self.assertRaises(ValueError):self.check(record)
    def test_requires_actual_artifacts(self):
        record=self.fixture();record['artifacts']=[]
        with self.assertRaises(ValueError):self.check(record)
    def test_identical_full_identity_deduplicated_without_mutating_raw(self):
        record=self.fixture();record['artifacts']*=2
        result=self.check(record)
        self.assertEqual(len(result['artifacts']),1)
        self.assertEqual(result['deduplicatedArtifactCount'],1)
        self.assertEqual(len(record['artifacts']),2)
    def test_identity_conflicting_bytes_fail(self):
        for field,value in [('sha256','b'*64),('bytes',43)]:
            record=self.fixture();other=copy.deepcopy(record['artifacts'][0]);other[field]=value;record['artifacts'].append(other)
            with self.assertRaisesRegex(ValueError,'conflicting'):self.check(record)
    def test_distinct_identity_same_basename_preserved(self):
        for field,value in [('classifier','android'),('type','jar'),('extension','jar'),('artifactIdentity','different'),('artifactName','other'),('componentSelectedVariants',[{'owner':'g:a:1','name':'other','attributes':{},'capabilities':[]}])]:
            record=self.fixture();other=copy.deepcopy(record['artifacts'][0]);other[field]=value;other['sha256']='b'*64;record['artifacts'].append(other)
            self.assertEqual(len(self.check(record)['artifacts']),2)
    def test_requires_complete_identity(self):
        for field in ('artifactIdentity','artifactName','type','extension','classifier','componentSelectedVariants'):
            record=self.fixture();del record['artifacts'][0][field]
            with self.assertRaises(ValueError):self.check(record)
    def test_diagnostics_persist_on_invalid_and_missing_graphs(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);raw=b'{"bad":"raw"}\n';(root/'other.json').write_bytes(raw)
            self.assertFalse(write_diagnostic(root,{'runId':'1'},{}))
            self.assertEqual((root/'other.json').read_bytes(),raw)
            receipt=json.loads((root/'receipt.json').read_text())
            self.assertIn('sha256',receipt['variants']['other'])
            self.assertFalse(receipt['publicationEligible'])
            self.assertEqual(json.loads((root/'diagnostics.json').read_text())['errors'],{'other':'ValueError','otherLegacy':'FileNotFoundError'})
    def test_diagnostics_success_retains_raw_duplicate_graph(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for variant in ('other','otherLegacy'):
                record=self.fixture();record['configuration']=variant+'ReleaseRuntimeClasspath';record['artifacts']*=2
                (root/(variant+'.json')).write_text(json.dumps(record))
            self.assertTrue(write_diagnostic(root,{},{}))
            receipt=json.loads((root/'receipt.json').read_text())
            self.assertEqual(receipt['variants']['other']['resolved']['deduplicatedArtifactCount'],1)
            self.assertEqual(len(json.loads((root/'other.json').read_text())['artifacts']),2)
    def test_workflow_bounded_failure_upload(self):
        text=(Path(__file__).resolve().parents[2]/'.github/workflows/android-runtime-materials.yml').read_text()
        self.assertEqual(text.count('if: always()'),2)
        self.assertIn('persist-credentials: false',text)
        self.assertIn('timeout-minutes: 30',text)
        self.assertIn('contents: read',text)
        self.assertIn('code=$?',text)
        upload=text.split('        path: |\n')[1].split('        if-no-files-found:')[0]
        self.assertEqual([line.strip() for line in upload.splitlines()],['runtime-evidence/other.json','runtime-evidence/otherLegacy.json','runtime-evidence/receipt.json','runtime-evidence/diagnostics.json','runtime-evidence/resolution-status.tsv'])

if __name__=='__main__':unittest.main()
