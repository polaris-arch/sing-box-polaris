import copy, unittest
from android_runtime_materials import validate
class AndroidRuntimeMaterialsTests(unittest.TestCase):
    def fixture(self):
        return {'schema':'polaris-android-runtime-materials-v1','configuration':'otherReleaseRuntimeClasspath',
            'components':[{'id':'g:a:1','module':'g:a:1'}],
            'artifacts':[{'module':'g:a:1','name':'a-1.aar','bytes':42,'sha256':'a'*64}]}
    def test_valid(self):
        record=self.fixture(); self.assertEqual(validate(record,record['configuration']),record)
    def test_missing_and_wrong_configuration(self):
        for record in [None,{},dict(self.fixture(),configuration='playReleaseRuntimeClasspath')]:
            with self.assertRaises(ValueError):validate(record,'otherReleaseRuntimeClasspath')
    def test_rejects_unbound_duplicate_and_invalid_bytes(self):
        for key,value in [('module','g:b:1'),('name','../a.aar'),('bytes',True),('sha256','z'*64)]:
            record=self.fixture();record['artifacts'][0][key]=value
            with self.assertRaises(ValueError):validate(record,'otherReleaseRuntimeClasspath')
        record=self.fixture();record['artifacts']*=2
        with self.assertRaises(ValueError):validate(record,'otherReleaseRuntimeClasspath')
    def test_requires_actual_artifacts(self):
        record=self.fixture();record['artifacts']=[]
        with self.assertRaises(ValueError):validate(record,'otherReleaseRuntimeClasspath')
if __name__=='__main__':unittest.main()
