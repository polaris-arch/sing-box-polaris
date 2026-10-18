import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('release_binding',Path(__file__).with_name('release_identity.py'))
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
SOURCE='a'*40;OBJECT='b'*40;TAG='v1.15.0-polaris-alpha.12'

class SourceBindingTests(unittest.TestCase):
    def remote(self,source=SOURCE,oid=OBJECT,kind='commit'):
        return [{'object':{'type':'tag','sha':oid}},
                {'sha':oid,'tag':TAG,'object':{'type':kind,'sha':source}}]

    def local(self,head=SOURCE,oid=OBJECT):
        answers={('rev-parse','HEAD'):head,('status','--porcelain','--untracked-files=no'):'',
                 ('cat-file','-t','refs/tags/'+TAG):'tag',('rev-parse','refs/tags/'+TAG):oid,
                 ('rev-parse','refs/tags/'+TAG+'^{commit}'):SOURCE}
        return lambda *args:answers[args]

    def environment(self):
        return patch.dict(b.os.environ,{'GITHUB_REPOSITORY':b.REPO,'GITHUB_REPOSITORY_ID':str(b.RID),'GITHUB_SHA':SOURCE})

    def test_actual_checkout_and_tag_binding(self):
        with self.environment(),patch.object(b,'git',side_effect=self.local()),patch.object(b,'api',side_effect=self.remote()):
            self.assertEqual(b.verify_checkout(TAG,SOURCE,OBJECT),OBJECT)

    def test_tag_checkout_can_never_substitute_for_dispatch_sha(self):
        with self.environment(),patch.object(b,'git',side_effect=self.local(head='c'*40)),patch.object(b,'api') as api:
            with self.assertRaisesRegex(ValueError,'actual producer checkout'):b.verify_checkout(TAG,SOURCE,OBJECT)
            api.assert_not_called()

    def test_tag_object_movement_and_mixed_local_tag_are_rejected(self):
        with self.environment(),patch.object(b,'git',side_effect=self.local()),patch.object(b,'api',side_effect=self.remote(oid='c'*40)):
            with self.assertRaisesRegex(ValueError,'tag object moved'):b.verify_checkout(TAG,SOURCE,OBJECT)
        with self.environment(),patch.object(b,'git',side_effect=self.local(oid='c'*40)),patch.object(b,'api',side_effect=self.remote()):
            with self.assertRaisesRegex(ValueError,'local and remote'):b.verify_checkout(TAG,SOURCE,OBJECT)

    def test_tag_must_directly_identify_dispatch_source(self):
        for source,kind in [('c'*40,'commit'),(SOURCE,'tag')]:
            with self.subTest(source=source,kind=kind),patch.object(b,'api',side_effect=self.remote(source=source,kind=kind)):
                with self.assertRaises(ValueError):b.remote_tag_identity(TAG,SOURCE,OBJECT)
        with patch.object(b,'api',return_value={'object':{'type':'commit','sha':SOURCE}}):
            with self.assertRaisesRegex(ValueError,'annotated'):b.remote_tag_identity(TAG,SOURCE,OBJECT)

if __name__=='__main__':unittest.main()
