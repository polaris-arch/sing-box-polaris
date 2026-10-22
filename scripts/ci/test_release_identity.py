import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import yaml
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

class AnnotatedCheckoutGitTests(unittest.TestCase):
    """Offline synthetic objects; real Git and the unchanged production verifier.

    Reproduce checkout@08c6903's depth-zero fetch/testRef/targeted-fetch paths,
    not a GitHub runner or a producer receipt. Only the remote API is simulated.
    """
    tag='v1.15.0-polaris-alpha.12.1'

    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='polaris-checkout-regression-')
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.env=dict(os.environ,GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL=os.devnull,
                      GIT_AUTHOR_NAME='Offline Fixture',GIT_AUTHOR_EMAIL='fixture@example.invalid',
                      GIT_COMMITTER_NAME='Offline Fixture',GIT_COMMITTER_EMAIL='fixture@example.invalid')
        self.origin=self.root/'origin';self.origin.mkdir()
        self.git(self.origin,'init','-b','polaris-main')
        (self.origin/'fixture.txt').write_text('synthetic checkout fixture\n')
        self.git(self.origin,'add','fixture.txt')
        self.git(self.origin,'commit','-m','Synthetic test only')
        self.source=self.git(self.origin,'rev-parse','HEAD')
        self.git(self.origin,'tag','-a',self.tag,'-m','Synthetic annotated tag')
        self.oid=self.git(self.origin,'rev-parse','refs/tags/'+self.tag)
        self.assertNotEqual(self.oid,self.source)

    def git(self,root,*args):
        result=subprocess.run(['git','-C',str(root),*args],env=self.env,
                              text=True,capture_output=True,check=True)
        return result.stdout.strip()

    def fetch_full_history(self,name='checkout'):
        repo=self.root/name;repo.mkdir()
        self.git(repo,'init')
        self.git(repo,'remote','add','origin',str(self.origin))
        self.git(repo,'-c','protocol.version=2','fetch','--prune','--no-recurse-submodules','origin',
                 '+refs/heads/*:refs/remotes/origin/*','+refs/tags/*:refs/tags/*')
        self.assertEqual(self.git(repo,'cat-file','-t','refs/tags/'+self.tag),'tag')
        self.assertEqual(self.git(repo,'rev-parse','refs/tags/'+self.tag),self.oid)
        return repo

    def verify(self,repo,accepted,event_ref):
        self.assertEqual(self.git(repo,'rev-parse','HEAD'),self.source)
        remote=[{'object':{'type':'tag','sha':self.oid}},
                {'sha':self.oid,'tag':self.tag,'object':{'type':'commit','sha':self.source}}]
        env=dict(self.env,GITHUB_REPOSITORY=b.REPO,GITHUB_REPOSITORY_ID=str(b.RID),
                 GITHUB_SHA=self.source,GITHUB_REF=event_ref)
        previous=Path.cwd()
        try:
            os.chdir(repo)
            with patch.dict(os.environ,env),patch.object(b,'api',side_effect=remote):
                # Do not mock b.git: these are the production verifier's Git calls.
                if accepted:self.assertEqual(b.verify_checkout(self.tag,self.source,self.oid),self.oid)
                else:
                    with self.assertRaisesRegex(ValueError,'local annotated tag missing'):
                        b.verify_checkout(self.tag,self.source,self.oid)
        finally:os.chdir(previous)
        self.assertEqual(self.git(self.origin,'cat-file','-t','refs/tags/'+self.tag),'tag')
        self.assertEqual(self.git(self.origin,'rev-parse','refs/tags/'+self.tag),self.oid)

    def test_implicit_tag_depth_zero_overwrites_local_annotation_and_is_rejected(self):
        repo=self.fetch_full_history()
        # checkout's testRef compares unpeeled tag OID with event commit, then
        # the fallback refspec fetches +commit:refs/tags/tag (local tag only).
        self.assertNotEqual(self.git(repo,'rev-parse','refs/tags/'+self.tag),self.source)
        self.git(repo,'-c','protocol.version=2','fetch','--no-tags','--prune','--no-recurse-submodules',
                 'origin','+'+self.source+':refs/tags/'+self.tag)
        self.git(repo,'checkout','--force','refs/tags/'+self.tag)
        self.assertEqual(self.git(repo,'cat-file','-t','refs/tags/'+self.tag),'commit')
        self.assertEqual(self.git(repo,'rev-parse','refs/tags/'+self.tag),self.source)
        self.verify(repo,False,'refs/tags/'+self.tag)

    def test_branch_depth_zero_preserves_annotation_and_is_accepted(self):
        repo=self.fetch_full_history()
        self.assertEqual(self.git(repo,'rev-parse','refs/remotes/origin/polaris-main'),self.source)
        self.git(repo,'checkout','--force','-B','polaris-main','refs/remotes/origin/polaris-main')
        self.verify(repo,True,'refs/heads/polaris-main')

    def test_explicit_sha_depth_zero_preserves_annotation_under_tag_dispatch(self):
        repo=self.fetch_full_history()
        self.git(repo,'cat-file','-e',self.source+'^{commit}')
        self.git(repo,'checkout','--force',self.source)
        # Event ref stays a tag; the source-owned explicit checkout input is SHA.
        self.verify(repo,True,'refs/tags/'+self.tag)

    def test_all_five_source_owned_gate_inputs_take_real_git_preserving_path(self):
        root=Path(__file__).resolve().parents[2]
        for workflow,jobs in [('build.yml',('calculate_version','native_index')),
                              ('signed-release.yml',('calculate_version','native_index','upload'))]:
            spec=yaml.safe_load((root/'.github/workflows'/workflow).read_text())
            for name in jobs:
                with self.subTest(workflow=workflow,job=name):
                    checkout=next(s for s in spec['jobs'][name]['steps'] if s.get('uses','').startswith('actions/checkout@'))
                    self.assertEqual(checkout['with']['ref'],'${{ github.sha }}')
                    self.assertEqual(checkout['with']['fetch-depth'],0)
                    repo=self.fetch_full_history(workflow+'-'+name)
                    self.git(repo,'cat-file','-e',self.source+'^{commit}')
                    self.git(repo,'checkout','--force',self.source)
                    self.verify(repo,True,'refs/tags/'+self.tag)

if __name__=='__main__':unittest.main()
