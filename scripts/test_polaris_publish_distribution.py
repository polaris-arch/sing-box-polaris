import contextlib
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import polaris_publish_distribution as publish
import polaris_native_distribution as pack

class PublicationTests(unittest.TestCase):
    def test_actual_local_manifest_and_all_ten_assets(self):
        repo=Path(__file__).resolve().parents[1]
        path=repo/'release/native-publication/prepared-upload-assets.json'
        # Test the actual verified local candidate folder supplied by author delivery.
        import os
        directory=os.environ.get('POLARIS_PREPARED_ASSETS')
        if not directory:self.skipTest('actual offline assets folder required for integration verification')
        actual=Path(directory)/'UPLOAD-ASSETS.json'
        self.assertEqual(actual.read_bytes(),path.read_bytes())
        publish.validate_manifest(actual,hashlib.sha256(actual.read_bytes()).hexdigest())
    def test_remote_extra_missing_wrong_size_digest_rejected(self):
        manifest={'assets':[{'name':str(i),'bytes':1,'sha256':'a'*64} for i in range(10)]}
        assets=[{'name':str(i),'size':1,'digest':'sha256:'+'a'*64} for i in range(10)]
        publish.validate_remote_assets({'assets':assets},manifest)
        for values in [assets[:-1],assets+[assets[0]], [dict(x,size=2) for x in assets], [dict(x,digest=None) for x in assets]]:
            with self.assertRaises(ValueError):publish.validate_remote_assets({'assets':values},manifest)
    def test_unannotated_or_wrong_tag_target_rejected(self):
        for refs in ['abc refs/tags/'+publish.TAG, 'abc refs/tags/'+publish.TAG+'\nwrong refs/tags/'+publish.TAG+'^{}']:
            with patch.object(publish,'command',return_value=refs):
                with self.assertRaises(ValueError):publish.validate_tag(Path('/tmp/source'))
    def test_unauthenticated_public_readback_hash_size(self):
        data=b'actual asset';digest=hashlib.sha256(data).hexdigest()
        assets=[{'name':str(i),'bytes':len(data),'sha256':digest} for i in range(10)]
        release={'assets':[{'name':str(i),'size':len(data),'digest':'sha256:'+digest} for i in range(10)]}
        class Response:
            def __enter__(self):self.done=False;return self
            def __exit__(self,*args):pass
            def read(self,count):
                if self.done:return b''
                self.done=True;return data
        requests=[]
        def open_request(request,timeout):requests.append(request);return Response()
        with patch.object(publish.urllib.request,'urlopen',side_effect=open_request):
            records=publish.public_readback(release,{'assets':assets})
        self.assertEqual(len(records),10)
        for request in requests:
            self.assertFalse(request.has_header('Authorization'))
            self.assertTrue(request.full_url.startswith('https://github.com/polaris-arch/polaris-box/releases/download/'+publish.TAG+'/'))
        with patch.object(publish.urllib.request,'urlopen',side_effect=open_request):
            assets[0]['sha256']='0'*64;release['assets'][0]['digest']='sha256:'+'0'*64
            with self.assertRaises(ValueError):publish.public_readback(release,{'assets':assets})
    def test_draft_list_pagination_requires_unique_exact_tag(self):
        r={'tag_name':publish.TAG,'id':409181431}
        with patch.object(publish,'api',side_effect=[[{'tag_name':'other'}]*100,[r]]) as api:
            self.assertEqual(publish.find_draft_release('endpoint'),r)
            self.assertEqual(api.call_args_list,[unittest.mock.call('endpoint?per_page=100&page=1'),unittest.mock.call('endpoint?per_page=100&page=2')])
        for pages in [[[]],[[r]*100,[r]]]:
            with patch.object(publish,'api',side_effect=pages):
                with self.assertRaises(ValueError):publish.find_draft_release('endpoint')

    def test_empty_draft_identity_rejects_all_drift(self):
        r={'id':409181431,'tag_name':publish.TAG,'draft':True,'prerelease':True,
           'name':publish.TITLE,'body':'exact notes\n','assets':[]}
        publish.validate_empty_draft(r,'exact notes\n',409181431)
        for key,value in [('id',1),('tag_name','old'),('draft',False),('prerelease',False),
                          ('name','changed'),('body','changed'),('assets',[{'name':'partial'}])]:
            with self.subTest(key=key),self.assertRaises(ValueError):
                publish.validate_empty_draft(dict(r,**{key:value}),'exact notes\n',409181431)

    def test_resume_empty_draft_real_snapshots_no_creation_or_overwrite(self):
        import json
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as d:
            directory=Path(d);names=['polaris-box-release-notes.md']+[str(i) for i in range(9)]
            assets=[]
            for name in names:
                path=directory/name;path.write_text('exact notes\n')
                assets.append(publish.file_identity(path))
            manifest={'repository':publish.REPO,'tag':publish.TAG,'tagTargetCommit':publish.SOURCE,'assets':assets}
            path=directory/'UPLOAD-ASSETS.json';path.write_text(json.dumps(manifest))
            args=SimpleNamespace(repo=directory,approved_head='approved',manifest=path,
                manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),action='resume-empty-draft',
                release_id=409181431,expected_tag_object='inspected',receipt=directory/'receipt.json')
            empty={'id':args.release_id,'tag_name':publish.TAG,'draft':True,'prerelease':True,
                   'name':publish.TITLE,'body':'exact notes\n','assets':[]}
            calls=[]
            def command(*values):
                calls.append(values)
                if 'rev-parse' in values:return 'approved'
                if 'get-url' in values:return 'https://github.com/'+publish.REPO+'.git'
                if values[:3]==('gh','release','upload'):
                    item=publish.file_identity(Path(values[4]))
                    self.assertIn(item,assets)
                return ''
            def api(endpoint,*values):
                if '?per_page=' in endpoint:return [empty]
                if sum(c[:3]==('gh','release','upload') for c in calls)==10:
                    return dict(empty,assets=[{'name':a['name'],'size':a['bytes'],'digest':'sha256:'+a['sha256']} for a in assets])
                return empty
            with patch.object(publish,'command',side_effect=command),patch.object(publish,'api',side_effect=api),patch.object(publish,'validate_tag',return_value='inspected'),contextlib.redirect_stdout(None):
                publish.execute(args)
            self.assertEqual(json.loads(args.receipt.read_text())['phase'],'draft-staged')
            self.assertEqual(sum(c[:3]==('gh','release','upload') for c in calls),10)
            self.assertFalse(any('create' in c or 'push' in c or 'tag' in c or '--clobber' in c for c in calls))
            for drift in [dict(empty,assets=[{'name':'partial'}]),dict(empty,id=1),dict(empty,body='changed')]:
                calls.clear()
                with patch.object(publish,'command',side_effect=command),patch.object(publish,'api',return_value=[drift]),patch.object(publish,'validate_tag',return_value='inspected'):
                    with self.assertRaises(ValueError):publish.execute(args)
                self.assertFalse(any(c[0]=='gh' for c in calls))
            calls.clear()
            with patch.object(publish,'command',side_effect=command),patch.object(publish,'validate_tag',return_value='drifted'):
                with self.assertRaises(ValueError):publish.execute(args)
            self.assertFalse(any(c[0]=='gh' for c in calls))

    def test_manifest_drift_blocks_before_any_remote_action(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'UPLOAD-ASSETS.json';path.write_text('{}')
            with self.assertRaises(ValueError):publish.validate_manifest(path,'0'*64)

if __name__=='__main__':unittest.main()
