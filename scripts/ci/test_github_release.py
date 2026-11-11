import importlib.util
import copy
import hashlib
import jsonschema
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import re
import os
import runpy
from contextlib import chdir, contextmanager
import zipfile
import io
import struct
import zlib
import errno

spec=importlib.util.spec_from_file_location('publisher',Path(__file__).with_name('github_release.py'))
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)


def receipt_context_fixture():
    policies=json.loads(p.SCOPE.read_text())['all']['receiptJobs']
    return {'GITHUB_REF':'refs/heads/fixture','RECEIPT_EVIDENCE_MODE':'final','RECEIPT_SOURCE_GENERATE_ONLY':'false',
            'NEEDS_JSON':json.dumps({key:{'result':'success','outputs':{}} for key in policies})}

def native_jobs_fixture(index):
    """Synthetic Actions data; only mocked metadata, never native authority."""
    from native_release_index import expected_native_job_names
    names=expected_native_job_names(index['platforms'])
    return [{'id':i+1,'name':name,'status':'completed','conclusion':'success',
             'head_sha':index['sourceCommit'],'run_id':42,'run_attempt':1}
            for i,(key,name) in enumerate(names.items())]

class BoundedStorageTests(unittest.TestCase):
    @staticmethod
    def zipped(rows, compression=zipfile.ZIP_DEFLATED):
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w',compression=compression) as archive:
            for name,data in rows:archive.writestr(name,data)
        return stream.getvalue()

    @staticmethod
    def metadata(data,name='test',ident=31):
        return {'id':ident,'name':name,'size_in_bytes':len(data),'digest':'sha256:'+hashlib.sha256(data).hexdigest(),
                'expired':False,'workflow_run':{'id':7,'head_sha':'a'*40}}

    @contextmanager
    def download(self,data,metadata=None,exit_code=0,limit=p.SCRATCH_LIMIT,reserve=0):
        class Child:
            def __init__(self):
                self.stdout=tempfile.TemporaryFile();self.stdout.write(b'HTTP/2 200 OK\r\n\r\n'+data);self.stdout.seek(0)
                self.stderr=tempfile.TemporaryFile();self.done=False;self.terminated=False;self.reaped=False
            def wait(self,timeout=None):self.done=True;self.reaped=True;return exit_code
            def poll(self):return exit_code if self.done else None
            def terminate(self):self.terminated=True;self.done=True
            def kill(self):self.terminated=True;self.done=True
        child=Child()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);budget=p.ScratchBudget(root,limit=limit,reserve=reserve)
            with mock.patch.object(p.subprocess,'Popen',return_value=child) as started:
                try:
                    yield metadata or self.metadata(data),budget,child,started
                finally:
                    child.stdout.close();child.stderr.close()
            self.assertEqual(list(root.iterdir()),[])
            self.assertEqual(budget.live,0)

    def test_streams_all_bytes_without_retaining_expanded_private_payloads(self):
        payload=b'x'*(4*1024**2)
        data=self.zipped([(f'sdk-{n}.bin',payload) for n in range(32)])
        with self.download(data) as (metadata,budget,child,_):
            with p.artifact_archive(metadata,budget) as (archive,members):
                self.assertEqual(len(members),32)
                for item in members:
                    measured,_=p.measure_member(archive,item)
                    self.assertEqual(measured,{'bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest()})
                    self.assertEqual(len(list(budget.root.iterdir())),1)
            self.assertEqual(budget.peak,len(data));self.assertTrue(child.reaped)

    def test_download_digest_size_child_errors_clean_and_reap(self):
        data=self.zipped([('payload',b'data')])
        for kind in ('digest','short','long','exit'):
            metadata=self.metadata(data);downloaded=data;code=0
            if kind=='digest':metadata['digest']='sha256:'+'0'*64
            elif kind=='short':downloaded=data[:-1]
            elif kind=='long':downloaded=data+b'extra'
            else:code=7
            with self.subTest(kind=kind),self.download(downloaded,metadata,exit_code=code) as (a,budget,child,_):
                with self.assertRaises(ValueError),p.artifact_archive(a,budget):pass
                self.assertTrue(child.reaped)
                if kind=='long':self.assertTrue(child.terminated)

    def test_scratch_and_available_space_admission_precede_download(self):
        data=self.zipped([('x',b'x')])
        with self.download(data,limit=len(data)-1) as (a,budget,_,started):
            with self.assertRaisesRegex(ValueError,'scratch budget'),p.artifact_archive(a,budget):pass
            started.assert_not_called()
        with self.download(data,reserve=128) as (a,budget,_,started),mock.patch.object(p.shutil,'disk_usage',return_value=type('Usage',(),{'free':len(data)+127})()):
            with self.assertRaisesRegex(ValueError,'free scratch'),p.artifact_archive(a,budget):pass
            started.assert_not_called()

    def test_archive_path_type_case_and_prefix_failures_before_member_writes(self):
        symlink=zipfile.ZipInfo('link');symlink.create_system=3;symlink.external_attr=(0o120777<<16)
        cases=[ [('a',b'x'),('A',b'y')], [('file',b'x'),('file/child',b'y')],
                [('parent/child',b'x'),('PARENT',b'y')], [('../escape',b'x')],
                [('a//b',b'x')], [(symlink,b'target')], [('name/',b'nonempty')]]
        for rows in cases:
            data=self.zipped(rows)
            with self.subTest(rows=str(rows)[:70]),self.download(data) as (a,budget,_,_):
                with self.assertRaises(ValueError),p.artifact_archive(a,budget):pass

    def test_crc_and_real_inflated_size_are_checked_not_zipfile_truncation(self):
        for compression in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED):
            original=self.zipped([('x',b'0123456789')],compression)
            for kind in ('crc','declared-short','declared-long'):
                data=bytearray(original);central=data.index(b'PK\x01\x02')
                if kind=='crc':
                    struct.pack_into('<L',data,14,0);struct.pack_into('<L',data,central+16,0)
                else:
                    size=5 if kind=='declared-short' else 20
                    struct.pack_into('<L',data,22,size);struct.pack_into('<L',data,central+24,size)
                    crc=zlib.crc32(b'01234') if kind=='declared-short' else zlib.crc32(b'0123456789')
                    struct.pack_into('<L',data,14,crc);struct.pack_into('<L',data,central+16,crc)
                with self.subTest(compression=compression,kind=kind),self.download(bytes(data)) as (a,budget,_,_):
                    with p.artifact_archive(a,budget) as (archive,members),self.assertRaises(ValueError):
                        p.measure_member(archive,members[0])

    def test_member_edquot_and_json_cap_clean_owned_member_and_zip(self):
        data=self.zipped([('record.json',b'{"data":"'+b'x'*10000+b'"}')])
        with self.download(data) as (a,budget,_,_):
            with p.artifact_archive(a,budget) as (archive,members):
                with self.assertRaisesRegex(ValueError,'JSON evidence'):
                    p.measure_member(archive,members[0],json_limit=100)
                with self.assertRaises(OSError) as caught:
                    with budget.temporary(members[0].file_size,'fixture') as f,mock.patch.object(f,'write',side_effect=OSError(errno.EDQUOT,'fixture quota')):
                        p.measure_member(archive,members[0],f)
                self.assertEqual(caught.exception.errno,errno.EDQUOT)
                self.assertEqual(len(list(budget.root.iterdir())),1)

    def test_audit_copy_and_json_write_quota_failures_remove_partial_destinations(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source=root/'source';source.write_bytes(b'x'*32);target=root/'audit'
            budget=p.ScratchBudget(root,reserve=0)
            def partial(src,dst,length):dst.write(b'partial');raise OSError(errno.EDQUOT,'quota')
            with mock.patch.object(p.shutil,'copyfileobj',side_effect=partial),self.assertRaises(OSError):budget.copy(source,target)
            self.assertFalse(target.exists());self.assertEqual(budget.live,0)
            with mock.patch.object(Path,'open',side_effect=OSError(errno.EDQUOT,'quota')),self.assertRaises(OSError):budget.write_json(target,{'small':True})
            self.assertFalse(target.exists());self.assertEqual(budget.live,0)

    def test_reviewed_contract_streams_extras_but_retains_only_reviewed_proposal(self):
        proposal=json.dumps({'sourceCommit':'a'*40,'reviewed':False}).encode()
        data=self.zipped([('release-inventory-proposal.json',proposal),('audit/private-sdk.bin',b'z'*2**20)])
        metadata=self.metadata(data,'github-release-validation')
        run={'repository':{'id':p.RID},'head_repository':{'id':p.RID},'path':'.github/workflows/publish-github.yml',
             'head_sha':'b'*40,'status':'completed','conclusion':'success'}
        with self.download(data,metadata) as (_,budget,_,_),mock.patch.object(p,'api',return_value=run),mock.patch.object(p,'pages',return_value=[metadata]), \
             mock.patch.dict(os.environ,GITHUB_SHA='b'*40):
            record=p.reviewed_contract('7',hashlib.sha256(proposal).hexdigest(),'a'*40,budget=budget)
            self.assertEqual(record,{'sourceCommit':'a'*40,'reviewed':True});self.assertIn(b'false',proposal)
            self.assertEqual(budget.peak,len(data))
            with self.assertRaisesRegex(ValueError,'revision'),mock.patch.dict(os.environ,GITHUB_SHA='c'*40):
                p.reviewed_contract('7',hashlib.sha256(proposal).hexdigest(),'a'*40,budget=budget)

    def public_fixture(self):
        name='sing-box-polaris-'+p.VERSION+'-linux-amd64.tar.gz';private='polaris-candidate-manifest-unused.json'
        rows=[(name,b'public'*100000),(private,b'private'*100000)];data=self.zipped(rows)
        artifact='binary-linux_amd64';metadata=self.metadata(data,artifact)
        files={n:dict(bytes=len(content),sha256=hashlib.sha256(content).hexdigest(),releaseName=p.publication('all',artifact,n)[0],
                      publicationDisposition=p.publication('all',artifact,n)[1]) for n,content in rows}
        actual={'sourceCommit':'a'*40,'runs':{'all':{'id':'7','attempt':1,'artifacts':{artifact:{'id':metadata['id'],
                    'archiveBytes':len(data),'archiveSha256':metadata['digest'],'files':files}}}}}
        return data,metadata,actual

    def test_public_supplier_closes_on_upload_failure_and_binds_second_pass(self):
        data,metadata,actual=self.public_fixture()
        with self.download(data) as (_,budget,_,_),mock.patch.object(p,'api',return_value=metadata):
            supplier=p.public_asset_stream(actual,budget)
            with self.assertRaisesRegex(RuntimeError,'upload failed'),p.closing(supplier):
                name,path=next(supplier);self.assertTrue(path.is_file());self.assertEqual(path.stat().st_size,600000)
                self.assertEqual(len(list(budget.root.iterdir())),2)
                raise RuntimeError('upload failed')
            self.assertEqual(list(budget.root.iterdir()),[])
            self.assertEqual(budget.peak,len(data)+600000)
        changed=dict(metadata,id=999)
        with self.download(data) as (_,budget,_,started),mock.patch.object(p,'api',return_value=changed):
            with self.assertRaisesRegex(ValueError,'identity changed'):list(p.public_asset_stream(actual,budget))
            started.assert_not_called()

    def test_public_supplier_refuses_wrong_member_hash_before_yield(self):
        data,metadata,actual=self.public_fixture()
        first=next(iter(actual['runs']['all']['artifacts'].values()))
        next(iter(first['files'].values()))['sha256']='0'*64
        with self.download(data) as (_,budget,_,_),mock.patch.object(p,'api',return_value=metadata):
            with self.assertRaisesRegex(ValueError,'member bytes changed'):list(p.public_asset_stream(actual,budget))

    def test_all_role_inventory_and_validation_keep_only_small_source_audit(self):
        source='a'*40;scope={};runs={};artifacts={};downloads={};ident=100
        source_bytes=b'original-source';source_name='source.tar.gz'
        index={'platforms':[],'sourceArchive':{'name':source_name,'bytes':len(source_bytes),'sha256':hashlib.sha256(source_bytes).hexdigest()}}
        for role,rid in [('all','7')]:
            workflow=f'.github/workflows/{role}.yml';runs[rid]={'repository':{'id':p.RID},'head_repository':{'id':p.RID},
                'head_sha':source,'path':workflow,'status':'completed','conclusion':'success','event':'workflow_dispatch',
                'run_attempt':1,'run_started_at':'2026-10-22T00:00:00Z'}
            receipt={'repository':p.REPO,'repositoryId':p.RID,'sourceCommit':source,'runId':rid,'attempt':1,'version':p.VERSION,
                     'build':'All','role':role,'publishStores':False,'publishRegistry':False}
            payloads={'publisher-run-receipt':[('publisher-run-receipt.json',json.dumps(receipt).encode())]}
            if role=='all':
                payloads['binary-native-index']=[('polaris-upstream-native-assets.json',json.dumps(index).encode()),(source_name,source_bytes)]
                payloads['libbox-internal-fixture']=[('large-private.bin',b'x'*(8*1024**2))]
                for flavor in ('other','other-legacy'):
                    payloads['binary-android-apks-'+flavor]=[(f'SFA-{p.VERSION}-{flavor}-version-metadata.json',b'{"version":1}')]
            scope[role]={'workflow':workflow,'requiredArtifacts':list(payloads),'payloadRules':{}}
            artifacts[rid]=[]
            for name,rows in payloads.items():
                data=self.zipped(rows);a=self.metadata(data,name,ident);a.update(created_at='2026-10-22T00:01:00Z',workflow_run={'id':int(rid),'head_sha':source})
                ident+=1;downloads[a['id']]=data;artifacts[rid].append(a)
                scope[role]['payloadRules'][name]=[{'pattern':re.escape(n),'count':1} for n,_ in rows]
        def child(command,**kwargs):
            data=downloads[int(command[-1].split('/')[-2])]
            out=tempfile.TemporaryFile();out.write(b'HTTP/2 200 OK\r\n\r\n'+data);out.seek(0)
            return type('Child',(),{'stdout':out,'stderr':tempfile.TemporaryFile(),'wait':lambda self,**k:0,'poll':lambda self:0})()
        def associate(result,*_):result['distributionMaterials']={};return result
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);work=root/'work';budget=p.ScratchBudget(work,reserve=0)
            with mock.patch.object(p,'release_scope',return_value=scope),mock.patch.object(p,'api',side_effect=lambda path:runs[path.split('/')[-1]]) as remote, \
                 mock.patch.object(p,'pages',side_effect=lambda path,key:artifacts[path.split('/')[-2]]), \
                 mock.patch.object(p.subprocess,'Popen',side_effect=child),mock.patch.object(p,'client_platform',return_value=None), \
                 mock.patch.object(p,'validate_final_index'),mock.patch.object(p,'associate_distribution_materials',side_effect=associate):
                actual=p.inventory({'all':'7'},source,work,'b'*40,'c'*40,budget=budget)
            self.assertEqual(len(remote.call_args_list),1)
            self.assertTrue(all(len(call.args)==1 for call in remote.call_args_list))
            self.assertFalse(actual['reviewed'])
            self.assertEqual({x.relative_to(work).as_posix() for x in work.rglob('*') if x.is_file()},
                {'all/binary-native-index/polaris-upstream-native-assets.json','all/binary-native-index/'+source_name})
            config=copy.deepcopy(actual);config['reviewed']=True
            receipt=p.assemble(actual,config,work,root/'dist',root/'audit',materialize=False,budget=budget)
            self.assertEqual(list((root/'dist').iterdir()),[]);self.assertEqual(len(receipt['assets']),1)
            self.assertLess(budget.peak,1024**2)
            self.assertTrue((root/'audit'/source_name).is_file())

    def test_publish_finalization_uncertainty_is_read_back_never_retried(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);out=root/'dist';out.mkdir();audit=root/'audit';audit.mkdir()
            (out/'payload').write_bytes(b'public');(audit/'polaris-upstream-native-assets.json').write_text('{}')
            budget=p.ScratchBudget(root/'scratch',reserve=0,audit=audit)
            release={'id':42,'draft':True,'tag_name':p.TAG,'upload_url':f'https://uploads.github.com/repos/{p.REPO}/releases/42/assets{{?name,label}}'}
            calls=[]
            def remote(path,method='GET',payload=None):
                calls.append((path,method))
                if method=='POST':return release
                if method=='PATCH':raise TimeoutError('response lost after final PATCH')
                return dict(release,draft=not any(m=='PATCH' for _,m in calls))
            listing_calls=0
            def pages(path):
                nonlocal listing_calls
                if path.endswith('/assets'):
                    return [{'name':'payload','state':'uploaded','size':6,'digest':'sha256:'+hashlib.sha256(b'public').hexdigest()}]
                listing_calls+=1
                return [] if listing_calls==1 else [release]
            with mock.patch.object(p,'api',side_effect=remote),mock.patch.object(p,'pages',side_effect=pages), \
                 mock.patch.object(p,'tag_identity',return_value='c'*40),mock.patch.object(p,'validate_publication_index'), \
                 mock.patch.object(p.subprocess,'run'),mock.patch.dict(os.environ,{'GITHUB_RUN_ID':'99'}),mock.patch('builtins.print'):
                with self.assertRaises(TimeoutError):p.publish(out,'a'*40,audit,budget=budget)
            self.assertEqual([m for _,m in calls].count('PATCH'),1)
            self.assertEqual(calls[-1],(f'repos/{p.REPO}/releases/42','GET'))
            self.assertEqual(budget.state['remoteWriteState'],'finalization-readback');self.assertIs(budget.state['observedDraft'],False)
            self.assertNotIn('DELETE',[m for _,m in calls])

    def test_audit_existing_files_are_never_removed_on_exclusive_open_failure(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source=root/'source';target=root/'existing';source.write_bytes(b'source');target.write_bytes(b'existing')
            budget=p.ScratchBudget(root,reserve=0)
            with self.assertRaises(FileExistsError):budget.copy(source,target)
            self.assertEqual(target.read_bytes(),b'existing')
            with self.assertRaises(FileExistsError):budget.write_json(target,{'value':1})
            self.assertEqual(target.read_bytes(),b'existing');self.assertEqual(budget.live,0)

    def test_zip64_directory_budget_is_checked_before_zipfile_allocation(self):
        original=self.zipped([('x',b'x')]);end=len(original)-22
        fields=struct.unpack('<4s4H2LH',original[end:]);count,size,offset=fields[4:7]
        def zip64(n=count,dsize=size):
            record=struct.pack('<4sQ2H2L4Q',b'PK\x06\x06',44,45,45,0,0,n,n,dsize,offset)
            locator=struct.pack('<4sLQL',b'PK\x06\x07',0,end,1)
            final=struct.pack('<4s4H2LH',b'PK\x05\x06',0,0,65535,65535,0xffffffff,0xffffffff,0)
            return original[:end]+record+locator+final
        with self.download(zip64()) as (a,budget,_,_):
            with p.artifact_archive(a,budget) as (archive,members):
                self.assertEqual(p.measure_member(archive,members[0])[0]['bytes'],1)
        for data in (zip64(16385),zip64(dsize=32*1024**2+1)):
            with self.download(data) as (a,budget,_,_),mock.patch.object(p.zipfile,'ZipFile') as opened:
                with self.assertRaisesRegex(ValueError,'directory exceeds'),p.artifact_archive(a,budget):pass
                opened.assert_not_called()

    def test_download_edquot_stops_and_reaps_child_without_retaining_zip(self):
        data=self.zipped([('x',b'x')]);real=p.tempfile.NamedTemporaryFile
        @contextmanager
        def failing_file(*args,**kwargs):
            with real(*args,**kwargs) as f,mock.patch.object(f,'write',side_effect=OSError(errno.EDQUOT,'download quota')):
                yield f
        with self.download(data) as (a,budget,child,_),mock.patch.object(p.tempfile,'NamedTemporaryFile',failing_file):
            with self.assertRaises(OSError) as caught,p.artifact_archive(a,budget):pass
            self.assertEqual(caught.exception.errno,errno.EDQUOT);self.assertTrue(child.terminated);self.assertTrue(child.reaped)

    def test_cleanup_error_does_not_mask_original_storage_failure(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);budget=p.ScratchBudget(root,reserve=0);primary=OSError(errno.EDQUOT,'primary')
            @contextmanager
            def cleanup_fails(*args,**kwargs):
                try:yield mock.Mock()
                finally:raise PermissionError(errno.EACCES,'cleanup')
            with mock.patch.object(p.tempfile,'NamedTemporaryFile',cleanup_fails),self.assertRaises(OSError) as caught:
                with budget.temporary(10,'test'):raise primary
            self.assertIs(caught.exception,primary);self.assertEqual(budget.live,0)
            source=root/'source';source.write_bytes(b'x');target=root/'target'
            with mock.patch.object(p.shutil,'copyfileobj',side_effect=primary),mock.patch.object(Path,'unlink',side_effect=PermissionError('cleanup')):
                with self.assertRaises(OSError) as caught:budget.copy(source,target)
            self.assertIs(caught.exception,primary);self.assertTrue(primary.__notes__);self.assertEqual(budget.live,0)

    def test_whole_public_staging_peak_is_admitted_before_any_draft_write(self):
        data,metadata,actual=self.public_fixture()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);out=root/'dist';out.mkdir();audit=root/'audit';audit.mkdir()
            (audit/'polaris-upstream-native-assets.json').write_text('{}')
            public=next(f for f in next(iter(actual['runs']['all']['artifacts'].values()))['files'].values() if f['releaseName'])
            (audit/p.RECEIPT).write_text(json.dumps({'assets':[public]}))
            budget=p.ScratchBudget(root/'scratch',limit=len(data)+public['bytes']-1,reserve=0)
            with mock.patch.object(p,'api') as remote,mock.patch.object(p,'pages',return_value=[]),mock.patch.object(p,'tag_identity',return_value='c'*40),mock.patch.object(p,'validate_publication_index'):
                with self.assertRaisesRegex(ValueError,'scratch budget'):p.publish(out,'a'*40,audit,measured=actual,budget=budget)
                remote.assert_not_called()

    def test_reviewed_inventory_failure_precedes_large_producer_downloads(self):
        with tempfile.TemporaryDirectory() as d:
            args=p.argparse.Namespace(audit=Path(d)/'audit',source_dir=Path('source'),source='a'*40,
                mode='validate',inventory_run='77',inventory_sha256='f'*64)
            with mock.patch.object(p,'command',return_value='b'*40),mock.patch.object(p,'tag_identity',return_value='c'*40), \
                 mock.patch.object(p,'reviewed_contract',side_effect=ValueError('original hash mismatch')) as reviewed, \
                 mock.patch.object(p,'inventory') as inventory,mock.patch('builtins.print'):
                with self.assertRaisesRegex(ValueError,'original hash mismatch'):p.bounded_release(args,{'all':'7'})
                inventory.assert_not_called();reviewed.assert_called_once()

    def test_reviewed_producer_input_mismatch_precedes_downloads(self):
        with tempfile.TemporaryDirectory() as d:
            args=p.argparse.Namespace(audit=Path(d)/'audit',source_dir=Path('source'),source='a'*40,
                mode='validate',inventory_run='77',inventory_sha256='f'*64)
            with mock.patch.object(p,'command',return_value='b'*40),mock.patch.object(p,'tag_identity',return_value='c'*40), \
                 mock.patch.object(p,'reviewed_contract',return_value={'runs':{'all':{'id':'wrong'}}}), \
                 mock.patch.object(p,'inventory') as inventory,mock.patch('builtins.print'):
                with self.assertRaisesRegex(ValueError,'producer inputs differ'):p.bounded_release(args,{'all':'7'})
                inventory.assert_not_called()

    def test_preflight_contract_then_all_producer_validation_still_required(self):
        calls=[];runs={'all':'7'};contract={'runs':{k:{'id':v} for k,v in runs.items()}}
        class StopInventory(Exception):pass
        def reviewed(*args,**kwargs):calls.append('reviewed');return contract
        def inventory(*args,**kwargs):calls.append('actual-inventory');raise StopInventory()
        with tempfile.TemporaryDirectory() as d:
            args=p.argparse.Namespace(audit=Path(d)/'audit',source_dir=Path('source'),source='a'*40,
                mode='validate',inventory_run='77',inventory_sha256='f'*64)
            with mock.patch.object(p,'command',return_value='b'*40),mock.patch.object(p,'tag_identity',return_value='c'*40), \
                 mock.patch.object(p,'reviewed_contract',side_effect=reviewed),mock.patch.object(p,'inventory',side_effect=inventory), \
                 mock.patch.object(p,'assemble') as assemble,mock.patch('builtins.print'):
                with self.assertRaises(StopInventory):p.bounded_release(args,runs)
                self.assertEqual(calls,['reviewed','actual-inventory']);assemble.assert_not_called()

    def test_new_artifact_clears_previous_member_and_read_error(self):
        data=self.zipped([('x',b'x')])
        with self.download(data) as (a,budget,_,_):
            budget.state.update(artifactId=999,artifact='old',member='old.tar',readError='old failure')
            with p.artifact_archive(a,budget):
                self.assertEqual(budget.state['artifactId'],31);self.assertEqual(budget.state['artifact'],'test')
                self.assertNotIn('member',budget.state);self.assertIsNone(budget.state['readError'])

    def test_repository_root_metadata_uses_real_read_admission(self):
        import github_read_transport as transport
        def attempt(path,stream,maximum,timeout):
            self.assertEqual(path,'repos/'+p.REPO)
            stream.write(b'{"id":1421657509}')
            return {'status':200,'headers':{},'bytes':17,'sha256':'unused-json-digest'}
        with mock.patch.object(transport,'_attempt',side_effect=attempt) as call:
            self.assertEqual(p.api('repos/'+p.REPO),{'id':1421657509})
            call.assert_called_once()

    def test_only_read_api_uses_retry_transport(self):
        def read(path,stream,maximum):stream.write(b'{"ok":true}')
        with mock.patch.object(p,'read_get',side_effect=read) as get,mock.patch.object(p.subprocess,'check_output',return_value=b'{}') as write:
            self.assertEqual(p.api('rate_limit'),{'ok':True})
            for method in ('POST','PATCH','DELETE'):p.api('repos/'+p.REPO+'/releases/1',method,{'x':1})
            self.assertEqual(get.call_count,1);self.assertEqual(write.call_count,3)

    def test_entire_release_preserves_primary_when_outer_scratch_cleanup_also_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);primary=OSError(errno.EDQUOT,'original inventory quota')
            @contextmanager
            def cleanup_fails(*args,**kwargs):
                owned=root/'scratch';owned.mkdir()
                try:yield str(owned)
                finally:raise PermissionError(errno.EACCES,'injected outer cleanup failure')
            args=p.argparse.Namespace(audit=root/'audit',source_dir=Path('reviewed-source'),source='a'*40,mode='inventory')
            with mock.patch.object(p.tempfile,'TemporaryDirectory',cleanup_fails),mock.patch.object(p,'command',return_value='b'*40),mock.patch.object(p,'tag_identity',return_value='c'*40),mock.patch.object(p,'inventory',side_effect=primary),mock.patch('builtins.print'):
                with self.assertRaises(OSError) as caught:p.bounded_release(args,{'all':'7'})
            self.assertIs(caught.exception,primary);self.assertEqual(caught.exception.errno,errno.EDQUOT)
            state=json.loads((args.audit/'storage-status.json').read_text())
            self.assertTrue(state['scratchCleanupFailed']);self.assertEqual(state['result'],'failed')
            self.assertTrue(any('Scratch directory cleanup' in note for note in state['cleanupNotes']))
            self.assertEqual(state['remoteWriteState'],'none')


class GateTests(unittest.TestCase):
    def test_scope_preserved(self):
        s=json.loads(p.SCOPE.read_text());scope=s['all']
        self.assertEqual(set(s),{'all'})
        self.assertEqual(len(scope['matrices']['build']['include'])+len(scope['matrices']['build_windows7']['include']),38)
        self.assertEqual(set(scope['requiredArtifacts']),set(scope['payloadRules']))
        self.assertEqual(len(scope['requiredArtifacts']),len(set(scope['requiredArtifacts'])))
        self.assertEqual(set(scope['receiptJobs']),set(scope['requiredJobs']))
        self.assertEqual((len(scope['requiredArtifacts']),len(scope['receiptJobs'])),(73,15))
        self.assertEqual(sum(len(scope['matrices'][job]['include'])
                             for job in ('build','build_windows7','build_darwin','build_windows')),44)

    def test_reviewed_current_version_renders_all_payloads(self):
        scope=p.release_scope(p.VERSION)
        old='1.15.0-polaris-alpha.11'
        for role in ['all']:
            rules=scope[role]['payloadRules']['binary-windows-client-x64']
            current=f'SFW-{p.VERSION}-x64.exe';previous=f'SFW-{old}-x64.exe'
            p.verify_payloads({current:{}},rules,'binary-windows-client-x64')
            for files in [{previous:{}},{current:{},previous:{}},{current.replace('alpha.','alphaX'):{}},{}]:
                with self.subTest(role=role,files=files),self.assertRaises(ValueError):
                    p.verify_payloads(files,rules,'binary-windows-client-x64')
            android=scope[role]['payloadRules']['binary-android-apks-other']
            files={f'SFA-{p.VERSION}-{arch}.apk':{} for arch in ['universal','arm64','arm','x64','x86']}
            files[f'SFA-{p.VERSION}-other-version-metadata.json']={}
            p.verify_payloads(files,android,'binary-android-apks-other')
            previous=dict(files);previous[f'SFA-{old}-other-version-metadata.json']=previous.pop(f'SFA-{p.VERSION}-other-version-metadata.json')
            with self.assertRaises(ValueError):p.verify_payloads(previous,android,'binary-android-apks-other')
        from native_release_index import expected_native
        for role in ['all']:
            patterns=[rule['pattern'] for rules in scope[role]['payloadRules'].values() for rule in rules]
            for name,value in expected_native(p.VERSION).items():
                archive=name+('.zip' if value['target'].startswith('windows/') else '.tar.gz')
                self.assertTrue(any(re.fullmatch(pattern,archive) for pattern in patterns),(role,archive))
                self.assertFalse(any(re.fullmatch(pattern,archive.replace(p.VERSION,old)) for pattern in patterns),(role,archive))
        self.assertRaises(ValueError,p.release_scope,old)
        self.assertRaises(ValueError,p.release_scope,'v'+p.VERSION)

    def test_client_payloads_bind_exact_version_and_target_architecture(self):
        scope=p.release_scope(p.VERSION)
        linux={'x64':{'deb':'amd64','rpm':'x86_64','pkg.tar.zst':'x64'},
               'arm64':{'deb':'arm64','rpm':'aarch64','pkg.tar.zst':'aarch64'},
               'armv7l':{'deb':'armv7l','rpm':'armv7l','pkg.tar.zst':'armv7l'}}
        for role in ['all']:
            for arch in ['x64','x86','arm64']:
                artifact='binary-windows-client-'+arch;rules=scope[role]['payloadRules'][artifact]
                current=f'SFW-{p.VERSION}-{arch}.exe';p.verify_payloads({current:{}},rules,artifact)
                wrong='x86' if arch=='x64' else 'x64'
                for invalid in [f'SFW-{p.VERSION}0-{arch}.exe',f'SFW-{p.VERSION}-{wrong}.exe',f'SFW-{p.VERSION}-extra-{arch}.exe']:
                    with self.subTest(role=role,artifact=artifact,name=invalid),self.assertRaises(ValueError):
                        p.verify_payloads({invalid:{}},rules,artifact)
            for arch,formats in linux.items():
                artifact='binary-linux-client-'+arch;rules=scope[role]['payloadRules'][artifact]
                files={f'SFL-{p.VERSION}-{cpu}.{ext}':{} for ext,cpu in formats.items()}
                p.verify_payloads(files,rules,artifact)
                adjacent={name.replace(p.VERSION,p.VERSION+'0'):value for name,value in files.items()}
                wrong_cpu='arm64' if arch=='x64' else 'amd64'
                wrong=dict(files);wrong[f'SFL-{p.VERSION}-{wrong_cpu}.deb']=wrong.pop(f'SFL-{p.VERSION}-{formats["deb"]}.deb')
                for invalid in [adjacent,wrong]:
                    with self.subTest(role=role,artifact=artifact),self.assertRaises(ValueError):p.verify_payloads(invalid,rules,artifact)

    def test_all_requires_each_exact_openwrt_ipk_and_apk_architecture(self):
        source=json.loads(p.SCOPE.read_text());rendered=p.release_scope(p.VERSION)
        for role in ['all']:
            ipk_count=apk_count=0
            for artifact,rules in source[role]['payloadRules'].items():
                ipks=[x for x in rules if 'openwrt_' in x['pattern'] and x['pattern'].endswith(r'\.ipk')]
                if not ipks:continue
                files={}
                for ipk in ipks:
                    apk={'pattern':ipk['pattern'][:-len(r'\.ipk')]+r'\.apk','count':1}
                    self.assertEqual(ipk['count'],1);self.assertIn(apk,rules)
                    escaped=ipk['pattern'].removeprefix(r'sing\-box_{version}_openwrt_').removesuffix(r'\.ipk')
                    arch=re.sub(r'\\(.)',r'\1',escaped)
                    for ext in ['ipk','apk']:files[f'sing-box_{p.VERSION}_openwrt_{arch}.{ext}']={}
                    ipk_count+=1;apk_count+=1
                controls=[x for x in rendered[role]['payloadRules'][artifact] if 'openwrt_' in x['pattern']]
                p.verify_payloads(files,controls,artifact)
                chosen=next(name for name in files if name.endswith('.apk'))
                missing=dict(files);missing.pop(chosen)
                wrong=dict(files);wrong[chosen.removesuffix('.apk')+'-wrong.apk']=wrong.pop(chosen)
                old=dict(files);old[chosen.replace(p.VERSION,'1.15.0-polaris-alpha.11')]=old.pop(chosen)
                for invalid in [missing,wrong,old]:
                    with self.subTest(role=role,artifact=artifact),self.assertRaises(ValueError):p.verify_payloads(invalid,controls,artifact)
            self.assertEqual((ipk_count,apk_count),(32,32))

    def test_scope_rejects_literal_versions_unknown_tokens_and_bad_counts(self):
        raw=json.loads(p.SCOPE.read_text())
        for kind in ['literal','token','duplicate','count']:
            value=copy.deepcopy(raw);rule=value['all']['payloadRules']['binary-windows-client-x64'][0]
            if kind=='literal':rule['pattern']=rule['pattern'].replace('{version}',re.escape(p.VERSION))
            elif kind=='token':rule['pattern']=rule['pattern'].replace('{version}','{release_version}')
            elif kind=='duplicate':rule['pattern']+='{version}'
            else:rule['count']=True
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'scope.json';path.write_text(json.dumps(value))
                with self.subTest(kind=kind),mock.patch.object(p,'SCOPE',path),self.assertRaises(ValueError):p.release_scope(p.VERSION)

    def test_producer_receipt_uses_current_source_contract_and_rejects_old_or_tag_version(self):
        release=json.loads(p.CONFIG.read_text());source='a'*40
        env={'PUBLISHER_ROLE':'all','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REPOSITORY':p.REPO,
             'GITHUB_REPOSITORY_ID':str(p.RID),'RELEASE_BUILD':'All','RELEASE_VERSION':p.VERSION,
             'GITHUB_SHA':source,'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':'1',
             'PUBLISH_STORES':'false','PUBLISH_REGISTRY':'false'}
        env.update(receipt_context_fixture())
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'release/ci').mkdir(parents=True)
            (root/'release/ci/github-release.json').write_text(json.dumps(release))
            (root/'release/ci/publisher-upstream-scope.json').write_bytes(p.SCOPE.read_bytes())
            script=p.ROOT/'scripts/ci/publisher_run_receipt.py'
            with chdir(root),mock.patch.dict(os.environ,env),mock.patch('subprocess.check_output',return_value=source):
                runpy.run_path(str(script),run_name='__main__')
                receipt=json.loads((root/'publisher-run-receipt.json').read_text())
                self.assertEqual((receipt['version'],receipt['sourceCommit'],receipt['role']),(p.VERSION,source,'all'))
                for version in ['1.15.0-polaris-alpha.11',p.VERSION+'0','v'+p.VERSION]:
                    with mock.patch.dict(os.environ,RELEASE_VERSION=version),self.assertRaises(AssertionError):
                        runpy.run_path(str(script),run_name='__main__')

    def test_path_traversal(self):
        for name in ['../bad','/bad','x/../../bad','C:/bad','x\\bad']:
            with self.assertRaises(ValueError):p.portable(name)

    def test_duplicate_zip(self):
        with tempfile.TemporaryDirectory() as d:
            z=Path(d)/'a.zip'
            with zipfile.ZipFile(z,'w') as f:
                f.writestr('A.txt','a');f.writestr('a.txt','b')
            with zipfile.ZipFile(z) as archive,self.assertRaisesRegex(ValueError,'duplicate ZIP path'):p.safe_zip_members(archive)

    def test_full_payload(self):
        rules=[{'pattern':'one','count':1},{'pattern':'two','count':1}]
        p.verify_payloads({'one':{},'two':{}},rules,'test')
        for files in [{'one':{}},{'one':{},'two':{},'extra':{}}]:
            with self.assertRaises(ValueError):p.verify_payloads(files,rules,'test')

    def test_publication_excludes_typed_nonpublic_producer_outputs(self):
        cases=[
            ('all','libbox-android-arm64','arm64/libbox.aar','internal-sdk'),
            ('all','unsigned-apple-ios-archive',f'unsigned-{p.VERSION}-ios.xcarchive.tar','internal-unsigned-archive'),
            ('all','binary-native-index','polaris-upstream-native-assets.json','audited-source-and-index'),
            ('all','binary-native-index','sing-box-polaris-source-'+'a'*40+'.tar.gz','audited-source-and-index'),
            ('all','publisher-run-receipt','publisher-run-receipt.json','producer-evidence'),
            ('all','binary-test','polaris-candidate-manifest-test.json','producer-evidence'),
            ('all','binary-test','native-row-test.json','producer-evidence')]
        for role,artifact,path,disposition in cases:
            with self.subTest(role=role,artifact=artifact,path=path):
                self.assertEqual(p.publication(role,artifact,path),(None,disposition))
                self.assertIsNone(p.default_name(role,artifact,path))

    def test_unknown_public_artifact_or_role_is_rejected(self):
        for role,artifact in [('all','unexpected-artifact'),('unknown','binary-test')]:
            with self.subTest(role=role,artifact=artifact),self.assertRaises(ValueError):
                p.publication(role,artifact,f'sing-box-{p.VERSION}-linux-amd64.tar.gz')

    def fixture(self, root):
        work=root/'work';work.mkdir()
        art=work/'all'/'binary-test';art.mkdir(parents=True)
        name='sing-box-'+p.VERSION+'-linux-amd64.tar.gz';(art/name).write_bytes(b'actual bytes')
        f={'bytes':12,'sha256':p.sha(art/name),'releaseName':p.public_asset_name(name),
           'publicationDisposition':'upstream-public-product'}
        run={'id':'42','attempt':1,'artifacts':{'binary-test':{'id':3,'archiveSha256':'a'*64,'files':{name:f}}}}
        actual={'repository':p.REPO,'repositoryId':p.RID,'version':p.VERSION,'sourceCommit':'a'*40,'scopeSha256':'b'*64,'sourceTree':'b'*40,'tag':p.TAG,'tagObject':'c'*40,'runs':{'all':run},'reviewed':False}
        config=json.loads(json.dumps(actual));config['reviewed']=True
        return work,actual,config,name

    def add_payload(self,work,actual,config,role,artifact,relative,data=b'private fixture'):
        path=work/role/artifact/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        name,disposition=p.publication(role,artifact,relative)
        record={'bytes':len(data),'sha256':p.sha(path),'releaseName':name,'publicationDisposition':disposition}
        for obj in [actual,config]:
            run=obj['runs'].setdefault(role,{'id':'43','attempt':1,'artifacts':{}})
            target=run['artifacts'].setdefault(artifact,{'id':len(run['artifacts'])+4,'archiveSha256':'a'*64,'files':{}})
            target['files'][relative]=copy.deepcopy(record)
        return record

    def test_actual_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);work,actual,cfg,name=self.fixture(root)
            receipt=p.assemble(actual,cfg,work,root/'out')
            self.assertEqual(receipt['assets'][0]['sha256'],p.sha(root/'out'/p.public_asset_name(name)))
            self.assertFalse(receipt['fullSignedRelease'])
            self.assertEqual({path.name for path in (root/'out').iterdir()},{p.public_asset_name(name)})
            self.assertEqual(json.loads((root/'out-audit'/p.RECEIPT).read_text()),receipt)
            self.assertEqual(receipt['assets'][0]['publicationDisposition'],'upstream-public-product')
            self.assertEqual({path.name for path in (work/'all'/'binary-test').iterdir()},{name})
            self.assertIn(p.VERSION,name)
            self.assertNotIn(p.VERSION,receipt['assets'][0]['releaseName'])
            self.assertIn(p.PUBLIC_VERSION,receipt['assets'][0]['releaseName'])

    def test_collision_and_omission(self):
        for failure in ['collision','omission','hash','unreviewed']:
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as d:
                root=Path(d);work,actual,cfg,name=self.fixture(root)
                if failure=='collision':
                    for obj in [actual,cfg]:obj['runs']['all']['artifacts']['binary-other']=obj['runs']['all']['artifacts']['binary-test']
                elif failure=='omission':
                    for obj in [actual,cfg]:obj['runs']['all']['artifacts']['binary-test']['files'][name]['releaseName']=None
                elif failure=='hash':cfg['runs']['all']['artifacts']['binary-test']['files'][name]['sha256']='0'*64
                else:cfg['reviewed']=False
                with self.assertRaises(ValueError):p.assemble(actual,cfg,work,root/'out')

    def test_assemble_requires_exact_disposition_in_actual_and_review(self):
        for target in ['actual','review','both','missing']:
            with self.subTest(target=target),tempfile.TemporaryDirectory() as d:
                root=Path(d);work,actual,cfg,name=self.fixture(root)
                for obj in ([actual] if target=='actual' else [cfg] if target=='review' else [actual,cfg]):
                    record=obj['runs']['all']['artifacts']['binary-test']['files'][name]
                    if target=='missing':record.pop('publicationDisposition')
                    else:record['publicationDisposition']='internal-sdk'
                with self.assertRaisesRegex(ValueError,'publication disposition'):
                    p.assemble(actual,cfg,work,root/'out')

    def test_assemble_cannot_hide_public_payload_with_typed_private_reason(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);work,actual,cfg,name=self.fixture(root)
            for obj in [actual,cfg]:
                obj['runs']['all']['artifacts']['binary-test']['files'][name].update(
                    releaseName=None,publicationDisposition='internal-sdk')
            with self.assertRaisesRegex(ValueError,'public filename'):
                p.assemble(actual,cfg,work,root/'out')

    def test_assemble_rejects_unknown_artifact(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);work,actual,cfg,name=self.fixture(root)
            for obj in [actual,cfg]:
                artifacts=obj['runs']['all']['artifacts'];artifacts['unexpected']=artifacts.pop('binary-test')
            with self.assertRaisesRegex(ValueError,'unknown public artifact'):
                p.assemble(actual,cfg,work,root/'out')

    def metadata_fixture(self):
        result={'runs':{'all':{'artifacts':{}}}}
        for flavor in ['other','other-legacy']:
            name=f'SFA-{p.VERSION}-{flavor}-version-metadata.json'
            public,disposition=p.publication('all','binary-android-apks-'+flavor,name)
            result['runs']['all']['artifacts']['binary-android-apks-'+flavor]={'files':{
                name:{'bytes':71,'sha256':'a'*64,'releaseName':public,'publicationDisposition':disposition}}}
        return result

    def test_android_metadata_requires_identical_bytes_and_hashes(self):
        p.verify_metadata_pair(self.metadata_fixture())
        for field,value in [('bytes',72),('sha256','b'*64)]:
            result=self.metadata_fixture()
            record=next(iter(result['runs']['all']['artifacts']['binary-android-apks-other-legacy']['files'].values()))
            record[field]=value
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'metadata differs'):
                p.verify_metadata_pair(result)

    def test_android_metadata_requires_both_unique_producers(self):
        for failure in ['missing-artifact','missing-file','duplicate-file']:
            result=self.metadata_fixture();artifacts=result['runs']['all']['artifacts']
            if failure=='missing-artifact':artifacts.pop('binary-android-apks-other-legacy')
            else:
                files=artifacts['binary-android-apks-other-legacy']['files']
                if failure=='missing-file':files.clear()
                else:files['duplicate-version-metadata.json']=copy.deepcopy(next(iter(files.values())))
            with self.subTest(failure=failure),self.assertRaises(ValueError):p.verify_metadata_pair(result)

    def test_assemble_accepts_single_versionless_canonical_android_metadata(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);work,actual,cfg,name=self.fixture(root);data=b'{"version":"fixture"}'
            for flavor in ['other','other-legacy']:
                self.add_payload(work,actual,cfg,'all','binary-android-apks-'+flavor,
                                 f'SFA-{p.VERSION}-{flavor}-version-metadata.json',data)
            p.verify_metadata_pair(actual)
            receipt=p.assemble(actual,cfg,work,root/'out')
            canonical='SFA-version-metadata.json'
            self.assertNotIn(p.VERSION,canonical)
            self.assertEqual({path.name for path in (root/'out').iterdir()},{p.public_asset_name(name),canonical})
            self.assertEqual((root/'out'/canonical).read_bytes(),data)
            metadata=[row for row in receipt['assets'] if row['releaseName']==canonical]
            self.assertEqual(len(metadata),1)
            self.assertEqual(metadata[0]['artifact'],'binary-android-apks-other')
            legacy=next(iter(receipt['runs']['all']['artifacts']['binary-android-apks-other-legacy']['files'].values()))
            self.assertEqual((legacy['releaseName'],legacy['publicationDisposition']),(None,'identical-android-metadata'))

    def test_assemble_keeps_nonpublic_payloads_and_receipt_in_audit_only(self):
        for custom in [False,True]:
            with self.subTest(custom_audit=custom),tempfile.TemporaryDirectory() as d:
                root=Path(d);work,actual,cfg,name=self.fixture(root)
                audited=['polaris-upstream-native-assets.json','sing-box-polaris-source-'+'a'*40+'.tar.gz']
                for basename in audited:self.add_payload(work,actual,cfg,'all','binary-native-index',basename)
                for role,artifact,path in [
                    ('all','libbox-android-arm64','arm64/libbox.aar'),
                    ('all','unsigned-apple-ios-archive',f'unsigned-{p.VERSION}-ios.xcarchive.tar'),
                    ('all','publisher-run-receipt','publisher-run-receipt.json')]:
                    self.add_payload(work,actual,cfg,role,artifact,path)
                audit=root/'separate'/'audit' if custom else root/'out-audit'
                receipt=p.assemble(actual,cfg,work,root/'out',audit=audit if custom else None)
                self.assertEqual({path.name for path in (root/'out').iterdir()},{p.public_asset_name(name)})
                self.assertEqual({path.name for path in audit.iterdir()},set(audited)|{p.RECEIPT})
                self.assertEqual(receipt['runs'],actual['runs'])
                self.assertEqual(json.loads((audit/p.RECEIPT).read_text()),receipt)
                for basename in audited:
                    self.assertEqual(p.sha(audit/basename),p.sha(work/'all'/'binary-native-index'/basename))

    def test_assemble_rejects_audit_inside_public_dist(self):
        for nested in [False,True]:
            with self.subTest(nested=nested),tempfile.TemporaryDirectory() as d:
                root=Path(d);work,actual,cfg,name=self.fixture(root);out=root/'out'
                with self.assertRaisesRegex(ValueError,'audit must be outside public dist'):
                    p.assemble(actual,cfg,work,out,audit=out/'audit' if nested else out)
                self.assertFalse(out.exists())


    def test_complete_upload_url(self):
        release={'id':12,'upload_url':f'https://uploads.github.com/repos/{p.REPO}/releases/12/assets{{?name,label}}'}
        self.assertEqual(p.upload_endpoint(release,'asset +.zip'),f'https://uploads.github.com/repos/{p.REPO}/releases/12/assets?name=asset%20%2B.zip')
        for endpoint in [f'https://api.uploads.github.com/repos/{p.REPO}/releases/12/assets',
                         f'https://uploads.github.com.evil.example/repos/{p.REPO}/releases/12/assets',
                         f'http://uploads.github.com/repos/{p.REPO}/releases/12/assets',
                         f'https://uploads.github.com/repos/other/repo/releases/12/assets',
                         f'https://uploads.github.com/repos/{p.REPO}/releases/13/assets',
                         f'https://uploads.github.com/repos/{p.REPO}/releases/12/assets?other=1',
                         f'https://uploads.github.com/repos/{p.REPO}/releases/12/assets#fragment']:
            with self.subTest(endpoint=endpoint),self.assertRaises(ValueError):
                p.upload_endpoint(dict(release,upload_url=endpoint),'asset.zip')

    def final_index(self):
        from native_release_index import expected_native
        expected=expected_native(p.VERSION);source='a'*40;tree='b'*40;rows=[]
        for ident,v in expected.items():
            rows.append({'schema':'polaris-upstream-native-receipt-v1','id':ident,'target':v['target'],'variant':v['variant'],
                         'version':p.VERSION,'tag':p.TAG,'sourceCommit':source,'sourceTree':tree,'goVersion':'go1.27.2',
                         'tags':'fixture','buildID':'','rawBuildInfo':'private test fixture',
                         'buildGraph':{'settings':{},'normalModules':[],'prebuiltAcquisitionModules':[],'localReplacements':[]},
                         'sourceIdentity':{'sourceOverlay':0,'goModSha256':'0'*64,'goSumSha256':'1'*64,'replacements':[]},
                         'archive':{'name':ident+('.zip' if v['target'].startswith('windows/') else '.tar.gz'),
                                    'releaseName':p.public_product_name(ident+('.zip' if v['target'].startswith('windows/') else '.tar.gz')),
                                    'bytes':1,'sha256':'2'*64,'root':ident,'members':{ident+'/sing-box':'3'*64}},
                         'core':{'member':'sing-box','bytes':1,'sha256':'3'*64},'sidecar':None,
                         'signatureObservation':None,'finalPackageCronetSmoke':None})
        index = {'schema':'polaris-upstream-native-assets-v1','repository':p.REPO,'repositoryId':p.RID,'version':p.VERSION,
                'tag':p.TAG,'tagObject':'c'*40,'sourceCommit':source,'sourceTree':tree,
                'producer':{'repository':p.REPO,'repositoryId':p.RID,'workflow':'.github/workflows/build.yml',
                            'workflowCommit':source,'runId':42,'runAttempt':1,
                            'nativeJobs':{k:{'id':i+1,'name':'Native final-package Cronet and gVisor smoke ('+ident+')'} for i,(k,ident) in enumerate([('linux','linux-amd64-purego'),('win','windows-amd64'),('mac-x64','darwin-amd64'),('mac-arm64','darwin-arm64')])}},
                'legalFiles':[{'path':'licenses/LICENSE','content':'x','bytes':1,'sha256':'4'*64}],
                'sourceArchive':{'name':'sing-box-polaris-source-'+source+'.tar.gz','bytes':1,'sha256':'5'*64},'platforms':rows}
        from native_release_index import distribution_materials
        index['distributionMaterials'] = distribution_materials(index, p.ROOT)
        return index

    def check_index(self,index):
        with mock.patch.object(p,'pages',return_value=native_jobs_fixture(index)):
            p.validate_final_index(index,'a'*40,'b'*40,'c'*40,'42',1,'.github/workflows/build.yml')

    def test_final_index_uses_original_source_root_for_distribution_materials(self):
        index=self.final_index()
        with tempfile.TemporaryDirectory() as d:
            source_root=Path(d)/'reviewed-source'
            # The index belongs to the original producer checkout; the new
            # publisher's own script hash must not replace its source binding.
            with mock.patch('native_release_index.distribution_materials',return_value=index['distributionMaterials']) as materials, mock.patch.object(p,'pages',return_value=native_jobs_fixture(index)):
                p.validate_final_index(index,'a'*40,'b'*40,'c'*40,'42',1,'.github/workflows/build.yml',source_root=source_root)
                materials.assert_called_once_with(index,source_root)
            with mock.patch('native_release_index.distribution_materials',return_value={'changed':True}),mock.patch.object(p,'pages',return_value=native_jobs_fixture(index)),self.assertRaisesRegex(ValueError,'source/notice bindings'):
                p.validate_final_index(index,'a'*40,'b'*40,'c'*40,'42',1,'.github/workflows/build.yml',source_root=source_root)
        with mock.patch('native_release_index.distribution_materials',return_value=index['distributionMaterials']) as materials:
            self.check_index(index)
            materials.assert_called_once_with(index,p.ROOT)

    def test_inventory_passes_original_source_root_to_native_index_validation(self):
        class StopInventory(Exception):pass
        index=self.final_index();source='a'*40;workflow='.github/workflows/build.yml'
        required=['binary-native-index','publisher-run-receipt']
        scope={'all':{'workflow':workflow,'requiredArtifacts':required,'payloadRules':{
            'binary-native-index':[{'pattern':r'polaris-upstream-native-assets\.json','count':1}],
            'publisher-run-receipt':[{'pattern':r'publisher-run-receipt\.json','count':1}]}}}
        run={'repository':{'id':p.RID},'head_repository':{'id':p.RID},'head_sha':source,
             'path':workflow,'status':'completed','conclusion':'success','event':'workflow_dispatch',
             'run_attempt':1,'run_started_at':'2026-10-18T00:00:00Z'}
        artifacts=[{'name':name,'id':number,'expired':False,'created_at':'2026-10-18T00:01:00Z',
                    'workflow_run':{'id':42,'head_sha':source},'digest':'sha256:'+'a'*64}
                   for number,name in enumerate(required,1)]
        receipt={'repository':p.REPO,'repositoryId':p.RID,'sourceCommit':source,'runId':'42',
                 'attempt':1,'version':p.VERSION,'build':'All','role':'all','publishStores':False,'publishRegistry':False}
        @contextmanager
        def archive_fixture(artifact,budget):
            name,value=('polaris-upstream-native-assets.json',index) if artifact['name']=='binary-native-index' else ('publisher-run-receipt.json',receipt)
            archive_path=budget.root/(artifact['name']+'.zip')
            with zipfile.ZipFile(archive_path,'w') as z:z.writestr(name,json.dumps(value))
            artifact['size_in_bytes']=archive_path.stat().st_size
            with zipfile.ZipFile(archive_path) as z:yield z,z.infolist()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source_root=root/'reviewed-source'
            with mock.patch.object(p,'release_scope',return_value=scope),mock.patch.object(p,'api',return_value=run), \
                 mock.patch.object(p,'pages',return_value=artifacts),mock.patch.object(p,'sha',return_value='a'*64), \
                 mock.patch.object(p,'artifact_archive',side_effect=archive_fixture), \
                 mock.patch.object(p,'validate_final_index',side_effect=StopInventory) as validate:
                with self.assertRaises(StopInventory):
                    p.inventory({'all':'42'},source,root/'work','b'*40,'c'*40,source_root=source_root)
                validate.assert_called_once_with(index,source,'b'*40,'c'*40,'42',1,workflow,source_root)

    def test_main_passes_verified_source_checkout_to_inventory(self):
        class StopInventory(Exception):pass
        source='a'*40;source_root=Path('/offline-fixture/reviewed-source')
        argv=['github_release.py','inventory','--source',source,'--source-dir',str(source_root),
              '--all-run','42']
        with tempfile.TemporaryDirectory() as audit_temp, mock.patch('sys.argv',argv+['--audit',str(Path(audit_temp)/'audit')]),mock.patch.object(p,'identity') as identity, \
             mock.patch.object(p,'command',return_value='b'*40) as command, \
             mock.patch.object(p,'tag_identity',return_value='c'*40), \
             mock.patch.object(p,'inventory',side_effect=StopInventory) as inventory:
            with self.assertRaises(StopInventory):p.main()
            identity.assert_called_once_with(source,source_root)
            command.assert_called_once_with('git','-C',str(source_root),'rev-parse','HEAD^{tree}')
            inventory.assert_called_once_with({'all':'42'},source,
                                              mock.ANY,'b'*40,'c'*40,source_root,budget=mock.ANY)

    def test_final_index_and_staging_wrong_tag_schema_mixed_source_controls(self):
        index=self.final_index();self.check_index(index)
        for kind in ['staging','wrong-object','wrong-tag','malformed-schema','mixed-source','mixed-tree','missing-row','source-name']:
            x=copy.deepcopy(index)
            if kind=='staging':x.update(schema='polaris-upstream-native-staging-v1',tagObject=None)
            elif kind=='wrong-object':x['tagObject']='d'*40
            elif kind=='wrong-tag':x['tag']='v1.15.0-polaris-alpha.999'
            elif kind=='malformed-schema':x['producer']['runId']='42'
            elif kind=='mixed-source':x['platforms'][-1]['sourceCommit']='d'*40
            elif kind=='mixed-tree':x['platforms'][-1]['sourceTree']='d'*40
            elif kind=='missing-row':x['platforms'].pop()
            else:x['sourceArchive']['name']='other.tar.gz'
            with self.subTest(kind=kind),self.assertRaises((ValueError,jsonschema.ValidationError)):self.check_index(x)

    def test_index_and_source_cannot_be_promoted_to_public_assets(self):
        for basename in ['polaris-upstream-native-assets.json','sing-box-polaris-source-'+'a'*40+'.tar.gz']:
            with self.subTest(basename=basename),tempfile.TemporaryDirectory() as d:
                root=Path(d);work,actual,cfg,name=self.fixture(root)
                self.add_payload(work,actual,cfg,'all','binary-native-index',basename)
                for obj in [actual,cfg]:
                    obj['runs']['all']['artifacts']['binary-native-index']['files'][basename].update(
                        releaseName=p.VERSION+'-renamed-'+basename,publicationDisposition='upstream-public-product')
                with self.assertRaisesRegex(ValueError,'public filename'):p.assemble(actual,cfg,work,root/'out')


class PublicAssetNameTests(unittest.TestCase):
    def test_public_names_apply_core_branding_and_client_names_exactly_once(self):
        cases=[
            ('sing-box-{version}-linux-amd64.tar.gz','sing-box-polaris-{public}-linux-amd64.tar.gz'),
            ('sing-box-polaris-{version}-windows-amd64.zip','sing-box-polaris-{public}-windows-amd64.zip'),
            ('sing-box_{version}_openwrt_mips_24kc.ipk','sing-box-polaris_{public}_openwrt_mips_24kc.ipk'),
            ('sing-box-polaris_{version}_linux_amd64.deb','sing-box-polaris_{public}_linux_amd64.deb'),
            ('SFA-{version}-arm64-v8a-unsigned.apk','SFA-{public}-arm64-v8a.apk'),
            ('sing-box-polaris-SFA-{version}-legacy-android-5-x86_64-unsigned.apk','SFA-{public}-legacy-android-5-x86_64.apk'),
            ('sing-box-polaris-SFA-version-metadata.json','SFA-version-metadata.json'),
            ('SFA-version-metadata.json','SFA-version-metadata.json'),
            ('SFI-{version}-iphoneos-arm64e.deb','SFI-{public}-iphoneos-arm64e.deb'),
            ('sing-box-polaris-SFL-{version}-aarch64.pkg.tar.zst','SFL-{public}-aarch64.pkg.tar.zst'),
            ('sing-box-polaris-SFM-{version}-universal.dmg','SFM-{public}-universal.dmg'),
            ('sing-box-polaris-SFW-{version}-x64.exe','SFW-{public}-x64.exe'),
        ]
        for before,after in cases:
            before=before.format(version=p.VERSION);after=after.format(public=p.PUBLIC_VERSION)
            with self.subTest(name=before):
                self.assertEqual(p.public_asset_name(before),after)

    def test_unsigned_removal_is_only_the_android_apk_suffix(self):
        cases=[
            ('SFA-{version}-unsigned-variant.apk','SFA-{public}-unsigned-variant.apk'),
            ('SFA-{version}-arm64-unsigned.apk.zip','SFA-{public}-arm64-unsigned.apk.zip'),
            ('SFW-{version}-x64-unsigned.exe','SFW-{public}-x64-unsigned.exe'),
            ('sing-box-{version}-linux-amd64-unsigned.tar.gz','sing-box-polaris-{public}-linux-amd64-unsigned.tar.gz'),
        ]
        for before,after in cases:
            with self.subTest(name=before):
                self.assertEqual(p.public_asset_name(before.format(version=p.VERSION)),after.format(public=p.PUBLIC_VERSION))

class DistributionMaterialsTests(unittest.TestCase):
    final_index = GateTests.final_index
    check_index = GateTests.check_index
    def test_apple_overlay_source_input_tampering_fails_final_native_gate(self):
        index=self.final_index()
        for path in ('release/ci/apple-swift-package-overlays.json','scripts/ci/apple_package_overlays.py'):
            candidate=copy.deepcopy(index)
            candidate['distributionMaterials']['inputs'][path]='0'*64
            with self.subTest(path=path),self.assertRaises(ValueError):self.check_index(candidate)

    def test_publisher_apple_policy_matches_actual_source_checkout(self):
        apple_paths=('release/ci/client-overlays.json','release/ci/owned-distribution.json',
               'release/ci/apple-swift-package-overlays.json','scripts/ci/apple_package_overlays.py','scripts/ci/client_source.py')
        paths=apple_paths
        with tempfile.TemporaryDirectory() as directory:
            source_root=Path(directory)
            for name in paths:
                if not (p.ROOT/name).exists():continue
                destination=source_root/name;destination.parent.mkdir(parents=True,exist_ok=True)
                destination.write_bytes((p.ROOT/name).read_bytes())
            environment={'GITHUB_REPOSITORY':p.REPO,'GITHUB_REPOSITORY_ID':str(p.RID)}
            with mock.patch.dict(os.environ,environment),mock.patch.object(p,'api',return_value={'id':p.RID}),\
                 mock.patch.object(p,'command',side_effect=lambda *args:'a'*40 if 'rev-parse' in args else ''):
                p.identity('a'*40,source_root)
                for name in apple_paths[2:]:
                    path=source_root/name;original=path.read_bytes();path.write_bytes(original+b'\n')
                    with self.subTest(path=name),self.assertRaisesRegex(ValueError,'Apple package policy'):
                        p.identity('a'*40,source_root)
                    path.write_bytes(original)
                (source_root/paths[2]).unlink()
                with self.assertRaisesRegex(ValueError,'Apple package policy'):p.identity('a'*40,source_root)

    def test_apple_overlay_evidence_stays_nested_without_new_public_asset(self):
        import apple_package_overlays as apple
        index=self.final_index();spec=apple.definition();packages=apple.expected_record(index['sourceCommit'])
        client={'coreSourceCommit':index['sourceCommit'],'repository':spec['client']['repository'],
                'baseCommit':spec['client']['commit'],'overlayManifestSHA256':p.sha(p.ROOT/'release/ci/client-overlays.json'),
                'diffSHA256':'8'*64,'swiftPackageOverlays':packages}
        result={'sourceCommit':index['sourceCommit'],'sourceTree':index['sourceTree'],
                'runs':{'all':{'artifacts':{'binary-apple-standalone-all':{'files':{
                    'fixture.pkg':{'releaseName':'fixture.pkg','publicationDisposition':'upstream-public-product'},
                    'polaris-candidate-manifest-fixture.json':{'releaseName':None,'publicationDisposition':'producer-evidence','clientSource':client}}}}}}}
        files=result['runs']['all']['artifacts']['binary-apple-standalone-all']['files'];names=set(files)
        p.associate_distribution_materials(result,index,'9'*64)
        self.assertEqual(set(files),names)
        self.assertEqual(sum(value['releaseName'] is not None for value in files.values()),1)
        extra=files['fixture.pkg']['distributionMaterials']['clientSource']['swiftPackageOverlays']
        self.assertEqual(extra['manifestSHA256'],packages['manifestSHA256'])
        self.assertEqual(extra['lockSHA256'],packages['lockSHA256'])
        self.assertEqual(extra['evidenceSHA256'],hashlib.sha256(apple.canonical(packages).encode()).hexdigest())
        self.assertNotIn('distributionMaterials',files['polaris-candidate-manifest-fixture.json'])

    def test_current_scope_materials_tampering_fails(self):
        index=self.final_index()
        for field,value in [('sourceCommit','d'*40),('modules',{}),('legalFiles',{})]:
            candidate=copy.deepcopy(index)
            if field=='modules':candidate['distributionMaterials'][field]={'injected':{}}
            else:candidate['distributionMaterials'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.check_index(candidate)

    def test_remote_replacement_uses_actual_source_and_go_escape(self):
        from native_release_index import distribution_materials
        index=self.final_index()
        index['platforms'][0]['buildGraph']['localReplacements']=[{
            'module':'old/module','version':'v1.0.0','h1':'',
            'replacement':{'module':'github.com/SomeOwner/fork','version':'v2.0.0','h1':'h1:test'}}]
        material=distribution_materials(index,p.ROOT)
        record=next(iter(material['modules'].values()))
        self.assertEqual(record['sourceURL'],'https://proxy.golang.org/github.com/!some!owner/fork/@v/v2.0.0.zip')
        self.assertEqual(record['replaces']['module'],'old/module')
        self.assertFalse(record['availabilityVerified'])
        self.assertFalse(material['publicationEligible'])
        self.assertTrue(material['unmappedMaterialIdentities'])
        with mock.patch('native_release_index.validate_distribution_assessment', return_value=True):
            self.assertFalse(distribution_materials(index,p.ROOT)['publicationEligible'])

    def test_shared_materials_associate_every_public_file_and_keep_metadata_private(self):
        index=self.final_index()
        result={'sourceCommit':index['sourceCommit'],'sourceTree':index['sourceTree'],
                'runs':{'all':{'artifacts':{'test':{'files':{
                    'binary':{'releaseName':'binary','publicationDisposition':'upstream-public-product'},
                    'metadata':{'releaseName':None,'publicationDisposition':'producer-evidence'}}}}}}}
        p.associate_distribution_materials(result,index,'9'*64)
        files=result['runs']['all']['artifacts']['test']['files']
        self.assertEqual(files['binary']['distributionMaterials'],result['distributionMaterials'])
        self.assertNotIn('distributionMaterials',files['metadata'])
        wrong=copy.deepcopy(index);wrong['sourceCommit']='d'*40
        self.assertRaises(ValueError,p.associate_distribution_materials,result,wrong,'9'*64)

    def test_assessment_requires_explicit_valid_empty_open_items(self):
        from native_release_index import validate_distribution_assessment
        valid={'schema':1,'status':'reviewed-current-scope','openItems':[]}
        self.assertTrue(validate_distribution_assessment(valid))
        for value in [None,False,'',{},0]:
            with self.subTest(value=value),self.assertRaises(ValueError):
                validate_distribution_assessment(dict(valid,openItems=value))
        del valid['openItems']
        self.assertRaises(ValueError,validate_distribution_assessment,valid)
        self.assertRaises(ValueError,validate_distribution_assessment,{'schema':1,'status':'anything','openItems':[]})
        self.assertFalse(validate_distribution_assessment({'schema':1,'status':'current-scope-review-required','openItems':[]}))


from test_github_read_transport import ReadTransportTests

if __name__=='__main__':
    unittest.main()
