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


def receipt_context_fixture(role, material):
    policies=json.loads(p.SCOPE.read_text())[role]['receiptJobs']
    return {'GITHUB_REF':'refs/tags/'+p.TAG if material else 'refs/heads/fixture',
            'RECEIPT_EVIDENCE_MODE':'final','RECEIPT_SOURCE_GENERATE_ONLY':'false',
            'RECEIPT_DISTRIBUTION_ENABLED':'false','RECEIPT_PUBLISH_GITHUB':'false',
            'POLARIS_DEBIAN_REQUIRED':'true' if material else 'false',
            'NEEDS_JSON':json.dumps({key:{'result':'skipped' if policy=='debian_required' and not material
                                                   else 'success','outputs':{}}
                                     for key,policy in policies.items()})}

@contextmanager
def historical_release():
    """Exercise immutable alpha.12 recovery evidence, never the current release plan."""
    version = '1.15.0-polaris-alpha.12'
    with tempfile.TemporaryDirectory() as directory:
        config = Path(directory) / 'github-release.json'
        current = json.loads(p.CONFIG.read_text())
        config.write_text(json.dumps(dict(current, version=version, tag='v' + version)))
        with mock.patch.multiple(p, CONFIG=config, VERSION=version, PUBLIC_VERSION='1.15.0-alpha.12',
                                 TAG='v' + version, RECEIPT='polaris-github-release-receipt-' + version + '.json'):
            yield


@contextmanager
def generic_algorithm_fixture():
    """Only fake-source, non-peer fixtures bypass exact producer admission.

    Storage/publication algorithms have no real CI identity. Both exact peer
    suites exercise inventory, assemble and stream with their real gates; this
    scoped override must never admit those sources or any peer artifact.
    """
    def select(_root, source, *_args, **_kwargs):
        if source != 'a' * 40:
            raise AssertionError('generic fixture requires its explicit fake source')
        return None
    def check(_root, actual, _publisher):
        if actual.get('sourceCommit') != 'a' * 40 or 'controlledPeerEvidence' in actual:
            raise AssertionError('generic fixture cannot replace exact peer admission')
        for run in actual.get('runs', {}).values():
            for name in run.get('artifacts', {}):
                if name.startswith('native-controlled-peer-'):
                    raise AssertionError('generic fixture cannot carry peer artifacts')
    with mock.patch.object(p.peer_evidence, 'select', side_effect=select), \
         mock.patch.object(p.peer_evidence, 'check_inventory', side_effect=check):
        yield



def native_jobs_fixture(index):
    """Synthetic Actions data; only mocked metadata, never native authority."""
    from native_release_index import expected_native_job_names
    names=expected_native_job_names(index['platforms'])
    return [{'id':i+1,'name':name,'status':'completed','conclusion':'success',
             'head_sha':index['sourceCommit'],'run_id':42,'run_attempt':1}
            for i,(key,name) in enumerate(names.items())]

class GenericFixtureIsolationTests(unittest.TestCase):
    def test_scope_restores_real_gates_after_normal_and_exception_exit(self):
        before = p.peer_evidence.select, p.peer_evidence.check_inventory
        for fail in (False, True):
            try:
                with generic_algorithm_fixture():
                    self.assertIsNone(p.peer_evidence.select(p.ROOT, 'a' * 40, 'any-version', 'any-tag'))
                    p.peer_evidence.check_inventory(p.ROOT, {'sourceCommit': 'a' * 40}, None)
                    if fail:
                        raise RuntimeError('fixture setup failed')
            except RuntimeError:
                if not fail:
                    raise
            self.assertEqual((p.peer_evidence.select, p.peer_evidence.check_inventory), before)

    def test_scope_cannot_stub_any_real_policy_or_peer_evidence(self):
        with generic_algorithm_fixture():
            for module in p.peer_evidence.MODULES:
                with self.assertRaises(AssertionError):
                    p.peer_evidence.select(p.ROOT, module.SOURCE, module.VERSION, 'v' + module.VERSION)
                with self.assertRaises(AssertionError):
                    p.peer_evidence.check_inventory(p.ROOT, {'sourceCommit': module.SOURCE}, None)
            for data in ({'sourceCommit': 'a' * 40, 'controlledPeerEvidence': {}},
                         {'sourceCommit': 'a' * 40, 'runs': {'all': {'artifacts': {'native-controlled-peer-fake': {}}}}}):
                with self.assertRaises(AssertionError):
                    p.peer_evidence.check_inventory(p.ROOT, data, None)


class BoundedStorageTests(unittest.TestCase):
    def setUp(self):
        # These synthetic storage fixtures have no real producer identity. The
        # exact current peer gate is exercised end-to-end in its own test file.
        self.enterContext(generic_algorithm_fixture())

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

    def test_stream_matches_legacy_extraction_hashes_and_sizes(self):
        data=self.zipped([('a.bin',b'a'*12345),('sub/b.json',b'{"value":42}')])
        with tempfile.TemporaryDirectory() as d,self.download(data) as (metadata,budget,_,_):
            path=Path(d)/'archive.zip';path.write_bytes(data);p.extract(path,Path(d)/'old')
            with p.artifact_archive(metadata,budget) as (archive,members):
                for item in members:
                    measured,_=p.measure_member(archive,item)
                    old=Path(d)/'old'/item.filename
                    self.assertEqual(measured,{'bytes':old.stat().st_size,'sha256':p.sha(old)})

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
        with self.download(data,metadata) as (_,budget,_,_),mock.patch.object(p,'api',return_value=run),mock.patch.object(p,'pages',return_value=[metadata]):
            record=p.reviewed_contract('7',hashlib.sha256(proposal).hexdigest(),'a'*40,publisher_commit='b'*40,budget=budget)
            self.assertEqual(record,{'sourceCommit':'a'*40,'reviewed':True});self.assertIn(b'false',proposal)
            self.assertEqual(budget.peak,len(data))
            with self.assertRaisesRegex(ValueError,'revision'):
                p.reviewed_contract('7',hashlib.sha256(proposal).hexdigest(),'a'*40,publisher_commit='c'*40,budget=budget)

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

    def test_all_roles_inventory_and_validation_keep_only_small_source_audit(self):
        source='a'*40;scope={};runs={};artifacts={};downloads={};ident=100
        source_bytes=b'original-source';source_name='source.tar.gz'
        index={'platforms':[],'sourceArchive':{'name':source_name,'bytes':len(source_bytes),'sha256':hashlib.sha256(source_bytes).hexdigest()}}
        for role,rid in [('all','7'),('linux','8'),('docker','9')]:
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
                actual=p.inventory({'all':'7','linux':'8','docker':'9'},source,work,'b'*40,'c'*40,budget=budget)
            self.assertEqual(len(remote.call_args_list),3)
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

    def test_workflow_keeps_guards_and_retains_only_bounded_evidence_on_failure(self):
        import yaml
        workflow=yaml.safe_load((p.ROOT/'.github/workflows/publish-github.yml').read_text())
        self.assertEqual(set(workflow['on']),{'workflow_dispatch'})
        self.assertEqual(workflow['permissions'],{'contents':'read'})
        self.assertEqual(workflow['jobs']['validate']['permissions'],{'contents':'read','actions':'read'})
        step=next(s for s in workflow['jobs']['validate']['steps'] if s.get('with',{}).get('name')=='github-release-validation')
        self.assertEqual(step['if'],'always()')
        self.assertEqual(step['with']['path'].splitlines(),['release-inventory-proposal.json','github-release-audit'])
        job=workflow['jobs']['publish'];self.assertEqual(job['environment'],'polaris-github-release')
        self.assertEqual(job['needs'],'validate');self.assertIn("vars.POLARIS_GITHUB_PUBLISH_ENABLED == 'true'",job['if'])
        self.assertEqual(job['permissions'],{'contents':'write','actions':'read'})

    def test_reviewed_inventory_failure_precedes_large_producer_downloads(self):
        with tempfile.TemporaryDirectory() as d:
            args=p.argparse.Namespace(audit=Path(d)/'audit',source_dir=Path('source'),source='a'*40,
                mode='validate',inventory_run='77',inventory_sha256='f'*64)
            with mock.patch.object(p,'command',return_value='b'*40),mock.patch.object(p,'tag_identity',return_value='c'*40), \
                 mock.patch.object(p,'reviewed_contract',side_effect=ValueError('original hash mismatch')) as reviewed, \
                 mock.patch.object(p,'inventory') as inventory,mock.patch('builtins.print'):
                with self.assertRaisesRegex(ValueError,'original hash mismatch'):p.bounded_release(args,{'all':'7','linux':'8','docker':'9'})
                inventory.assert_not_called();reviewed.assert_called_once()

    def test_reviewed_producer_input_mismatch_precedes_downloads(self):
        with tempfile.TemporaryDirectory() as d:
            args=p.argparse.Namespace(audit=Path(d)/'audit',source_dir=Path('source'),source='a'*40,
                mode='validate',inventory_run='77',inventory_sha256='f'*64)
            with mock.patch.object(p,'command',return_value='b'*40),mock.patch.object(p,'tag_identity',return_value='c'*40), \
                 mock.patch.object(p,'reviewed_contract',return_value={'runs':{'all':{'id':'wrong'}}}), \
                 mock.patch.object(p,'inventory') as inventory,mock.patch('builtins.print'):
                with self.assertRaisesRegex(ValueError,'producer inputs differ'):p.bounded_release(args,{'all':'7','linux':'8','docker':'9'})
                inventory.assert_not_called()

    def test_preflight_contract_then_all_producer_validation_still_required(self):
        calls=[];runs={'all':'7','linux':'8','docker':'9'};contract={'runs':{k:{'id':v} for k,v in runs.items()}}
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
                with self.assertRaises(OSError) as caught:p.bounded_release(args,{'all':'7','linux':'8','docker':'9'})
            self.assertIs(caught.exception,primary);self.assertEqual(caught.exception.errno,errno.EDQUOT)
            state=json.loads((args.audit/'storage-status.json').read_text())
            self.assertTrue(state['scratchCleanupFailed']);self.assertEqual(state['result'],'failed')
            self.assertTrue(any('Scratch directory cleanup' in note for note in state['cleanupNotes']))
            self.assertEqual(state['remoteWriteState'],'none')


class GateTests(unittest.TestCase):
    def setUp(self):
        # Preserve the scope of legacy synthetic package fixtures, rather than
        # making the production peer gate recognize or bypass fake identities.
        self.enterContext(generic_algorithm_fixture())

    def test_scope_preserved(self):
        import yaml
        s=json.loads(p.SCOPE.read_text())
        self.assertEqual(len(s['all']['matrices']['build']['include'])+len(s['all']['matrices']['build_windows7']['include']),38)
        for role,scope in s.items():
            self.assertEqual(set(scope['requiredArtifacts']),set(scope['payloadRules']))
            self.assertEqual(len(scope['requiredArtifacts']),len(set(scope['requiredArtifacts'])))
            self.assertEqual(set(scope['receiptJobs']),set(scope['requiredJobs']))
        self.assertEqual({role:len(s[role]['requiredArtifacts']) for role in ('all','linux','docker')},
                         {'all':74,'linux':14,'docker':22})
        self.assertEqual({role:len(scope['receiptJobs']) for role,scope in s.items()},
                         {'all':16,'linux':3,'docker':21,'signed':16})
        for role in ('all','signed'):
            self.assertEqual(sum(len(s[role]['matrices'][job]['include'])
                                 for job in ('build','build_windows7','build_darwin','build_windows')),44)
        baseline=json.loads((p.ROOT/'release/ci/upstream-matrices.json').read_text())['matrices']['docker.yml']
        jobs=yaml.safe_load((p.ROOT/'.github/workflows/docker.yml').read_text())['jobs']
        products={'linux/amd64':'','linux/arm64':'_arm64','linux/386':'_386',
                  'linux/arm/v7':'_armv7','linux/arm/v6':'_armv6','linux/mipsle':'_mipsle',
                  'linux/riscv64':'_riscv64','linux/loong64':'_loong64',
                  'linux/ppc64le':'_ppc64le','linux/s390x':'_s390x'}
        binary_rows={row['docker_platform']:row for row in baseline['build_binary']['include']}
        image_rows={row['platform']:row for row in baseline['build_docker']['include']}
        self.assertEqual(len(baseline['build_binary']['include']),10)
        self.assertEqual(len(baseline['build_docker']['include']),9)
        self.assertEqual(set(binary_rows),set(products))
        self.assertEqual(set(image_rows),set(products)-{'linux/mipsle'})
        expected_jobs=set();expected_artifacts={'publisher-run-receipt','debian-candidate-raw','debian-material-ready'}
        for platform,suffix in products.items():
            binary='build_binary'+suffix;expected_jobs.add(binary)
            row=binary_rows[platform];job=jobs[binary]
            self.assertEqual(job['name'],binary)
            self.assertEqual(job['needs'],['source'])
            self.assertEqual(job['strategy']['matrix'],{'include':[row]})
            self.assertEqual(s['docker']['matrices'][binary],job['strategy']['matrix'])
            self.assertIs(job['strategy']['fail-fast'],False)
            self.assertNotIn('needs.debian_materials',job['if'])
            self.assertEqual(job['steps'],jobs['build_binary']['steps'])
            for name in ('Build (naive)','Build (non-naive)'):
                self.assertIn('go build',next(step for step in job['steps'] if step.get('name')==name)['run'])
            prepare=next(step for step in job['steps'] if step.get('name')=='Prepare artifact')
            self.assertIn('platform=${{ matrix.docker_platform }}',prepare['run'])
            upload=next(step for step in job['steps'] if step.get('name')=='Upload binary')
            self.assertEqual(upload['with']['name'],'binary-${{ env.PLATFORM_PAIR }}')
            expected_artifacts.add('binary-'+platform.replace('/','-'))
            if platform=='linux/mipsle':continue
            image='build_docker'+suffix;expected_jobs.add(image);job=jobs[image]
            self.assertEqual(job['name'],image)
            self.assertEqual(job['needs'],[binary,'source'])
            self.assertEqual(job['strategy']['matrix'],{'include':[image_rows[platform]]})
            self.assertEqual(s['docker']['matrices'][image],job['strategy']['matrix'])
            self.assertIs(job['strategy']['fail-fast'],False)
            self.assertEqual(job['steps'],jobs['build_docker']['steps'])
            self.assertNotIn('always()',job.get('if',''))
            prepare=next(step for step in job['steps'] if step.get('name')=='Prepare')
            self.assertIn('platform=${{ matrix.platform }}',prepare['run'])
            download=next(step for step in job['steps'] if step.get('name')=='Download binary')
            self.assertEqual(download['with'],{'name':'binary-${{ env.PLATFORM_PAIR }}','path':'.'})
            build=next(step for step in job['steps'] if step.get('uses')=='docker/build-push-action@v6')
            self.assertFalse(build['with']['push']);self.assertIn('type=oci,dest=',build['with']['outputs'])
            upload=next(step for step in job['steps'] if step.get('name')=='Upload OCI archive')
            self.assertEqual(upload['with']['name'],'oci-${{ env.PLATFORM_PAIR }}')
            expected_artifacts.add('oci-'+platform.replace('/','-'))
        self.assertEqual(set(s['docker']['matrices']),expected_jobs)
        self.assertEqual({name for name in jobs if name.startswith(('build_binary','build_docker'))},expected_jobs)
        self.assertEqual(set(s['docker']['requiredArtifacts']),expected_artifacts)
        self.assertEqual(set(s['docker']['requiredJobs']),expected_jobs|{'source','debian_materials'})
        self.assertEqual(jobs['publisher_receipt']['needs'],list(s['docker']['receiptJobs']))
        self.assertEqual(s['docker']['receiptJobs'],{name:'debian_required' if name=='debian_materials' else 'required'
                                                   for name in expected_jobs|{'source','debian_materials'}})

    def test_reviewed_current_version_renders_all_linux_and_signed_payloads(self):
        scope=p.release_scope(p.VERSION)
        old='1.15.0-polaris-alpha.11'
        for role in ['all','signed']:
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
        rules=scope['linux']['payloadRules']['binary-linux_amd64']
        files={f'sing-box-polaris-testing_{p.VERSION}_linux_amd64.deb':{},f'sing-box-polaris-testing_{p.VERSION}_linux_x86_64.rpm':{}}
        p.verify_payloads(files,rules,'binary-linux_amd64')
        old_mix={name.replace(p.VERSION,old) if name.endswith('.rpm') else name:value for name,value in files.items()}
        with self.assertRaises(ValueError):p.verify_payloads(old_mix,rules,'binary-linux_amd64')
        from native_release_index import expected_native
        for role in ['all','signed']:
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
        for role in ['all','signed']:
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
        # Independent Linux packages have their own exact version/architecture contract.
        rules=scope['linux']['payloadRules']['binary-linux_amd64']
        files={f'sing-box-polaris-testing_{p.VERSION}_linux_amd64.deb':{},f'sing-box-polaris-testing_{p.VERSION}_linux_x86_64.rpm':{}}
        for invalid in [{name.replace(p.VERSION,p.VERSION+'0'):v for name,v in files.items()},
                        {name.replace('linux_amd64','linux_arm64'):v for name,v in files.items()}]:
            with self.assertRaises(ValueError):p.verify_payloads(invalid,rules,'binary-linux_amd64')

    def test_current_linux_requires_all_22_exact_testing_packages(self):
        raw = json.loads(p.SCOPE.read_text())['linux']
        scope = p.release_scope(p.VERSION)['linux']
        # Independent expected architectures keep a permissive channel regex or
        # changes to the producer matrix from silently redefining this contract.
        architectures = {
            '386': ('i386', 'i386'), 'amd64': ('amd64', 'x86_64'),
            'arm64': ('arm64', 'aarch64'), 'armv6': ('armel', 'armv6hl'),
            'armv7': ('armhf', 'armv7hl'), 'loong64': ('loongarch64', 'loongarch64'),
            'mips64le': ('mips64el', 'mips64el'), 'mipsle': ('mipsel', 'mipsel'),
            'ppc64le': ('ppc64el', 'ppc64le'), 'riscv64': ('riscv64', 'riscv64'),
            's390x': ('s390x', 's390x'),
        }
        self.assertEqual(set(scope['requiredArtifacts']),
                         {'binary-linux_' + arch for arch in architectures} | {'publisher-run-receipt','debian-candidate-raw','debian-material-ready'})
        checked = 0
        for arch, cpus in architectures.items():
            artifact = 'binary-linux_' + arch
            rules = scope['payloadRules'][artifact]
            expected = [{'pattern': re.escape('sing-box-polaris-testing_') + '{version}' +
                         re.escape('_linux_' + cpu + '.' + ext), 'count': 1}
                        for ext, cpu in zip(['deb', 'rpm'], cpus)]
            self.assertEqual(raw['payloadRules'][artifact], expected)
            files = {f'sing-box-polaris-testing_{p.VERSION}_linux_{cpu}.{ext}': {}
                     for ext, cpu in zip(['deb', 'rpm'], cpus)}
            p.verify_payloads(files, rules, artifact)
            checked += len(files)
            for name in files:
                ext = name.rsplit('.', 1)[1]
                cpu = cpus[0 if ext == 'deb' else 1]
                wrong_cpu = ('arm64' if cpu == 'amd64' else 'amd64') if ext == 'deb' else (
                            'aarch64' if cpu == 'x86_64' else 'x86_64')
                replacements = [name.replace('sing-box-polaris-testing_', 'sing-box-polaris' + suffix + '_')
                                for suffix in ['', '-beta', '-oldstable']]
                replacements += [name.replace(p.VERSION, p.VERSION + '0'),
                                 name.replace(p.VERSION, '1.15.0-polaris-alpha.11'),
                                 name.replace('_linux_' + cpu + '.', '_linux_' + wrong_cpu + '.')]
                for replacement in replacements:
                    invalid = dict(files)
                    invalid[replacement] = invalid.pop(name)
                    with self.subTest(artifact=artifact, rejected=replacement), self.assertRaises(ValueError):
                        p.verify_payloads(invalid, rules, artifact)
                missing = dict(files)
                missing.pop(name)
                with self.subTest(artifact=artifact, missing=name), self.assertRaises(ValueError):
                    p.verify_payloads(missing, rules, artifact)
                extra = dict(files)
                extra[name.replace('sing-box-polaris-testing_', 'sing-box-polaris_')] = {}
                with self.subTest(artifact=artifact, extra=name), self.assertRaises(ValueError):
                    p.verify_payloads(extra, rules, artifact)
        self.assertEqual(checked, 22)

    def test_all_and_signed_require_each_exact_openwrt_ipk_and_apk_architecture(self):
        source=json.loads(p.SCOPE.read_text());rendered=p.release_scope(p.VERSION)
        for role in ['all','signed']:
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

    def test_docker_keeps_exact_products_and_rejects_missing_extra_or_diagnostic_assets(self):
        scope=p.release_scope(p.VERSION);required=scope['docker']['requiredArtifacts']
        self.assertEqual(len(required),22)
        p.verify_artifact_names(list(required),required,'docker')
        for names in [required[:-1],required+['unexpected'],required+['repository~random.dockerbuild'],
                      required[:-1]+['repository~random.dockerbuild'],required+[required[0]]]:
            with self.subTest(names=names),self.assertRaises(ValueError):p.verify_artifact_names(names,required,'docker')

    def test_producer_receipt_uses_current_source_contract_and_rejects_old_or_tag_version(self):
        release=json.loads(p.CONFIG.read_text());source='a'*40
        env={'PUBLISHER_ROLE':'docker','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REPOSITORY':p.REPO,
             'GITHUB_REPOSITORY_ID':str(p.RID),'RELEASE_BUILD':'All','RELEASE_VERSION':p.VERSION,
             'GITHUB_SHA':source,'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':'1',
             'PUBLISH_STORES':'false','PUBLISH_REGISTRY':'false'}
        env.update(receipt_context_fixture('docker',False))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'release/ci').mkdir(parents=True)
            (root/'release/ci/github-release.json').write_text(json.dumps(release))
            (root/'release/ci/publisher-upstream-scope.json').write_bytes(p.SCOPE.read_bytes())
            script=p.ROOT/'scripts/ci/publisher_run_receipt.py'
            with chdir(root),mock.patch.dict(os.environ,env),mock.patch('subprocess.check_output',return_value=source):
                runpy.run_path(str(script),run_name='__main__')
                receipt=json.loads((root/'publisher-run-receipt.json').read_text())
                self.assertEqual((receipt['version'],receipt['sourceCommit'],receipt['role']),(p.VERSION,source,'docker'))
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
            with self.assertRaises(ValueError):p.extract(z,Path(d)/'out')

    def test_full_payload(self):
        rules=[{'pattern':'one','count':1},{'pattern':'two','count':1}]
        p.verify_payloads({'one':{},'two':{}},rules,'test')
        for files in [{'one':{}},{'one':{},'two':{},'extra':{}}]:
            with self.assertRaises(ValueError):p.verify_payloads(files,rules,'test')

    def reconciliation_operations(self):
        return json.loads((p.ROOT/'release/ci/github-release-reconciliation.json').read_text())['operations']

    def test_publication_excludes_typed_nonpublic_producer_outputs(self):
        cases=[
            ('all','libbox-android-arm64','arm64/libbox.aar','internal-sdk'),
            ('all','unsigned-apple-ios-archive',f'unsigned-{p.VERSION}-ios.xcarchive.tar','internal-unsigned-archive'),
            ('all','binary-native-index','polaris-upstream-native-assets.json','audited-source-and-index'),
            ('all','binary-native-index','sing-box-polaris-source-'+'a'*40+'.tar.gz','audited-source-and-index'),
            ('linux','binary-linux_amd64',f'sing-box-polaris-testing_{p.VERSION}_linux_amd64.deb','separate-distribution-channel'),
            ('docker','binary-linux-amd64','sing-box-amd64','separate-distribution-channel'),
            ('docker','oci-linux-arm64','image.tar','separate-distribution-channel'),
            ('signed','binary-darwin_arm64',f'sing-box-{p.VERSION}-darwin-arm64.tar.gz','separate-signed-distribution'),
            ('all','publisher-run-receipt','publisher-run-receipt.json','producer-evidence'),
            ('all','binary-test','polaris-candidate-manifest-test.json','producer-evidence'),
            ('all','binary-test','native-row-test.json','producer-evidence')]
        for role,artifact,path,disposition in cases:
            with self.subTest(role=role,artifact=artifact,path=path):
                self.assertEqual(p.publication(role,artifact,path),(None,disposition))
                self.assertIsNone(p.default_name(role,artifact,path))

    @historical_release()
    def test_publication_matches_exact_reviewed_168_asset_set(self):
        operations=self.reconciliation_operations()
        self.assertEqual(len(operations),228)
        expected={p.public_asset_name(row.get('newName',row['oldName'])):row for row in operations if row['operation']!='remove'}
        self.assertEqual(len(expected),168)
        selected={}
        for row in operations:
            producer=row['producer']
            if not producer:
                self.assertEqual((row['oldName'],row['operation']),(p.RECEIPT,'remove'))
                continue
            name,disposition=p.publication(producer['role'],producer['artifact'],producer['path'])
            with self.subTest(asset=row['oldName']):
                if row['operation']=='remove':
                    self.assertIsNone(name)
                    self.assertNotEqual(disposition,'upstream-public-product')
                else:
                    self.assertEqual(name,p.public_asset_name(row.get('newName',row['oldName'])))
                    self.assertEqual(p.producer_publication(producer['role'],producer['artifact'],producer['path']),
                                     (row.get('newName',row['oldName']),'upstream-public-product'))
                    self.assertEqual(disposition,'upstream-public-product')
                    self.assertEqual(producer['role'],'all')
                    self.assertTrue(producer['artifact'].startswith('binary-'))
                    self.assertNotIn(name,selected)
                    selected[name]=row
                self.assertEqual(p.default_name(producer['role'],producer['artifact'],producer['path']),name)
        self.assertEqual(selected,expected)
        self.assertEqual(len({name.casefold() for name in selected}),168)
        self.assertNotIn(p.RECEIPT,selected)
        self.assertFalse(any('-build.' in name for name in selected))

    @historical_release()
    def test_22_distro_names_keep_all_producer_identity_and_digest(self):
        operations=self.reconciliation_operations()
        all_packages=[row for row in operations if row['operation']=='rename' and row['oldName'].endswith(('.deb','.rpm'))]
        linux_packages={row['oldName']:row for row in operations if row['producer'].get('role')=='linux'}
        self.assertEqual((len(all_packages),len(linux_packages)),(22,22))
        self.assertEqual({row['newName'] for row in all_packages},set(linux_packages))
        for row in all_packages:
            producer=row['producer'];other=linux_packages[row['newName']]
            with self.subTest(name=row['newName']):
                self.assertEqual(producer['role'],'all')
                self.assertIn('-build.',row['oldName'])
                self.assertEqual(p.publication('all',producer['artifact'],producer['path']),
                                 (p.public_asset_name(row['newName']),'upstream-public-product'))
                self.assertEqual(other['operation'],'remove')
                self.assertIsNone(p.default_name('linux',other['producer']['artifact'],other['producer']['path']))
                self.assertNotEqual(row['id'],other['id'])
                self.assertNotEqual(row['digest'],other['digest'])
                self.assertGreater(row['bytes'],0)
                self.assertRegex(row['digest'],r'^sha256:[0-9a-f]{64}$')

    def test_sdk_and_docker_still_require_complete_producer_payloads(self):
        scope=p.release_scope(p.VERSION);groups={};counts={'sdk':0,'docker':0}
        for row in self.reconciliation_operations():
            producer=row['producer'];role=producer.get('role');artifact=producer.get('artifact','')
            if role=='docker' or artifact.startswith('libbox-'):
                counts['docker' if role=='docker' else 'sdk']+=1
                self.assertEqual(row['operation'],'remove')
                groups.setdefault((role,artifact),{})[producer['path']]={}
        self.assertEqual(counts,{'sdk':12,'docker':19})
        for (role,artifact),files in groups.items():
            with self.subTest(role=role,artifact=artifact):
                self.assertIn(artifact,scope[role]['requiredArtifacts'])
                rules=scope[role]['payloadRules'][artifact]
                p.verify_payloads(files,rules,artifact)
                missing=dict(files);missing.pop(next(iter(missing)))
                extra=dict(files,unexpected={})
                for invalid in [missing,extra]:
                    with self.assertRaises(ValueError):p.verify_payloads(invalid,rules,artifact)

    @historical_release()
    def test_unsigned_android_apk_names_remain_explicit(self):
        apks=[row for row in self.reconciliation_operations()
              if row['producer'].get('artifact','').startswith('binary-android-apks-') and row['oldName'].endswith('.apk')]
        self.assertEqual(len(apks),10)
        for row in apks:
            producer=row['producer'];name=p.default_name('all',producer['artifact'],producer['path'])
            self.assertEqual(name,p.public_asset_name(row['oldName']))
            # The original producer still records unsigned APKs even though the
            # public basename now matches upstream. No signing state is changed.
            self.assertTrue(producer['path'].endswith('-unsigned.apk'))
            self.assertEqual(p.producer_publication('all',producer['artifact'],producer['path'])[0],row['oldName'])
            self.assertTrue(name.startswith('SFA-'+p.PUBLIC_VERSION+'-'))
            self.assertFalse(name.endswith('-unsigned.apk'))

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
                    ('all','publisher-run-receipt','publisher-run-receipt.json'),
                    ('linux','binary-linux_amd64',f'sing-box-polaris-testing_{p.VERSION}_linux_amd64.deb'),
                    ('docker','oci-linux-arm64','image.tar'),
                    ('signed','binary-darwin_arm64',f'sing-box-{p.VERSION}-darwin-arm64.tar.gz')]:
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
                    p.inventory({'all':'42','linux':'43','docker':'44'},source,root/'work','b'*40,'c'*40,source_root=source_root)
                validate.assert_called_once_with(index,source,'b'*40,'c'*40,'42',1,workflow,source_root)

    def test_main_passes_verified_source_checkout_to_inventory(self):
        class StopInventory(Exception):pass
        source='a'*40;source_root=Path('/offline-fixture/reviewed-source')
        argv=['github_release.py','inventory','--source',source,'--source-dir',str(source_root),
              '--all-run','42','--linux-run','43','--docker-run','44']
        with tempfile.TemporaryDirectory() as audit_temp, mock.patch('sys.argv',argv+['--audit',str(Path(audit_temp)/'audit')]),mock.patch.object(p,'identity') as identity, \
             mock.patch.object(p,'command',return_value='b'*40) as command, \
             mock.patch.object(p,'tag_identity',return_value='c'*40), \
             mock.patch.object(p,'inventory',side_effect=StopInventory) as inventory:
            with self.assertRaises(StopInventory):p.main()
            identity.assert_called_once_with(source,source_root)
            command.assert_called_once_with('git','-C',str(source_root),'rev-parse','HEAD^{tree}')
            inventory.assert_called_once_with({'all':'42','linux':'43','docker':'44'},source,
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

    @historical_release()
    def test_all_168_public_names_match_the_reviewed_local_contract(self):
        # This committed, hash-locked snapshot was compared with the reviewed
        # mapping.csv offline. CI must not depend on an external workspace file.
        plan=p.public_name_plan();rows=plan['operations']
        self.assertEqual(p.sha(p.NAME_ALIGNMENT),'c77f674bddbd0f6f77ee636b1bd93643faf8e6cd62d5d9ce7a6a667c789d8064')
        self.assertEqual(len(rows),168)
        self.assertEqual(len({row['id'] for row in rows}),168)
        self.assertEqual(len({row['newName'].casefold() for row in rows}),168)
        for row in rows:
            with self.subTest(asset=row['id']):
                self.assertEqual(p.public_asset_name(row['oldName']),row['newName'])
                self.assertNotIn(p.VERSION,row['newName'])
                self.assertNotIn('sing-box-polaris-SF',row['newName'])
                self.assertNotEqual(row['oldName'],row['newName'])
        self.assertEqual(sum(row['newName'].startswith('sing-box-polaris') for row in rows),139)
        self.assertEqual(sum(row['newName'].startswith('SF') for row in rows),29)
        producers=json.loads(p.RECONCILIATION.read_text())['operations']
        selected={p.publication(row['producer']['role'],row['producer']['artifact'],row['producer']['path'])[0]
                  for row in producers if row['producer']}
        selected.discard(None)
        self.assertEqual(selected,{row['newName'] for row in rows})

    @historical_release()
    def test_public_name_contract_cannot_be_modified(self):
        plan=p.public_name_plan()
        for field,value in [('id',1),('oldName','unexpected.zip'),('newName','unexpected.zip'),
                            ('bytes',1),('digest','sha256:'+'0'*64)]:
            candidate=copy.deepcopy(plan);candidate['operations'][0][field]=value
            with self.subTest(field=field),tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'names.json';path.write_text(json.dumps(candidate))
                with mock.patch.object(p,'NAME_ALIGNMENT',path),self.assertRaisesRegex(ValueError,'snapshot changed'):
                    p.public_name_plan()


class PublicNameRenameTests(unittest.TestCase):
    """All API traffic is mocked; the reviewed 168 asset IDs are never mutated."""

    def setUp(self):
        self.enterContext(historical_release())
        self.plan=p.public_name_plan()
        self.release=dict(self.plan['release'],id=self.plan['releaseId'])
        self.original_release=copy.deepcopy(self.release)
        self.assets={row['id']:{'id':row['id'],'name':row['oldName'],'size':row['bytes'],
                               'digest':row['digest'],'label':self.plan['assetLabel'],'state':'uploaded'}
                     for row in self.plan['operations']}
        self.repository_id=p.RID
        self.commit={'sha':self.plan['sourceCommit'],'tree':{'sha':self.plan['sourceTree']}}
        self.releases=[{'id':self.plan['releaseId'],'tag_name':p.TAG}]
        self.writes=[]
        self.fail_after=None
        self.bad_response=None
        self.budget=5000

    def api(self,path,method='GET',payload=None):
        if method=='GET':
            if path==f'repos/{p.REPO}':return {'id':self.repository_id}
            if path==f'repos/{p.REPO}/git/commits/{self.plan["sourceCommit"]}':return copy.deepcopy(self.commit)
            if path==f'repos/{p.REPO}/releases/{self.plan["releaseId"]}':return copy.deepcopy(self.release)
            if path=='rate_limit':return {'resources':{'core':{'remaining':self.budget,'reset':2000000000}}}
            ident=int(path.rsplit('/',1)[-1])
            self.assertEqual(path,f'repos/{p.REPO}/releases/assets/{ident}')
            return copy.deepcopy(self.assets[ident])
        ident=int(path.rsplit('/',1)[-1])
        row=next(row for row in self.plan['operations'] if row['id']==ident)
        self.assertEqual((path,method,payload),(f'repos/{p.REPO}/releases/assets/{ident}','PATCH',{'name':row['newName']}))
        self.assertEqual(self.assets[ident]['name'],row['oldName'])
        self.assertFalse(any(asset['name']==payload['name'] for key,asset in self.assets.items() if key!=ident))
        self.assets[ident]['name']=payload['name']
        self.writes.append((method,ident,copy.deepcopy(payload)))
        if len(self.writes)==self.fail_after:raise OSError('uncertain response after successful name PATCH')
        result=copy.deepcopy(self.assets[ident])
        if self.bad_response:
            field,value=self.bad_response;result[field]=value
        return result

    def pages(self,path,key=None):
        if path==f'repos/{p.REPO}/releases/{self.plan["releaseId"]}/assets':
            return copy.deepcopy(list(self.assets.values()))
        self.assertEqual(path,f'repos/{p.REPO}/releases')
        return copy.deepcopy(self.releases)

    def remote(self):
        from contextlib import ExitStack
        stack=ExitStack()
        stack.enter_context(mock.patch.object(p,'api',side_effect=self.api))
        stack.enter_context(mock.patch.object(p,'pages',side_effect=self.pages))
        stack.enter_context(mock.patch.object(p,'tag_identity',return_value=self.plan['tagObject']))
        stack.enter_context(mock.patch.object(p,'command',side_effect=AssertionError('unexpected real command')))
        stack.enter_context(mock.patch.object(p.subprocess,'run',side_effect=AssertionError('unexpected real process')))
        stack.enter_context(mock.patch.object(p.time,'sleep'))
        return stack

    def test_default_check_is_read_only_and_covers_the_full_snapshot(self):
        with self.remote():
            result=p.rename_public_assets(self.plan)
        self.assertEqual((result['assetCount'],result['remaining'],result['complete']),(168,168,False))
        self.assertEqual(result['assets'],{row['id']:(row['oldName'],row['bytes'],row['digest'],self.plan['assetLabel'])
                                          for row in self.plan['operations']})
        self.assertEqual(self.writes,[])
        self.assertEqual(self.release,self.original_release)

    def test_rename_changes_only_all_168_outer_names_and_is_idempotent(self):
        with self.remote():
            result=p.rename_public_assets(self.plan,execute=True)
            writes=list(self.writes)
            self.assertEqual(p.rename_public_assets(self.plan,execute=True),result)
        self.assertEqual((result['assetCount'],result['remaining'],result['complete']),(168,0,True))
        self.assertEqual(len(writes),168)
        self.assertEqual(self.writes,writes)
        self.assertEqual(self.release,self.original_release)
        self.assertEqual(result['assets'],{row['id']:(row['newName'],row['bytes'],row['digest'],self.plan['assetLabel'])
                                          for row in self.plan['operations']})
        self.assertEqual({ident for _,ident,_ in writes},set(self.assets))

    def test_completed_snapshot_has_zero_writes_even_without_mutation_budget(self):
        for row in self.plan['operations']:self.assets[row['id']]['name']=row['newName']
        self.budget=0
        with self.remote():result=p.rename_public_assets(self.plan,execute=True)
        self.assertTrue(result['complete'])
        self.assertEqual(self.writes,[])

    def test_every_168_uncertain_patch_response_resumes_from_exact_ids(self):
        for position in range(1,169):
            with self.subTest(position=position):
                self.setUp();self.fail_after=position
                with self.remote():
                    with self.assertRaises(OSError):p.rename_public_assets(self.plan,execute=True)
                    self.fail_after=None
                    self.assertTrue(p.rename_public_assets(self.plan,execute=True)['complete'])
                self.assertEqual(len(self.writes),168)
                self.assertEqual(len({ident for _,ident,_ in self.writes}),168)
                self.assertEqual(self.release,self.original_release)

    def test_unknown_assets_bytes_labels_release_source_and_tag_fail_before_writes(self):
        failures=['extra','missing','name','digest','size','label','state','duplicate-name','duplicate-id',
                  'repository','commit','tree','release-id','draft','immutable','prerelease','body',
                  'target_commitish','tag_name','release-name','competing-release','tag','modified-plan']
        for failure in failures:
            with self.subTest(failure=failure):
                self.setUp();row=self.plan['operations'][0];asset=self.assets[row['id']]
                if failure=='extra':self.assets[1]=dict(asset,id=1,name='unexpected')
                elif failure=='missing':del self.assets[row['id']]
                elif failure in ('name','digest','label','state'):asset[failure]='unexpected'
                elif failure=='size':asset['size']+=1
                elif failure=='duplicate-name':self.assets[self.plan['operations'][1]['id']]['name']=asset['name'].upper()
                elif failure=='duplicate-id':self.assets[self.plan['operations'][1]['id']]['id']=asset['id']
                elif failure=='repository':self.repository_id=1
                elif failure=='commit':self.commit['sha']='0'*40
                elif failure=='tree':self.commit['tree']['sha']='0'*40
                elif failure=='release-id':self.release['id']=1
                elif failure in ('draft','immutable','prerelease'):self.release[failure]=not self.release[failure]
                elif failure in ('body','target_commitish','tag_name'):self.release[failure]='unexpected'
                elif failure=='release-name':self.release['name']='unexpected'
                elif failure=='competing-release':self.releases.append({'id':1,'tag_name':p.TAG})
                elif failure=='modified-plan':self.plan['operations'][0]['newName']='unexpected'
                with self.remote():
                    if failure=='tag':
                        with mock.patch.object(p,'tag_identity',return_value='0'*40),self.assertRaises(ValueError):
                            p.rename_public_assets(self.plan,execute=True)
                    else:
                        with self.assertRaises(ValueError):p.rename_public_assets(self.plan,execute=True)
                self.assertEqual(self.writes,[])

    def test_mismatched_patch_response_stops_immediately_and_rechecks_on_resume(self):
        for field,value in [('id',1),('name','unexpected'),('size',1),('digest','sha256:'+'0'*64),
                            ('label','unexpected'),('state','new')]:
            with self.subTest(field=field):
                self.setUp();self.bad_response=(field,value)
                with self.remote():
                    with self.assertRaisesRegex(ValueError,'PATCH response mismatch'):
                        p.rename_public_assets(self.plan,execute=True)
                    self.assertEqual(len(self.writes),1)
                    self.bad_response=None
                    self.assertTrue(p.rename_public_assets(self.plan,execute=True)['complete'])
                self.assertEqual(len(self.writes),168)

    def test_between_snapshot_change_and_insufficient_budget_stop_before_writes(self):
        original=p.public_name_snapshot;calls=0
        def racing(plan):
            nonlocal calls
            calls+=1
            if calls==2:
                row=plan['operations'][0];self.assets[row['id']]['name']=row['newName']
            return original(plan)
        with self.remote(),mock.patch.object(p,'public_name_snapshot',side_effect=racing):
            with self.assertRaisesRegex(ValueError,'before first write'):p.rename_public_assets(self.plan,execute=True)
        self.assertEqual(self.writes,[])
        self.setUp();self.budget=0
        with self.remote(),self.assertRaisesRegex(ValueError,'budget insufficient'):
            p.rename_public_assets(self.plan,execute=True)
        self.assertEqual(self.writes,[])

    def test_immediate_asset_read_rejects_concurrent_change_before_patch(self):
        original=self.api
        def racing(path,method='GET',payload=None):
            if method=='GET' and '/releases/assets/' in path:
                self.assets[int(path.rsplit('/',1)[-1])]['label']='unexpected'
            return original(path,method,payload)
        with self.remote(),mock.patch.object(p,'api',side_effect=racing):
            with self.assertRaisesRegex(ValueError,'before rename'):p.rename_public_assets(self.plan,execute=True)
        self.assertEqual(self.writes,[])

    def test_periodic_snapshot_detects_concurrent_mutation_after_80_names(self):
        original=p.public_name_snapshot;calls=0
        def racing(plan):
            nonlocal calls
            calls+=1
            if calls==3:self.assets[plan['operations'][0]['id']]['digest']='sha256:'+'0'*64
            return original(plan)
        with self.remote(),mock.patch.object(p,'public_name_snapshot',side_effect=racing):
            with self.assertRaises(ValueError):p.rename_public_assets(self.plan,execute=True)
        self.assertEqual(len(self.writes),80)

    def test_name_cli_uses_fixed_snapshot_without_rebuilding_or_old_checkout_identity(self):
        for mode in ['check-names','rename-names']:
            self.setUp()
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                audit=Path(directory)/'audit'
                argv=['github_release.py',mode,'--source',self.plan['sourceCommit'],'--audit',str(audit)]
                with self.remote(),mock.patch('sys.argv',argv),mock.patch('builtins.print'), \
                     mock.patch.dict(os.environ,POLARIS_GITHUB_PUBLISH_ENABLED='true'), \
                     mock.patch.object(p,'identity') as identity,mock.patch.object(p,'inventory') as inventory, \
                     mock.patch.object(p,'reviewed_contract') as reviewed,mock.patch.object(p,'assemble') as assemble:
                    p.main()
                    identity.assert_not_called();inventory.assert_not_called()
                    reviewed.assert_not_called();assemble.assert_not_called()
                result=json.loads((audit/'public-name-result.json').read_text())
                self.assertEqual(result['complete'],mode=='rename-names')
                self.assertEqual(result['assetCount'],168)
                self.assertEqual(len(self.writes),168 if mode=='rename-names' else 0)
                self.assertEqual(self.release,self.original_release)

    def test_name_cli_rejects_wrong_source_or_disabled_write_gate(self):
        for mode,source,enabled in [('check-names','0'*40,'true'),('rename-names','0'*40,'true'),
                                    ('rename-names',self.plan['sourceCommit'],'false')]:
            with self.subTest(mode=mode,source=source,enabled=enabled),tempfile.TemporaryDirectory() as directory:
                argv=['github_release.py',mode,'--source',source,'--audit',str(Path(directory)/'audit')]
                with mock.patch('sys.argv',argv),mock.patch.dict(os.environ,POLARIS_GITHUB_PUBLISH_ENABLED=enabled), \
                     mock.patch.object(p,'rename_public_assets') as rename,self.assertRaises(ValueError):
                    p.main()
                rename.assert_not_called()


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
        material_paths=('scripts/ci/cronet_material_supply.py','scripts/ci/cronet_material_bootstrap.py',
                        'release/ci/cronet-material-profiles.json','release/ci/cronet-material-inputs.json',
                        '.github/patches/cronet-sysroot-transport.patch','.github/CRONET_GO_VERSION')
        paths=apple_paths+material_paths
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


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(historical_release())
        self.plan = json.loads(p.RECONCILIATION.read_text())
        self.actual = {k:self.plan[k] for k in ('sourceCommit','tag','tagObject')}
        self.actual['runs'] = {}
        for row in self.plan['operations']:
            if not row.get('producer'):continue
            origin = row['producer'];role, artifact, path = (origin[k] for k in ('role','artifact','path'))
            item = self.actual['runs'].setdefault(role,{'artifacts':{}})['artifacts'].setdefault(
                artifact,{'id':len(self.actual['runs'][role]['artifacts'])+1,'archiveSha256':'sha256:'+'1'*64,'files':{}})
            item['files'][path] = {'bytes':row['bytes'],'sha256':row['digest'].removeprefix('sha256:')}
        self.release = dict(self.plan['release'],id=self.plan['releaseId'])
        self.assets = {r['id']:{'id':r['id'],'name':r['oldName'],'size':r['bytes'],'digest':r['digest'],'state':'uploaded'}
                       for r in self.plan['operations']}
        self.writes = []
        self.fail_after = None

    def api(self,path,method='GET',payload=None):
        if method=='GET':
            self.assertEqual(path,f'repos/{p.REPO}/releases/{self.plan["releaseId"]}')
            return copy.deepcopy(self.release)
        ident=int(path.rsplit('/',1)[-1]);self.writes.append((method,ident,payload))
        if '/releases/assets/' in path:
            if method=='DELETE':del self.assets[ident]
            else:
                self.assertEqual(method,'PATCH')
                self.assertFalse(any(a['name']==payload['name'] for key,a in self.assets.items() if key!=ident))
                self.assets[ident]['name']=payload['name']
        else:
            self.assertEqual((method,ident),('PATCH',self.plan['releaseId']))
            self.release.update(payload)
        if self.fail_after==len(self.writes):raise OSError('uncertain response after successful mutation')
        return {}

    def pages(self,path,key=None):
        if path.endswith('/assets'):return copy.deepcopy(list(self.assets.values()))
        self.assertEqual(path,f'repos/{p.REPO}/releases')
        return [{'id':self.plan['releaseId'],'tag_name':p.TAG}]

    def remote(self):
        from contextlib import ExitStack
        stack=ExitStack()
        stack.enter_context(mock.patch.object(p,'api',self.api))
        stack.enter_context(mock.patch.object(p,'pages',self.pages))
        stack.enter_context(mock.patch.object(p,'tag_identity',return_value=self.plan['tagObject']))
        return stack

    def test_exact_plan_binds_every_producer_byte_and_fixed_release(self):
        self.assertEqual(p.reconciliation_plan(self.actual),self.plan)
        for failure in ['digest','source','tag','object']:
            actual=copy.deepcopy(self.actual)
            if failure=='digest':
                next(iter(next(iter(actual['runs']['all']['artifacts'].values()))['files'].values()))['sha256']='0'*64
            else:actual[{'source':'sourceCommit','tag':'tag','object':'tagObject'}[failure]]='0'*40
            with self.subTest(failure=failure),self.assertRaises(ValueError):p.reconciliation_plan(actual)
        for change in [{'releaseId':1},{'deferRemovalIds':[],'consumerEvidence':[]},{'deferRemovalIds':[653244600]}]:
            plan=dict(self.plan,**change)
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'plan.json';path.write_text(json.dumps(plan))
                with mock.patch.object(p,'RECONCILIATION',path),self.assertRaises(ValueError):p.reconciliation_plan(self.actual)

    def test_final_set_keeps_all_original_ids_and_bytes_and_defers_consumers(self):
        self.plan['deferRemovalIds']=[653244600,653251914]
        with self.remote():
            result=p.reconcile(self.plan)
            self.assertEqual(result,{'releaseId':416392475,'assetCount':170,'complete':False,
                                    'deferredAssetIds':[653244600,653251914]})
            self.assertEqual(sum(method=='DELETE' for method,_,_ in self.writes),58)
            self.assertEqual(sum(method=='PATCH' and ident!=416392475 for method,ident,_ in self.writes),23)
            for row in self.plan['operations']:
                if row['operation']=='remove' and row['id'] not in self.plan['deferRemovalIds']:
                    self.assertNotIn(row['id'],self.assets);continue
                asset=self.assets[row['id']]
                self.assertEqual((asset['name'],asset['size'],asset['digest']),
                                 (row.get('newName',row['oldName']),row['bytes'],row['digest']))
            before=list(self.writes);self.assertEqual(p.reconcile(self.plan),result)
            self.assertEqual(self.writes,before)

    def test_full_168_convergence_after_reviewed_consumer_prerequisite(self):
        plan=dict(self.plan,deferRemovalIds=[])
        with self.remote():
            result=p.reconcile(plan)
            self.assertTrue(result['complete']);self.assertEqual(result['assetCount'],168)
            self.assertEqual(sum(method=='DELETE' for method,_,_ in self.writes),60)

    def test_every_uncertain_mutation_is_resumable_without_reupload_or_tag_change(self):
        # Every interruption point in the exact 23 renames + 60 removals + notes.
        for position in range(1,85):
            with self.subTest(position=position):
                self.setUp();self.plan['deferRemovalIds']=[];self.fail_after=position
                with self.remote():
                    with self.assertRaises(OSError):p.reconcile(self.plan)
                    self.fail_after=None
                    self.assertEqual(p.reconcile(self.plan)['assetCount'],168)
                    self.assertFalse(any(method=='POST' for method,_,_ in self.writes))

    def test_unknown_concurrent_assets_metadata_bytes_and_tag_fail_before_writes(self):
        for change in ['unknown','name','digest','size','state','missing-keep','missing-deferred','draft','immutable','body','tag']:
            with self.subTest(change=change):
                self.setUp();row=next(r for r in self.plan['operations'] if r['operation']=='keep')
                if change=='unknown':self.assets[1]=dict(self.assets[row['id']],id=1,name='unexpected')
                elif change in ('name','digest','state'):self.assets[row['id']][change]='unexpected'
                elif change=='size':self.assets[row['id']]['size']+=1
                elif change=='missing-keep':del self.assets[row['id']]
                elif change=='missing-deferred':
                    self.plan['deferRemovalIds']=[653244600,653251914];del self.assets[653244600]
                elif change in ('draft','immutable'):self.release[change]=True
                elif change=='body':self.release['body']='unexpected'
                else:self.plan['tagObject']='0'*40
                with self.remote():
                    if change=='tag':
                        with mock.patch.object(p,'tag_identity',return_value='f'*40),self.assertRaises(ValueError):p.reconcile(self.plan)
                    else:
                        with self.assertRaises(ValueError):p.reconcile(self.plan)
                self.assertEqual(self.writes,[])

    def test_between_snapshot_concurrent_change_is_not_accepted(self):
        original=p.reconciliation_snapshot;calls=0
        def racing(plan,body):
            nonlocal calls
            calls+=1
            if calls==2:
                asset=next(r for r in plan['operations'] if r['operation']=='rename')
                self.assets[asset['id']]['name']=asset['newName']
            return original(plan,body)
        with self.remote(),mock.patch.object(p,'reconciliation_snapshot',side_effect=racing),self.assertRaises(ValueError):
            p.reconcile(self.plan)
        self.assertEqual(self.writes,[])

    def test_expired_or_changed_recovery_artifact_blocks_removal(self):
        def artifact(path,method='GET',payload=None):
            ident=int(path.rsplit('/',1)[-1])
            row=next(r for r in self.plan['operations'] if r['operation']=='remove' and r.get('producer'))
            return {'id':ident,'name':row['producer']['artifact'],'digest':'sha256:'+'1'*64,
                    'expired':True,'expires_at':'2000-01-01T00:00:00Z'}
        with mock.patch.object(p,'api',side_effect=artifact),self.assertRaises(ValueError):
            p.recovery_references(self.actual,self.plan)
        self.assertEqual(self.writes,[])

    def test_reconcile_reuses_reviewed_inventory_without_downloading_producers(self):
        actual=dict(self.actual,repository=p.REPO,repositoryId=p.RID,version=p.VERSION,
                    sourceTree='b'*40,scopeSha256=p.sha(p.SCOPE))
        for role,run in actual['runs'].items():run['id']={'all':'42','linux':'43','docker':'44'}[role]
        with tempfile.TemporaryDirectory() as directory:
            audit=Path(directory)/'audit'
            argv=['github_release.py','check-reconcile','--source',self.plan['sourceCommit'],
                  '--all-run','42','--linux-run','43','--docker-run','44','--inventory-run','45',
                  '--inventory-sha256','a'*64,'--recovery-run','46','--audit',str(audit)]
            with mock.patch('sys.argv',argv),mock.patch.object(p,'identity'), \
                 mock.patch.object(p,'command',return_value='b'*40), \
                 mock.patch.object(p,'reviewed_contract',return_value=actual), \
                 mock.patch.object(p,'verify_metadata_pair'), \
                 mock.patch.object(p,'reviewed_recovery',return_value=self.plan) as recovery, \
                 mock.patch.object(p,'reconciliation_snapshot'), \
                 mock.patch.object(p,'inventory') as inventory,mock.patch.object(p,'reconcile') as reconcile:
                p.main()
                recovery.assert_called_once_with('46',actual,audit)
                inventory.assert_not_called();reconcile.assert_not_called()

    def test_workflow_retains_protection_and_persists_recovery_before_reconcile(self):
        import yaml
        workflow=yaml.safe_load((p.ROOT/'.github/workflows/publish-github.yml').read_text())
        self.assertEqual(workflow['permissions'],{'contents':'read'})
        self.assertEqual(workflow['concurrency'],{'group':'polaris-github-release-'+json.loads((p.ROOT/'release/ci/github-release.json').read_text())['tag'],'cancel-in-progress':False})
        job=workflow['jobs']['publish']
        self.assertEqual(job['environment'],'polaris-github-release')
        self.assertEqual(job['needs'],'validate')
        self.assertEqual(job['permissions'],{'contents':'write','actions':'read'})
        self.assertIn("vars.POLARIS_GITHUB_PUBLISH_ENABLED == 'true'",job['if'])
        backup=[step for step in workflow['jobs']['validate']['steps'] if step.get('with',{}).get('name')=='github-release-recovery']
        self.assertEqual(len(backup),1)
        self.assertEqual(backup[0]['if'],"inputs.mode == 'prepare-reconcile' || inputs.mode == 'prepare-replacement'")
        self.assertEqual(backup[0]['with']['retention-days'],90)

    def test_delete_api_accepts_empty_204_response(self):
        with mock.patch('subprocess.check_output',return_value=b''):
            self.assertIsNone(p.api('test','DELETE'))


class ReplacementTests(unittest.TestCase):
    """Offline, exact-ID replacement tests. No GitHub operation leaves the fake."""

    def setUp(self):
        ReconciliationTests.setUp(self)
        self.original_inventory = self.actual
        self.plan = p.replacement_baseline()
        self.source = 'd' * 40
        self.tag_object = 'e' * 40
        self.inventory_digest = 'f' * 64
        self.original_ids = set(self.assets)
        self.release.update(upload_url=f'https://uploads.github.com/repos/{p.REPO}/releases/416392475/assets{{?name,label}}',
                            html_url=f'https://github.com/{p.REPO}/releases/tag/{p.TAG}')
        self.initial_release = copy.deepcopy(self.release)
        self.initial_assets = copy.deepcopy(self.assets)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / 'dist'
        self.output.mkdir()
        self.actual = copy.deepcopy(self.original_inventory)
        self.actual.update(repository=p.REPO, repositoryId=p.RID, version=p.VERSION,
                           sourceCommit=self.source, sourceTree='b' * 40, tagObject=self.tag_object,
                           reviewed=True, scopeSha256=p.sha(p.SCOPE))
        artifact_id = 1000
        for role, run in self.original_inventory['runs'].items():
            run.update(id={'all': '42', 'linux': '43', 'docker': '44'}[role], attempt=1)
            for artifact in run['artifacts'].values():
                artifact_id += 1
                artifact['id'] = artifact_id
        self.original_inventory.update(repository=p.REPO, repositoryId=p.RID, version=p.VERSION)
        for role, run in self.actual['runs'].items():
            run.update(id={'all': '52', 'linux': '53', 'docker': '54'}[role], attempt=1)
            for artifact, item in run['artifacts'].items():
                for path, record in list(item['files'].items()):
                    new_path = path.replace(p.REPLACEMENT_ORIGINAL['sourceCommit'], self.source)
                    if new_path != path:
                        item['files'][new_path] = item['files'].pop(path)
                        path = new_path
                    name, disposition = p.publication(role, artifact, path)
                    data = f'fresh rebuild from {self.source}: {role}/{artifact}/{path}\n'.encode()
                    record.update(bytes=len(data), sha256=p.hashlib.sha256(data).hexdigest(),
                                  releaseName=name, publicationDisposition=disposition)
                    if name is not None:
                        (self.output / name).write_bytes(data)
        self.assertEqual(len(list(self.output.iterdir())), 168)
        self.audit = self.output.with_name(self.output.name + '-audit')
        self.audit.mkdir()
        self.index_path = self.audit / 'polaris-upstream-native-assets.json'
        self.native_index = {'schema': 'polaris-upstream-native-assets-v1', 'repository': p.REPO,
                             'repositoryId': p.RID, 'version': p.VERSION, 'sourceCommit': self.source,
                             'sourceTree': self.actual['sourceTree'], 'tag': p.TAG, 'tagObject': self.tag_object,
                             'sourceArchive': {'name': 'sing-box-polaris-source-' + self.source + '.tar.gz',
                                               'bytes': len(b'fixture source archive'),
                                               'sha256': p.hashlib.sha256(b'fixture source archive').hexdigest()},
                             'distributionMaterials': {'publicationEligible': True}}
        self.index_path.write_text(json.dumps(self.native_index))
        for path, record in self.actual['runs']['all']['artifacts']['binary-native-index']['files'].items():
            data = self.index_path.read_bytes() if path == self.index_path.name else b'fixture source archive'
            record.update(bytes=len(data), sha256=p.hashlib.sha256(data).hexdigest())
        p.associate_distribution_materials(self.actual, self.native_index, p.sha(self.index_path))
        self.assertEqual(set(self.actual['distributionMaterials']), {'sourceArchive', 'noticeIndex', 'bindingSHA256'})
        self.events = []
        self.interrupt_at = None
        self.fail_upload_before = None
        self.next_id = 900000000
        self.budget = 5000
        self.budget_after_uploads = None
        self.environment = mock.patch.dict(os.environ, GITHUB_SHA=self.source,
                                          GITHUB_REF='refs/tags/' + p.TAG, GITHUB_RUN_ID='99')
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def reset_remote(self):
        self.release = copy.deepcopy(self.initial_release)
        self.assets = copy.deepcopy(self.initial_assets)
        self.events = []
        self.interrupt_at = None
        self.fail_upload_before = None
        self.next_id = 900000000
        self.budget = 5000
        self.budget_after_uploads = None

    def record_event(self, kind, ident, payload=None):
        self.events.append((kind, ident, copy.deepcopy(payload)))
        if len(self.events) == self.interrupt_at:
            raise OSError('uncertain response after successful replacement mutation')

    def api(self, path, method='GET', payload=None):
        if path == 'rate_limit':
            self.assertEqual(method, 'GET')
            remaining = self.budget_after_uploads if self.budget_after_uploads is not None and sum(
                kind == 'upload' for kind, _, _ in self.events) == 168 else self.budget
            return {'resources': {'core': {'remaining': remaining, 'reset': 2000000000}}}
        if method == 'GET':
            self.assertEqual(path, f'repos/{p.REPO}/releases/416392475')
            return dict(self.release)
        ident = int(path.rsplit('/', 1)[-1])
        if '/releases/assets/' in path:
            self.assertTrue(self.release['draft'])
            if method == 'DELETE':
                self.assertIn(ident, self.original_ids)
                self.assertEqual(len(set(self.assets) - self.original_ids), 168,
                                 'an original must never be deleted before all 168 replacements exist')
                del self.assets[ident]
                self.record_event('delete', ident)
            else:
                self.assertEqual(method, 'PATCH')
                self.assertNotIn(ident, self.original_ids)
                self.assertFalse(set(self.assets) & self.original_ids,
                                 'canonical names cannot appear while old assets remain')
                self.assertFalse(any(a['name'] == payload['name'] for key, a in self.assets.items() if key != ident))
                self.assets[ident].update(payload)
                self.record_event('rename', ident, payload)
            return dict(self.assets[ident]) if ident in self.assets else None
        self.assertEqual((method, ident), ('PATCH', 416392475))
        if payload.get('draft') is False:
            self.assertEqual(len(self.assets), 168)
            self.assertFalse(set(self.assets) & self.original_ids)
            self.assertEqual({a['name'] for a in self.assets.values()}, {path.name for path in self.output.iterdir()})
        self.release.update({key: value for key, value in payload.items() if key != 'make_latest'})
        self.record_event('publish' if payload.get('draft') is False else 'stage', ident, payload)
        return dict(self.release)

    def pages(self, path, key=None):
        if path == f'repos/{p.REPO}/releases/416392475/assets':
            return [dict(asset) for asset in self.assets.values()]
        self.assertEqual(path, f'repos/{p.REPO}/releases')
        return [{'id': 416392475, 'tag_name': p.TAG}]

    def command(self, *args):
        from urllib.parse import parse_qs, urlsplit
        self.assertEqual(args[:4], ('gh', 'api', '--method', 'POST'))
        endpoint = urlsplit(args[4])
        self.assertEqual((endpoint.scheme, endpoint.netloc, endpoint.path),
                         ('https', 'uploads.github.com', f'/repos/{p.REPO}/releases/416392475/assets'))
        self.assertEqual(args[5:8], ('-H', 'Content-Type: application/octet-stream', '--input'))
        self.assertEqual(len(args), 9)
        self.assertTrue(self.release['draft'])
        self.assertEqual(set(self.assets) & self.original_ids, self.original_ids)
        params = parse_qs(endpoint.query)
        self.assertEqual(set(params), {'name', 'label'})
        name, label = params['name'][0], params['label'][0]
        self.assertFalse(any(asset['name'] == name for asset in self.assets.values()))
        if self.fail_upload_before == 1 + sum(kind == 'upload' for kind, _, _ in self.events):
            raise OSError('upload failed before creating a remote asset')
        path = Path(args[8])
        self.next_id += 1
        ident = self.next_id
        self.assets[ident] = {'id': ident, 'name': name, 'label': label, 'size': path.stat().st_size,
                              'digest': 'sha256:' + p.sha(path), 'state': 'uploaded'}
        self.record_event('upload', ident, {'name': name, 'label': label})
        return json.dumps(self.assets[ident])

    def remote(self):
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(mock.patch.object(p, 'api', side_effect=self.api))
        stack.enter_context(mock.patch.object(p, 'pages', side_effect=self.pages))
        stack.enter_context(mock.patch.object(p, 'command', side_effect=self.command))
        stack.enter_context(mock.patch.object(p, 'tag_identity', return_value=self.tag_object))
        stack.enter_context(mock.patch.object(p.subprocess, 'run', side_effect=AssertionError('unexpected real process')))
        stack.enter_context(mock.patch.object(p.time, 'sleep'))
        return stack

    def stage(self):
        result = p.stage_replacement(self.plan, self.source)
        self.assertEqual(result, {'releaseId': 416392475, 'draft': True, 'assetCount': 228, 'sourceCommit': self.source})
        self.events = []
        return result

    def replace(self):
        return p.replace_release(self.plan, self.actual, self.inventory_digest, self.output)

    def add_replacements(self, count=168, canonical=False):
        expected = p.replacement_expected(self.actual, self.inventory_digest)
        for name, row in list(sorted(expected.items()))[:count]:
            self.next_id += 1
            self.assets[self.next_id] = {'id': self.next_id, 'name': name if canonical else row['stagedName'],
                                        'size': row['size'], 'digest': row['digest'], 'state': 'uploaded',
                                        'label': 'polaris-alpha12-replacement:' + self.source + ':' + self.inventory_digest}
        return expected

    def test_original_snapshot_is_hash_locked_and_all_228_ids_are_retired(self):
        baseline = json.loads(p.RECONCILIATION.read_text())
        self.assertEqual(p.REPLACEMENT_ORIGINAL['snapshotSHA256'],
                         '262d6d17c916e6f771c6bb50bdfa5eddae844bbf1318f31d0b7bea87ff600b20')
        self.assertEqual(len(self.plan['operations']), 228)
        self.assertEqual(self.plan['deferRemovalIds'], [])
        self.assertEqual({row['id'] for row in self.plan['operations']}, self.original_ids)
        for old, replacement in zip(baseline['operations'], self.plan['operations']):
            self.assertEqual(replacement, dict({key: value for key, value in old.items() if key != 'newName'}, operation='remove'))
        for field, value in [('id', 123), ('digest', 'sha256:' + '0' * 64), ('bytes', 1), ('oldName', 'other.zip')]:
            changed = copy.deepcopy(baseline)
            changed['operations'][0][field] = value
            path = Path(self.temp.name) / 'tampered-snapshot.json'
            path.write_text(json.dumps(changed))
            with self.subTest(field=field), mock.patch.object(p, 'RECONCILIATION', path), self.assertRaisesRegex(ValueError, 'snapshot changed'):
                p.replacement_baseline()

    def test_original_inventory_uses_fixed_run_publisher_hash_and_artifact(self):
        with mock.patch.object(p, 'reviewed_contract', return_value=self.original_inventory) as reviewed:
            self.assertEqual(p.replacement_original_inventory(self.plan), self.original_inventory)
        reviewed.assert_called_once_with('39124650790',
            'a493800dca182ed527ba8b1959f6e2257b19f876c4e2036600f27079bbc2c711',
            'c0023dbc6dcd7b6eb2f54dd036ae150168bd8e6e',
            publisher_commit='388db8964afc4686f07e284fea5ef27185bd6daf',
            artifact_identity=(12135921586, 'sha256:ef48b2218d85b0b000d56bf55f1be91807fb7428c8a10453aaaf9d074a67c9c1'))
        for field, value in [('bytes', 1), ('sha256', '0' * 64)]:
            changed = copy.deepcopy(self.original_inventory)
            origin = self.plan['operations'][0]['producer']
            changed['runs'][origin['role']]['artifacts'][origin['artifact']]['files'][origin['path']][field] = value
            with self.subTest(field=field), mock.patch.object(p, 'reviewed_contract', return_value=changed), self.assertRaises(ValueError):
                p.replacement_original_inventory(self.plan)

    def test_recovery_references_cover_all_227_producer_originals_including_former_keeps(self):
        artifacts = {artifact['id']: dict(artifact, name=name, digest=artifact['archiveSha256'],
                     expired=False, expires_at='2099-01-01T00:00:00Z')
                     for run in self.original_inventory['runs'].values() for name, artifact in run['artifacts'].items()}
        def lookup(path, method='GET', payload=None):
            self.assertEqual(method, 'GET')
            return copy.deepcopy(artifacts[int(path.rsplit('/', 1)[-1])])
        with mock.patch.object(p, 'api', side_effect=lookup) as api:
            references = p.recovery_references(self.original_inventory, self.plan)
        self.assertEqual(set(references), {str(row['id']) for row in self.plan['operations'] if row.get('producer')})
        self.assertEqual(len(references), 227)
        self.assertEqual(api.call_count, len({row['artifactId'] for row in references.values()}))
        formerly_kept = next(row for row in json.loads(p.RECONCILIATION.read_text())['operations'] if row['operation'] == 'keep')
        origin = formerly_kept['producer']
        ident = self.original_inventory['runs'][origin['role']]['artifacts'][origin['artifact']]['id']
        for invalid in [{'expired': True}, {'digest': 'sha256:' + '0' * 64}, {'expires_at': '2000-01-01T00:00:00Z'}]:
            saved = copy.deepcopy(artifacts[ident]); artifacts[ident].update(invalid)
            with self.subTest(invalid=invalid), mock.patch.object(p, 'api', side_effect=lookup), self.assertRaises(ValueError):
                p.recovery_references(self.original_inventory, self.plan)
            artifacts[ident] = saved

    def test_recovery_requires_actual_original_receipt_bytes_and_complete_saved_record(self):
        plan = copy.deepcopy(self.plan)
        receipt = next(row for row in plan['operations'] if not row.get('producer'))
        data = b'original public receipt fixture\n'
        receipt.update(bytes=len(data), digest='sha256:' + p.hashlib.sha256(data).hexdigest())
        references = {str(row['id']): {'digest': row['digest']} for row in plan['operations'] if row.get('producer')}
        original = {row['id']: (row['oldName'], row['bytes'], row['digest']) for row in plan['operations']}
        audit = Path(self.temp.name) / 'recovery'; audit.mkdir()
        def download(args, stdout, check):
            self.assertEqual(args, ['gh', 'api', f'repos/{p.REPO}/releases/assets/{receipt["id"]}',
                                    '-H', 'Accept: application/octet-stream'])
            self.assertTrue(check)
            stdout.write(data)
        with mock.patch.object(p, 'replacement_baseline', return_value=plan), \
             mock.patch.object(p, 'replacement_original_inventory', return_value=self.original_inventory), \
             mock.patch.object(p, 'recovery_references', return_value=references), \
             mock.patch.object(p, 'reconciliation_snapshot', return_value=(plan['release']['body'], original)), \
             mock.patch.object(p.subprocess, 'run', side_effect=download):
            self.assertEqual(p.replacement_recovery(audit), plan)
            self.assertEqual((audit / 'original-public-receipt.json').read_bytes(), data)
            saved = json.loads((audit / 'reconciliation-recovery.json').read_text())
            self.assertEqual(len(saved['assets']), 227)
            self.assertEqual(saved['publisherCommit'], self.source)
            with mock.patch.object(p, 'load_recovery'):
                self.assertEqual(p.replacement_recovery(audit, '100'), plan)
                for failure in ['missing-reference', 'publisher', 'receipt']:
                    changed = copy.deepcopy(saved)
                    (audit / 'original-public-receipt.json').write_bytes(data)
                    if failure == 'missing-reference': changed['assets'].pop(next(iter(changed['assets'])))
                    elif failure == 'publisher': changed['publisherCommit'] = '0' * 40
                    else: (audit / 'original-public-receipt.json').write_bytes(b'not the actual old receipt')
                    (audit / 'reconciliation-recovery.json').write_text(json.dumps(changed))
                    with self.subTest(failure=failure), self.assertRaises(ValueError):
                        p.replacement_recovery(audit, '100')

    def test_new_source_must_be_exact_publisher_and_protected_tag(self):
        with self.remote():
            self.assertEqual(p.replacement_target(self.source), self.tag_object)
            for source, environment in [
                ('a' * 40, {}), (p.REPLACEMENT_ORIGINAL['sourceCommit'], {}),
                (p.REPLACEMENT_ORIGINAL['sourceCommit'], {'GITHUB_SHA': p.REPLACEMENT_ORIGINAL['sourceCommit']}),
                (self.source, {'GITHUB_REF': 'refs/heads/release/1.15'}),
                (self.source, {'GITHUB_REF': 'refs/tags/v1.15.0-polaris-alpha.11'})]:
                with self.subTest(source=source, environment=environment), mock.patch.dict(os.environ, environment), self.assertRaises(ValueError):
                    p.replacement_target(source)
        self.assertEqual(self.events, [])

    def test_new_inventory_requires_review_exact_168_mapping_and_tag(self):
        with self.remote():
            expected = p.replacement_expected(self.actual, self.inventory_digest)
            self.assertEqual(set(expected), {path.name for path in self.output.iterdir()})
            for name, row in expected.items():
                self.assertEqual(row['stagedName'], 'replacement-' + self.source[:12] + '-' + self.inventory_digest[:12] + '-' + name)
            for failure in ['unreviewed', 'source', 'tag-object', 'missing', 'mapping', 'disposition', 'digest']:
                actual = copy.deepcopy(self.actual)
                digest = self.inventory_digest
                artifact = next(item for run in actual['runs'].values() for item in run['artifacts'].values()
                                if any(record['releaseName'] is not None for record in item['files'].values()))
                path = next(path for path, record in artifact['files'].items() if record['releaseName'] is not None)
                if failure == 'unreviewed': actual['reviewed'] = False
                elif failure == 'source': actual['sourceCommit'] = '0' * 40
                elif failure == 'tag-object': actual['tagObject'] = '0' * 40
                elif failure == 'missing': artifact['files'].pop(path)
                elif failure == 'mapping': artifact['files'][path]['releaseName'] = 'arbitrary.zip'
                elif failure == 'disposition': artifact['files'][path]['publicationDisposition'] = 'internal-sdk'
                else: digest = 'not-reviewed'
                with self.subTest(failure=failure), self.assertRaises(ValueError):
                    p.replacement_expected(actual, digest)
        self.assertEqual(self.events, [])

    def test_stage_only_drafts_exact_original_release_and_is_idempotent(self):
        with self.remote():
            result = p.stage_replacement(self.plan, self.source)
            self.assertTrue(result['draft'])
            self.assertEqual(self.assets, self.initial_assets)
            self.assertEqual(self.events, [('stage', 416392475, {'draft': True, 'target_commitish': self.source,
                                                               'body': p.replacement_notes(self.source)})])
            before = list(self.events)
            self.assertEqual(p.stage_replacement(self.plan, self.source), result)
            self.assertEqual(self.events, before)
        self.assertEqual(self.release['id'], 416392475)

    def test_uncertain_stage_response_is_resumed_without_asset_mutation(self):
        with self.remote():
            self.interrupt_at = 1
            with self.assertRaises(OSError): p.stage_replacement(self.plan, self.source)
            self.assertTrue(self.release['draft'])
            self.interrupt_at = None
            p.stage_replacement(self.plan, self.source)
        self.assertEqual(len(self.events), 1)
        self.assertEqual(self.assets, self.initial_assets)

    def test_replace_uploads_all_168_then_deletes_exact_228_then_renames_and_publishes(self):
        with self.remote():
            self.stage()
            result = self.replace()
            self.assertEqual((result['releaseId'], result['sourceCommit'], result['tagObject'], result['inventorySHA256'],
                              result['assetCount'], result['complete']),
                             (416392475, self.source, self.tag_object, self.inventory_digest, 168, True))
            self.assertEqual([kind for kind, _, _ in self.events],
                             ['upload'] * 168 + ['delete'] * 228 + ['rename'] * 168 + ['publish'])
            self.assertEqual({ident for kind, ident, _ in self.events if kind == 'delete'}, self.original_ids)
            self.assertFalse(self.release['draft'])
            self.assertTrue(self.release['prerelease'])
            self.assertEqual(len(self.assets), 168)
            before = list(self.events)
            self.assertEqual(self.replace(), result)
            self.assertEqual(self.events, before)

    def test_uncertain_upload_delete_rename_and_publish_responses_are_resumable(self):
        # Every uncertain response: 168 uploads, 228 deletions, 168 renames and publication.
        # Reuse the same tiny local payloads; only reset the in-memory remote.
        for position in range(1, 566):
            with self.subTest(position=position), self.remote():
                self.reset_remote(); self.stage(); self.interrupt_at = position
                with self.assertRaises(OSError): self.replace()
                if position < 565: self.assertTrue(self.release['draft'])
                self.interrupt_at = None
                result = self.replace()
                self.assertTrue(result['complete'])
                self.assertEqual([kind for kind, _, _ in self.events],
                                 ['upload'] * 168 + ['delete'] * 228 + ['rename'] * 168 + ['publish'])
                self.assertEqual(len(self.assets), 168)

    def test_failed_upload_leaves_every_original_and_resumes_remaining_uploads(self):
        with self.remote():
            self.stage(); self.fail_upload_before = 84
            with self.assertRaises(OSError): self.replace()
            self.assertTrue(self.release['draft'])
            self.assertEqual(set(self.assets) & self.original_ids, self.original_ids)
            self.assertEqual(len(self.assets), 228 + 83)
            self.assertEqual([kind for kind, _, _ in self.events], ['upload'] * 83)
            self.fail_upload_before = None
            self.assertTrue(self.replace()['complete'])
            self.assertEqual(sum(kind == 'upload' for kind, _, _ in self.events), 168)

    def test_unknown_original_or_staged_asset_changes_stop_without_more_writes(self):
        for failure in ['foreign-id', 'old-name', 'old-size', 'old-digest', 'old-state', 'new-label',
                        'new-digest', 'new-size', 'new-name', 'new-state', 'missing-original',
                        'canonical-too-early', 'duplicate-replacement']:
            with self.subTest(failure=failure), self.remote():
                self.reset_remote(); self.stage(); self.add_replacements(1)
                old = self.assets[next(iter(self.original_ids))]
                new = self.assets[self.next_id]
                if failure == 'foreign-id': self.assets[123] = dict(old, id=123, name='unknown.zip')
                elif failure.startswith('old-'):
                    field = failure.removeprefix('old-'); old[field] = old[field] + 1 if field == 'size' else 'changed'
                elif failure.startswith('new-'):
                    field = failure.removeprefix('new-'); new[field] = new[field] + 1 if field == 'size' else ('starter' if field == 'state' else 'changed')
                elif failure == 'missing-original': del self.assets[old['id']]
                elif failure == 'canonical-too-early': new['name'] = next(iter(sorted(path.name for path in self.output.iterdir())))
                else:
                    self.assets[123] = dict(new, id=123, name=next(iter(sorted(path.name for path in self.output.iterdir()))))
                with self.assertRaises(ValueError): self.replace()
                self.assertEqual(self.events, [])
                self.assertTrue(self.release['draft'])

    def test_unknown_release_metadata_and_tag_changes_stop_before_mutation(self):
        for failure in ['id', 'name', 'target_commitish', 'body', 'immutable', 'prerelease', 'draft', 'tag']:
            with self.subTest(failure=failure), self.remote():
                self.reset_remote(); self.stage()
                if failure == 'tag':
                    with mock.patch.object(p, 'tag_identity', return_value='0' * 40), self.assertRaises(ValueError): self.replace()
                else:
                    self.release[failure] = (not self.release[failure]) if isinstance(self.release[failure], bool) else 'changed'
                    with self.assertRaises(ValueError): self.replace()
                self.assertEqual(self.events, [])

    def test_output_and_unstaged_release_fail_before_upload(self):
        with self.remote():
            with self.assertRaises(ValueError): self.replace()
            self.assertEqual(self.events, [])
            self.stage()
            path = next(self.output.iterdir()); saved = path.read_bytes()
            for failure in ['bytes', 'missing', 'extra']:
                if failure == 'bytes': path.write_bytes(b'tampered')
                elif failure == 'missing': path.unlink()
                else: (self.output / 'unexpected').write_bytes(b'extra')
                with self.subTest(failure=failure), self.assertRaises(ValueError): self.replace()
                self.assertEqual(self.events, [])
                self.assertTrue(self.release['draft'])
                path.write_bytes(saved)
                (self.output / 'unexpected').unlink(missing_ok=True)

    def test_concurrent_asset_between_snapshots_stops_before_any_old_deletion(self):
        original = p.replacement_snapshot
        calls = 0
        def racing(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                old = next(iter(self.assets.values()))
                self.assets[123] = dict(old, id=123, name='concurrent.zip')
            return original(*args, **kwargs)
        with self.remote():
            self.stage()
            with mock.patch.object(p, 'replacement_snapshot', side_effect=racing), self.assertRaises(ValueError): self.replace()
        self.assertTrue(all(kind == 'upload' for kind, _, _ in self.events))
        self.assertLessEqual(len(self.events), 80)
        self.assertEqual(set(self.assets) & self.original_ids, self.original_ids)
        self.assertTrue(self.release['draft'])

    def test_partial_public_replacement_cannot_be_accepted_as_complete(self):
        with self.remote():
            self.stage(); self.add_replacements(canonical=True)
            for ident in self.original_ids: del self.assets[ident]
            self.release.update(draft=False, body=p.replacement_notes(self.source, self.inventory_digest))
            self.assets.pop(self.next_id)
            with self.assertRaises(ValueError): self.replace()
        self.assertEqual(self.events, [])

    def test_insufficient_budget_blocks_staging_and_old_deletion(self):
        with self.remote():
            self.budget = 0
            with self.assertRaisesRegex(ValueError, 'budget insufficient'):
                p.stage_replacement(self.plan, self.source)
            self.assertEqual(self.events, [])
            self.assertEqual(self.assets, self.initial_assets)
            self.assertFalse(self.release['draft'])
            self.budget = 5000
            self.stage()
            self.budget_after_uploads = 0
            with self.assertRaisesRegex(ValueError, 'budget insufficient'): self.replace()
            self.assertEqual([kind for kind, _, _ in self.events], ['upload'] * 168)
            self.assertEqual(set(self.assets) & self.original_ids, self.original_ids)
            self.assertTrue(self.release['draft'])
            self.budget_after_uploads = None
            self.assertTrue(self.replace()['complete'])

    def test_mismatched_upload_response_stops_before_original_deletion(self):
        invalid = [('id', 0), ('id', True), ('id', next(iter(self.original_ids))), ('state', 'starter'),
                   ('name', 'unrecognized.zip'), ('size', 1), ('digest', 'sha256:' + '0' * 64), ('label', 'unrecognized')]
        for field, value in invalid:
            original = self.command
            def wrong_response(*args):
                response = json.loads(original(*args))
                response[field] = value
                return json.dumps(response)
            with self.subTest(field=field, value=value), self.remote():
                self.reset_remote(); self.stage()
                with mock.patch.object(p, 'command', side_effect=wrong_response), self.assertRaisesRegex(ValueError, 'upload response mismatch'):
                    self.replace()
                self.assertEqual([kind for kind, _, _ in self.events], ['upload'])
                self.assertEqual(set(self.assets) & self.original_ids, self.original_ids)
                self.assertTrue(self.release['draft'])
                # A verified remote identity resolves an uncertain response on retry.
                self.assertTrue(self.replace()['complete'])
                self.assertEqual(sum(kind == 'upload' for kind, _, _ in self.events), 168)

    def test_mismatched_rename_response_stops_with_draft_and_resumes_by_remote_identity(self):
        invalid = [('id', 0), ('state', 'starter'), ('name', 'unrecognized.zip'),
                   ('size', 1), ('digest', 'sha256:' + '0' * 64), ('label', 'unrecognized')]
        for field, value in invalid:
            original = self.api
            def wrong_response(path, method='GET', payload=None):
                response = original(path, method, payload)
                if '/releases/assets/' in path and method == 'PATCH':
                    response[field] = value
                return response
            with self.subTest(field=field, value=value), self.remote():
                self.reset_remote(); self.stage()
                with mock.patch.object(p, 'api', side_effect=wrong_response), self.assertRaisesRegex(ValueError, 'rename response mismatch'):
                    self.replace()
                self.assertEqual([kind for kind, _, _ in self.events], ['upload'] * 168 + ['delete'] * 228 + ['rename'])
                self.assertTrue(self.release['draft'])
                self.assertTrue(self.replace()['complete'])
                self.assertEqual(sum(kind == 'rename' for kind, _, _ in self.events), 168)

    def test_final_snapshot_detects_concurrent_asset_and_retains_draft(self):
        original = p.replacement_snapshot
        def racing(*args, **kwargs):
            if self.assets and not (set(self.assets) & self.original_ids) and all(
                    asset['name'] in {path.name for path in self.output.iterdir()} for asset in self.assets.values()):
                self.assets[123] = dict(next(iter(self.assets.values())), id=123, name='late-concurrent.zip')
            return original(*args, **kwargs)
        with self.remote():
            self.stage()
            with mock.patch.object(p, 'replacement_snapshot', side_effect=racing), self.assertRaises(ValueError):
                self.replace()
        self.assertEqual([kind for kind, _, _ in self.events], ['upload'] * 168 + ['delete'] * 228 + ['rename'] * 168)
        self.assertTrue(self.release['draft'])

    def cli(self, mode, audit):
        return ['github_release.py', mode, '--source', self.source, '--all-run', '52', '--linux-run', '53',
                '--docker-run', '54', '--inventory-run', '55', '--inventory-sha256', self.inventory_digest,
                '--recovery-run', '56', '--output', str(self.output), '--audit', str(audit)]

    def test_replace_cli_collects_and_assembles_new_inventory_once_before_protected_write(self):
        audit = Path(self.temp.name) / 'cli-audit'
        actual = copy.deepcopy(self.actual); actual['reviewed'] = False
        reviewed = copy.deepcopy(self.actual)
        calls = mock.Mock()
        def assemble(*args):
            audit.mkdir()
            return {'assets': []}
        with mock.patch('sys.argv', self.cli('replace', audit)), \
             mock.patch.dict(os.environ, POLARIS_GITHUB_PUBLISH_ENABLED='true'), \
             mock.patch.object(p, 'identity'), mock.patch.object(p, 'command', return_value='b' * 40), \
             mock.patch.object(p, 'tag_identity', return_value=self.tag_object), \
             mock.patch.object(p, 'inventory', return_value=actual) as inventory, \
             mock.patch.object(p, 'reviewed_contract', return_value=reviewed) as contract, \
             mock.patch.object(p, 'assemble', side_effect=assemble) as assembled, \
             mock.patch.object(p, 'replacement_recovery', return_value=self.plan) as recovery, \
             mock.patch.object(p, 'replace_release', return_value={'complete': True}) as replaced, \
             mock.patch('builtins.print'):
            calls.attach_mock(inventory, 'inventory'); calls.attach_mock(assembled, 'assemble')
            calls.attach_mock(recovery, 'recovery'); calls.attach_mock(replaced, 'replace')
            p.main()
            inventory.assert_called_once_with({'all': '52', 'linux': '53', 'docker': '54'}, self.source,
                                              mock.ANY, 'b' * 40, self.tag_object, Path('reviewed-source'), materialize=True)
            contract.assert_called_once_with('55', self.inventory_digest, self.source)
            assembled.assert_called_once_with(actual, reviewed, mock.ANY, self.output, audit)
            recovery.assert_called_once_with(audit, '56')
            replaced.assert_called_once_with(self.plan, actual, self.inventory_digest, self.output, audit)
            self.assertEqual([call[0] for call in calls.mock_calls], ['inventory', 'assemble', 'recovery', 'replace'])
            self.assertTrue(actual['reviewed'])
        self.assertEqual(json.loads((audit / 'replacement-result.json').read_text()), {'complete': True})

    def test_read_only_replacement_check_reuses_reviewed_inventory_without_producer_download(self):
        audit = Path(self.temp.name) / 'check-audit'
        with mock.patch('sys.argv', self.cli('check-replacement', audit)), \
             mock.patch.object(p, 'identity'), mock.patch.object(p, 'tag_identity', return_value=self.tag_object), \
             mock.patch.object(p, 'load_recovery') as load, \
             mock.patch.object(p, 'reviewed_contract', return_value=self.actual) as contract, \
             mock.patch.object(p, 'replacement_original_inventory') as old_inventory, \
             mock.patch.object(p, 'inventory') as inventory, mock.patch.object(p, 'assemble') as assembled, \
             mock.patch.object(p, 'api') as api, mock.patch.object(p, 'replace_release') as replaced:
            p.main()
            load.assert_called_once_with('56', audit)
            contract.assert_called_once_with('55', self.inventory_digest, self.source)
            old_inventory.assert_not_called(); inventory.assert_not_called(); assembled.assert_not_called()
            api.assert_not_called(); replaced.assert_not_called()

    def test_stage_and_replace_cli_do_not_write_when_publication_disabled(self):
        for mode in ['stage-replacement', 'replace']:
            audit = Path(self.temp.name) / ('disabled-' + mode)
            def assemble(*args): audit.mkdir()
            with self.subTest(mode=mode), mock.patch('sys.argv', self.cli(mode, audit)), \
                 mock.patch.dict(os.environ, POLARIS_GITHUB_PUBLISH_ENABLED='false'), \
                 mock.patch.object(p, 'identity'), mock.patch.object(p, 'command', return_value='b' * 40), \
                 mock.patch.object(p, 'tag_identity', return_value=self.tag_object), \
                 mock.patch.object(p, 'inventory', return_value=copy.deepcopy(self.actual)), \
                 mock.patch.object(p, 'reviewed_contract', return_value=self.actual), \
                 mock.patch.object(p, 'assemble', side_effect=assemble), \
                 mock.patch.object(p, 'replacement_recovery', return_value=self.plan), \
                 mock.patch.object(p, 'stage_replacement') as stage, mock.patch.object(p, 'replace_release') as replace, \
                 mock.patch.object(p, 'api') as api, self.assertRaisesRegex(ValueError, 'publication disabled'):
                try:
                    p.main()
                finally:
                    stage.assert_not_called(); replace.assert_not_called(); api.assert_not_called()

    def test_workflow_keeps_replacement_writes_in_original_protected_job(self):
        import yaml
        workflow = yaml.safe_load((p.ROOT / '.github/workflows/publish-github.yml').read_text())
        self.assertEqual(set(workflow['jobs']), {'validate', 'publish'})
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        self.assertEqual(workflow['concurrency'], {'group': 'polaris-github-release-' + json.loads((p.ROOT/'release/ci/github-release.json').read_text())['tag'], 'cancel-in-progress': False})
        inputs = workflow['on']['workflow_dispatch']['inputs']
        self.assertTrue({'prepare-replacement', 'stage-replacement', 'replace'} <= set(inputs['mode']['options']))
        publish = workflow['jobs']['publish']
        self.assertEqual(publish['needs'], 'validate')
        self.assertEqual(publish['environment'], 'polaris-github-release')
        self.assertEqual(publish['permissions'], {'contents': 'write', 'actions': 'read'})
        self.assertIn("vars.POLARIS_GITHUB_PUBLISH_ENABLED == 'true'", publish['if'])
        for mode in ['stage-replacement', 'replace']: self.assertIn("inputs.mode == '" + mode + "'", publish['if'])
        validate_scripts = '\n'.join(step.get('run', '') for step in workflow['jobs']['validate']['steps'])
        self.assertIn('github_release.py check-stage-replacement ', validate_scripts)
        self.assertIn('github_release.py check-replacement ', validate_scripts)
        self.assertNotIn('github_release.py stage-replacement ', validate_scripts)
        self.assertNotIn('github_release.py replace ', validate_scripts)
        self.assertEqual(sum('github_release.py replace ' in step.get('run', '') for step in publish['steps']), 1)

    def test_real_association_summary_has_three_binding_fields_and_no_eligibility_flag(self):
        summary = self.actual['distributionMaterials']
        self.assertEqual(set(summary), {'sourceArchive', 'noticeIndex', 'bindingSHA256'})
        self.assertNotIn('publicationEligible', summary)
        self.assertEqual(summary['noticeIndex'], {'name': self.index_path.name, 'sha256': p.sha(self.index_path)})
        for run in self.actual['runs'].values():
            for artifact in run['artifacts'].values():
                for record in artifact['files'].values():
                    if record['releaseName'] is not None:
                        self.assertEqual(record['distributionMaterials'], summary)
        with self.remote():
            self.assertEqual(len(p.replacement_expected(self.actual, self.inventory_digest)), 168)
            self.stage()
            self.assertTrue(self.replace()['complete'])

    def test_replacement_reads_eligibility_from_bound_native_index_before_any_write(self):
        original_summary = copy.deepcopy(self.actual['distributionMaterials'])
        cases = ['false-eligibility', 'missing-eligibility', 'missing-materials', 'source', 'tree', 'tag',
                 'tag-object', 'missing-source', 'missing-tag-object', 'index-hash', 'index-name']
        for failure in cases:
            with self.subTest(failure=failure), self.remote():
                self.reset_remote(); self.stage()
                index = copy.deepcopy(self.native_index)
                self.actual['distributionMaterials'] = copy.deepcopy(original_summary)
                if failure == 'false-eligibility': index['distributionMaterials']['publicationEligible'] = False
                elif failure == 'missing-eligibility': index['distributionMaterials'].pop('publicationEligible')
                elif failure == 'missing-materials': index.pop('distributionMaterials')
                elif failure in ['source', 'tree', 'tag', 'tag-object']:
                    index[{'source': 'sourceCommit', 'tree': 'sourceTree', 'tag': 'tag', 'tag-object': 'tagObject'}[failure]] = 'changed'
                elif failure.startswith('missing-'):
                    index.pop({'missing-source': 'sourceCommit', 'missing-tag-object': 'tagObject'}[failure])
                self.index_path.write_text(json.dumps(index))
                self.actual['distributionMaterials']['noticeIndex']['sha256'] = p.sha(self.index_path)
                if failure == 'index-hash': self.actual['distributionMaterials']['noticeIndex']['sha256'] = '0' * 64
                elif failure == 'index-name': self.actual['distributionMaterials']['noticeIndex']['name'] = 'other.json'
                # Adding an invented summary flag cannot override the bound index.
                self.actual['distributionMaterials']['publicationEligible'] = True
                with self.assertRaises(ValueError): self.replace()
                self.assertEqual(self.events, [])
                self.assertEqual(set(self.assets) & self.original_ids, self.original_ids)
                self.assertTrue(self.release['draft'])

    def test_replacement_uses_explicit_audit_directory_for_bound_native_index(self):
        custom_audit = Path(self.temp.name) / 'custom-audit'; custom_audit.mkdir()
        self.index_path.replace(custom_audit / self.index_path.name)
        with self.remote():
            self.stage()
            result = p.replace_release(self.plan, self.actual, self.inventory_digest, self.output, custom_audit)
        self.assertTrue(result['complete'])

    def test_historical_three_field_proposal_shape_does_not_approve_original_source(self):
        # Extracted from inventory run 39124650790, proposal SHA-256
        # a493800dca182ed527ba8b1959f6e2257b19f876c4e2036600f27079bbc2c711.
        # It remains bound to the old source, never rewritten to claim a fresh producer PASS.
        historical = copy.deepcopy(self.actual)
        historical.update(sourceCommit=p.REPLACEMENT_ORIGINAL['sourceCommit'],
                          tagObject=p.REPLACEMENT_ORIGINAL['tagObject'])
        historical['distributionMaterials'] = {
            'sourceArchive': {'name': 'sing-box-polaris-source-c0023dbc6dcd7b6eb2f54dd036ae150168bd8e6e.tar.gz',
                              'bytes': 7996159, 'sha256': 'f0862fada6162401e059944a0e98129921ee28f16910f35205f774ada9e59f84'},
            'noticeIndex': {'name': 'polaris-upstream-native-assets.json',
                            'sha256': '3b8d8db9ee9261ec7bf724ea7877544a0252a848da663b4706d457cf93c8b391'},
            'bindingSHA256': 'b61af8071fee1b7cef57a4d73574aeb5abdf875a170f915ed968bc3530e4428c'}
        self.assertEqual(set(historical['distributionMaterials']), set(self.actual['distributionMaterials']))
        self.assertNotIn('publicationEligible', historical['distributionMaterials'])
        with self.remote(), self.assertRaisesRegex(ValueError, 'source/tag mismatch'):
            p.replacement_expected(historical, self.inventory_digest)
        self.assertEqual(self.events, [])

    def test_final_body_target_and_audit_receipt_bind_only_new_source_and_exclude_public_receipt(self):
        with self.remote():
            self.stage()
            result = self.replace()
        body = self.release['body']
        self.assertEqual(self.release['target_commitish'], self.source)
        for expected in [self.source, self.inventory_digest, 'Changes in this alpha.12 rebuild',
                         '168 uploaded products', 'DEB/RPM', 'Android version-metadata', 'unsigned',
                         'do not claim new device/runtime acceptance or signing']:
            self.assertIn(expected, body)
        self.assertNotIn(p.REPLACEMENT_ORIGINAL['sourceCommit'], body)
        self.assertNotIn(p.REPLACEMENT_ORIGINAL['sourceCommit'], json.dumps(result))
        self.assertEqual(result['assetCount'], 168)
        self.assertNotIn(p.RECEIPT, {asset['name'] for asset in self.assets.values()})
        work = Path(self.temp.name) / 'receipt-work'
        for role, run in self.actual['runs'].items():
            for artifact, item in run['artifacts'].items():
                for path, record in item['files'].items():
                    if artifact == 'binary-native-index':
                        data = self.index_path.read_bytes() if path == self.index_path.name else b'fixture source archive'
                    else:
                        data = f'fresh rebuild from {self.source}: {role}/{artifact}/{path}\n'.encode()
                    self.assertEqual((len(data), p.hashlib.sha256(data).hexdigest()), (record['bytes'], record['sha256']))
                    local = work / role / artifact / path
                    local.parent.mkdir(parents=True, exist_ok=True); local.write_bytes(data)
        output = Path(self.temp.name) / 'receipt-dist'
        audit = Path(self.temp.name) / 'receipt-audit'
        receipt = p.assemble(self.actual, copy.deepcopy(self.actual), work, output, audit)
        self.assertEqual((receipt['sourceCommit'], receipt['tagObject']), (self.source, self.tag_object))
        self.assertEqual(len(receipt['assets']), 168)
        self.assertFalse(receipt['fullSignedRelease'])
        self.assertNotIn(p.REPLACEMENT_ORIGINAL['sourceCommit'], json.dumps(receipt))
        self.assertEqual(json.loads((audit / p.RECEIPT).read_text()), receipt)
        self.assertEqual(len(list(output.iterdir())), 168)
        self.assertFalse((output / p.RECEIPT).exists())


from test_github_read_transport import ReadTransportTests

# Execute the exact nonpublic peer regressions in this existing CI command.
from publisher_peer_evidence_tests import PeerEvidenceTests
from publisher_peer_evidence_12_5_tests import CurrentPeerEvidenceTests

# Keep historical classes and their method IDs; do not shadow 12.5 imports.
from publisher_peer_evidence_12_6_tests import Alpha126PeerEvidenceTests
from publisher_peer_evidence_12_7_tests import Alpha127PeerEvidenceTests
from publisher_peer_evidence_12_9_tests import Alpha129PeerEvidenceTests
from publisher_peer_successor_tests import SuccessorPeerPreparationTests

if __name__=='__main__':
    unittest.main()


class TrustedExecutionPublisherTests(unittest.TestCase):
    def index(self):
        import test_native_release_index as fixtures
        index=GateTests().final_index();row=fixtures.sealed_row_fixture(version=p.VERSION)
        index['platforms']=[row if old['id']==row['id'] else old for old in index['platforms']]
        from native_release_index import distribution_materials
        index['distributionMaterials']=distribution_materials(index,p.ROOT)
        return index

    def check(self,index):
        with mock.patch.object(p,'pages',return_value=native_jobs_fixture(index)):
            p.validate_final_index(index,'a'*40,'b'*40,'c'*40,'42',1,'.github/workflows/build.yml')

    def test_final_index_accepts_bound_synthetic_sealed_proof_and_keeps_original_row(self):
        index=self.index();before=copy.deepcopy(index)
        self.check(index);self.assertEqual(index,before)

    def test_final_index_rejects_policy_injection_missing_proof_and_mixed_bindings(self):
        mutations=[lambda r:r.pop('trustedExecution'),lambda r:r['finalPackageCronetSmoke'].pop('sealedExecution'),
                   lambda r:r['trustedExecution'].update(extra=True),lambda r:r['trustedExecution'].update(sourceTree='f'*40),
                   lambda r:r['trustedExecution'].update(loader='path-loader'),lambda r:r['trustedExecution']['purposes'].append('invented'),
                   lambda r:r['trustedExecution']['purposes'].append(r['trustedExecution']['purposes'][0]),
                   lambda r:r['finalPackageCronetSmoke']['sealedExecution'].update(runId=43),
                   lambda r:r['finalPackageCronetSmoke']['sealedExecution'].update(runAttempt=2),
                   lambda r:r['archive'].update(sha256='f'*64),lambda r:r['core'].update(sha256='f'*64),
                   lambda r:r['sidecar'].update(sha256='f'*64)]
        index=self.index()
        for mutate in mutations:
            candidate=copy.deepcopy(index);row=next(r for r in candidate['platforms'] if 'trustedExecution' in r);mutate(row)
            with self.subTest(mutate=mutate),self.assertRaises((ValueError,jsonschema.ValidationError)):self.check(candidate)

    def test_materials_cannot_omit_or_relabel_execution_observation_binding(self):
        index=self.index()
        selected=next(r for r in index['distributionMaterials']['nativeArchives'] if 'sealedExecutionSHA256' in r)
        for field in ('sealedExecutionSHA256','trustedExecutionSHA256'):
            candidate=copy.deepcopy(index)
            row=next(r for r in candidate['distributionMaterials']['nativeArchives'] if r['archive']==selected['archive'])
            row.pop(field)
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'source/notice bindings'):self.check(candidate)

    def test_existing_assembly_entry_rejects_injected_or_mixed_run_proof_before_any_archive_work(self):
        import native_release_index as native
        import test_native_release_index as fixtures
        for field,value in [('runId',43),('runAttempt',2),('sourceTree','f'*40)]:
            row=fixtures.sealed_row_fixture();row['finalPackageCronetSmoke']['sealedExecution'][field]=value
            with self.subTest(field=field),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);(root/'native-row-synthetic.json').write_text(json.dumps(row))
                with mock.patch.object(native,'identity',return_value=('a'*40,'b'*40)), \
                     mock.patch.dict(os.environ,{'VERSION':p.VERSION,'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':'1','REQUIRE_RELEASE_TAG':'false'}), \
                     mock.patch.object(native.subprocess,'check_output',side_effect=AssertionError('archive work escaped')):
                    with self.assertRaises(ValueError):native.assemble(root)
                self.assertFalse((root/'polaris-upstream-native-assets.json').exists())

    def test_existing_assembly_entry_preserves_one_proven_policy_across_all_44_receipts(self):
        import native_release_index as native
        index=self.index();rows=index['platforms'];source='a'*40;tree='b'*40
        payload=b'synthetic-final-archive';archive_sha=hashlib.sha256(payload).hexdigest()
        for row in rows:
            row['archive']['sha256']=archive_sha
            if 'trustedExecution' in row:row['finalPackageCronetSmoke']['sealedExecution']['archiveSha256']=archive_sha
        selected=next(r for r in rows if 'trustedExecution' in r)
        jobs=[{'id':i+1,'name':'Native final-package Cronet and gVisor smoke ('+ident+')','conclusion':'success','status':'completed',
               'head_sha':source,'run_id':42,'run_attempt':1}
              for i,ident in enumerate(['linux-amd64-purego','windows-amd64','darwin-amd64','darwin-arm64'])]
        # Source tar/member identity is independently covered by the original 44-row tests.
        # Keep this fixture small and exercise the actual duplicate/assembly/policy bridge.
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for i,row in enumerate(rows):
                (root/('native-row-'+str(i)+'.json')).write_text(json.dumps(row))
                (root/row['archive']['name']).write_bytes(payload)
            # A pre-smoke collector row can coexist, but cannot replace the proven smoke row.
            plain=copy.deepcopy(selected);plain.pop('trustedExecution');plain['finalPackageCronetSmoke']=None
            (root/'native-row-z-collector.json').write_text(json.dumps(plain))
            env={'VERSION':p.VERSION,'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':'1','GITHUB_WORKFLOW_SHA':source,
                 'GITHUB_WORKFLOW_REF':native.REPO+'/.github/workflows/build.yml@refs/heads/synthetic','REQUIRE_RELEASE_TAG':'false'}
            with mock.patch.object(native,'identity',return_value=(source,tree)),mock.patch.dict(os.environ,env), \
                 mock.patch.object(native.subprocess,'check_output',return_value=b'synthetic-source-tar'), \
                 mock.patch.object(native,'validate_archived_source_identity') as archived, \
                 mock.patch.object(native,'run',return_value=json.dumps([{'jobs':jobs}])), \
                 mock.patch.object(native,'distribution_materials',return_value={'synthetic':True}):
                native.assemble(root)
            output=json.loads((root/'polaris-upstream-native-assets.json').read_text())
            self.assertEqual(len(output['platforms']),44);self.assertEqual(sum('trustedExecution' in r for r in output['platforms']),1)
            actual=next(r for r in output['platforms'] if 'trustedExecution' in r)
            self.assertEqual(actual,selected);archived.assert_called_once()


class WindowsProducerPublisherControls(unittest.TestCase):
    def index(self):
        from test_windows_native_execution import windows_row_fixture
        from native_release_index import distribution_materials, select_native_jobs
        index=GateTests().final_index();row=windows_row_fixture()
        row['archive']['releaseName']=p.public_product_name(row['archive']['name'])
        index['platforms']=[row if old['id']==row['id'] else old for old in index['platforms']]
        index['producer']['nativeJobs']=select_native_jobs(index['platforms'],native_jobs_fixture(index),'a'*40,42,1)
        index['distributionMaterials']=distribution_materials(index,p.ROOT)
        return index

    def check(self,index,jobs):
        with mock.patch.object(p,'pages',return_value=jobs) as metadata:
            p.validate_final_index(index,'a'*40,'b'*40,'c'*40,'42',1,'.github/workflows/build.yml')
            metadata.assert_called_once_with(f'repos/{p.REPO}/actions/runs/42/attempts/1/jobs','jobs',maximum=1000)

    def test_final_consumer_binds_actual_system_job_id_name_and_exact_attempt_api(self):
        index=self.index();self.check(index,native_jobs_fixture(index))

    def test_successful_hosted_job_cannot_replace_real_system_producer(self):
        index=self.index();jobs=native_jobs_fixture(index)
        index['producer']['nativeJobs']['win']['name']='Native final-package Cronet and gVisor smoke (windows-amd64)'
        jobs.append(dict(jobs[1],id=9,name=index['producer']['nativeJobs']['win']['name']))
        with self.assertRaisesRegex(ValueError,'job mapping'):self.check(index,jobs)

    def test_final_consumer_rejects_missing_wrong_skipped_duplicate_or_foreign_api_producer(self):
        for case in ('missing','name','id','skipped','status','source','run','attempt','duplicate'):
            with self.subTest(case=case):
                index=self.index();jobs=native_jobs_fixture(index);job=jobs[1]
                if case=='missing':jobs.pop(1)
                elif case=='name':job['name']='unrelated successful job'
                elif case=='id':job['id']=99
                elif case=='skipped':job['conclusion']='skipped'
                elif case=='status':job['status']='in_progress'
                elif case=='source':job['head_sha']='f'*40
                elif case=='run':job['run_id']=43
                elif case=='attempt':job['run_attempt']=2
                else:jobs.append(copy.deepcopy(job))
                with self.assertRaises(ValueError):self.check(index,jobs)

    def test_final_consumer_checks_overlay_using_original_source_root(self):
        index=self.index();jobs=native_jobs_fixture(index);root=Path('cold-source-exact-root')
        with mock.patch.object(p,'pages',return_value=jobs), \
             mock.patch('native_release_index.validate_overlay',side_effect=ValueError('bad original overlay')) as overlay:
            with self.assertRaisesRegex(ValueError,'bad original overlay'):
                p.validate_final_index(index,'a'*40,'b'*40,'c'*40,'42',1,'.github/workflows/build.yml',root)
            overlay.assert_called_once_with(root)

    def test_job_api_pagination_enforces_bounded_total_scope(self):
        with mock.patch.object(p,'api',return_value={'jobs':[{}]*100}) as api:
            with self.assertRaisesRegex(ValueError,'item bound'):
                p.pages('repos/test/actions/runs/42/attempts/1/jobs','jobs',maximum=1000)
            self.assertEqual(api.call_count,11)

    def test_existing_assembly_selects_retained_system_producer_from_exact_api_jobs(self):
        import native_release_index as native
        index=self.index();rows=index['platforms'];payload=b'synthetic-final-archive'
        for row in rows:
            row['archive']['sha256']=hashlib.sha256(payload).hexdigest()
            if 'trustedExecution' in row:
                row['finalPackageCronetSmoke']['windowsExecution']['archiveSha256']=row['archive']['sha256']
        jobs=native_jobs_fixture(index)
        jobs.append(dict(jobs[1],id=99,name='Native final-package Cronet and gVisor smoke (windows-amd64)'))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for i,row in enumerate(rows):
                (root/('native-row-'+str(i)+'.json')).write_text(json.dumps(row))
                (root/row['archive']['name']).write_bytes(payload)
            env={'VERSION':p.VERSION,'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':'1','GITHUB_WORKFLOW_SHA':'a'*40,
                 'GITHUB_WORKFLOW_REF':native.REPO+'/.github/workflows/build.yml@refs/heads/synthetic','REQUIRE_RELEASE_TAG':'false'}
            with mock.patch.object(native,'identity',return_value=('a'*40,'b'*40)),mock.patch.dict(os.environ,env), \
                 mock.patch.object(native.subprocess,'check_output',return_value=b'synthetic-source-tar'), \
                 mock.patch.object(native,'validate_archived_source_identity'), \
                 mock.patch.object(native,'run',return_value=json.dumps([{'jobs':jobs}])), \
                 mock.patch.object(native,'distribution_materials',return_value={'synthetic':True}):
                native.assemble(root)
            output=json.loads((root/'polaris-upstream-native-assets.json').read_text())
            self.assertEqual(output['producer']['nativeJobs']['win'],{'id':2,'name':native.WINDOWS_PROOF_JOB})


class DebianMaterialPublisherTests(unittest.TestCase):
    """Real new validators/ZIP streams over synthetic contract data, not crypto acceptance."""
    def bundle(self, role='linux'):
        from test_cronet_material_supply import fixture_bundle
        workflow={'all':'build','linux':'linux','docker':'docker'}[role]
        context={'repository':p.REPO,'repositoryID':p.RID,'sourceCommit':'a'*40,'sourceTree':'b'*40,
                 'tag':p.TAG,'tagObject':'c'*40,'workflow':f'.github/workflows/{workflow}.yml',
                 'runID':42,'runAttempt':1,'role':role}
        return fixture_bundle(role, context=context)

    def run_record(self, bundle):
        c=bundle['context']
        return {'id':c['runID'],'repository':{'id':p.RID},'head_repository':{'id':p.RID},
                'head_sha':c['sourceCommit'],'head_branch':c['tag'],'path':c['workflow'],
                'event':'workflow_dispatch','status':'in_progress','conclusion':None,
                'run_attempt':c['runAttempt'],'run_started_at':bundle['supplier_job']['started_at']}

    def artifacts(self, bundle):
        return [dict(id=bundle[key]['id'],name=bundle[key]['name'],digest=bundle[key]['digest'],
                     size_in_bytes=bundle[key]['size_in_bytes'],expired=False,
                     workflow_run={'id':bundle['context']['runID'],'head_sha':bundle['context']['sourceCommit']},
                     created_at=bundle['supplier_job']['completed_at'])
                for key in ('raw_artifact','ready_artifact')]

    @contextmanager
    def transport(self, downloads):
        children=[]
        class Child:
            def __init__(self,data):
                self.stdout=tempfile.TemporaryFile();self.stdout.write(b'HTTP/2 200 OK\r\n\r\n'+data);self.stdout.seek(0)
                self.stderr=tempfile.TemporaryFile();self.done=False
            def wait(self,timeout=None):self.done=True;return 0
            def poll(self):return 0 if self.done else None
            def terminate(self):self.done=True
            def kill(self):self.done=True
        def spawn(command,**kwargs):
            ident=int(command[-1].split('/')[-2])
            child=Child(downloads[ident]);children.append(child);return child
        try:
            with mock.patch.object(p.subprocess,'Popen',side_effect=spawn) as remote:
                yield remote
        finally:
            for child in children:
                child.stdout.close();child.stderr.close()

    def read(self, bundle, *, context=None, artifacts=None, supplier_job=None, run=None, with_ready=False):
        downloads={bundle['raw_artifact']['id']:bundle['raw_zip'],
                   bundle['ready_artifact']['id']:bundle['ready_zip']}
        with tempfile.TemporaryDirectory() as directory,self.transport(downloads):
            root=Path(directory);budget=p.ScratchBudget(root,reserve=0)
            try:
                api_artifacts=self.artifacts(bundle) if artifacts is None else artifacts
                binding,entries,manifest,ready_metadata=p.read_debian_artifacts(api_artifacts,
                    bundle['context'] if context is None else context,
                    self.run_record(bundle) if run is None else run,
                    bundle['supplier_job'] if supplier_job is None else supplier_job,budget)
                self.assertEqual(manifest,bundle['manifest'])
                self.assertIs(ready_metadata,next(item for item in api_artifacts if item['name']==p.DEBIAN_READY))
                return (binding,entries,ready_metadata) if with_ready else (binding,entries)
            finally:
                self.assertEqual(list(root.iterdir()),[])
                self.assertEqual(budget.live,0)
                self.assertLessEqual(budget.peak,max(len(bundle['raw_zip']),len(bundle['ready_zip'])))
                self.assertEqual(p.SCRATCH_LIMIT,4294967296)

    def rewrite(self, bundle, *, manifest=None, ready=None, extra=None):
        """Rehash fixture containers; the production validator remains the only predicate."""
        from cronet_material_supply import artifact_ref, encode_json
        bundle=copy.deepcopy(bundle)
        if manifest is not None:manifest(bundle['manifest'])
        with zipfile.ZipFile(io.BytesIO(bundle['raw_zip'])) as archive:
            rows=[(member.filename,archive.read(member)) for member in archive.infolist()
                  if not member.is_dir() and member.filename!=p.DEBIAN_MANIFEST]
        raw=encode_json(bundle['manifest'])
        rows.append((p.DEBIAN_MANIFEST,raw))
        if extra is not None:rows.extend(extra)
        bundle['raw_zip']=BoundedStorageTests.zipped(rows)
        bundle['raw_artifact'].update(size_in_bytes=len(bundle['raw_zip']),digest='sha256:'+hashlib.sha256(bundle['raw_zip']).hexdigest())
        bundle['ready']['manifestSHA256']=hashlib.sha256(raw).hexdigest()
        bundle['ready']['rawArtifact']=artifact_ref(bundle['raw_artifact'])
        if ready is not None:ready(bundle['ready'])
        bundle['ready_zip']=BoundedStorageTests.zipped([('debian-material-ready.json',encode_json(bundle['ready']))])
        bundle['ready_artifact'].update(size_in_bytes=len(bundle['ready_zip']),digest='sha256:'+hashlib.sha256(bundle['ready_zip']).hexdigest())
        return bundle

    def eligible(self, role):
        from cronet_material_supply import expected_use
        return [name for name in p.release_scope(p.VERSION)[role]['requiredArtifacts'] if expected_use(role,name) is not None]

    def test_all_three_roles_measure_actual_private_pair_without_retaining_raw_objects(self):
        for role,count in [('all',18),('linux',7),('docker',7)]:
            with self.subTest(role=role):
                b=self.bundle(role);binding,entries=self.read(b)
                self.assertEqual(binding,b['binding'])
                self.assertEqual(len(self.eligible(role)),count)
                self.assertEqual(set(entries),{p.DEBIAN_RAW,p.DEBIAN_READY})
                self.assertEqual(entries[p.DEBIAN_RAW]['files'][p.DEBIAN_MANIFEST]['sha256'],binding['manifestSHA256'])
                for artifact,item in entries.items():
                    for name,record in item['files'].items():
                        self.assertEqual(p.publication(role,artifact,name),(None,record['publicationDisposition']))
                        self.assertIsNone(record['releaseName'])

    def test_noop_rewrite_reaches_real_receiver_with_fresh_outer_zip_refs(self):
        from cronet_material_supply import artifact_ref, encode_json
        for role,count in [('all',8),('linux',1),('docker',1)]:
            with self.subTest(role=role):
                original=self.bundle(role);before=copy.deepcopy(original)
                # Freeze each authority independently before touching the candidate graph.
                authority={'context':copy.deepcopy(original['context']),
                           'artifacts':copy.deepcopy(self.artifacts(original)),
                           'run':copy.deepcopy(self.run_record(original)),
                           'supplier':copy.deepcopy(original['supplier_job'])}
                authority_before=copy.deepcopy(authority)
                rewritten=self.rewrite(original)
                self.assertEqual(rewritten['manifest'],original['manifest'])
                artifacts=copy.deepcopy(authority['artifacts'])
                for api,key in zip(artifacts,('raw_artifact','ready_artifact')):
                    api.update(size_in_bytes=rewritten[key]['size_in_bytes'],digest=rewritten[key]['digest'])
                # Only ZIP measurements change; source/run/supplier authority stays external.
                binding,entries=self.read(rewritten,context=authority['context'],artifacts=artifacts,
                                          run=authority['run'],supplier_job=authority['supplier'])
                self.assertEqual(original,before)
                self.assertEqual(authority,authority_before)
                self.assertEqual(binding['context'],authority['context'])
                self.assertEqual(len(binding['requiredProfiles']),count)
                manifest=encode_json(rewritten['manifest'])
                manifest_sha=hashlib.sha256(manifest).hexdigest()
                self.assertEqual(binding['manifestSHA256'],manifest_sha)
                raw_files=entries[p.DEBIAN_RAW]['files']
                self.assertEqual(raw_files[p.DEBIAN_MANIFEST]['bytes'],len(manifest))
                self.assertEqual(raw_files[p.DEBIAN_MANIFEST]['sha256'],manifest_sha)
                for api in artifacts:
                    self.assertNotIn('size',api)
                for key,zip_key,ref_key in [('raw_artifact','raw_zip','rawArtifact'),
                                           ('ready_artifact','ready_zip','readyArtifact')]:
                    api=rewritten[key];outer=rewritten[zip_key]
                    digest='sha256:'+hashlib.sha256(outer).hexdigest()
                    self.assertNotIn('size',api)
                    self.assertEqual(api['size_in_bytes'],len(outer))
                    self.assertEqual(api['digest'],digest)
                    reference=artifact_ref(api)
                    self.assertEqual(set(reference),{'id','name','digest','size'})
                    self.assertEqual(binding[ref_key],reference)
                    measured=entries[api['name']]
                    self.assertEqual(measured['archiveBytes'],len(outer))
                    self.assertEqual(measured['archiveSha256'],digest)
                self.assertEqual(set(rewritten['ready']['rawArtifact']),{'id','name','digest','size'})
                self.assertEqual(rewritten['ready']['rawArtifact'],artifact_ref(rewritten['raw_artifact']))

    def test_current_source_tag_run_attempt_plan_and_profile_not_asserted_from_self_hash(self):
        import cronet_material_supply as supply
        changes=[
            ('sourceCommit',lambda m:m['context'].update(sourceCommit='f'*40)),
            ('tag',lambda m:m['context'].update(tag=p.TAG+'0')),
            ('tagObject',lambda m:m['context'].update(tagObject='f'*40)),
            ('sourceTree',lambda m:m['context'].update(sourceTree='f'*40)),
            ('runID',lambda m:m['context'].update(runID=43)),
            ('runAttempt',lambda m:m['context'].update(runAttempt=2)),
            ('planSHA256',lambda m:m.update(planSHA256='f'*64)),
            ('requiredProfilesEmpty',lambda m:m.update(requiredProfiles=[])),
            ('requiredProfilesWrong',lambda m:m.update(requiredProfiles=['bullseye-arm64'])),
            ('unlisted',lambda m:m.update(unlisted='forbidden'))]
        for role,count in [('all',8),('linux',1),('docker',1)]:
            for number,(axis,change) in enumerate(changes):
                with self.subTest(role=role,number=number,axis=axis):
                    original=self.bundle(role);before=copy.deepcopy(original)
                    # A whole-bundle deepcopy preserves aliases; it is not an expectation.
                    authority={'context':copy.deepcopy(original['context']),
                               'artifacts':copy.deepcopy(self.artifacts(original)),
                               'run':copy.deepcopy(self.run_record(original)),
                               'supplier':copy.deepcopy(original['supplier_job'])}
                    authority_before=copy.deepcopy(authority)
                    self.assertEqual(len(original['manifest']['requiredProfiles']),count)
                    rewritten=self.rewrite(original,manifest=change)
                    for candidate_context in (rewritten['context'],rewritten['manifest']['context'],
                                              rewritten['ready']['context'],rewritten['binding']['context']):
                        self.assertIsNot(authority['context'],candidate_context)
                    self.assertIsNot(authority['supplier'],rewritten['supplier_job'])
                    artifacts=copy.deepcopy(authority['artifacts'])
                    for pinned,api,key,zip_key in zip(authority['artifacts'],artifacts,
                            ('raw_artifact','ready_artifact'),('raw_zip','ready_zip')):
                        # Keep API identity/timing fixed and remeasure only the changed container.
                        api.update(size_in_bytes=rewritten[key]['size_in_bytes'],digest=rewritten[key]['digest'])
                        self.assertEqual(api['size_in_bytes'],len(rewritten[zip_key]))
                        self.assertEqual(api['digest'],'sha256:'+hashlib.sha256(rewritten[zip_key]).hexdigest())
                        self.assertEqual({k:v for k,v in api.items() if k not in ('size_in_bytes','digest')},
                                         {k:v for k,v in pinned.items() if k not in ('size_in_bytes','digest')})
                        self.assertIsNot(api['workflow_run'],rewritten[key]['workflow_run'])
                    self.assertEqual(original,before)
                    self.assertEqual(authority,authority_before)
                    guard='candidate manifest fields' if axis=='unlisted' else 'candidate source/plan/state'
                    # Wrap the actual imported validator; no accepting predicate replaces it.
                    with mock.patch.object(supply,'validate_manifest',wraps=supply.validate_manifest) as manifest_guard:
                        with self.assertRaisesRegex(ValueError,'^Debian material admission: '+guard+'$'):
                            self.read(rewritten,context=authority['context'],artifacts=artifacts,
                                      run=authority['run'],supplier_job=authority['supplier'])
                    manifest_guard.assert_called_once()
                    decoded=manifest_guard.call_args.args[0]
                    self.assertEqual(decoded,rewritten['manifest'])
                    self.assertIs(manifest_guard.call_args.kwargs['context'],authority['context'])
                    if number<6:
                        self.assertNotEqual(decoded['context'][axis],authority['context'][axis])
                        self.assertEqual({k:v for k,v in decoded['context'].items() if k!=axis},
                                         {k:v for k,v in authority['context'].items() if k!=axis})
                    self.assertEqual(original,before)
                    self.assertEqual(authority,authority_before)

    def test_exact_cas_rejects_extra_missing_wrong_hash_oversize_and_object_count(self):
        base=self.bundle()
        cases=[
            self.rewrite(base,extra=[('unlisted.txt',b'private')]),
            self.rewrite(base,extra=[('objects/'+'f'*64,b'unlisted')]),
            self.rewrite(base,manifest=lambda m:m.update(objects=[])),
            self.rewrite(base,manifest=lambda m:m['objects'][0].update(sha256='f'*64)),
            self.rewrite(base,manifest=lambda m:m['objects'][0].update(bytes=67108865)),
            self.rewrite(base,manifest=lambda m:m.update(objects=[copy.deepcopy(m['objects'][0]) for _ in range(513)]))]
        for number,bundle in enumerate(cases):
            with self.subTest(number=number),self.assertRaises(ValueError):self.read(bundle)

    def test_api_expiry_size_digest_prior_attempt_and_supplier_identity_are_independent(self):
        b=self.bundle()
        for change in [
            lambda rows:rows[0].update(expired=True),
            lambda rows:rows[0].update(id=True),
            lambda rows:rows[0].update(size_in_bytes=1075838977),
            lambda rows:rows[0].update(digest='sha256:'+'f'*64),
            lambda rows:rows[1].update(digest='sha256:'+'f'*64),
            lambda rows:rows[0]['workflow_run'].update(head_sha='f'*40),
            lambda rows:rows[0]['workflow_run'].update(id=43),
            lambda rows:rows[0].update(created_at='2000-01-01T00:00:00Z'),
            lambda rows:rows[1].update(created_at=b['supplier_job']['started_at'])]:
            rows=self.artifacts(b);change(rows)
            with self.subTest(change=change),self.assertRaises(ValueError):self.read(b,artifacts=rows)
        for change in [
            lambda job:job.update(status='in_progress',conclusion=None),
            lambda job:job.update(conclusion='failure'),
            lambda job:job.update(run_attempt=2),
            lambda job:job.update(head_sha='f'*40),
            lambda job:job.update(id=True)]:
            job=copy.deepcopy(b['supplier_job']);change(job)
            with self.subTest(change=change),self.assertRaises(ValueError):self.read(b,supplier_job=job)

    def use_files(self, bundle, artifact, *, local=False):
        from test_cronet_material_supply import fixture_use, fixture_local_use
        from cronet_material_supply import encode_json
        use=(fixture_local_use if local else fixture_use)(bundle,artifact);raw=encode_json(use)
        fact={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
              'releaseName':None,'publicationDisposition':'private-debian-use','debianRawUse':use}
        return {p.DEBIAN_USE:fact}

    def test_all_candidate_pointer_is_written_by_existing_real_recorder(self):
        from cronet_material_supply import encode_json, expected_use, load_profile_plan
        b=self.bundle('all');binding,_=self.read(b)
        jobs=[b['supplier_job'],*b['consumer_jobs']]
        # C1 is the positive for this build environment. C2 is the original cross-job negative.
        cases=[('binary-linux_amd64-glibc','C1_ALL_BINARY','amd64',['bullseye-amd64'],'build'),
               ('binary-linux-client-arm64','C2_ALL_LINUX_CLIENT','arm64',
                ['bullseye-amd64','bullseye-arm64'],'build_linux_client')]
        for artifact,caller,arch,profiles,sidecar_key,local in [(*case,local) for case in cases for local in (False,True)]:
            with self.subTest(artifact=artifact,caller=caller):
                self.assertIn(artifact,self.eligible('all'))
                self.assertEqual(expected_use('all',artifact),
                                 {'caller':caller,'targetArch':arch,'libc':'glibc','profiles':profiles})
                source_caller=next(item for item in load_profile_plan()['callers'] if item['id']==caller)
                self.assertEqual(source_caller['job'],sidecar_key)
                self.assertEqual(source_caller['workflow'],b['context']['workflow'])
                files=self.use_files(b,artifact,local=local);use=files[p.DEBIAN_USE]['debianRawUse']
                self.assertEqual((use['caller'],use['targetArch'],use['libc'],
                                  [profile['id'] for profile in (use['manifest']['profiles'] if local else use['profiles'])],use['consumerJob']['key']),
                                 (caller,arch,'glibc',profiles,sidecar_key))
                raw=encode_json(use)
                self.assertEqual(files[p.DEBIAN_USE]['bytes'],len(raw))
                self.assertEqual(files[p.DEBIAN_USE]['sha256'],hashlib.sha256(raw).hexdigest())
                env={'GITHUB_REPOSITORY':p.REPO,'GITHUB_REPOSITORY_ID':str(p.RID),'GITHUB_JOB':'build',
                     'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':'1','CANDIDATE_MATRIX_KEY':'build-0'}
                if caller=='C1_ALL_BINARY':
                    self.assertEqual(env['GITHUB_JOB'],source_caller['job'])
                else:
                    self.assertNotEqual(env['GITHUB_JOB'],source_caller['job'])
                with tempfile.TemporaryDirectory() as directory:
                    root=Path(directory);(root/p.DEBIAN_USE).write_bytes(raw)
                    (root/'inert-package').write_bytes(b'inert fixture')
                    with mock.patch.dict(os.environ,env,clear=True),mock.patch('subprocess.check_output',side_effect=lambda command,**_: 'b'*40 if command[-1]=='HEAD^{tree}' else 'a'*40):
                        namespace=runpy.run_path(str(p.ROOT/'scripts/ci/record_candidate.py'),run_name='fixture_recorder')
                        namespace['main'](str(root))
                    self.assertEqual((root/p.DEBIAN_USE).read_bytes(),raw)
                    emitted_use=json.loads((root/p.DEBIAN_USE).read_bytes())
                    self.assertEqual(emitted_use,use)
                    candidates=list(root.glob('polaris-candidate-manifest-*.json'))
                    self.assertEqual(len(candidates),1)
                    candidate=json.loads(candidates[0].read_text())
                self.assertEqual(candidate['job'],env['GITHUB_JOB'])
                self.assertEqual(candidate['matrixKey'],env['CANDIDATE_MATRIX_KEY'])
                self.assertEqual((candidate['sourceCommit'],candidate['sourceTree'],
                                  candidate['workflowRunId'],candidate['workflowAttempt']),
                                 ('a'*40,'b'*40,'42','1'))
                reference={'member':p.DEBIAN_USE,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
                self.assertEqual(candidate['debianMaterialUse'],reference)
                self.assertEqual([row for row in candidate['files'] if row['path']==p.DEBIAN_USE],
                                 [{'path':p.DEBIAN_USE,'bytes':reference['bytes'],'sha256':reference['sha256']}])
                self.assertEqual(emitted_use['consumerJob']['key'],source_caller['job'])
                if caller=='C2_ALL_LINUX_CLIENT':
                    # All other fields are valid; the real build recorder cannot claim C2's job.
                    with self.assertRaisesRegex(ValueError,'^candidate Debian consumer job mismatch$'):
                        p.validate_debian_use(files,[candidate],artifact,binding,jobs=jobs,canonical_manifest=b['manifest'])
                    continue
                self.assertEqual(candidate['job'],emitted_use['consumerJob']['key'])
                self.assertTrue(p.validate_debian_use(files,[candidate],artifact,binding,jobs=jobs,canonical_manifest=b['manifest']))
                for change,guard in [
                    (lambda c:c.pop('debianMaterialUse'),'candidate Debian useRef mismatch'),
                    (lambda c:c['debianMaterialUse'].update(sha256='f'*64),'candidate Debian useRef mismatch'),
                    (lambda c:c.update(job='build_windows'),'candidate Debian consumer job mismatch'),
                    (lambda c:c.update(files=[]),'candidate did not measure its Debian use sidecar')]:
                    bad=copy.deepcopy(candidate);change(bad)
                    with self.subTest(guard=guard),self.assertRaisesRegex(ValueError,'^'+guard+'$'):
                        p.validate_debian_use(files,[bad],artifact,binding,jobs=jobs,canonical_manifest=b['manifest'])

    def test_real_use_validation_rejects_mismatched_artifact_context_target_and_profile(self):
        for role in ['all','linux','docker']:
            b=self.bundle(role);binding,_=self.read(b);artifact=self.eligible(role)[0]
            files=self.use_files(b,artifact)
            # All pointer presence is separately tested using the actual recorder.
            if role=='all':continue
            self.assertTrue(p.validate_debian_use(files,[],artifact,binding,jobs=[b['supplier_job'],*b['consumer_jobs']]))
            for change in [
                lambda u:u['context'].update(runAttempt=2),
                lambda u:u['context'].update(sourceCommit='f'*40),
                lambda u:u['context'].update(tag=p.TAG+'0'),
                lambda u:u.update(planSHA256='f'*64),
                lambda u:u['rawArtifact'].update(id=u['rawArtifact']['id']+1),
                lambda u:u['readyArtifact'].update(id=u['readyArtifact']['id']+1),
                lambda u:u.update(targetArch='other'),
                lambda u:u.update(profiles=[])]:
                bad=copy.deepcopy(files);change(bad[p.DEBIAN_USE]['debianRawUse'])
                with self.subTest(role=role,change=change),self.assertRaises(ValueError):
                    p.validate_debian_use(bad,[],artifact,binding,jobs=[b['supplier_job'],*b['consumer_jobs']])
            with self.assertRaises(ValueError):p.validate_debian_use({},[],artifact,binding,jobs=[b['supplier_job'],*b['consumer_jobs']])
            with self.assertRaises(ValueError):p.validate_debian_use(files,[],'unlisted-artifact',binding,jobs=[b['supplier_job'],*b['consumer_jobs']])

    def test_local_original_before_ready_and_legacy_timing_are_distinct(self):
        for role in ('all','linux','docker'):
            b=self.bundle(role);binding,_,ready_metadata=self.read(b,with_ready=True)
            self.assertEqual(set(binding['readyArtifact']),{'id','name','digest','size'})
            self.assertEqual(p.debian_artifact_ref(ready_metadata),binding['readyArtifact'])
            artifact=self.eligible(role)[0]
            row=b['consumer_job_by_artifact'][artifact]
            row.update(started_at='2020-01-01T00:00:05Z',completed_at='2020-01-01T00:00:40Z')
            jobs=[b['supplier_job'],*b['consumer_jobs']]
            metadata={'created_at':'2020-01-01T00:00:40Z'}
            files=self.use_files(b,artifact,local=True)
            def candidates_for(members):
                fact=members[p.DEBIAN_USE];use=fact['debianRawUse']
                reference={'member':p.DEBIAN_USE,'bytes':fact['bytes'],'sha256':fact['sha256']}
                return ([{'job':use['consumerJob']['key'],'debianMaterialUse':reference,
                          'files':[dict(path=p.DEBIAN_USE,bytes=fact['bytes'],sha256=fact['sha256'])]}]
                        if role=='all' else [])
            candidates=candidates_for(files)
            self.assertTrue(p.validate_debian_use(files,candidates,artifact,binding,jobs=jobs,
                canonical_manifest=b['manifest'],artifact_metadata=metadata,ready_metadata=ready_metadata))
            remote=self.use_files(b,artifact)
            remote_candidates=candidates_for(remote)
            after={'created_at':'2020-01-01T00:02:30Z'}
            row.update(started_at='2020-01-01T00:02:10Z',completed_at='2020-01-01T00:03:00Z')
            # The actual reader's compact binding plus authenticated API READY
            # metadata accepts a legacy consumer after both independent gates.
            self.assertTrue(p.validate_debian_use(remote,remote_candidates,artifact,binding,jobs=jobs,
                canonical_manifest=b['manifest'],artifact_metadata=after,ready_metadata=ready_metadata))
            with self.subTest(role=role),self.assertRaisesRegex(ValueError,'Debian consumer artifact predates READY'):
                p.validate_debian_use(remote,remote_candidates,artifact,binding,jobs=jobs,
                    canonical_manifest=b['manifest'],artifact_metadata=metadata,ready_metadata=ready_metadata)
            row.update(started_at='2020-01-01T00:00:05Z')
            with self.assertRaisesRegex(ValueError,'Debian consumer started before'):
                p.validate_debian_use(remote,remote_candidates,artifact,binding,jobs=jobs,
                    canonical_manifest=b['manifest'],artifact_metadata=after,ready_metadata=ready_metadata)
            for missing_or_foreign in (None,dict(ready_metadata,id=ready_metadata['id']+1)):
                with self.assertRaisesRegex(ValueError,'legacy authenticated READY metadata missing or mismatched'):
                    p.validate_debian_use(remote,remote_candidates,artifact,binding,jobs=jobs,
                        canonical_manifest=b['manifest'],artifact_metadata=after,ready_metadata=missing_or_foreign)
            for changed in ({},dict(binding,manifestSHA256='f'*64)):
                with self.assertRaises(ValueError):
                    p.validate_debian_use(files,candidates,artifact,changed,jobs=jobs,
                        canonical_manifest=b['manifest'],artifact_metadata=metadata)
            for mutate in (lambda u:u.update(schema='unknown'),lambda u:u.pop('manifest'),
                           lambda u:u.update(schema='polaris-debian-use-v1')):
                bad=copy.deepcopy(files);mutate(bad[p.DEBIAN_USE]['debianRawUse'])
                with self.assertRaises(ValueError):
                    p.validate_debian_use(bad,candidates,artifact,binding,jobs=jobs,
                        canonical_manifest=b['manifest'],artifact_metadata=metadata)
            with self.assertRaises(ValueError):
                p.validate_debian_use({},candidates,artifact,binding,jobs=jobs,canonical_manifest=b['manifest'])

    def test_local_manifest_self_hash_cannot_replace_actual_canonical_bytes(self):
        from cronet_material_supply import encode_json
        b=self.bundle('linux');binding,_=self.read(b);artifact=self.eligible('linux')[0]
        files=self.use_files(b,artifact,local=True);use=files[p.DEBIAN_USE]['debianRawUse']
        use['manifest']['objects'][0]['bytes']+=1
        use['manifestSHA256']=hashlib.sha256(encode_json(use['manifest'])).hexdigest()
        with self.assertRaisesRegex(ValueError,'local URL/CAS differs from canonical bytes'):
            p.validate_debian_use(files,[],artifact,binding,jobs=b['consumer_jobs'],canonical_manifest=b['manifest'])
        with self.assertRaises(ValueError):
            p.validate_debian_use(self.use_files(b,artifact,local=True),[],artifact,binding,jobs=b['consumer_jobs'])
        self.assertFalse(p.validate_debian_use({},[],'binary-linux_s390x',binding,jobs=b['consumer_jobs'],
                                             canonical_manifest=b['manifest']))
        with self.assertRaises(ValueError):
            p.validate_debian_use(files,[],'binary-linux_s390x',binding,jobs=b['consumer_jobs'],
                                 canonical_manifest=b['manifest'])

    def test_exact_payload_member_is_required_only_in_actual_consumers(self):
        files={'package':{},p.DEBIAN_USE:{}}
        rule=[{'pattern':'package','count':1}]
        p.verify_payloads(files,rule,'fixture',debian_use=True)
        for members,required in [({'package':{}},True),(files,False),
                                 (dict(files,extra={}),True),(dict(files,**{'nested/'+p.DEBIAN_USE:{}}),True)]:
            with self.subTest(members=members,required=required),self.assertRaises(ValueError):
                p.verify_payloads(members,rule,'fixture',debian_use=required)
        for role,artifact,name in [('all','binary-linux_amd64',p.DEBIAN_USE),
                                    ('all','binary-windows_amd64',p.DEBIAN_USE),
                                    ('signed','binary-linux_amd64_glibc',p.DEBIAN_USE),
                                    ('linux','binary-linux_amd64','nested/'+p.DEBIAN_USE),
                                    ('docker',p.DEBIAN_READY,'other.json'),
                                    ('all',p.DEBIAN_RAW,'objects/not-a-digest')]:
            with self.subTest(role=role,artifact=artifact,name=name),self.assertRaises(ValueError):
                p.publication(role,artifact,name)

    def test_optional_mode_retains_original_receipt_shape_and_never_reads_API(self):
        with mock.patch.object(p,'api') as remote:
            for value in [{},{'POLARIS_DEBIAN_REQUIRED':'false'}]:
                self.assertIsNone(p.producer_debian_materials('all','a'*40,None,env=value))
            for value in [{'POLARIS_DEBIAN_REQUIRED':'TRUE'},
                          {'POLARIS_DEBIAN_REQUIRED':'true'},
                          {'POLARIS_DEBIAN_REQUIRED':'false','POLARIS_DEBIAN_RAW_ID':'1'}]:
                with self.subTest(value=value),self.assertRaises(ValueError):
                    p.producer_debian_materials('all','a'*40,None,env=value)
            remote.assert_not_called()

    def test_producer_receipt_recomputes_same_run_binding_without_whole_run_success_cycle(self):
        b=self.bundle('linux');c=b['context'];run=self.run_record(b);artifacts=self.artifacts(b)
        table={f'repos/{p.REPO}/actions/runs/42':run}
        for artifact in artifacts:table[f'repos/{p.REPO}/actions/artifacts/{artifact["id"]}']=artifact
        env={'POLARIS_DEBIAN_REQUIRED':'true','POLARIS_DEBIAN_RAW_ID':str(b['raw_artifact']['id']),
             'POLARIS_DEBIAN_RAW_DIGEST':b['raw_artifact']['digest'].removeprefix('sha256:'),
             'POLARIS_DEBIAN_READY_ID':str(b['ready_artifact']['id']),'POLARIS_DEBIAN_READY_DIGEST':b['ready_artifact']['digest'],
             'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REF':'refs/tags/'+p.TAG,'GITHUB_SHA':c['sourceCommit'],
             'GITHUB_WORKFLOW_SHA':c['sourceCommit'],'GITHUB_WORKFLOW_REF':p.REPO+'/'+c['workflow']+'@refs/tags/'+p.TAG,
             'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':'1'}
        with self.transport({b['raw_artifact']['id']:b['raw_zip'],b['ready_artifact']['id']:b['ready_zip']}), \
             mock.patch.object(p,'api',side_effect=lambda path:copy.deepcopy(table[path])), \
             mock.patch.object(p,'pages',return_value=[b['supplier_job']]),mock.patch.object(p,'tag_identity',return_value=c['tagObject']):
            self.assertEqual(p.producer_debian_materials('linux',c['sourceCommit'],c['sourceTree'],env=env),b['binding'])

    def test_public_stream_skips_private_family_and_filters_sidecar_from_mixed_archive(self):
        b=self.bundle('all');artifact=self.eligible('all')[0];files=self.use_files(b,artifact)
        use_bytes=json.dumps(files[p.DEBIAN_USE]['debianRawUse']).encode()
        public=f'sing-box-{p.VERSION}-linux-amd64.tar.gz';content=b'inert public fixture'
        zipped=BoundedStorageTests.zipped([(public,content),(p.DEBIAN_USE,use_bytes)])
        metadata=BoundedStorageTests.metadata(zipped,artifact,99)
        files={}
        for name,data in [(public,content),(p.DEBIAN_USE,use_bytes)]:
            release,disposition=p.publication('all',artifact,name)
            files[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
                         'releaseName':release,'publicationDisposition':disposition}
        actual={'sourceCommit':'a'*40,'runs':{'all':{'id':'7','attempt':1,'artifacts':{
            artifact:{'id':99,'archiveBytes':len(zipped),'archiveSha256':metadata['digest'],'files':files},
            p.DEBIAN_RAW:{'id':100,'files':{p.DEBIAN_MANIFEST:{'releaseName':None,'publicationDisposition':'private-debian-raw'}}}}}}}
        with tempfile.TemporaryDirectory() as directory,self.transport({99:zipped}) as remote, \
             mock.patch.object(p,'api',return_value=metadata) as lookup:
            budget=p.ScratchBudget(Path(directory),reserve=0)
            with p.closing(p.public_asset_stream(actual,budget)) as supplier:
                name,path=next(supplier);self.assertEqual(name,p.publication('all',artifact,public)[0])
                self.assertEqual(path.read_bytes(),content)
                with self.assertRaises(StopIteration):next(supplier)
            self.assertEqual(lookup.call_count,1);self.assertEqual(remote.call_count,1)
            self.assertEqual(list(Path(directory).iterdir()),[])
        files[p.DEBIAN_USE]['releaseName']='leak.json'
        with tempfile.TemporaryDirectory() as directory,mock.patch.object(p,'api') as lookup,self.assertRaises(ValueError):
            list(p.public_asset_stream(actual,p.ScratchBudget(Path(directory),reserve=0)))
        lookup.assert_not_called()


    def test_native_index_cannot_copy_itself_as_independent_material_proof(self):
        from native_release_index import distribution_materials
        b=self.bundle('all');binding,_=self.read(b);index=GateTests.final_index(self)
        index['distributionMaterials']=distribution_materials(index,p.ROOT,debian_raw=binding)
        with mock.patch.object(p,'pages',return_value=native_jobs_fixture(index)):
            p.validate_final_index(index,'a'*40,'b'*40,'c'*40,'42',1,'.github/workflows/build.yml',debian_raw=binding)
        for change in [
            lambda d:d['rawArtifact'].update(id=d['rawArtifact']['id']+1),
            lambda d:d['readyArtifact'].update(digest='sha256:'+'f'*64),
            lambda d:d['context'].update(runAttempt=2),
            lambda d:d.update(manifestSHA256='f'*64)]:
            bad=copy.deepcopy(index);change(bad['distributionMaterials']['debianRaw'])
            with self.subTest(change=change),mock.patch.object(p,'pages',return_value=native_jobs_fixture(index)),self.assertRaises(ValueError):
                p.validate_final_index(bad,'a'*40,'b'*40,'c'*40,'42',1,'.github/workflows/build.yml',debian_raw=binding)
        # Omitting external measured evidence cannot reproduce a field carried by index.
        with mock.patch.object(p,'pages',return_value=native_jobs_fixture(index)),self.assertRaises(ValueError):
            p.validate_final_index(index,'a'*40,'b'*40,'c'*40,'42',1,'.github/workflows/build.yml')

    def test_assemble_compares_reviewed_role_material_binding_before_any_public_write(self):
        b=self.bundle('all');binding,_=self.read(b)
        actual={'repository':p.REPO,'repositoryId':p.RID,'version':p.VERSION,
                'sourceCommit':'a'*40,'sourceTree':'b'*40,'tag':p.TAG,'tagObject':'c'*40,
                'scopeSha256':p.sha(p.SCOPE),'runs':{'all':{'id':'42','attempt':1,
                'distributionMaterials':{'debianRaw':binding},'artifacts':{}}}}
        for change in [lambda d:d['context'].update(runAttempt=2),
                       lambda d:d['rawArtifact'].update(id=d['rawArtifact']['id']+1),
                       lambda d:d.update(manifestSHA256='f'*64)]:
            review=copy.deepcopy(actual);review['reviewed']=True;change(review['runs']['all']['distributionMaterials']['debianRaw'])
            with tempfile.TemporaryDirectory() as directory,generic_algorithm_fixture(),self.assertRaisesRegex(ValueError,'role Debian'):
                root=Path(directory);p.assemble(actual,review,root,root/'out',materialize=False)

    def test_source_owned_scope_adds_only_two_private_artifacts_and_one_job(self):
        scope=p.release_scope(p.VERSION)
        for role,count in [('all',74),('linux',14),('docker',22)]:
            self.assertEqual(len(scope[role]['requiredArtifacts']),count)
            self.assertEqual(scope[role]['requiredJobs'].count('debian_materials'),1)
            self.assertEqual(scope[role]['debianMaterials'],p.DEBIAN_POLICY)
            p.debian_policy(scope,role)
            bad=copy.deepcopy(scope);bad[role]['debianMaterials']['rawArtifact']='arbitrary'
            with self.assertRaises(ValueError):p.debian_policy(bad,role)
        self.assertIsNone(p.debian_policy(scope,'signed'))
        self.assertNotIn('debian_materials',scope['signed']['requiredJobs'])

    def test_receipt_script_adds_only_the_recomputed_role_binding(self):
        release=json.loads(p.CONFIG.read_text());source='a'*40;b=self.bundle('linux')
        env={'PUBLISHER_ROLE':'linux','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REPOSITORY':p.REPO,
             'GITHUB_REPOSITORY_ID':str(p.RID),'RELEASE_BUILD':'All','RELEASE_VERSION':p.VERSION,
             'GITHUB_SHA':source,'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':'1',
             'PUBLISH_STORES':'false','PUBLISH_REGISTRY':'false','POLARIS_DEBIAN_REQUIRED':'true'}
        env.update(receipt_context_fixture('linux',True))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'release/ci').mkdir(parents=True)
            (root/'release/ci/github-release.json').write_text(json.dumps(release))
            (root/'release/ci/publisher-upstream-scope.json').write_bytes(p.SCOPE.read_bytes())
            with chdir(root),mock.patch.dict(os.environ,env,clear=True), \
                 mock.patch('subprocess.check_output',side_effect=lambda command,**_: 'b'*40 if command[-1]=='HEAD^{tree}' else source), \
                 mock.patch('github_release.producer_debian_materials',return_value=b['binding']) as measured:
                runpy.run_path(str(p.ROOT/'scripts/ci/publisher_run_receipt.py'),run_name='__main__')
                receipt=json.loads((root/'publisher-run-receipt.json').read_text())
            measured.assert_called_once_with('linux',source,'b'*40)
            self.assertEqual(receipt['distributionMaterials'],{'debianRaw':b['binding']})
            self.assertEqual(set(receipt),{'repository','repositoryId','sourceCommit','runId','attempt','version','build','role',
                                           'publishStores','publishRegistry','distributionMaterials'})

    def test_real_material_contract_hash_compares_both_source_roots(self):
        inputs=('scripts/ci/cronet_material_supply.py','scripts/ci/cronet_material_bootstrap.py',
                'release/ci/cronet-material-profiles.json','release/ci/cronet-material-inputs.json',
                '.github/patches/cronet-sysroot-transport.patch','.github/CRONET_GO_VERSION',
                'release/ci/client-overlays.json','release/ci/owned-distribution.json',
                'release/ci/apple-swift-package-overlays.json','scripts/ci/apple_package_overlays.py','scripts/ci/client_source.py')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in inputs:
                if not (p.ROOT/name).is_file():continue
                destination=root/name;destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes((p.ROOT/name).read_bytes())
            environment={'GITHUB_REPOSITORY':p.REPO,'GITHUB_REPOSITORY_ID':str(p.RID)}
            with mock.patch.dict(os.environ,environment),mock.patch.object(p,'api',return_value={'id':p.RID}), \
                 mock.patch.object(p,'command',side_effect=lambda *args:'a'*40 if 'rev-parse' in args else ''):
                p.identity('a'*40,root)
                for name in inputs[:6]:
                    path=root/name;original=path.read_bytes();path.write_bytes(original+b'\n')
                    with self.subTest(name=name),self.assertRaises(ValueError):p.identity('a'*40,root)
                    path.write_bytes(original)


    def test_actual_consumer_job_is_required_unique_successful_and_matches_recorded_runner(self):
        b=self.bundle('linux');binding,_=self.read(b);artifact=self.eligible('linux')[0]
        files=self.use_files(b,artifact);ident=files[p.DEBIAN_USE]['debianRawUse']['consumerJob']['id']
        for change in [
            lambda jobs:jobs.clear(),
            lambda jobs:jobs.append(copy.deepcopy(next(j for j in jobs if j['id']==ident))),
            lambda jobs:next(j for j in jobs if j['id']==ident).update(status='in_progress',conclusion=None),
            lambda jobs:next(j for j in jobs if j['id']==ident).update(conclusion='failure'),
            lambda jobs:next(j for j in jobs if j['id']==ident).update(run_id=43),
            lambda jobs:next(j for j in jobs if j['id']==ident).update(run_attempt=2),
            lambda jobs:next(j for j in jobs if j['id']==ident).update(head_sha='f'*40),
            lambda jobs:next(j for j in jobs if j['id']==ident).update(name='another job'),
            lambda jobs:next(j for j in jobs if j['id']==ident).update(runner_name='another runner')]:
            jobs=copy.deepcopy([b['supplier_job'],*b['consumer_jobs']]);change(jobs)
            with self.subTest(change=change),self.assertRaises(ValueError):
                p.validate_debian_use(files,[],artifact,binding,jobs=jobs)
        for change in [
            lambda u:u['consumerJob'].update(id=True),
            lambda u:u['consumerJob'].update(id=99999999),
            lambda u:u['consumerJob'].update(key='build_windows'),
            lambda u:u['consumerJob'].update(name='another job'),
            lambda u:u['consumerJob'].update(runner='another runner'),
            lambda u:u['consumerJob'].update(unlisted='forbidden')]:
            bad=copy.deepcopy(files);change(bad[p.DEBIAN_USE]['debianRawUse'])
            with self.subTest(change=change),self.assertRaises(ValueError):
                p.validate_debian_use(bad,[],artifact,binding,jobs=[b['supplier_job'],*b['consumer_jobs']])


    def test_actual_material_timing_never_borrows_pre_READY_producer_outputs(self):
        b=self.bundle('linux');binding,_=self.read(b);artifact=self.eligible('linux')[0]
        files=self.use_files(b,artifact);ident=files[p.DEBIAN_USE]['debianRawUse']['consumerJob']['id']
        jobs=copy.deepcopy([b['supplier_job'],*b['consumer_jobs']])
        next(job for job in jobs if job['id']==ident)['started_at']='2000-01-01T00:00:00Z'
        with self.assertRaisesRegex(ValueError,'started before'):
            p.validate_debian_use(files,[],artifact,binding,jobs=jobs)
        ready=self.artifacts(b)[1]
        p.debian_consumer_artifact({'created_at':ready['created_at']},ready)
        with self.assertRaisesRegex(ValueError,'predates READY'):
            p.debian_consumer_artifact({'created_at':'2000-01-01T00:00:00Z'},ready)
