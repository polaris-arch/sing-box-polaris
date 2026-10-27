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

    def test_supplement_wrapper_keeps_strict_graph_and_exact_core_identity_without_fallback(self):
        policy={'reference_path':Path('new-reference'),'material_map_path':Path('new-map'),'selector_sha256':'9'*64}
        expected={'coreBytes':10,'coreSHA256':'a'*64,'installedSHA256':'b'*64,'imageManifest':'c'*64}
        measured=dict(expected);measured['actualImageManifest']=measured.pop('imageManifest')
        with mock.patch.object(oci_supplement,'check_image',return_value=expected),mock.patch.object(p,'validate_oci_material_reuse',return_value=measured) as strict:
            result=p.measure_oci_materials(Path('image'),'oci-linux-amd64','d'*40,'42',1,policy)
            strict.assert_called_once_with(Path('image'),'oci-linux-amd64','d'*40,'42',1,reference_paths=(policy['reference_path'],policy['material_map_path']))
            self.assertEqual(result['supplementSelectorSHA256'],'9'*64)
        for failure in ('graph','core'):
            with mock.patch.object(oci_supplement,'check_image',return_value=expected),mock.patch.object(p,'validate_oci_material_reuse',side_effect=ValueError('graph') if failure=='graph' else None,return_value=dict(measured,coreSHA256='0'*64)) as strict:
                with self.assertRaises(ValueError):p.measure_oci_materials(Path('image'),'oci-linux-amd64','d'*40,'42',1,policy)
                self.assertEqual(strict.call_count,1)


class GateTests(unittest.TestCase):
    def setUp(self):
        # Preserve the scope of legacy synthetic package fixtures, rather than
        # making the production peer gate recognize or bypass fake identities.
        self.enterContext(generic_algorithm_fixture())

    def test_scope_preserved(self):
        s=json.loads(p.SCOPE.read_text())
        self.assertEqual(len(s['all']['matrices']['build']['include'])+len(s['all']['matrices']['build_windows7']['include']),38)
        for role,scope in s.items():
            self.assertEqual(set(scope['requiredArtifacts']),set(scope['payloadRules']))
            self.assertEqual(len(scope['requiredArtifacts']),len(set(scope['requiredArtifacts'])))
        self.assertEqual(len(s['docker']['matrices']['build_binary']['include']),10)
        self.assertEqual(len(s['docker']['matrices']['build_docker']['include']),9)

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
                         {'binary-linux_' + arch for arch in architectures} | {'publisher-run-receipt'})
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
        self.assertEqual(len(required),20)
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
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'release/ci').mkdir(parents=True)
            (root/'release/ci/github-release.json').write_text(json.dumps(release))
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
                            'nativeJobs':{k:{'id':i+1,'name':'private test fixture'} for i,k in enumerate(['linux','win','mac-x64','mac-arm64'])}},
                'legalFiles':[{'path':'licenses/LICENSE','content':'x','bytes':1,'sha256':'4'*64}],
                'sourceArchive':{'name':'sing-box-polaris-source-'+source+'.tar.gz','bytes':1,'sha256':'5'*64},'platforms':rows}
        from native_release_index import distribution_materials
        index['distributionMaterials'] = distribution_materials(index, p.ROOT)
        return index

    def check_index(self,index):
        p.validate_final_index(index,'a'*40,'b'*40,'c'*40,'42',1,'.github/workflows/build.yml')

    def test_final_index_uses_original_source_root_for_distribution_materials(self):
        index=self.final_index()
        with tempfile.TemporaryDirectory() as d:
            source_root=Path(d)/'reviewed-source'
            # The index belongs to the original producer checkout; the new
            # publisher's own script hash must not replace its source binding.
            with mock.patch('native_release_index.distribution_materials',return_value=index['distributionMaterials']) as materials:
                p.validate_final_index(index,'a'*40,'b'*40,'c'*40,'42',1,'.github/workflows/build.yml',source_root=source_root)
                materials.assert_called_once_with(index,source_root)
            with mock.patch('native_release_index.distribution_materials',return_value={'changed':True}),self.assertRaisesRegex(ValueError,'source/notice bindings'):
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
    def test_public_version_preserves_producer_and_tag_identity(self):
        self.assertEqual(p.VERSION,'1.15.0-polaris-alpha.12.6')
        self.assertEqual(p.PUBLIC_VERSION,'1.15.0-alpha.12.6')
        self.assertEqual(p.TAG,'v1.15.0-polaris-alpha.12.6')
        self.assertEqual(p.CANONICAL_METADATA,'SFA-version-metadata.json')

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
        paths=('release/ci/client-overlays.json','release/ci/owned-distribution.json',
               'release/ci/apple-swift-package-overlays.json','scripts/ci/apple_package_overlays.py','scripts/ci/client_source.py')
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
                for name in paths[2:]:
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


import contextlib
import gzip
import shutil
import tarfile
import oci_material_supplement as oci_supplement

_SUPPLEMENT_REFERENCE=json.loads((p.ROOT/oci_supplement.DIRECTORY/'reuse-reference.json').read_text())
SUPPLEMENT_API=[{'id':row['artifactId'],'name':name,'size_in_bytes':row['archiveBytes'],
    'digest':row['artifactAPIDigest'],'expired':False,
    'workflow_run':{'id':oci_supplement.RUN_ID,'head_sha':oci_supplement.SOURCE,
        'repository_id':p.RID,'head_repository_id':p.RID}}
    for name,row in _SUPPLEMENT_REFERENCE['artifacts'].items()]

def load_supplement_fixture(**kwargs):
    args = dict(source=oci_supplement.SOURCE, tree=oci_supplement.TREE, tag=oci_supplement.TAG, tag_object=oci_supplement.TAG_OBJECT,
                run_id=oci_supplement.RUN_ID, attempt=oci_supplement.ATTEMPT, workflow=oci_supplement.WORKFLOW,
                artifacts=copy.deepcopy(SUPPLEMENT_API), source_root=p.ROOT, publisher_root=p.ROOT)
    args.update(kwargs)
    return oci_supplement.load_for_run(**args)


@contextlib.contextmanager
def changed_supplement_publication():
    with tempfile.TemporaryDirectory(prefix='helper-pub-') as tmp:
        root = Path(tmp)
        shutil.copytree(p.ROOT / oci_supplement.DIRECTORY, root / oci_supplement.DIRECTORY)
        yield root, root / oci_supplement.DIRECTORY


class OciSupplementTests(unittest.TestCase):
    def test_actual_material_closure_and_budget(self):
        policy = load_supplement_fixture()
        self.assertEqual(set(policy['artifacts']), oci_supplement.ARTIFACT_NAMES)
        self.assertEqual(policy['bundle_tar_bytes'], 3399680)
        self.assertEqual(policy['bundle_maximum_bytes'], 3877824)

    def test_wrong_tuple_never_falls_back(self):
        for key, value in [('source', 'a' * 40), ('tree', 'b' * 40), ('tag', 'other'),
                           ('tag_object', 'c' * 40), ('run_id', 1), ('attempt', 2),
                           ('workflow', '.github/workflows/other.yml'), ('attempt', True), ('run_id', str(oci_supplement.RUN_ID))]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                load_supplement_fixture(**{key: value})

    def test_api_exact_set(self):
        variants = [SUPPLEMENT_API[:-1], SUPPLEMENT_API + [SUPPLEMENT_API[0]], SUPPLEMENT_API[:-1] + [SUPPLEMENT_API[0]]]
        for artifact_rows in variants:
            with self.subTest(count=len(artifact_rows)), self.assertRaises(ValueError):
                load_supplement_fixture(artifacts=artifact_rows)

    def test_api_identity_fields(self):
        for field, value in [('id', 1), ('name', 'oci-other'), ('size_in_bytes', 1),
                             ('digest', 'sha256:' + '0' * 64), ('expired', True), ('expired', None)]:
            api = copy.deepcopy(SUPPLEMENT_API)
            api[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                load_supplement_fixture(artifacts=api)
        for field, value in [('id', 1), ('head_sha', 'a' * 40), ('repository_id', 1), ('head_repository_id', 1)]:
            api = copy.deepcopy(SUPPLEMENT_API)
            api[0]['workflow_run'][field] = value
            with self.subTest(runfield=field), self.assertRaises(ValueError):
                load_supplement_fixture(artifacts=api)
        api = copy.deepcopy(SUPPLEMENT_API)
        api[0]['id'] = api[1]['id']
        with self.assertRaises(ValueError):
            load_supplement_fixture(artifacts=api)

    def test_selector_tamper(self):
        with changed_supplement_publication() as (root, directory):
            path = directory / 'selection-manifest.json'
            path.write_bytes(path.read_bytes() + b'\n')
            with self.assertRaises(ValueError):
                load_supplement_fixture(publisher_root=root)

    def test_missing_payload_supplement_fixture(self):
        with changed_supplement_publication() as (root, directory):
            (directory / 'README.md').unlink()
            with self.assertRaises(ValueError):
                load_supplement_fixture(publisher_root=root)

    def test_extra_file_and_empty_directory(self):
        for extra_directory in (False, True):
            with self.subTest(extra_directory=extra_directory), changed_supplement_publication() as (root, directory):
                path = directory / 'extra'
                if extra_directory:
                    path.mkdir()
                else:
                    path.write_text('unlisted')
                with self.assertRaises(ValueError):
                    load_supplement_fixture(publisher_root=root)

    def test_nonregular_fifo_rejected_without_opening(self):
        import os
        with changed_supplement_publication() as (root, directory):
            os.mkfifo(directory / 'fifo')
            with self.assertRaises(ValueError):
                load_supplement_fixture(publisher_root=root)

    def test_symlink_file_and_directory(self):
        for target_name in ('README.md', 'sources'):
            with self.subTest(target_name=target_name), changed_supplement_publication() as (root, directory):
                path = directory / target_name
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
                path.symlink_to(p.ROOT / oci_supplement.DIRECTORY / target_name, target_is_directory=target_name == 'sources')
                with self.assertRaises(ValueError):
                    load_supplement_fixture(publisher_root=root)

    def test_changed_source_recipe_notice_indexes(self):
        originals = ['sources/ca-certificates-20261020.tar.bz2', 'reuse-reference.json',
                     'oci-source-notice-map.json', 'source-acquisition.json', 'notice-inventory.json',
                     'http-get-receipts.json', 'notices/ca-certificates-20261020.tar.bz2/certdata.txt.license-header.txt',
                     'aports/ee92350c8a4509152dc91c693814215a884c07c3/main/alpine-base/APKBUILD']
        for name in originals:
            with self.subTest(name=name), changed_supplement_publication() as (root, directory):
                path = directory / name
                data = path.read_bytes()
                path.write_bytes(bytes([data[0] ^ 1]) + data[1:])
                with self.assertRaises(ValueError):
                    load_supplement_fixture(publisher_root=root)

    def test_source_root_anchor_is_not_publisher_root(self):
        with tempfile.TemporaryDirectory(prefix='helper-old-') as tmp:
            root = Path(tmp)
            for name in ('oci-source-notice-map.json', 'reuse-reference.json', 'source-acquisition.json'):
                relative = Path('release/dependency-sources/oci') / name
                (root / relative).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(p.ROOT / relative, root / relative)
            path = root / 'release/dependency-sources/oci/oci-source-notice-map.json'
            path.write_bytes(path.read_bytes() + b'\n')
            with self.assertRaises(ValueError):
                load_supplement_fixture(source_root=root)

    def test_historical_record_and_association_negatives(self):
        policy = load_supplement_fixture()
        reference = json.loads(policy['reference_path'].read_text())
        original = json.loads(policy['material_map_path'].read_text())
        for case in ('canonical', 'missing', 'duplicate', 'wrong-origin', 'unknown-kind', 'wrong-package'):
            material = copy.deepcopy(original)
            if case == 'canonical':
                material['historicalRecipeReferences'][0]['historicalRecordSHA256'] = '0' * 64
            elif case == 'missing':
                material['packageAssociations'].pop()
            elif case == 'duplicate':
                material['packageAssociations'][-1] = copy.deepcopy(material['packageAssociations'][0])
            elif case == 'wrong-origin':
                material['packageAssociations'][0]['origin'] = 'other'
            elif case == 'unknown-kind':
                material['packageAssociations'][0]['materialKind'] = 'fallback'
            else:
                material['packageAssociations'][0]['package']['C'] = 'forged'
            with self.subTest(case=case), self.assertRaises(ValueError):
                oci_supplement._materials(policy['directory'], p.ROOT, policy['selector'], reference, material)

    def test_path_and_json_negatives(self):
        for name in ('../other', '/etc/passwd', 'a/../b', './x', 'a//b', 'a\\b', '', 'a\0b'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                oci_supplement._relative(name)
        with self.assertRaises(ValueError):
            oci_supplement._json(b'{"key":1,"key":2}')

    def test_bounded_read_after_hash(self):
        requested = []
        class Reader(io.BytesIO):
            def read(self, size=-1):
                requested.append(size)
                return super().read(size)
        expected = {'path': 'fake', 'bytes': 3, 'sha256': hashlib.sha256(b'abc').hexdigest()}
        with mock.patch.object(oci_supplement, '_path', return_value=Path('fake')), \
             mock.patch.object(oci_supplement, '_digest_file', return_value=(3, expected['sha256'])), \
             mock.patch.object(Path, 'open', return_value=Reader(b'abcEXCESS')):
            with self.assertRaises(ValueError):
                oci_supplement._file(Path('.'), expected, read=True)
        self.assertEqual(requested, [4])

    def test_image_negative_and_mocked_positive_only(self):
        policy = load_supplement_fixture()
        with tempfile.TemporaryDirectory(prefix='helper-image-') as tmp:
            path = Path(tmp) / 'not-an-oci-image'
            path.write_bytes(b'not actual OCI bytes')
            with self.assertRaises(ValueError):
                oci_supplement.check_image(policy, 'oci-linux-amd64', path)
            with self.assertRaises(ValueError):
                oci_supplement.check_image(policy, 'oci-unknown', path)
            real_digest = oci_supplement._digest_file
            expected = policy['artifacts']['oci-linux-amd64']
            def mocked_digest(candidate, expected_bytes=None):
                if Path(candidate) == path:
                    return expected['imageBytes'], expected['imageSHA256']
                return real_digest(candidate, expected_bytes)
            with mock.patch.object(oci_supplement, '_digest_file', side_effect=mocked_digest):
                self.assertEqual(oci_supplement.check_image(policy, 'oci-linux-amd64', path), expected)

    def test_policy_mutation_rejected(self):
        policy = load_supplement_fixture()
        policy['artifacts']['oci-linux-amd64']['imageSHA256'] = '0' * 64
        with self.assertRaises(ValueError):
            oci_supplement.check_image(policy, 'oci-linux-amd64', Path('unused'))

    def test_bundle_determinism_receipt_and_no_self_reference(self):
        with tempfile.TemporaryDirectory(prefix='helper-bundle-') as tmp:
            first, second = Path(tmp) / 'first.tar.gz', Path(tmp) / 'second.tar.gz'
            p1, p2 = load_supplement_fixture(), load_supplement_fixture()
            r1, r2 = oci_supplement.write_bundle(p1, first), oci_supplement.write_bundle(p2, second)
            self.assertEqual((r1['bytes'], r1['sha256']), (r2['bytes'], r2['sha256']))
            self.assertEqual(r1['bytes'], 2919816)
            self.assertEqual(r1['sha256'], 'b7b2d88bc429d130e4bdcabf1063cb6e409e002ef681d6cb8a83362e519241e0')
            self.assertEqual(len(gzip.open(first, 'rb').read()), p1['bundle_tar_bytes'])
            with tarfile.open(first, 'r:gz') as archive:
                members = archive.getmembers()
                self.assertEqual(len(members), 53)
                self.assertTrue(all(x.isfile() and x.mode == 0o644 and x.mtime == 0 for x in members))
                self.assertNotIn('oci_material_supplement.py', [Path(x.name).name for x in members])
            receipt = oci_supplement.record(p1, 'a' * 40, first)
            self.assertFalse(receipt['legalConclusion'])
            self.assertTrue(receipt['publicReleaseAssetSetUnchanged'])
            self.assertEqual(receipt['auditBundle']['sha256'], r1['sha256'])
            self.assertIn('/' + 'a' * 40 + '/', receipt['publisherImmutableURL'])
            self.assertNotIn('sourceMaterialsReusable', receipt)
            with self.assertRaises(ValueError):
                oci_supplement.record(p1, 'HEAD', first)
            with self.assertRaises(ValueError):
                oci_supplement.record(p1, 'a' * 40, second)
            first.write_bytes(first.read_bytes() + b'x')
            with self.assertRaises(ValueError):
                oci_supplement.record(p1, 'a' * 40, first)

    def test_bundle_destination_preserved_and_partial_cleaned(self):
        policy = load_supplement_fixture()
        with tempfile.TemporaryDirectory(prefix='helper-clean-') as tmp:
            existing = Path(tmp) / 'existing.tar.gz'
            existing.write_bytes(b'preserve')
            with self.assertRaises(ValueError):
                oci_supplement.write_bundle(policy, existing)
            self.assertEqual(existing.read_bytes(), b'preserve')
            target = Path(tmp) / 'failed.tar.gz'
            with mock.patch.object(tarfile.TarFile, 'addfile', side_effect=OSError('injected write failure')):
                with self.assertRaises(OSError):
                    oci_supplement.write_bundle(policy, target)
            self.assertFalse(target.exists())
            self.assertNotIn('_written_bundle', policy)
            with self.assertRaises(ValueError):
                oci_supplement.record(policy, 'a' * 40, target)

    def test_bundle_writes_exact_checked_bytes_and_cleans_midstream_drift(self):
        policy = load_supplement_fixture()
        real_file = oci_supplement._file
        reads = []
        def changed_after_loading(root, row, read=False):
            if read and row['path'].startswith('aports/'):
                reads.append(row['path'])
                raise ValueError('simulated bounded member verification failure')
            return real_file(root, row, read=read)
        with tempfile.TemporaryDirectory(prefix='helper-drift-') as tmp:
            target = Path(tmp) / 'failed.tar.gz'
            with mock.patch.object(oci_supplement, '_file', side_effect=changed_after_loading):
                with self.assertRaises(ValueError):
                    oci_supplement.write_bundle(policy, target)
            self.assertTrue(reads)
            self.assertFalse(target.exists())

    def test_cleanup_error_does_not_mask_primary_failure(self):
        policy = load_supplement_fixture()
        with tempfile.TemporaryDirectory(prefix='helper-cleanup-error-') as tmp:
            target = Path(tmp) / 'failed.tar.gz'
            primary = OSError(122, 'injected EDQUOT during addfile')
            with mock.patch.object(tarfile.TarFile, 'addfile', side_effect=primary), \
                 mock.patch.object(Path, 'unlink', side_effect=PermissionError(13, 'injected cleanup failure')):
                with self.assertRaises(OSError) as caught:
                    oci_supplement.write_bundle(policy, target)
            self.assertIs(caught.exception, primary)
            self.assertEqual(caught.exception.errno, 122)
            if hasattr(primary, 'add_note'):
                self.assertTrue(any('partial cleanup failed' in note for note in primary.__notes__))
            self.assertNotIn('_written_bundle', policy)



# Keep the exact current-selection regressions in the existing publisher CI gate.
from test_oci_material_registry import RegistryTests

from test_github_read_transport import ReadTransportTests

# Execute the exact nonpublic peer regressions in this existing CI command.
from publisher_peer_evidence_tests import PeerEvidenceTests
from oci_material_selection_12_3_tests import CurrentOCISelectionTests
from publisher_peer_evidence_12_5_tests import CurrentPeerEvidenceTests
from oci_material_selection_12_5_tests import NewOCISelectionTests

if __name__=='__main__':
    unittest.main()
