"""Inert source controls only: no Windows process, SYSTEM actor or native PASS.

The synthetic DTOs exercise parsing/rejection and derived *data*. Every native
adapter command is mocked. These tests cannot create an App execution issuer.
"""
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import jsonschema
import native_release_index as index
import tls_fingerprint_probe as tls
import windows_native_execution as windows


def windows_row_fixture():
    # Reuse the existing source-owned capability/module fixture, not a producer.
    from test_native_release_index import sealed_row_fixture
    row = sealed_row_fixture()
    old = copy.deepcopy(row['finalPackageCronetSmoke']['sealedExecution'])
    root = 'sing-box-' + row['version'] + '-windows-amd64'
    row.update(id=root, target='windows/amd64', variant=copy.deepcopy(windows.VARIANT))
    row['core']['member'] = 'sing-box.exe'
    row['sidecar']['member'] = 'libcronet.dll'
    row['archive'].update(name=root+'.zip', releaseName=index.public_product_name(root+'.zip'),
                          root=root, members={root+'/sing-box.exe':row['core']['sha256'],
                                              root+'/libcronet.dll':row['sidecar']['sha256']})
    row['buildGraph']['settings'].update(GOOS='windows', GOARCH='amd64', CGO_ENABLED='0',
                                         **{'vcs.revision':row['sourceCommit'], 'vcs.modified':'false'})
    receipt = old['tlsProbe']
    receipt['capabilities'].update(os='windows', arch='amd64')
    cohort_id = 'a'*32
    cohort_path = 'C:\\Windows\\SystemTemp\\polaris-native-' + cohort_id
    native_path = '\\Device\\HarddiskVolume4\\Windows\\SystemTemp\\polaris-native-' + cohort_id
    protected = {'volumeSerial':'0000000000000001', 'ownerSid':'S-1-5-18',
                 'protectedDacl':True, 'systemOnlyDacl':True, 'reparsePoint':False}
    cohort = dict(protected, id=cohort_id, path=cohort_path, nativePath=native_path,
                  fileId='3'*32, fileSystem='NTFS', createdNew=True)
    objects = {}
    for key, pin, identity in [('coreObject',row['core'],'1'*32), ('sidecarObject',row['sidecar'],'2'*32)]:
        objects[key] = dict(protected, path=cohort_path+'\\'+pin['member'],
                            nativePath=native_path+'\\'+pin['member'], fileId=identity,
                            bytes=pin['bytes'], sha256=pin['sha256'], linkCount=1, shareReadOnly=True)
    version = json.loads((index.ROOT/'release/polaris-candidate-inputs.json').read_text())['cronetVersion']
    side = objects['sidecarObject']
    library = {'volumeSerial':side['volumeSerial'], 'fileId':side['fileId'],
               'nativePath':side['nativePath'], 'modulePath':side['path'], 'mappedPath':side['nativePath'],
               'moduleBase':'0000000180000000', 'memoryType':16777216, 'loadFlags':2304,
               'parentFileId':cohort['fileId'], 'parentVolumeSerial':cohort['volumeSerial'], 'shareReadOnly':True}
    cronet = {'os':'windows','arch':'amd64','go':row['goVersion'],'linkage':'shared-purego',
              'library':side['path'],'sha256':side['sha256'],'libraryBytes':side['bytes'],
              'librarySelection':'captured-windows-module-v1','version':version,
              'gvisorCompiled':True,'windowsLibrary':library}
    records = []

    def record(purpose, argv, data=b'', code=0, stdout='', stderr=''):
        pid = 500 + len(records)
        birth = format(0x1001 + len(records), '016x')
        actor = {'sid':'S-1-5-18','tokenType':'primary','threadImpersonation':False,
                 'processId':pid,'creationTime':birth}
        value = {'purpose':purpose,'argv':argv,'stdinSHA256':windows.sha_bytes(data),'stdinBytes':len(data),
                 'processId':pid,'creationTime':birth,'actor':actor,'imageNativePath':objects['coreObject']['nativePath'],
                 'imageLoadPolicy':7,'inheritedHandleCount':3,'jobAssignedAtCreation':True,'exitCode':code,
                 'actualWait':True,'stdoutEOF':True,'stderrEOF':True,'stdout':stdout,'stderr':stderr,
                 'outputTruncated':False,'timedOut':False,'forcedKill':False,'jobActiveAfterWait':0,'handlesClosed':True}
        records.append(value)
        return value

    record('capabilities',['tools','tls-fingerprints'],stdout=windows.canonical(receipt['capabilities']).decode()+'\n')
    for observation, (_, config, _) in zip(receipt['configurationChecks'],tls.configuration_cases(receipt['capabilities'])):
        record('check-config-v1',['--disable-color','check','-c','stdin'],windows.canonical(config),
               observation['exitCode'],stderr=observation['output'])
    record('cronet-observation',['tools','cronet','--expected-version',version,'--sha256',side['sha256']],
           stdout=windows.canonical(cronet).decode()+'\n')
    port = 43123
    config = {'log':{'level':'error'},'inbounds':[{'type':'mixed','listen':'127.0.0.1','listen_port':port}],
              'outbounds':[{'type':'direct','tag':'direct'},
                           {'type':'naive','tag':'module-only','server':'127.0.0.1','server_port':9,
                            'username':'native-proof','password':'native-proof',
                            'tls':{'enabled':True,'server_name':'tls.invalid'}}], 'route':{'final':'direct'}}
    main = record('run-main-v1',['run','-c','stdin'],windows.canonical(config))
    native = {'actor':{'sid':'S-1-5-18','tokenType':'primary','threadImpersonation':False,
                       'processId':400,'creationTime':'0000000000001000'},
              'producer':{'sourceCommit':row['sourceCommit'],'sourceTree':row['sourceTree'],
                          'sha256':'5'*64,'bytes':12345,'goVersion':row['goVersion']},
              'cohort':cohort, **objects, 'executions':records,
              'runMain':{'listenAddress':'127.0.0.1','port':port,'ownerPid':main['processId'],'ready':True,
                         'dllModule':{'nativePath':side['nativePath'],'moduleBase':'0000000181000000','memoryType':16777216}},
              'cleanup':{'allChildrenWaited':True,'readersJoined':True,'jobActiveProcesses':0,
                         'heldObjectsClosed':True,'cohortRemoved':True,'configurationRetained':False,'forcedTermination':False}}
    proof = {key:row[key] for key in ('sourceCommit','sourceTree','version','target')}
    proof.update(schema=windows.SCHEMA,runId=42,runAttempt=1,archiveSha256=row['archive']['sha256'],
                 core=copy.deepcopy(row['core']),sidecar=copy.deepcopy(row['sidecar']),tlsProbe=receipt,cronet=cronet,native=native)
    row['finalPackageCronetSmoke'] = {'status':'passed','os':'windows','arch':'amd64','go':row['goVersion'],
        'gvisorCompiled':True,'naiveOutbound':True,'linkage':'shared-purego','version':version,
        'librarySha256':side['sha256'],'coreSha256':row['core']['sha256'],'windowsExecution':proof}
    row['trustedExecution'] = {'schema':'polaris-trusted-execution-v1','sourceCommit':row['sourceCommit'],
                              'sourceTree':row['sourceTree'],'loader':'windows-helper-private-cohort-v1',
                              'purposes':['check-config-v1','run-main-v1']}
    return row


class WindowsFactControls(unittest.TestCase):
    """A passing parser assertion is not a real native execution result."""
    def check(self, row):
        return index.validate_trusted_execution(row, {'runId':42,'runAttempt':1})

    def rejected(self, mutate):
        row = windows_row_fixture()
        mutate(row, row['finalPackageCronetSmoke']['windowsExecution'])
        with self.assertRaises((ValueError,jsonschema.ValidationError,KeyError,TypeError)):
            self.check(row)

    def test_inert_dto_derives_only_the_exact_two_purpose_data_fields(self):
        row = windows_row_fixture()
        self.assertEqual(self.check(row),row['trustedExecution'])
        self.assertEqual(set(self.check(row)),{'schema','sourceCommit','sourceTree','loader','purposes'})
        self.assertEqual(self.check(row)['purposes'],['check-config-v1','run-main-v1'])

    def test_source_tree_tag_target_variant_and_build_settings_are_exact(self):
        changes = [lambda r,p:r.update(sourceCommit='f'*40),lambda r,p:r.update(sourceTree='f'*40),
                   lambda r,p:r.update(tag='v1.15.0-polaris-alpha.999'),lambda r,p:r.update(target='windows/arm64'),
                   lambda r,p:r['variant'].update(legacy=True),lambda r,p:r['variant'].update(legacy=0),
                   lambda r,p:r['variant'].update(linkage='static-cgo'),lambda r,p:r['archive'].update(root='other'),
                   lambda r,p:r['archive'].update(name='other.zip')]
        for key in ['GOOS','GOARCH','CGO_ENABLED','vcs.revision','vcs.modified']:
            changes += [lambda r,p,k=key:r['buildGraph']['settings'].pop(k),
                        lambda r,p,k=key:r['buildGraph']['settings'].__setitem__(k,'wrong')]
        changes += [lambda r,p:r['buildGraph']['settings'].__setitem__('-tags','with_purego'),
                    lambda r,p:r.update(tags=r['tags']+',with_purego')]
        for change in changes:
            with self.subTest(change=change):self.rejected(change)

    def test_wrong_final_pin_member_archive_or_integer_alias_never_passes(self):
        changes=[lambda r,p:p.update(archiveSha256='f'*64),lambda r,p:r['archive'].update(bytes=1.0),
                 lambda r,p:r['core'].update(bytes=True),lambda r,p:p['sidecar'].update(bytes=11.0),
                 lambda r,p:p['core'].update(sha256='f'*64),lambda r,p:r['sidecar'].update(member='other.dll'),
                 lambda r,p:r['archive']['members'].__setitem__(r['id']+'/libcronet.dll','f'*64),
                 lambda r,p:r['archive']['members'].__setitem__(r['id']+'/../escape','a'*64),
                 lambda r,p:p.update(runId=True),lambda r,p:p.update(runAttempt=2)]
        for change in changes:
            with self.subTest(change=change):self.rejected(change)
        row=windows_row_fixture();proof=row['finalPackageCronetSmoke']['windowsExecution']
        for context in [{'runId':True,'runAttempt':1},{'runId':42,'runAttempt':1.0}]:
            with self.assertRaises(ValueError):index.derive_trusted_execution(row,proof,context)

    def test_actor_domain_birth_and_each_child_are_not_expected_strings(self):
        changes=[]
        for where in ['actor','child']:
            for key,value in [('sid','S-1-5-21-untrusted'),('tokenType','impersonation'),('threadImpersonation',True),
                              ('threadImpersonation',0),('creationTime','0'*16),('creationTime',4096),('processId',True)]:
                def change(r,p,w=where,k=key,v=value):
                    target=p['native']['actor'] if w=='actor' else p['native']['executions'][1]['actor']
                    target[k]=v
                changes.append(change)
        def same_incarnation(r,p):
            before,child=p['native']['executions'][:2]
            for key in ('processId','creationTime'):
                child[key]=before[key];child['actor'][key]=before[key]
        changes += [same_incarnation,
                    lambda r,p:p['native']['executions'][1]['actor'].update(processId=999),
                    lambda r,p:p['native']['executions'][1].update(processId=400)]
        for change in changes:
            with self.subTest(change=change):self.rejected(change)

    def test_ntfs_fresh_protection_and_held_identity_fields_are_all_mandatory(self):
        changes=[]
        for name in ['cohort','coreObject','sidecarObject']:
            for key,value in [('ownerSid','S-1-5-32-544'),('protectedDacl',False),('systemOnlyDacl',False),
                              ('reparsePoint',True),('volumeSerial','0'*16),('volumeSerial',1),('fileId','0'*32),
                              ('fileId','F'*32),('nativePath','/tmp/fake')]:
                changes.append(lambda r,p,n=name,k=key,v=value:p['native'][n].__setitem__(k,v))
        changes += [lambda r,p:p['native']['cohort'].update(fileSystem='FAT32'),
                    lambda r,p:p['native']['cohort'].update(createdNew=False),
                    lambda r,p:p['native']['coreObject'].update(fileId=p['native']['cohort']['fileId']),
                    lambda r,p:p['native']['sidecarObject'].update(shareReadOnly=False),
                    lambda r,p:p['native']['coreObject'].update(linkCount=2),
                    lambda r,p:p['native']['sidecarObject'].update(bytes=10),
                    lambda r,p:p['native']['producer'].update(sourceCommit='f'*40),
                    lambda r,p:p['native']['producer'].update(sourceTree='f'*40)]
        for change in changes:
            with self.subTest(change=change):self.rejected(change)

    def test_every_configuration_case_has_its_own_fixed_input_argv_and_normal_exit(self):
        def bad_index(p):
            return next(i+1 for i,x in enumerate(p['tlsProbe']['configurationChecks']) if not x['expectedPass'])
        def crash(r,p,code=0xc0000005):
            i=bad_index(p);p['native']['executions'][i]['exitCode']=code
            p['tlsProbe']['configurationChecks'][i-1]['exitCode']=code
        changes=[crash,lambda r,p:crash(r,p,2),lambda r,p:p['native']['executions'][1].update(argv=['check','-c','arbitrary.json']),
                 lambda r,p:p['native']['executions'][1].update(stdinSHA256='f'*64),
                 lambda r,p:p['native']['executions'][1].update(stdinBytes=True),
                 lambda r,p:p['native']['executions'].pop(1),
                 lambda r,p:p['native']['executions'].insert(1,copy.deepcopy(p['native']['executions'][1])),
                 lambda r,p:p['tlsProbe']['configurationChecks'][bad_index(p)-1].update(output='DLL loader failed'),
                 lambda r,p:p['native']['executions'][bad_index(p)].update(stderr='DLL loader failed')]
        for change in changes:
            with self.subTest(change=change):self.rejected(change)

    def test_native_completion_is_required_for_every_case_and_entire_suite(self):
        changes=[]
        for key,value in [('actualWait',False),('stdoutEOF',False),('stderrEOF',False),('outputTruncated',True),
                          ('timedOut',True),('forcedKill',True),('jobActiveAfterWait',1),('handlesClosed',False),
                          ('imageLoadPolicy',0),('inheritedHandleCount',4),('jobAssignedAtCreation',False)]:
            changes.append(lambda r,p,k=key,v=value:p['native']['executions'][1].__setitem__(k,v))
        for key,value in [('allChildrenWaited',False),('readersJoined',False),('jobActiveProcesses',1),
                          ('heldObjectsClosed',False),('cohortRemoved',False),('configurationRetained',True),
                          ('forcedTermination',True),('jobActiveProcesses',False)]:
            changes.append(lambda r,p,k=key,v=value:p['native']['cleanup'].__setitem__(k,v))
        for change in changes:
            with self.subTest(change=change):self.rejected(change)

    def test_actual_library_mapping_not_path_or_selected_true_controls_loader(self):
        changes=[]
        for key,value in [('mappedPath','\\Device\\HarddiskVolume4\\other.dll'),('fileId','f'*32),
                          ('parentFileId','f'*32),('memoryType',131072),('loadFlags',0),('moduleBase','0'*16),
                          ('moduleBase',6442450944),('shareReadOnly',False)]:
            changes.append(lambda r,p,k=key,v=value:p['cronet']['windowsLibrary'].__setitem__(k,v))
        changes += [lambda r,p:p['cronet'].update(librarySelection='standalone-path'),
                    lambda r,p:p['native']['runMain'].update(ownerPid=999),
                    lambda r,p:p['native']['runMain'].update(port=True),
                    lambda r,p:p['native']['runMain'].update(ready=False),
                    lambda r,p:p['native']['runMain']['dllModule'].update(memoryType=131072),
                    lambda r,p:p['native']['runMain']['dllModule'].update(nativePath='\\Device\\HarddiskVolume4\\foreign.dll')]
        for change in changes:
            with self.subTest(change=change):self.rejected(change)

    def test_observed_documents_require_one_exact_json_frame_and_source(self):
        for output in ['{}{}','{} trailing','\ufeff{}','{"x":1,"x":2}','[]','NaN']:
            self.rejected(lambda r,p,s=output:p['native']['executions'][0].update(stdout=s))
        self.rejected(lambda r,p:p['tlsProbe']['capabilities'].update(sourceCommit='f'*40))
        self.rejected(lambda r,p:p['native']['executions'][0].update(stdout='é'*262144))
        self.rejected(lambda r,p:p['native']['executions'][-2].update(stdout='{}\n{}'))

    def test_ordinary_smoke_missing_policy_proof_or_other_purpose_is_not_authority(self):
        row=windows_row_fixture();del row['trustedExecution'];del row['finalPackageCronetSmoke']['windowsExecution']
        row['finalPackageCronetSmoke']['selected']=True
        self.assertIsNone(self.check(row))
        for change in [lambda r,p:r.pop('trustedExecution'),lambda r,p:r['finalPackageCronetSmoke'].pop('windowsExecution'),
                       lambda r,p:r['trustedExecution']['purposes'].reverse(),lambda r,p:r['trustedExecution']['purposes'].append('tls-inventory-v1'),
                       lambda r,p:r['finalPackageCronetSmoke'].__setitem__('macosExecution',p),
                       lambda r,p:r['finalPackageCronetSmoke'].__setitem__('sealedExecution',p)]:
            with self.subTest(change=change):self.rejected(change)


class NativeAdapterControls(unittest.TestCase):
    def tool_fixture(self, directory):
        tool=Path(directory)/'producer.exe';tool.write_bytes(b'not executable; mocked native producer')
        archive=Path(directory)/'archive.zip';archive.write_bytes(b'not a product')
        return tool,archive

    def child(self, stdout=b'{}', stderr=b'', wait=None, code=0):
        child=Mock();child.stdout=io.BytesIO(stdout);child.stderr=io.BytesIO(stderr);child.stdin=io.BytesIO()
        child.wait.side_effect=wait;child.wait.return_value=code
        return child

    def test_fixed_command_no_shell_and_bounded_streams_with_mock_only(self):
        with tempfile.TemporaryDirectory() as td:
            tool,archive=self.tool_fixture(td);child=self.child(b'{"synthetic":true}\n')
            with patch.object(windows.subprocess,'Popen',return_value=child) as start:
                self.assertEqual(windows.native_command(tool,archive,b'{}'),b'{"synthetic":true}\n')
            self.assertEqual(start.call_args.args[0],[str(tool),'--archive',str(archive)])
            self.assertIs(start.call_args.kwargs['shell'],False)
            self.assertIs(start.call_args.kwargs['close_fds'],True)
            child.wait.assert_called_once_with(timeout=windows.PROCESS_SECONDS)
            self.assertFalse((Path(td)/'adapter-diagnostic.json').exists())

    def test_nonzero_timeout_pipe_errors_and_overflow_keep_non_authoritative_diagnostics(self):
        for which in ['exit','timeout','wait-unknown','stdout','stderr','stdin']:
            with self.subTest(which=which),tempfile.TemporaryDirectory() as td:
                tool,archive=self.tool_fixture(td)
                child=self.child(code=1 if which=='exit' else 0)
                if which=='timeout':child.wait.side_effect=[subprocess.TimeoutExpired('fixed',1),0]
                if which=='wait-unknown':child.wait.side_effect=[subprocess.TimeoutExpired('fixed',1),subprocess.TimeoutExpired('fixed',1)]
                if which=='stdout':child.stdout=io.BytesIO(b'x'*33)
                if which=='stderr':child.stderr=io.BytesIO(b'x'*33)
                if which=='stdin':child.stdin=Mock();child.stdin.write.return_value=0
                with patch.object(windows.subprocess,'Popen',return_value=child),patch.object(windows,'OUTPUT_LIMIT',32),patch.object(windows,'ERROR_LIMIT',32):
                    with self.assertRaises(ValueError):windows.native_command(tool,archive,b'{}')
                diagnostic=json.loads((Path(td)/'adapter-diagnostic.json').read_text())
                self.assertIs(diagnostic['publicationEligible'],False);self.assertIs(diagnostic['executionAuthority'],False)
                self.assertEqual(diagnostic['nativeCleanup'],'unknown')
                self.assertLessEqual(diagnostic['stdoutBytesRetained'],32)
                self.assertLessEqual(diagnostic['stderrBytesRetained'],32)
                if which=='wait-unknown':self.assertIs(diagnostic['actualWait'],False)

    def test_utf8_duplicate_trailing_and_nonfinite_json_rejected(self):
        for raw in [b'\xff',b'\xff\xfe{\x00}\x00',b'\xef\xbb\xbf{}',b'{"x":1,"x":2}',b'{}{}',b'NaN']:
            with self.subTest(raw=raw),self.assertRaises((ValueError,UnicodeError)):
                windows.exact_json(raw)

    def test_fixed_file_namespaces_reject_links_without_running_anything(self):
        with tempfile.TemporaryDirectory() as td:
            tool,_=self.tool_fixture(td)
            self.assertEqual(windows.plain_file(tool)[2],tool.stat().st_size)
            alias=Path(td)/'alias.exe';alias.symlink_to(tool)
            self.assertRaises(ValueError,windows.plain_file,alias)
            self.assertRaises(ValueError,windows.plain_file,Path('relative.exe'))

    def test_adapter_request_requires_formal_admission_before_any_native_command(self):
        row=windows_row_fixture()
        env={'POLARIS_WINDOWS_NATIVE_PROOF_AUTHORIZED':'true','GITHUB_ACTIONS':'true',
             'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REPOSITORY':index.REPO,
             'GITHUB_REPOSITORY_ID':str(index.RID),'GITHUB_SHA':row['sourceCommit'],
             'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':'1','POLARIS_WINDOWS_NATIVE_ADMISSION_RECEIPT':'{}'}
        with patch.dict(os.environ,env),patch.object(windows,'windows_host',return_value=True),\
             patch('windows_native_admission.consume',side_effect=ValueError('not admitted')),\
             patch.object(windows,'native_command') as command:
            self.assertRaises(ValueError,windows.produce,row,Path('/not-read.zip'),context={'runId':42,'runAttempt':1})
            command.assert_not_called()
        for context in [{'runId':True,'runAttempt':1},{'runId':42,'runAttempt':1,'sourceCommit':'f'*40}]:
            with patch.object(windows,'windows_host',return_value=True),patch.dict(os.environ,env),\
                 patch.object(windows,'native_command') as command:
                self.assertRaises(ValueError,windows.produce,row,Path('/not-read.zip'),context=context)
                command.assert_not_called()

    def test_mocked_adapter_binds_fixed_tool_exact_request_and_after_bytes(self):
        # Plain inert bytes only. Popen/native_command never execute a program.
        for mutation in ['none','producer','archive','foreign-producer','foreign-source','foreign-run','framing']:
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as td:
                directory=Path(td)/'polaris-windows-native-execution';directory.mkdir()
                tool,archive=self.tool_fixture(directory)
                row=windows_row_fixture();proof=row['finalPackageCronetSmoke']['windowsExecution']
                row['archive'].update(bytes=archive.stat().st_size,sha256=windows.sha_file(archive))
                proof['archiveSha256']=row['archive']['sha256']
                proof['native']['producer'].update(bytes=tool.stat().st_size,sha256=windows.sha_file(tool))
                env={'RUNNER_TEMP':td,'POLARIS_WINDOWS_NATIVE_PROOF_AUTHORIZED':'true','GITHUB_ACTIONS':'true',
                     'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REPOSITORY':index.REPO,
                     'GITHUB_REPOSITORY_ID':str(index.RID),'GITHUB_SHA':row['sourceCommit'],
                     'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':'1','POLARIS_WINDOWS_NATIVE_ADMISSION_RECEIPT':'{}'}
                receipt={'context':{'sourceCommit':row['sourceCommit'],'runId':42,'runAttempt':1}}
                def command(actual_tool,actual_archive,raw):
                    self.assertEqual(actual_tool,tool);self.assertEqual(actual_archive,archive)
                    request=json.loads(raw)
                    self.assertEqual(request['schema'],'polaris-windows-native-execution-request-v1')
                    self.assertEqual(request['sourceCommit'],row['sourceCommit'])
                    self.assertEqual(request['sourceTree'],row['sourceTree'])
                    self.assertEqual(request['runId'],42);self.assertEqual(request['runAttempt'],1)
                    self.assertEqual(request['core'],row['core']);self.assertEqual(request['sidecar'],row['sidecar'])
                    self.assertEqual(request['archive'],{key:row['archive'][key] for key in ('root','bytes','sha256','members')})
                    if mutation=='producer':tool.write_bytes(b'changed producer')
                    if mutation=='archive':archive.write_bytes(b'changed archive')
                    if mutation=='foreign-producer':proof['native']['producer']['sha256']='f'*64
                    if mutation=='foreign-source':proof['sourceCommit']='f'*40
                    if mutation=='foreign-run':proof['runAttempt']=2
                    return b'{}{}' if mutation=='framing' else windows.canonical(proof)
                with patch.dict(os.environ,env),patch.object(windows,'windows_host',return_value=True),\
                     patch('windows_native_admission.consume',return_value=receipt) as consume,\
                     patch.object(windows,'native_command',side_effect=command) as native:
                    if mutation=='none':self.assertEqual(windows.produce(row,archive,context={'runId':42,'runAttempt':1}),proof)
                    else:
                        with self.assertRaises(ValueError):windows.produce(row,archive,context={'runId':42,'runAttempt':1})
                    consume.assert_called_once_with({});native.assert_called_once()

    def test_no_host_no_privileged_flag_and_oversized_receipt_do_not_spawn(self):
        row=windows_row_fixture()
        env={'POLARIS_WINDOWS_NATIVE_PROOF_AUTHORIZED':'true','GITHUB_ACTIONS':'true',
             'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REPOSITORY':index.REPO,
             'GITHUB_REPOSITORY_ID':str(index.RID),'GITHUB_SHA':row['sourceCommit'],
             'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':'1','POLARIS_WINDOWS_NATIVE_ADMISSION_RECEIPT':'x'*65537}
        for host,authorized in [(False,'true'),(True,'false'),(True,'true')]:
            with self.subTest(host=host,authorized=authorized),patch.dict(os.environ,dict(env,POLARIS_WINDOWS_NATIVE_PROOF_AUTHORIZED=authorized)),\
                 patch.object(windows,'windows_host',return_value=host),patch.object(windows,'native_command') as native,\
                 patch('windows_native_admission.consume') as consume:
                self.assertRaises(ValueError,windows.produce,row,Path('/unused.zip'),context={'runId':42,'runAttempt':1})
                native.assert_not_called();consume.assert_not_called()


class WindowsSchemaControls(unittest.TestCase):
    def schemas(self):
        return [json.loads((index.ROOT/'release/ci'/name).read_text()) for name in
                ('native-release-index.schema.json','native-release-contract.schema.json')]

    def binding(self, document, row):
        schema={'$defs':document['$defs'], **document['$defs']['nativeExecutionBinding']}
        jsonschema.Draft202012Validator(schema).validate(row)

    def test_exact_windows_definition_and_all_embedded_binding_schemas(self):
        documents=self.schemas();row=windows_row_fixture()
        self.assertEqual(documents[0]['$defs']['windowsExecution'],documents[1]['$defs']['windowsExecution'])
        for document in documents:
            self.binding(document,row)
            for change in [lambda r:r.update(target='linux/amd64'),lambda r:r['variant'].update(legacy=True),
                           lambda r:r['finalPackageCronetSmoke'].update(os='linux'),
                           lambda r:r['finalPackageCronetSmoke'].pop('windowsExecution'),
                           lambda r:r['finalPackageCronetSmoke'].__setitem__('macosExecution',r['finalPackageCronetSmoke']['windowsExecution']),
                           lambda r:r['core'].pop('member')]:
                bad=copy.deepcopy(row);change(bad)
                with self.subTest(change=change),self.assertRaises(jsonschema.ValidationError):self.binding(document,bad)

    def test_key_schema_mismatch_does_not_enter_another_native_validator(self):
        row=windows_row_fixture();proof=row['finalPackageCronetSmoke']['windowsExecution']
        proof['schema']='polaris-macos-native-execution-proof-v1'
        with patch.object(index,'derive_trusted_execution') as derive:
            self.assertRaisesRegex(ValueError,'key/schema',index.validate_trusted_execution,row,{'runId':42,'runAttempt':1})
            derive.assert_not_called()
