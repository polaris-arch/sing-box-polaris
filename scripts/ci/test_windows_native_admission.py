"""Synthetic metadata controls only, never native execution or SYSTEM authority.

Every HTTP/Git operation is mocked. No token, runner, protection change, native
producer or system functionality is used by these ordinary source tests.
"""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import windows_native_admission as admission
from github_read_transport import ReadFailure

SOURCE = 'a' * 40
TAG_OBJECT = 'c' * 40
VERSION = '1.15.0-polaris-alpha.12.9'
TAG = 'v' + VERSION


def environment(os_name='Linux'):
    return {'GITHUB_ACTIONS':'true','GITHUB_EVENT_NAME':'workflow_dispatch',
            'WINDOWS_NATIVE_PROOF_REQUESTED':'true','WINDOWS_NATIVE_BUILD':'All',
            'WINDOWS_NATIVE_EVIDENCE_MODE':'final','WINDOWS_NATIVE_SOURCE_GENERATE_ONLY':'false',
            'GITHUB_REPOSITORY':'polaris-arch/sing-box-polaris','GITHUB_REPOSITORY_ID':'1421657509',
            'GITHUB_SHA':SOURCE,'GITHUB_WORKFLOW_SHA':SOURCE,'WINDOWS_NATIVE_VERSION':VERSION,
            'GITHUB_REF':'refs/tags/'+TAG,
            'GITHUB_WORKFLOW_REF':'polaris-arch/sing-box-polaris/.github/workflows/build.yml@refs/tags/'+TAG,
            'GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1','RUNNER_OS':os_name,
            'EXPECTED_RELEASE_TAG_OBJECT':TAG_OBJECT}


def metadata():
    started = (datetime.now(timezone.utc)-timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    repository = {'id':1421657509,'full_name':'polaris-arch/sing-box-polaris'}
    run = {'id':1,'run_attempt':1,'head_sha':SOURCE,'head_branch':TAG,'event':'workflow_dispatch',
           'path':'.github/workflows/build.yml','repository':repository,'head_repository':copy.deepcopy(repository),
           'run_started_at':started}
    protection = {'id':11,'name':'polaris-windows-native-proof',
                  'deployment_branch_policy':{'protected_branches':False,'custom_branch_policies':True},
                  'protection_rules':[{'id':22,'type':'required_reviewers','prevent_self_review':False,
                                       'reviewers':[{'type':'User','reviewer':{'id':33}}]},
                                      {'id':23,'type':'branch_policy'}]}
    policies = {'total_count':1,'branch_policies':[{'id':44,'name':TAG,'type':'tag'}]}
    return [run,protection,policies]


def receipt_fixture():
    started = metadata()[0]['run_started_at']
    context = {'repository':'polaris-arch/sing-box-polaris','repositoryId':1421657509,
               'sourceCommit':SOURCE,'workflowCommit':SOURCE,'runId':1,'runAttempt':1,'ref':'refs/tags/'+TAG}
    facts = {'id':11,'name':'polaris-windows-native-proof','reviewRuleId':22,'preventSelfReview':False,
             'reviewers':[{'type':'User','id':33}],'tagPolicyId':44,'tagPolicyName':TAG,'tagPolicyType':'tag'}
    reads = [{'phase':phase,'readAttempt':1,'readStatus':200,'readHeaders':{'content-type':'application/json'},
              'readBytes':2,'readSHA256':hashlib.sha256(b'{}').hexdigest(),'readError':None,'extraGETs':0}
             for phase in ['current_run','protected_environment','exact_tag_policy']]
    return {'schema':'polaris-windows-native-admission-v1','context':context,'tagObject':TAG_OBJECT,
            'runStartedAt':started,'checkedAt':datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'environment':facts,'reads':reads}


def transport(documents, failure=None, alter=None, clock=None):
    calls = []
    def request(path,sink,max_bytes,timeout):
        index = len(calls)
        calls.append((path,max_bytes,timeout))
        if failure is not None and failure[0] == index: raise failure[1]
        document = documents[index]
        raw = document if type(document) is bytes else json.dumps(document,separators=(',',':')).encode()
        sink.write(raw)
        result = {'status':200,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                  'headers':{'content-type':'application/json','x-github-request-id':'synthetic-read'}}
        if alter: alter(index,result)
        if clock is not None: clock(index)
        return result
    return request,calls


class WindowsAdmissionContextControls(unittest.TestCase):
    def test_exact_seven_context_fields_and_binary_or_all_only(self):
        for build in ['All','Binary']:
            env=environment();env['WINDOWS_NATIVE_BUILD']=build
            self.assertEqual(admission.context(env),receipt_fixture()['context'])
            self.assertEqual(set(admission.context(env)),{'repository','repositoryId','sourceCommit','workflowCommit','runId','runAttempt','ref'})

    def test_missing_wrong_source_tag_workflow_repository_and_scope_fail(self):
        changes={'GITHUB_ACTIONS':['false',True], 'GITHUB_EVENT_NAME':['push','workflow_call'],
                 'WINDOWS_NATIVE_PROOF_REQUESTED':['false',True], 'WINDOWS_NATIVE_BUILD':['Docker','all'],
                 'WINDOWS_NATIVE_EVIDENCE_MODE':['staging'], 'WINDOWS_NATIVE_SOURCE_GENERATE_ONLY':['true',False],
                 'GITHUB_REPOSITORY':['other/repository'], 'GITHUB_REPOSITORY_ID':[1421657509,'1'],
                 'GITHUB_SHA':['f'*40,'0'*40,'A'*40,True], 'GITHUB_WORKFLOW_SHA':['f'*40],
                 'GITHUB_REF':['refs/heads/'+TAG,'refs/tags/v1.15.0-polaris-alpha.12.8'],
                 'GITHUB_WORKFLOW_REF':['other/repo/.github/workflows/build.yml@refs/tags/'+TAG],
                 'WINDOWS_NATIVE_VERSION':['../../tag']}
        for key,values in changes.items():
            for value in [None,*values]:
                with self.subTest(key=key,value=value):
                    env=environment();env[key]=value
                    self.assertRaises(ValueError,admission.context,env)

    def test_run_attempt_numeric_strings_are_positive_bounded_and_not_aliases(self):
        for key in ['GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT']:
            for value in [True,1,1.0,'0','-1','01','1.0','+1',' 1','1\n',str(2**64),'9'*100]:
                with self.subTest(key=key,value=value):
                    env=environment();env[key]=value
                    self.assertRaises(ValueError,admission.context,env)


class WindowsProtectionControls(unittest.TestCase):
    def test_actual_projection_nonempty_reviewers_and_exact_tag_policy(self):
        _,raw,policies=metadata()
        raw['api_extra']='not a native fact'
        self.assertEqual(admission.environment_facts(raw,policies,TAG),receipt_fixture()['environment'])
        raw['protection_rules'][0]['reviewers'].append({'type':'Team','reviewer':{'id':33}})
        result=admission.environment_facts(raw,policies,TAG)
        self.assertEqual(result['reviewers'],[{'type':'User','id':33},{'type':'Team','id':33}])
        self.assertNotIn('api_extra',result);self.assertNotIn('actor',result)

    def test_environment_shape_protection_booleans_and_ids_reject_aliases(self):
        changes=[lambda e:e.update(id=True),lambda e:e.update(id=11.0),lambda e:e.update(id=0),
                 lambda e:e.update(name='lookalike-environment'),lambda e:e.update(deployment_branch_policy=None),
                 lambda e:e['deployment_branch_policy'].update(protected_branches=0),
                 lambda e:e['deployment_branch_policy'].update(custom_branch_policies=1),
                 lambda e:e.update(protection_rules=[]),lambda e:e['protection_rules'].append(None),
                 lambda e:e['protection_rules'].append({'id':24,'type':'unknown_protection'}),
                 lambda e:e['protection_rules'].append(copy.deepcopy(e['protection_rules'][0])),
                 lambda e:e['protection_rules'][0].update(id=True),
                 lambda e:e['protection_rules'][0].update(prevent_self_review=0),
                 lambda e:e['protection_rules'][0].pop('prevent_self_review'),
                 lambda e:e['protection_rules'][0].update(reviewers=[]),
                 lambda e:e['protection_rules'][0].update(reviewers=[None]),
                 lambda e:e['protection_rules'][0]['reviewers'][0].update(type='Bot'),
                 lambda e:e['protection_rules'][0]['reviewers'][0]['reviewer'].update(id=True),
                 lambda e:e['protection_rules'][0]['reviewers'][0]['reviewer'].update(id=33.0),
                 lambda e:e['protection_rules'][0]['reviewers'].append(copy.deepcopy(e['protection_rules'][0]['reviewers'][0])),
                 lambda e:e['protection_rules'].append({'id':25,'type':'wait_timer','wait_timer':True})]
        for change in changes:
            with self.subTest(change=change):
                _,raw,policies=metadata();change(raw)
                self.assertRaises(ValueError,admission.environment_facts,raw,policies,TAG)

    def test_policy_requires_single_complete_tag_not_branch_wildcard_or_missing_type(self):
        changes=[lambda p:p.update(total_count=True),lambda p:p.update(total_count=1.0),lambda p:p.update(total_count=2),
                 lambda p:p.update(branch_policies=[]),lambda p:p['branch_policies'].append(copy.deepcopy(p['branch_policies'][0])),
                 lambda p:p['branch_policies'].__setitem__(0,None),lambda p:p['branch_policies'][0].update(id=True),
                 lambda p:p['branch_policies'][0].update(id=44.0),lambda p:p['branch_policies'][0].update(type='branch'),
                 lambda p:p['branch_policies'][0].pop('type'),lambda p:p['branch_policies'][0].update(name='*'),
                 lambda p:p['branch_policies'][0].update(name='v1.15.0-polaris-alpha.12.8')]
        for change in changes:
            with self.subTest(change=change):
                _,raw,policies=metadata();change(policies)
                self.assertRaises(ValueError,admission.environment_facts,raw,policies,TAG)


class WindowsAdmissionAcquireControls(unittest.TestCase):
    def acquire(self,request,env=None,clock=None):
        with patch.object(admission,'_attempt',side_effect=request),\
             patch.object(admission,'local_checkout',return_value=TAG_OBJECT) as checkout,\
             patch.object(admission.time,'monotonic',side_effect=clock or (lambda:100)):
            value=admission.acquire(env or environment())
        checkout.assert_called_once()
        return value

    def test_exactly_three_bounded_actual_gets_no_retry_no_implicit_tag_gets(self):
        request,calls=transport(metadata())
        receipt=self.acquire(request)
        self.assertEqual([item[0] for item in calls],[
            'repos/polaris-arch/sing-box-polaris/actions/runs/1',
            'repos/polaris-arch/sing-box-polaris/environments/polaris-windows-native-proof',
            'repos/polaris-arch/sing-box-polaris/environments/polaris-windows-native-proof/deployment-branch-policies?per_page=100&page=1'])
        self.assertTrue(all(item[1]==1024*1024 and 0<item[2]<=15 for item in calls))
        self.assertEqual([x['phase'] for x in receipt['reads']],list(admission.PHASES))
        self.assertTrue(all(x['readAttempt']==1 and x['extraGETs']==0 for x in receipt['reads']))
        self.assertEqual(receipt['environment'],receipt_fixture()['environment'])
        self.assertNotIn('trustedExecution',receipt);self.assertNotIn('native',receipt)

    def test_permission_missing_notfound_transient_and_timeout_stop_without_followup(self):
        failures=[ReadFailure('HTTP response',403),ReadFailure('HTTP response',404),
                  ReadFailure('HTTP response',503,retryable=True),ReadFailure('read deadline',retryable=True)]
        for index in range(3):
            for error in failures:
                with self.subTest(index=index,error=str(error)):
                    request,calls=transport(metadata(),failure=(index,error))
                    with self.assertRaises(ReadFailure):self.acquire(request)
                    self.assertEqual(len(calls),index+1)

    def test_malformed_run_or_environment_stops_before_next_endpoint(self):
        changes=[(0,lambda d:d.update(id=True)),(0,lambda d:d.update(run_attempt=2)),
                 (0,lambda d:d.update(head_sha='f'*40)),(0,lambda d:d['repository'].update(id=True)),
                 (0,lambda d:d['head_repository'].update(full_name='other/repo')),
                 (0,lambda d:d.update(run_started_at='2099-01-01T00:00:00Z')),
                 (1,lambda d:d.update(protection_rules=[])),(1,lambda d:d.update(id=11.0))]
        for index,change in changes:
            with self.subTest(index=index,change=change):
                documents=metadata();change(documents[index]);request,calls=transport(documents)
                with self.assertRaises(ValueError):self.acquire(request)
                self.assertEqual(len(calls),index+1)
        for index in [0,1,2]:
            for raw in [b'{}{}',b'{"id":1,"id":2}',b'\xff',b'\xef\xbb\xbf{}',b'NaN']:
                documents=metadata();documents[index]=raw;request,calls=transport(documents)
                with self.subTest(index=index,raw=raw),self.assertRaises((ValueError,UnicodeError)):self.acquire(request)
                self.assertEqual(len(calls),index+1)

    def test_transport_status_digest_bytes_and_safe_headers_are_not_trusted_implicitly(self):
        changes=[lambda r:r.update(status=204),lambda r:r.update(status=200.0),lambda r:r.update(bytes=True),
                 lambda r:r.update(bytes=float(r['bytes'])),lambda r:r.update(sha256='f'*64),
                 lambda r:r.update(headers={'authorization':'synthetic forbidden header'}),
                 lambda r:r.update(headers={'content-type':'application/json\r\nunsafe'})]
        for change in changes:
            request,calls=transport(metadata(),alter=lambda i,r,c=change:c(r))
            with self.subTest(change=change),self.assertRaises(ValueError):self.acquire(request)
            self.assertEqual(len(calls),1)
        documents=metadata();documents[0]=b'x'*(1024*1024+1);request,calls=transport(documents)
        with self.assertRaises(ValueError):self.acquire(request)
        self.assertEqual(len(calls),1)

    def test_ninety_second_total_deadline_covers_checkout_and_actual_gets(self):
        request,calls=transport(metadata())
        with self.assertRaisesRegex(ValueError,'deadline'):self.acquire(request,clock=iter([0,91]).__next__)
        self.assertEqual(calls,[])
        now=[0.0]
        def advance(index):now[0]=90.01
        request,calls=transport(metadata(),clock=advance)
        with self.assertRaisesRegex(ValueError,'deadline'):self.acquire(request,clock=lambda:now[0])
        self.assertEqual(len(calls),1)
        # When only one second remains, the fixed request gets that one second.
        request,calls=transport(metadata())
        sequence=iter([0,89,89,89,89,89,89,89])
        self.acquire(request,clock=sequence.__next__)
        self.assertTrue(all(0<item[2]<=1 for item in calls))

    def test_windows_host_and_unpinned_annotated_tag_cannot_start_metadata_gets(self):
        with patch.object(admission,'_attempt') as get:
            self.assertRaises(ValueError,admission.acquire,environment('Windows'));get.assert_not_called()
        for pin in [None,True,'0'*40,'bad','C'*40]:
            env=environment();env['EXPECTED_RELEASE_TAG_OBJECT']=pin
            with patch.object(admission,'_attempt') as get,patch.object(admission,'_git') as git:
                self.assertRaises(ValueError,admission.acquire,env);get.assert_not_called();git.assert_not_called()


class WindowsAdmissionCheckoutControls(unittest.TestCase):
    def values(self):
        return [SOURCE,'','tag',TAG_OBJECT,'object '+SOURCE+'\ntype commit\ntag '+TAG+'\ntagger Synthetic Source <none@invalid> 0 +0000\n\nsynthetic message']

    def test_local_annotated_direct_tag_rebind_has_no_remote_or_credentials(self):
        with patch.object(admission,'_git',side_effect=self.values()) as git,patch.object(admission,'_attempt') as http:
            self.assertEqual(admission.local_checkout(receipt_fixture()['context'],TAG_OBJECT,100),TAG_OBJECT)
            self.assertEqual(git.call_count,5);http.assert_not_called()
        values=self.values();values[-1]+='\nobject unrelated-message'
        with patch.object(admission,'_git',side_effect=values):
            self.assertEqual(admission.local_checkout(receipt_fixture()['context'],TAG_OBJECT,100),TAG_OBJECT)

    def test_wrong_dirty_lightweight_nested_or_moved_tag_stops_checkout(self):
        changes=[(0,'f'*40),(1,' M source.go'),(2,'commit'),(3,'f'*40),
                 (4,'object '+TAG_OBJECT+'\ntype tag\ntag '+TAG),
                 (4,'object '+SOURCE+'\ntype commit\ntag other-tag'),
                 (4,'object '+SOURCE+'\nobject '+SOURCE+'\ntype commit\ntag '+TAG)]
        for index,value in changes:
            with self.subTest(index=index,value=value):
                values=self.values();values[index]=value
                with patch.object(admission,'_git',side_effect=values) as git:
                    self.assertRaises(ValueError,admission.local_checkout,receipt_fixture()['context'],TAG_OBJECT,100)
                    self.assertEqual(git.call_count,index+1)

    def test_git_commands_are_bounded_readonly_and_do_not_refresh_index_or_fsmonitor(self):
        with patch.object(admission.time,'monotonic',return_value=100),\
             patch.object(admission.subprocess,'check_output',return_value=b'synthetic\n') as command:
            self.assertEqual(admission._git(101,'rev-parse','HEAD'),'synthetic')
        self.assertEqual(command.call_args.args[0],['git','--no-optional-locks','-c','core.fsmonitor=false','-C',str(admission.ROOT),'rev-parse','HEAD'])
        self.assertEqual(command.call_args.kwargs['timeout'],1)
        self.assertIs(command.call_args.kwargs['stderr'],subprocess.DEVNULL)
        for raw in [b'x'*65537,b'\xff']:
            with patch.object(admission.time,'monotonic',return_value=100),\
                 patch.object(admission.subprocess,'check_output',return_value=raw):
                self.assertRaises((ValueError,UnicodeError),admission._git,101,'status','--porcelain','--untracked-files=no')
        with patch.object(admission.time,'monotonic',return_value=101),patch.object(admission.subprocess,'check_output') as command:
            self.assertRaises(ValueError,admission._git,100,'rev-parse','HEAD');command.assert_not_called()


class WindowsAdmissionConsumeControls(unittest.TestCase):
    def consume(self,receipt,env=None):
        with patch.object(admission,'local_checkout',return_value=TAG_OBJECT) as checkout,\
             patch.object(admission,'_attempt') as http:
            result=admission.consume(receipt,env or environment('Windows'))
            http.assert_not_called()
        checkout.assert_called_once()
        return result

    def rejects_before_checkout(self,change):
        receipt=receipt_fixture();change(receipt)
        with patch.object(admission,'local_checkout') as checkout,patch.object(admission,'_attempt') as http:
            self.assertRaises(ValueError,admission.consume,receipt,environment('Windows'))
            checkout.assert_not_called();http.assert_not_called()

    def test_token_free_consume_rechecks_same_context_without_granting_native_authority(self):
        class CredentialPoison(dict):
            def get(self,key,*args):
                if key in ('GH_TOKEN','GITHUB_TOKEN','TOKEN','ACTIONS_ID_TOKEN_REQUEST_TOKEN'):
                    raise AssertionError('credentials must not be inspected')
                return super().get(key,*args)
        receipt=receipt_fixture()
        self.assertIs(self.consume(receipt,CredentialPoison(environment('Windows'))),receipt)
        self.assertNotIn('trustedExecution',receipt);self.assertNotIn('actor',receipt)
        self.assertNotIn('native',receipt);self.assertNotIn('publicationEligible',receipt)

    def test_receipt_context_exact_types_source_workflow_tag_run_and_attempt(self):
        for key,value in [('repository','other/repo'),('repositoryId',1421657509.0),('sourceCommit','f'*40),
                          ('workflowCommit','f'*40),('runId',True),('runId',1.0),('runAttempt',2),('runAttempt',True),
                          ('ref','refs/heads/'+TAG),('unexpected','extra')]:
            with self.subTest(key=key,value=value):
                self.rejects_before_checkout(lambda r,k=key,v=value:r['context'].__setitem__(k,v))
        for key in receipt_fixture()['context']:
            self.rejects_before_checkout(lambda r,k=key:r['context'].pop(k))
        for key,value in [('schema','other-schema'),('tagObject','0'*40),('tagObject','C'*40),
                          ('actor',{'sid':'S-1-5-18'}),('trustedExecution',{'purposes':['run-main-v1']})]:
            self.rejects_before_checkout(lambda r,k=key,v=value:r.__setitem__(k,v))

    def test_malformed_nested_shapes_numeric_aliases_reviewers_and_exact_policy_fail_closed(self):
        changes=[lambda r:r.update(environment=None),lambda r:r['environment'].update(id=True),
                 lambda r:r['environment'].update(id=11.0),lambda r:r['environment'].update(reviewRuleId=False),
                 lambda r:r['environment'].update(preventSelfReview=0),lambda r:r['environment'].update(reviewers=None),
                 lambda r:r['environment'].update(reviewers=[None]),lambda r:r['environment'].update(reviewers=[]),
                 lambda r:r['environment']['reviewers'][0].update(id=True),
                 lambda r:r['environment']['reviewers'][0].update(id=33.0),
                 lambda r:r['environment']['reviewers'][0].update(type='Bot'),
                 lambda r:r['environment']['reviewers'][0].update(extra='ignored?'),
                 lambda r:r['environment']['reviewers'].append(copy.deepcopy(r['environment']['reviewers'][0])),
                 lambda r:r['environment'].update(tagPolicyId=True),lambda r:r['environment'].update(tagPolicyType='branch'),
                 lambda r:r['environment'].update(tagPolicyName='*'),lambda r:r['environment'].update(extra='ignored?'),
                 lambda r:r['environment'].pop('reviewers')]
        for change in changes:
            with self.subTest(change=change):self.rejects_before_checkout(change)

    def test_read_family_shape_order_bool_aliases_retry_errors_and_unsafe_headers_fail(self):
        changes=[lambda r:r.update(reads=None),lambda r:r['reads'].pop(),
                 lambda r:r['reads'].append(copy.deepcopy(r['reads'][0])),lambda r:r['reads'].reverse(),
                 lambda r:r['reads'][0].update(readAttempt=True),lambda r:r['reads'][0].update(readAttempt=1.0),
                 lambda r:r['reads'][0].update(readStatus=204),lambda r:r['reads'][0].update(readStatus=200.0),
                 lambda r:r['reads'][0].update(extraGETs=False),lambda r:r['reads'][0].update(extraGETs=1),
                 lambda r:r['reads'][0].update(readError='permission denied'),lambda r:r['reads'][0].update(readBytes=True),
                 lambda r:r['reads'][0].update(readBytes=1024*1024+1),lambda r:r['reads'][0].update(readSHA256='bad'),
                 lambda r:r['reads'][0].update(readHeaders={'location':'https://invalid/?signed=synthetic'}),
                 lambda r:r['reads'][0].update(readHeaders={'content-type':'json\nheader'}),
                 lambda r:r['reads'][0].update(readHeaders={'content-type':False}),
                 lambda r:r['reads'][0].update(extra='field')]
        for change in changes:
            with self.subTest(change=change):self.rejects_before_checkout(change)

    def test_timestamps_size_depth_and_windows_job_context_are_required(self):
        future=(datetime.now(timezone.utc)+timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        for key,value in [('checkedAt',future),('checkedAt','1970-01-01T00:00:00Z'),
                          ('runStartedAt',future),('checkedAt','2026-02-30T00:00:00Z'),('checkedAt',True)]:
            self.rejects_before_checkout(lambda r,k=key,v=value:r.__setitem__(k,v))
        self.rejects_before_checkout(lambda r:r.update(schema='x'*65537))
        self.rejects_before_checkout(lambda r:r['reads'][0].update(readBytes=1.0))
        nested={};leaf=nested
        for _ in range(20):leaf['nested']={};leaf=leaf['nested']
        self.rejects_before_checkout(lambda r:r.update(environment=nested))
        with patch.object(admission,'local_checkout') as checkout,patch.object(admission,'_attempt') as http:
            self.assertRaises(ValueError,admission.consume,receipt_fixture(),environment('Linux'))
            checkout.assert_not_called();http.assert_not_called()

    def test_actual_checkout_failure_never_falls_back_to_network_or_ordinary_evidence(self):
        with patch.object(admission,'local_checkout',side_effect=ValueError('wrong actual tag')) as checkout,\
             patch.object(admission,'_attempt') as http:
            self.assertRaises(ValueError,admission.consume,receipt_fixture(),environment('Windows'))
            checkout.assert_called_once();http.assert_not_called()

    def test_cli_rejects_oversize_duplicate_bad_encoding_and_trailing_receipt_before_consume(self):
        for raw in ['x'*65537,'{}{}','{"schema":1,"schema":2}','\ufeff{}','NaN']:
            with self.subTest(raw=raw[:40]),patch.object(sys,'argv',['windows_native_admission.py']),\
                 patch.dict(admission.os.environ,{'POLARIS_WINDOWS_NATIVE_ADMISSION_RECEIPT':raw}),\
                 patch.object(admission,'consume') as consume,patch.object(admission,'_attempt') as http:
                self.assertRaises(ValueError,admission.main);consume.assert_not_called();http.assert_not_called()
