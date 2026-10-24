"""Runner controls, not Naive/MASQUE protocol PASS or native-core execution."""
import ast
import contextlib
import shlex
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import copy
import re
import yaml
import zipfile
from unittest import mock

import protocol_peer as peer
import protocol_peer_diagnostic as diagnostic

ROOT = Path(__file__).resolve().parents[2]


def normal_build_matrix(matrix):
    if isinstance(matrix, dict):return copy.deepcopy(matrix)
    match=re.fullmatch(r"\$\{\{ fromJSON\(inputs\.build == 'NativePeerLinux' && '(.*?)' \|\| '(.*?)'\) \}\}",matrix)
    if match is None:raise AssertionError('unexpected native matrix expression')
    narrow,normal=map(json.loads,match.groups())
    if narrow!={'include':[{'os':'linux','arch':'amd64','variant':'purego','naive':True}]}:
        raise AssertionError('Linux peer build is not the exact existing native row')
    if narrow['include'][0] not in normal['include']:raise AssertionError('new peer row is not an original producer')
    return normal


def native_smoke_dependency_contract(workflow, source_dir=ROOT/'scripts/ci'):
    """Cover both peer modes and all smoke branches, without importing product code."""
    todo = ['test_protocol_peer', 'protocol_peer', 'protocol_peer_diagnostic', 'native_release_index']
    visited, external = set(), set()
    while todo:
        name = todo.pop()
        if name in visited:
            continue
        visited.add(name)
        tree = ast.parse((source_dir/(name+'.py')).read_text())
        for node in ast.walk(tree):
            imports = []
            if isinstance(node, ast.Import):
                imports = [entry.name for entry in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.level:
                    raise AssertionError('relative native smoke import needs explicit closure review')
                imports = [node.module]
            elif isinstance(node, ast.Call) and ((isinstance(node.func, ast.Name) and node.func.id == '__import__')
                    or (isinstance(node.func, ast.Attribute) and node.func.attr == 'import_module')):
                if not node.args or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
                    raise AssertionError('dynamic native smoke import is not statically bound')
                imports = [node.args[0].value]
            for imported in imports:
                module = imported.split('.')[0]
                if (source_dir/(module+'.py')).is_file():
                    todo.append(module)
                elif module not in sys.stdlib_module_names:
                    external.add(module)
    if external != {'yaml', 'jsonschema'}:
        raise AssertionError('native smoke external import closure changed: '+repr(sorted(external)))
    steps = workflow['jobs']['native_smoke']['steps']
    installs = [step for step in steps if step.get('name') == 'Install native smoke and peer validators']
    if len(installs) != 1:
        raise AssertionError('exactly one unconditional native dependency installer required')
    install = installs[0]
    if ('if' in install or 'continue-on-error' in install
            or shlex.split(install.get('run', '')) != ['python', '-m', 'pip', 'install', 'PyYAML==6.0.2', 'jsonschema==4.23.0']):
        raise AssertionError('native smoke dependencies must use both reviewed exact pins unconditionally')
    installer_index = steps.index(install)
    python_steps = [i for i, step in enumerate(steps) if step.get('uses', '').startswith('actions/setup-python@')]
    if len(python_steps) != 1 or python_steps[0] >= installer_index:
        raise AssertionError('native dependency installer must follow the selected Python runtime')
    for name in ('Acquire only the frozen original Linux carrier for QA', 'Execute final-package Cronet smoke',
                 'Verify controlled native peer runner contracts',
                 'Execute same-run Linux native Naive and MASQUE controlled peers',
                 'Diagnose the original Linux product with separately bound QA code'):
        consumers = [i for i, step in enumerate(steps) if step.get('name') == name]
        if len(consumers) != 1 or consumers[0] <= installer_index:
            raise AssertionError('native dependencies must precede every smoke/peer consumer')
    return visited, external


class ControlledPeerContracts(unittest.TestCase):
    def test_native_smoke_python_dependency_closure_and_install_order(self):
        workflow = yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text())
        modules, external = native_smoke_dependency_contract(workflow)
        self.assertEqual(external, {'yaml', 'jsonschema'})
        self.assertEqual(modules, {'test_protocol_peer', 'protocol_peer', 'protocol_peer_diagnostic',
            'native_release_index', 'tls_fingerprint_probe', 'release_identity', 'polaris_version',
            'apple_package_overlays', 'legacy_binary_version'})

    def test_native_smoke_dependency_omission_or_conditional_or_late_install_is_rejected(self):
        original = yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text())
        for mutation in ('omit-yaml', 'omit-jsonschema', 'wrong-version', 'conditional', 'ignore-failure', 'late'):
            with self.subTest(mutation=mutation):
                workflow = copy.deepcopy(original)
                steps = workflow['jobs']['native_smoke']['steps']
                step = next(item for item in steps if item.get('name') == 'Install native smoke and peer validators')
                if mutation == 'omit-yaml': step['run'] = step['run'].replace('PyYAML==6.0.2 ', '')
                elif mutation == 'omit-jsonschema': step['run'] = step['run'].replace(' jsonschema==4.23.0', '')
                elif mutation == 'wrong-version': step['run'] = step['run'].replace('6.0.2', '6.0.3')
                elif mutation == 'conditional': step['if'] = "inputs.build != 'NativePeerDiagnostic'"
                elif mutation == 'ignore-failure': step['continue-on-error'] = True
                else: steps.remove(step); steps.append(step)
                with self.assertRaises(AssertionError): native_smoke_dependency_contract(workflow)

    def test_native_smoke_new_external_or_dynamic_import_requires_review(self):
        workflow = yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text())
        modules, _ = native_smoke_dependency_contract(workflow)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            for name in modules:
                (source/(name+'.py')).write_bytes((ROOT/'scripts/ci'/(name+'.py')).read_bytes())
            file = source/'protocol_peer.py'
            original = file.read_text()
            for extra in ('import requests', '__import__("requests")', '__import__(unreviewed_module_name)'):
                with self.subTest(extra=extra):
                    file.write_text(original+'\n'+extra+'\n')
                    with self.assertRaises(AssertionError): native_smoke_dependency_contract(workflow, source)

    def test_linux_exact_source_dispatch_is_staging_only(self):
        valid={'GITHUB_ACTIONS':'true','RUNNER_OS':'Linux','GITHUB_EVENT_NAME':'workflow_dispatch',
               'PEER_BUILD':'NativePeerLinux','PEER_EVIDENCE_MODE':'staging','PEER_SOURCE_GENERATE_ONLY':'false',
               'PEER_VERSION':'1.15.0-polaris-alpha.12.3','GITHUB_REPOSITORY':diagnostic.REPOSITORY,
               'GITHUB_REPOSITORY_ID':str(diagnostic.REPOSITORY_ID)}
        peer.validate_linux_dispatch(valid)
        for key,wrong in [('PEER_BUILD','Binary'),('PEER_EVIDENCE_MODE','final'),('PEER_SOURCE_GENERATE_ONLY','true'),
                          ('PEER_VERSION','1.15.0-polaris-alpha.12.2'),('GITHUB_EVENT_NAME','push'),
                          ('GITHUB_REPOSITORY','other/repo'),('GITHUB_REPOSITORY_ID','1'),
                          ('GITHUB_ACTIONS','false'),('RUNNER_OS','Windows')]:
            with self.subTest(key=key),self.assertRaises(ValueError):peer.validate_linux_dispatch(dict(valid,**{key:wrong}))

    def test_linux_selector_preserves_default_matrix_and_does_not_publish(self):
        workflow=yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text())
        jobs=workflow['jobs']; build=jobs['build']; pre=jobs['calculate_version']; smoke=jobs['native_smoke']
        normal=normal_build_matrix(build['strategy']['matrix'])
        baseline=json.loads((ROOT/'release/ci/upstream-matrices.json').read_text())['matrices']['build.yml']['build']
        self.assertCountEqual(normal['include']+jobs['build_windows7']['strategy']['matrix']['include'],baseline['include'])
        self.assertEqual(build['needs'],['calculate_version'])
        self.assertIn("inputs.build == 'NativePeerLinux'",build['if'])
        self.assertIn("|| inputs.build == 'NativePeerLinux'",pre['if'])
        guard=next(s for s in pre['steps'] if s.get('name')=='Reject incompatible exact-source Linux peer inputs')
        self.assertEqual(guard['if'],"inputs.build == 'NativePeerLinux'")
        self.assertEqual(guard['run'],'python3 -B scripts/ci/protocol_peer.py --validate-linux-dispatch')
        tag=next(s for s in pre['steps'] if s.get('id')=='release_source')
        self.assertLess(pre['steps'].index(guard),pre['steps'].index(tag))
        self.assertIn("!failure()",smoke['if'])
        self.assertIn("inputs.build == 'NativePeerLinux'",smoke['if'])
        self.assertIn("(inputs.build == 'NativePeerDiagnostic' || inputs.build == 'NativePeerLinux')",smoke['strategy']['matrix'])
        for name,job in jobs.items():
            if name not in {'build','calculate_version','native_smoke'}:
                self.assertNotIn('NativePeerLinux',job.get('if',''),name)
        for step in build['steps']:
            if 'sudo' in step.get('run','') or 'docker run' in step.get('run',''):
                self.assertTrue(any(key in step.get('if','') for key in ('.debian','.rpm','.pacman','.openwrt','.alpine')),step['name'])
        self.assertEqual(workflow['permissions'],{'contents':'read'})

    def test_core_environment_does_not_inherit_tokens_or_injection(self):
        with mock.patch.dict(os.environ, {'GH_TOKEN':'secret', 'GITHUB_TOKEN':'secret', 'HTTP_PROXY':'proxy', 'LD_PRELOAD':'library'}):
            env = peer.core_environment(Path('/private/test'))
        self.assertEqual(set(env), {'PATH','HOME','TMPDIR','LANG','LC_ALL'})
        self.assertNotIn('secret', str(env))

    def test_configs_are_loopback_scoped_and_have_no_direct_client_fallback(self):
        for kind in ('naive-h2','naive-h3','masque-h3','masque-h3-on-demand'):
            with self.subTest(kind=kind):
                server, client = peer.configs(kind, 44001, 44002, 44003, 'CA', 'CERT', 'KEY', 'PASSWORD', [44004,44005])
                self.assertEqual(client['route']['rules'][-1], {'action':'reject'})
                self.assertEqual(server['route']['rules'][-1], {'action':'reject'})
                self.assertEqual(server['route']['rules'][0]['port'], [44004,44005])
                self.assertEqual(client['dns']['servers'][0]['type'], 'hosts')
                self.assertEqual(len(client['dns']['servers']), 1)
                self.assertEqual(client['dns']['servers'][0]['predefined'], {'controlled.invalid':['127.0.0.1']})
                endpoint = (client.get('outbounds') or client['endpoints'])[0]
                self.assertEqual(endpoint['server'], '127.0.0.1')
                self.assertEqual(endpoint['tls']['server_name'], 'controlled.invalid')
                self.assertNotIn('insecure', endpoint['tls'])
                self.assertEqual(endpoint['tls']['certificate'], ['CA'])
                self.assertNotIn('set_system_proxy', client['inbounds'][0])
                if kind.startswith('naive'):
                    self.assertEqual(server['inbounds'][0]['network'], 'tcp' if kind=='naive-h2' else 'udp')
                    self.assertEqual(endpoint['quic'], kind=='naive-h3')
                    self.assertNotIn('disable_version_fallback',endpoint)
                else:
                    self.assertFalse(endpoint['system'])
                    self.assertEqual(endpoint['version'],3)
                    self.assertTrue(endpoint['disable_version_fallback'])
                    self.assertEqual(server['endpoints'][0]['version'],[3])
                    self.assertEqual(server['endpoints'][0]['advertise_routes'],['198.18.0.1/32'])
                    self.assertEqual(endpoint['on_demand'],kind.endswith('on-demand'))

    def test_protocol_specific_auth_rejection_does_not_publish_username(self):
        for kind, raw, expected in [('naive-h3',b'authorization failed', 'authorization failed'),
                                    ('masque-h3',b'authentication failed: username=PRIVATE_TEST_USER', 'authentication failed: username=')]:
            result=peer.negative_evidence(kind,'wrong-auth',b'',raw)
            self.assertEqual(result['matchedAllowlistedFragment'],expected)
            self.assertEqual(result['logRole'],'peer')
            self.assertEqual(result['privateRawLogSHA256'],peer.digest(raw))
            self.assertNotIn('PRIVATE_TEST_USER',json.dumps(result))
        with self.assertRaisesRegex(RuntimeError,'lacks actual'):
            peer.negative_evidence('masque-h3','wrong-auth',b'timeout',b'')

    def test_negative_certificate_and_path_require_specific_evidence(self):
        for mutation, text in [('wrong-ca','ERR_CERT_AUTHORITY_INVALID'),('wrong-sni','certificate is valid for controlled.invalid, not wrong.invalid'),('wrong-path','unexpected status: 404')]:
            self.assertTrue(peer.negative_evidence('masque-h3',mutation,text,b'')['specificRejectionObserved'])
            with self.assertRaisesRegex(RuntimeError,'lacks actual'):
                peer.negative_evidence('masque-h3',mutation,b'generic timeout',b'')

    def test_exact_read_rejects_drip_beyond_absolute_deadline(self):
        sock=mock.Mock();sock.recv.return_value=b'x'
        with mock.patch.object(peer.time,'monotonic',side_effect=[0,.1,1,9]), mock.patch.object(peer,'SUITE_DEADLINE',None):
            with self.assertRaises(TimeoutError):peer.exact_read(sock,3)
        self.assertEqual(sock.recv.call_count,1)

    def test_exact_read_rejects_truncation(self):
        sock=mock.Mock();sock.recv.side_effect=[b'x',b'']
        with self.assertRaises(EOFError):peer.exact_read(sock,2)

    def test_suite_budget_does_not_return_negative_timeout(self):
        with mock.patch.object(peer,'SUITE_DEADLINE',10), mock.patch.object(peer.time,'monotonic',return_value=11):
            with self.assertRaises(TimeoutError):peer.remaining(8)

    def test_echo_partial_initialization_closes_own_socket(self):
        sock=mock.Mock();sock.bind.side_effect=OSError('bind failed')
        with mock.patch.object(peer.socket,'socket',return_value=sock), self.assertRaises(OSError):peer.Echo()
        sock.close.assert_called_once()

    def test_relay_partial_initialization_closes_each_acquired_socket(self):
        first=mock.Mock();second=mock.Mock();first.getsockname.return_value=('127.0.0.1',12345)
        second.connect.side_effect=OSError('connect failed')
        with mock.patch.object(peer.socket,'socket',side_effect=[first,second]), self.assertRaises(OSError):peer.UDPRelay(12346)
        first.close.assert_called_once();second.close.assert_called_once()

    def test_descendant_selection_never_includes_unknown_pid_or_ancestor(self):
        rows={1:{'ppid':0},10:{'ppid':1},11:{'ppid':10},12:{'ppid':11},13:{'ppid':1},14:{'ppid':13}}
        self.assertEqual(set(peer.descendant_rows(rows,10)),{11,12})

    @unittest.skipUnless(sys.platform=='linux','Linux pidfd runner only')
    def test_pid_reuse_does_not_signal_unknown_replacement(self):
        root=os.getpid();one={44:{'pid':44,'ppid':root,'startTicks':100,'state':'S'}}
        changed={44:{'pid':44,'ppid':root,'startTicks':101,'state':'S'}}
        with mock.patch.object(peer,'process_snapshot',side_effect=[one,changed]), mock.patch.object(peer.os,'waitpid',side_effect=ChildProcessError), mock.patch.object(peer.os,'pidfd_open',return_value=99), mock.patch.object(peer.os,'close') as close, mock.patch.object(peer.signal,'pidfd_send_signal') as send:
            with self.assertRaisesRegex(RuntimeError,'identity changed'):peer.drain_owned_children()
            send.assert_not_called();close.assert_called_once_with(99)

    def test_unknown_preexisting_children_rejects_scope_before_prctl(self):
        row={123:{'pid':123,'ppid':os.getpid(),'startTicks':1,'state':'S'}}
        with mock.patch.object(peer,'process_snapshot',return_value=row), mock.patch.object(peer.ctypes,'CDLL') as library:
            with self.assertRaisesRegex(RuntimeError,'unknown children'):
                with peer.owned_child_scope({}):pass
            library.assert_not_called()

    def test_echo_fixture_actual_tcp_udp_and_release(self):
        for udp in (False,True):
            echo=peer.Echo(udp=udp)
            try:
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as sock:
                    sock.settimeout(2);sock.connect(('127.0.0.1',echo.port))
                    sock.sendall(b'owned-fixture')
                    self.assertEqual(sock.recv(99),b'owned-fixture')
            finally:echo.close()
            self.assertEqual(echo.received,13)
            self.assertTrue(peer.assert_port_released(echo.port,udp)['released'])

    @unittest.skipUnless(sys.platform=='linux','Linux pidfd/subreaper runner only')
    def test_actual_parent_first_exit_and_setsid_child_is_reaped_but_not_pass(self):
        code=r'''
import json,os,subprocess,sys,time
import protocol_peer as p
receipt={}
try:
 with p.owned_child_scope(receipt):
  proc=subprocess.Popen([sys.executable,'-c',"import os,time; pid=os.fork(); (os._exit(0) if pid else None); os.setsid(); time.sleep(30)"])
  proc.wait(timeout=5)
  time.sleep(.1)
except RuntimeError as err:
 assert 'graceful cleanup failed' in str(err),str(err)
else: raise AssertionError('orphan recovery was incorrectly PASS')
assert receipt['descendantRetirement']['retired'],receipt
assert receipt['descendantRetirement']['remaining']==[],receipt
assert receipt['status']=='FAIL',receipt
print(json.dumps(receipt))
'''
        result=subprocess.run([sys.executable,'-B','-c',code],cwd=ROOT/'scripts/ci',capture_output=True,text=True,timeout=25)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'],'FAIL')

    @unittest.skipUnless(sys.platform=='linux','Linux pidfd/subreaper runner only')
    def test_actual_clean_child_exit_has_no_adoption_or_forced_cleanup(self):
        code="import subprocess,sys,json; import protocol_peer as p; r={};\nwith p.owned_child_scope(r):\n subprocess.run([sys.executable,'-c','pass'],check=True)\nprint(json.dumps(r))"
        result=subprocess.run([sys.executable,'-B','-c',code],cwd=ROOT/'scripts/ci',capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['descendantRetirement'],{'remaining':[],'forcedKill':False,'retired':[]})

    def test_retired_stream_timeout_is_unknown_not_closed(self):
        sock=mock.Mock();sock.send.side_effect=len;sock.recv.side_effect=socket.timeout()
        with self.assertRaisesRegex(RuntimeError,'unknown after timeout'):peer.retire_old_stream(sock)
        sock.close.assert_called_once()
        for outcome in (b'', ConnectionResetError(), BrokenPipeError()):
            sock=mock.Mock()
            sock.send.side_effect=len
            if isinstance(outcome,Exception):sock.recv.side_effect=outcome
            else:sock.recv.return_value=outcome
            self.assertTrue(peer.retire_old_stream(sock)['transportClosed'])
        sock=mock.Mock();sock.send.side_effect=len;sock.recv.return_value=b'late nonce'
        with self.assertRaisesRegex(RuntimeError,'returned a new payload'):peer.retire_old_stream(sock)

    def test_keep_connection_is_closed_when_payload_fails(self):
        sock=mock.Mock();sock.send.side_effect=len;sock.recv.return_value=b''
        with mock.patch.object(peer,'socks_connect',return_value=sock), self.assertRaises(EOFError):
            peer.tcp_exchange(1,'127.0.0.1',2,keep=True)
        sock.close.assert_called_once()

    def test_native_row_member_cannot_escape_or_disagree_with_archive(self):
        members={'sing-box':b'core','libcronet.so':b'library'}
        def row():return {kind:{'member':name,'bytes':len(members[name]),'sha256':peer.digest(members[name])} for kind,name in [('core','sing-box'),('sidecar','libcronet.so')]}
        peer.validate_executable_members(row(),members)
        for name in ('../sing-box','/usr/bin/python','absent','libcronet.so'):
            candidate=row();candidate['core']['member']=name
            with self.assertRaises(ValueError):peer.validate_executable_members(candidate,members)
        candidate=row();candidate['core']['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'raw bytes differ'):peer.validate_executable_members(candidate,members)

    def test_core_pidfd_acquisition_failure_closes_log_and_preserves_primary(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc=mock.Mock(pid=123456);proc.poll.return_value=0;proc.returncode=0
            with mock.patch.object(peer.subprocess,'Popen',return_value=proc), mock.patch.object(peer.os,'pidfd_open',side_effect=OSError('pidfd test failure')), mock.patch.object(peer,'process_group_members',return_value=[]):
                with self.assertRaisesRegex(OSError,'pidfd test failure'):
                    peer.CoreProcess(Path('/unused/core'),{},Path(tmp),'case','0'*64)
            # The log can be removed immediately and the failure is not masked.
            (Path(tmp)/'case.private.log').unlink()

    def test_generated_certificate_is_valid_only_for_declared_controlled_name(self):
        if not peer.shutil.which('openssl'):self.skipTest('existing OpenSSL absent')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);old=os.umask(0o077)
            try:ca,cert,key=peer.certificate(root,'test')
            finally:os.umask(old)
            self.assertIn('BEGIN CERTIFICATE',ca);self.assertIn('BEGIN PRIVATE KEY',key)
            valid=subprocess.run(['openssl','verify','-CAfile',str(root/'test-ca.pem'),'-verify_hostname','controlled.invalid',str(root/'test.pem')],capture_output=True)
            invalid=subprocess.run(['openssl','verify','-CAfile',str(root/'test-ca.pem'),'-verify_hostname','wrong.invalid',str(root/'test.pem')],capture_output=True)
            self.assertEqual(valid.returncode,0,valid.stderr)
            self.assertNotEqual(invalid.returncode,0)
            self.assertEqual((root/'test.key').stat().st_mode & 0o777,0o600)

    def test_native_workflow_is_same_run_linux_only_no_new_privilege(self):
        source=(ROOT/'.github/workflows/build.yml').read_text()
        job=source[source.index('  native_smoke:'):source.index('  native_index:')]
        start=job.index('    - name: Execute same-run Linux native Naive and MASQUE controlled peers')
        end=job.index('    - name:',start+5)
        control=job[start:end]
        self.assertIn("      if: matrix.id == 'linux-amd64-purego'",control)
        self.assertNotIn('env:',control);self.assertNotIn('continue-on-error:',control)
        self.assertIn('      timeout-minutes: 12',control)
        self.assertIn('permissions:\n  contents: read\n',source)
        self.assertLess(job.index('Execute final-package Cronet smoke'),start)
        self.assertIn('path: ${{ runner.temp }}/native-controlled-peer-public/receipt.json',job)
        self.assertNotIn('sudo',control)


class FixedNativeDiagnosticContracts(unittest.TestCase):
    def valid_env(self):
        return {'GITHUB_ACTIONS':'true','RUNNER_OS':'Linux','GITHUB_EVENT_NAME':'workflow_dispatch',
                'PEER_BUILD':diagnostic.MODE,'PEER_EVIDENCE_MODE':'staging','PEER_SOURCE_GENERATE_ONLY':'false',
                'PEER_VERSION':'1.15.0-polaris-alpha.12.3','GITHUB_REPOSITORY':diagnostic.REPOSITORY,
                'GITHUB_REPOSITORY_ID':str(diagnostic.REPOSITORY_ID)}

    def test_fixed_dispatch_rejects_incompatible_or_foreign_inputs(self):
        valid=self.valid_env(); diagnostic.validate_dispatch(valid)
        for key,wrong in [('PEER_BUILD','Binary'),('PEER_EVIDENCE_MODE','final'),('PEER_SOURCE_GENERATE_ONLY','true'),
                          ('PEER_VERSION','1.15.0-polaris-alpha.12.2'),('GITHUB_EVENT_NAME','push'),
                          ('GITHUB_REPOSITORY','other/repo'),('GITHUB_REPOSITORY_ID','1'),
                          ('GITHUB_ACTIONS','false'),('RUNNER_OS','Windows')]:
            with self.subTest(key=key), self.assertRaises(ValueError):diagnostic.validate_dispatch(dict(valid,**{key:wrong}))

    def origins(self):
        p=diagnostic.PRODUCER
        run={'id':p['run'],'run_attempt':p['attempt'],'head_sha':p['commit'],'path':'.github/workflows/build.yml',
             'event':'workflow_dispatch','status':'completed','repository':{'id':diagnostic.REPOSITORY_ID,'full_name':diagnostic.REPOSITORY}}
        jobs={'jobs':[{'id':p['job'],'conclusion':'success','status':'completed','head_sha':p['commit'],
                       'run_id':p['run'],'run_attempt':p['attempt']}]}
        artifact={'id':p['artifact'],'name':p['artifactName'],'size_in_bytes':p['zipBytes'],
            'digest':'sha256:'+p['zipSHA256'],'expired':False,'expires_at':'2099-01-01T00:00:00Z',
            'workflow_run':{'id':p['run'],'head_sha':p['commit'],'repository_id':diagnostic.REPOSITORY_ID,'head_repository_id':diagnostic.REPOSITORY_ID}}
        return run,jobs,artifact

    def test_origin_rejects_each_wrong_run_artifact_or_success_fact(self):
        run,jobs,artifact=self.origins();diagnostic.validate_origin(run,jobs,artifact)
        for target,key,value in [('run','head_sha','0'*40),('run','run_attempt',2),('run','id',1),
            ('artifact','expired',True),('artifact','digest','sha256:'+'0'*64),('artifact','id',1),
            ('artifact','name','arbitrary'),('artifact','expires_at','2000-01-01T00:00:00Z'),
            ('artifact','size_in_bytes',1)]:
            a,b,c=copy.deepcopy((run,jobs,artifact));(a if target=='run' else c)[key]=value
            with self.subTest(target=target,key=key),self.assertRaises(ValueError):diagnostic.validate_origin(a,b,c)
        a,b,c=copy.deepcopy((run,jobs,artifact));b['jobs'][0]['conclusion']='failure'
        with self.assertRaises(ValueError):diagnostic.validate_origin(a,b,c)
        for key in ('head_repository_id','repository_id','head_sha','id'):
            a,b,c=copy.deepcopy((run,jobs,artifact));c['workflow_run'][key]='wrong'
            with self.subTest(origin=key),self.assertRaises(ValueError):diagnostic.validate_origin(a,b,c)
        with self.assertRaises(ValueError):diagnostic.validate_origin(run,{'jobs':[]},artifact)

    def zip_fixture(self,mode=0o100644,extra=False):
        p=dict(diagnostic.PRODUCER)
        contents={p['archiveName']:b'archive',p['rowName']:b'row',p['manifestName']:b'manifest'}
        for prefix in ('archive','row','manifest'):
            raw=contents[p[prefix+'Name']];p[prefix+'Bytes']=len(raw);p[prefix+'SHA256']=diagnostic.sha(raw)
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as archive:
            for name,raw in contents.items():
                entry=zipfile.ZipInfo(name);entry.external_attr=mode<<16;archive.writestr(entry,raw)
            if extra:archive.writestr('../escape',b'foreign')
        raw=stream.getvalue();p['zipBytes']=len(raw);p['zipSHA256']=diagnostic.sha(raw)
        return p,raw,contents

    def test_exact_outer_zip_and_all_members_are_required_before_materialization(self):
        pins,raw,contents=self.zip_fixture()
        with mock.patch.object(diagnostic,'PRODUCER',pins):
            self.assertEqual(diagnostic.validate_zip(raw),contents)
            with self.assertRaises(ValueError):diagnostic.validate_zip(raw+b'changed')
            changed=dict(pins,rowSHA256='0'*64)
            with mock.patch.object(diagnostic,'PRODUCER',changed),self.assertRaises(ValueError):diagnostic.validate_zip(raw)
        for mode,extra in [(0o120777,False),(0o100755,False),(0o100644,True)]:
            pins,raw,_=self.zip_fixture(mode,extra)
            with mock.patch.object(diagnostic,'PRODUCER',pins),self.assertRaises(ValueError):diagnostic.validate_zip(raw)

    def clean_case(self,status='PASS'):
        return {'status':status,'fixturesJoined':True,'expectedCoreSHA256':'a'*64,'cleanup':[
            {'exitCode':0,'forcedKill':False,'remainingGroup':[],'cleanupErrorLog':False,
             'pid':123,'startIdentity':{'pid':123,'pgrp':123,'session':123,'startTicks':456},'boundCoreSHA256':'a'*64}],
            'descendantRetirement':{'remaining':[],'forcedKill':False,'retired':[]},
            'portsReleased':[{'released':True}]}

    def test_ordinary_failure_can_continue_only_after_complete_clean_retirement(self):
        clean=self.clean_case('FAIL');self.assertTrue(diagnostic.safe_to_continue(clean))
        for key,value in [('identityUncertain',True),('cleanupErrors',['unknown']),('fixturesJoined',False),
                          ('descendantRetirement',None),('portsReleased',[])]:
            with self.subTest(key=key):self.assertFalse(diagnostic.safe_to_continue(dict(clean,**{key:value})))
        for key,value in [('exitCode',2),('forcedKill',True),('remainingGroup',[123]),('cleanupErrorLog',True)]:
            changed=copy.deepcopy(clean);changed['cleanup'][0][key]=value
            with self.subTest(key=key):self.assertFalse(diagnostic.safe_to_continue(changed))
        for key,value in [('startIdentity',None),('boundCoreSHA256','0'*64),('pid',999)]:
            changed=copy.deepcopy(clean);changed['cleanup'][0][key]=value
            with self.subTest(identity=key):self.assertFalse(diagnostic.safe_to_continue(changed))

    def test_full_matrix_retains_ordinary_fail_and_continues_independent_cases(self):
        receipt={'cases':[]};executed=[]
        def execute(kind,mutation):
            executed.append((kind,mutation));return dict(self.clean_case('FAIL' if len(executed)==1 else 'PASS'),kind=kind,mutation=mutation)
        peer.execute_cases(receipt,execute,time.monotonic()+30)
        self.assertEqual(executed,peer.case_matrix());self.assertEqual(len(executed),14)
        self.assertEqual(receipt['cases'][0]['status'],'FAIL')
        self.assertEqual(sum(c['status']=='PASS' for c in receipt['cases']),13)

    def test_any_cleanup_or_identity_uncertainty_stops_entire_matrix(self):
        for failure in ({'cleanupErrors':['unknown']},{'identityUncertain':True},{'cleanup':[{'exitCode':2}]}, {'fixturesJoined':False}):
            receipt={'cases':[]};calls=[]
            def execute(kind,mutation):
                calls.append(kind);return dict(self.clean_case(),kind=kind,mutation=mutation,**failure)
            peer.execute_cases(receipt,execute,time.monotonic()+30)
            self.assertEqual(len(calls),1);self.assertEqual(len(receipt['cases']),14)
            self.assertEqual(receipt['cases'][0]['status'],'FAIL')
            self.assertTrue(all(c['reason']=='blocked_by_cleanup_or_identity' for c in receipt['cases'][1:]))
        receipt={'cases':[]}
        def crash(*args):raise RuntimeError('secret unknown exception')
        peer.execute_cases(receipt,crash,time.monotonic()+30)
        self.assertEqual(receipt['cases'][0]['error'],'non-public exception details withheld')
        self.assertNotIn('secret',json.dumps(receipt))

    def test_byte_progress_and_stage_survive_partial_tcp_failure(self):
        events=[];sock=mock.Mock();sock.recv.side_effect=[b'one',EOFError('fixture')]
        with self.assertRaises(EOFError):peer.exact_read(sock,8,events=events,stage='healthy.tcp.payload.receive')
        self.assertEqual(events[0]['completedBytes'],3)
        self.assertEqual(events[0]['partialSHA256'],peer.digest(b'one'))
        self.assertEqual(events[0]['status'],'FAIL')
        events=[];sock=mock.Mock();sock.send.side_effect=[2,BrokenPipeError()]
        with self.assertRaises(BrokenPipeError):peer.send_exact(sock,b'hello',events,'healthy.tcp.payload.send')
        self.assertEqual(events[0]['completedBytes'],2);self.assertEqual(events[0]['status'],'FAIL')

    def test_partial_payload_list_does_not_claim_no_traffic(self):
        sock=mock.Mock();sock.send.side_effect=len;sock.recv.side_effect=[b'x',EOFError()]
        facts=[];events=[]
        with mock.patch.object(peer,'socks_connect',return_value=sock),mock.patch.object(peer.secrets,'token_bytes',side_effect=[b'x',b'yy']):
            with self.assertRaises(EOFError):peer.tcp_exchange(1,'127.0.0.1',2,(1,2),events=events,facts=facts)
        self.assertEqual(facts[0]['status'],'PASS');self.assertEqual(facts[1]['status'],'RUNNING')
        self.assertEqual(events[-1]['status'],'FAIL');sock.close.assert_called_once()

    def test_udp_substage_and_partial_counts_survive_receive_timeout(self):
        control=mock.Mock();udp=mock.Mock();udp.send.side_effect=len;udp.recv.side_effect=socket.timeout()
        facts=[];events=[]
        with mock.patch.object(peer,'socks_udp',return_value=(control,udp)),self.assertRaises(socket.timeout):
            peer.udp_exchange(1,'198.18.0.1',2,events=events,facts=facts)
        self.assertEqual(len(facts),1);self.assertEqual(facts[0]['status'],'RUNNING')
        self.assertEqual(events[-1]['stage'],'client.udp.payload.receive')
        self.assertEqual(events[-1]['status'],'FAIL')
        self.assertEqual(events[-2]['completedBytes'],11)
        udp.close.assert_called_once();control.close.assert_called_once()

    def test_actual_case_sidecar_change_stops_before_any_native_process(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);binary=root/'sing-box';binary.write_bytes(b'core')
            side=root/'libcronet.so';side.write_bytes(b'changed')
            row={'core':{'member':binary.name,'bytes':4,'sha256':peer.digest(b'core')},
                 'sidecar':{'member':side.name,'bytes':4,'sha256':peer.digest(b'side')}}
            receipt={'cases':[]}
            with mock.patch.object(peer,'certificate') as cert,mock.patch.object(peer,'CoreProcess') as process:
                peer.execute_cases(receipt,lambda k,m:peer.run_case(binary,row,root,k,m),time.monotonic()+30)
            cert.assert_not_called();process.assert_not_called()
            self.assertTrue(receipt['cases'][0]['identityUncertain'])
            self.assertEqual(receipt['cases'][0]['failedOperationStages'],['case.native_identity.verify'])
            self.assertEqual(sum(c['status']=='NOT_RUN' for c in receipt['cases']),13)

    def test_actual_case_mapping_identity_failure_stops_despite_clean_retirement(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);binary=root/'sing-box';binary.write_bytes(b'core')
            side=root/'libcronet.so';side.write_bytes(b'side')
            row={'core':{'member':binary.name,'bytes':4,'sha256':peer.digest(b'core')},
                 'sidecar':{'member':side.name,'bytes':4,'sha256':peer.digest(b'side')},
                 'variant':{'linkage':'shared-purego'}}
            class FakeCore:
                def __init__(self,binary,config,directory,role,core_hash,events):
                    self.role=role;self.pid=123;self.start_identity={'pid':123,'pgrp':123,'session':123,'startTicks':456}
                    self.config_fact={'sha256':peer.digest(b'config'),'bytes':6}
                    self.process=mock.Mock();self.process.poll.return_value=None
                    self.cleanup={'exitCode':0,'forcedKill':False,'remainingGroup':[],'cleanupErrorLog':False,
                        'pid':self.pid,'startIdentity':self.start_identity,'boundCoreSHA256':core_hash}
                def wait_tcp(self,port):pass
                def close(self):pass
            receipt={'cases':[]};connection=mock.Mock()
            with mock.patch.object(peer,'certificate',return_value=('CA','CERT','KEY')), \
                 mock.patch.object(peer,'config_check',return_value={}),mock.patch.object(peer,'CoreProcess',FakeCore), \
                 mock.patch.object(peer,'process_snapshot',return_value={}), \
                 mock.patch.object(peer,'drain_owned_children',return_value={'remaining':[],'forcedKill':False,'retired':[]}), \
                 mock.patch.object(peer,'process_identity',return_value={'pid':123,'startTicks':999}), \
                 mock.patch.object(peer,'tcp_exchange',return_value=([],connection)):
                peer.execute_cases(receipt,lambda k,m:peer.run_case(binary,row,root,k,m),time.monotonic()+30)
            result=receipt['cases'][0]
            self.assertEqual(result['errorType'],'IdentityFailure');self.assertTrue(result['identityUncertain'])
            self.assertFalse(result['continuationSafe']);self.assertNotIn('cleanupErrors',result)
            self.assertTrue(result['fixturesJoined']);self.assertTrue(all(x['released'] for x in result['portsReleased']))
            self.assertEqual(len(result['cleanup']),2)
            self.assertIn('healthy.native_identity.verify',result['failedOperationStages'])
            self.assertFalse(result['observedStageIsUniqueRootCause'])
            self.assertEqual(sum(c['status']=='NOT_RUN' for c in receipt['cases']),13)

    def test_acquisition_and_dispatch_failure_retain_safe_not_run_receipt(self):
        for action,function,stage in [('--fetch-diagnostic','fetch_diagnostic','artifact_acquisition'),
                                       ('--validate-diagnostic-dispatch','validate_dispatch','dispatch_preflight')]:
            with self.subTest(stage=stage),tempfile.TemporaryDirectory() as td:
                root=Path(td);output=root/'public';secret='PRIVATE_CANARY_URL_TOKEN'
                argv=['protocol_peer.py',action,'--output',str(output)]
                if action=='--fetch-diagnostic':argv.insert(1,str(root/'native'))
                with mock.patch.object(sys,'argv',argv),mock.patch.object(diagnostic,function,side_effect=ValueError(secret)):
                    with self.assertRaises(ValueError):peer.main()
                raw=(output/'receipt.json').read_text();result=json.loads(raw)
                self.assertNotIn(secret,raw);self.assertEqual(result['stage'],stage)
                self.assertFalse(result['publicationEligible']);self.assertEqual(len(result['cases']),14)
                self.assertTrue(all(c['status']=='NOT_RUN' for c in result['cases']))

    def test_successful_fetch_and_dispatch_do_not_precreate_execution_receipt(self):
        for action,function in [('--fetch-diagnostic','fetch_diagnostic'),
                                ('--validate-diagnostic-dispatch','validate_dispatch')]:
            with self.subTest(action=action),tempfile.TemporaryDirectory() as td:
                root=Path(td);output=root/'public';argv=['protocol_peer.py',action,'--output',str(output)]
                if action=='--fetch-diagnostic':argv.insert(1,str(root/'native'))
                with mock.patch.object(sys,'argv',argv),mock.patch.object(diagnostic,function,return_value={}):peer.main()
                self.assertFalse(output.exists())

    def test_safe_logs_preserve_fixed_category_but_never_arbitrary_secret_lines(self):
        secret='CANARY_PRIVATE_PASSWORD_7edbc'
        raw=('panic: '+secret+'\n'+
             'github.com/sagernet/sing-box/adapter/outbound.(*RuntimeIOCreation).Done('+secret+')\n'+
             '    /private/'+secret+'/runtime_lifecycle.go:668 +0x45\n'+
             'Authorization: Basic '+secret+'\n-----BEGIN PRIVATE KEY-----\n'+secret+'\n'+
             'https://blob.invalid/?sig='+secret+'\n').encode()
        result=diagnostic.safe_log_observation(raw,ROOT);public=json.dumps(result)
        self.assertTrue(result['panicMarker']);self.assertFalse(result['unknownTextRetained'])
        self.assertEqual(result['goFrames'][0]['file'],'runtime_lifecycle.go')
        self.assertNotIn(secret,public);self.assertNotIn('PRIVATE KEY',public);self.assertNotIn('sig=',public)
        self.assertEqual(result['sha256'],peer.digest(raw));self.assertEqual(result['categories'],[])
        fixed=diagnostic.safe_log_observation(b'panic: runtime error: invalid memory address or nil pointer dereference\n',ROOT)
        self.assertIn('go_nil_pointer',[x['category'] for x in fixed['categories']])
        unknown=diagnostic.safe_log_observation(b'client error: quic protocol error\n',ROOT)
        self.assertIn('ERR_QUIC_PROTOCOL_ERROR',[x['category'] for x in unknown['categories']])
        self.assertEqual(diagnostic.safe_exception(RuntimeError(secret)),'non-public exception details withheld')
        with self.assertRaises(RuntimeError):
            peer.negative_evidence('masque-h3','wrong-sni','certificate is valid for '+secret+', not wrong.invalid',b'')
        fake=('panic: unknown\ngithub.com/'+secret+'/outbound.(*RuntimeIOCreation).Done(0x1)\n    /source/runtime_lifecycle.go:668 +0x1\n').encode()
        result=diagnostic.safe_log_observation(fake,ROOT)
        self.assertEqual(result['goFrames'],[]);self.assertNotIn(secret,json.dumps(result))

    def test_real_git_bridge_rejects_product_delta_and_worktree_tampering(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            def git(*args):return subprocess.check_output(['git',*args],cwd=root,stderr=subprocess.DEVNULL).decode().strip()
            git('init');git('config','user.name','Fixture');git('config','user.email','fixture@example.invalid')
            for name in diagnostic.BRIDGE_PATHS:
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('original\n')
            (root/'product.go').write_text('package fixture\n');git('add','.');git('commit','-qm','original')
            original=git('rev-parse','HEAD');original_tree=git('rev-parse','HEAD^{tree}')
            path=root/'scripts/ci/protocol_peer.py';path.write_text('reviewed QA only\n')
            git('add','.');git('commit','-qm','diagnostic')
            def env():return dict(self.valid_env(),GITHUB_SHA=git('rev-parse','HEAD'),GITHUB_WORKFLOW_SHA=git('rev-parse','HEAD'),GITHUB_RUN_ID='456',GITHUB_RUN_ATTEMPT='1')
            with mock.patch.dict(diagnostic.PRODUCER,{'commit':original,'tree':original_tree}):
                bound=diagnostic.verify_runner_bridge(root,env())
                self.assertEqual(bound['bridgeChangedPaths'],['scripts/ci/protocol_peer.py'])
                path.write_text('unreviewed\n')
                with self.assertRaises(ValueError):diagnostic.verify_runner_bridge(root,env())
                git('restore',str(path.relative_to(root)))
                (root/'product.go').write_text('package modified\n');git('add','.');git('commit','-qm','product changed')
                with self.assertRaisesRegex(ValueError,'product changes'):diagnostic.verify_runner_bridge(root,env())
                wrong=dict(env(),GITHUB_WORKFLOW_SHA='0'*40)
                with self.assertRaisesRegex(ValueError,'workflow differ'):diagnostic.verify_runner_bridge(root,wrong)

    def test_download_never_forwards_api_authorization_to_storage(self):
        pins,raw,_=self.zip_fixture()
        runner={'sourceCommit':'1'*40,'sourceTree':'2'*40}
        with mock.patch.object(diagnostic,'PRODUCER',pins):
            run,jobs,artifact=self.origins()
            response=mock.MagicMock();response.__enter__.return_value=response;response.read.return_value=raw
            opener=mock.Mock();opener.open.return_value=response
            with tempfile.TemporaryDirectory() as td, mock.patch.object(diagnostic,'verify_runner_bridge',return_value=runner), \
                 mock.patch.object(diagnostic,'api',side_effect=[run,jobs,artifact,'https://fixed.blob.core.windows.net/file?sig=SECRET']), \
                 mock.patch.object(diagnostic.urllib.request,'build_opener',return_value=opener),mock.patch.dict(os.environ,{'GH_TOKEN':'PRIVATE_TOKEN'}):
                output=Path(td)/'native';result=diagnostic.fetch_diagnostic(output,ROOT)
                request=opener.open.call_args.args[0]
                self.assertNotIn('Authorization',request.headers)
                self.assertNotIn('PRIVATE_TOKEN',str(request.headers))
                self.assertEqual((output/pins['rowName']).read_bytes(),b'row')
                self.assertEqual((output/pins['rowName']).stat().st_mode&0o777,0o444)
                self.assertEqual((output/'original-artifact.zip').read_bytes(),raw)
                self.assertNotIn('SECRET',json.dumps(result));self.assertFalse(result['publicationEligible'])

    def test_api_redirect_rejects_foreign_or_cleartext_origin_without_leaking_token(self):
        import urllib.error
        for url in ('http://fixed.blob.core.windows.net/file','https://attacker.invalid/file',
                    'https://user:pass@fixed.blob.core.windows.net/file'):
            opener=mock.Mock();opener.open.side_effect=urllib.error.HTTPError('https://api.github.com/',302,'Found',{'Location':url},None)
            with mock.patch.object(diagnostic.urllib.request,'build_opener',return_value=opener),mock.patch.dict(os.environ,{'GH_TOKEN':'PRIVATE_TOKEN'}):
                with self.assertRaisesRegex(ValueError,'storage origin rejected'):diagnostic.api('actions/artifacts/1/zip',redirect=True)
                request=opener.open.call_args.args[0]
                self.assertEqual(request.headers['Authorization'],'Bearer PRIVATE_TOKEN')
                self.assertTrue(request.full_url.startswith('https://api.github.com/'))

    def test_original_row_cannot_be_replaced_with_post_smoke_derived_receipt(self):
        p=diagnostic.PRODUCER
        row={'schema':'polaris-upstream-native-receipt-v1','sourceCommit':p['commit'],'sourceTree':p['tree'],
             'version':'1.15.0-polaris-alpha.12.3','goVersion':'go1.27.2','target':'linux/amd64',
             'variant':{'linkage':'shared-purego'},'finalPackageCronetSmoke':None,
             'archive':{'name':p['archiveName'],'sha256':p['archiveSHA256'],'bytes':p['archiveBytes']},
             'core':{'member':'sing-box','sha256':p['coreSHA256'],'bytes':p['coreBytes']},
             'sidecar':{'member':'libcronet.so','sha256':p['sidecarSHA256'],'bytes':p['sidecarBytes']}}
        raw=json.dumps(row).encode()
        with mock.patch.dict(p,{'rowBytes':len(raw),'rowSHA256':diagnostic.sha(raw)}):
            diagnostic.verify_product_row(row,raw)
            for field,value in [('sourceCommit','0'*40),('target','darwin/arm64'),('finalPackageCronetSmoke',{'status':'passed'})]:
                with self.subTest(field=field),self.assertRaises(ValueError):diagnostic.verify_product_row(dict(row,**{field:value}),raw)
            with self.assertRaises(ValueError):diagnostic.verify_product_row(row,raw+b'changed')

    def test_diagnostic_workflow_is_linux_only_and_does_not_mutate_producer_row(self):
        source=(ROOT/'.github/workflows/build.yml').read_text()
        job=source[source.index('  native_smoke:'):source.index('  native_index:')]
        expression=next(line for line in job.splitlines() if line.strip().startswith('matrix:'))
        matrices=__import__('re').findall(r"'(\{.*?\})'",expression)
        self.assertEqual(len(matrices),2)
        diagnostic_rows,normal_rows=map(json.loads,matrices)
        self.assertEqual(len(diagnostic_rows['include']),1)
        self.assertEqual(diagnostic_rows['include'][0]['id'],'linux-amd64-purego')
        self.assertEqual([r['id'] for r in normal_rows['include']],['linux-amd64-purego','windows-amd64','darwin-amd64','darwin-arm64'])
        self.assertIn('      actions: read',job);self.assertNotIn('write',job.split('    needs:',1)[0])
        self.assertEqual(job.count('GH_TOKEN:'),1)
        for name in ('Execute final-package Cronet smoke','Upload actual smoke receipt','Download exact same-run native archive'):
            step=job[job.index('    - name: '+name):].split('\n    - name:',1)[0]
            self.assertIn("if: inputs.build != 'NativePeerDiagnostic'",step)
        execution=job[job.index('    - name: Diagnose the original Linux product'):].split('    - name: Preserve',1)[0]
        for forbidden in ('GH_TOKEN','sudo','docker','continue-on-error','--insecure'):
            self.assertNotIn(forbidden,execution)
        self.assertIn('--diagnostic --output',execution)
        self.assertNotIn('NativePeerDiagnostic',source[source.index('  native_index:'):source.index("'on':")])
        # Incompatible final mode is rejected before calculate_version could bind a release tag.
        calculation=source[source.index('  calculate_version:'):source.index('  prepare_windows7:')]
        self.assertLess(calculation.index('--validate-diagnostic-dispatch'),calculation.index('Bind final evidence'))


if __name__=='__main__':unittest.main()
