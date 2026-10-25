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
import threading
import select
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
    def test_same_source_linux_diagnostic_tests_are_exact_and_required(self):
        workflow=yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text())
        steps=workflow['jobs']['build']['steps']
        matches=[item for item in steps if item.get('name')=='Verify exact Linux cleanup diagnostic tests']
        self.assertEqual(len(matches),1);step=matches[0]
        self.assertEqual(step['if'],"inputs.build == 'NativePeerLinux'")
        self.assertEqual(step['env'],{'CGO_ENABLED':'0','GOOS':'linux','GOARCH':'amd64','GOENV':'off','GOWORK':'off','GOTOOLCHAIN':'local'})
        self.assertNotIn('continue-on-error',step)
        command=step['run'];self.assertIn('set -euo pipefail',command)
        self.assertIn('-tags "$BUILD_TAGS"',command)
        self.assertIn('-ldflags "$TEST_LDFLAGS"',command)
        self.assertIn('constant.Version=${{ needs.calculate_version.outputs.version }} ${LDFLAGS_SHARED} -s -w -buildid=',command)
        self.assertIn("'TEST_LDFLAGS'",command)
        self.assertIn("-run '^(TestCleanup(Diagnostic|Snapshot)|TestFinalLogicalFlow|TestRuntimeFinal|TestRuntimeOwnedCloseCallbackCanRequestWithoutJoiningItself|TestRuntimeNestedOwnedCloseJoinsOneFixedWorker|TestRuntimeCarrierUncertainCloseIsStickyAndRetains)'",command)
        self.assertIn('passed != names',command);self.assertIn("{'fail', 'skip'}",command)
        self.assertIn("!= set(required)",command)
        python=command.split("<<'PYDIAGNOSTIC'\n",1)[1].split('\nPYDIAGNOSTIC',1)[0]
        tree=ast.parse(python);assignment=next(node for node in tree.body if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='required' for t in node.targets))
        names=set()
        for node in ast.walk(assignment.value):
            if isinstance(node,ast.Constant) and isinstance(node.value,str) and node.value.startswith(('TestCleanup','TestFinalLogicalFlow','TestRuntime')):names.add(node.value)
        self.assertEqual(len(names),35)
        for name in names:
            self.assertEqual(sum(bool(re.search(r'^func '+name+r'\(',file.read_text(),re.M)) for file in ROOT.rglob('*_test.go')),1)
        preserve=next(item for item in steps if item.get('name')=='Preserve exact Linux cleanup diagnostic test evidence')
        self.assertEqual(preserve['if'],"always() && inputs.build == 'NativePeerLinux'")
        self.assertEqual(preserve['with']['if-no-files-found'],'error')
        self.assertNotIn('sudo',command)

    def test_cleanup_snapshot_finite_schema_and_secret_rejection(self):
        snapshot = {'schema':'runtime-cleanup-v1','atomic':False,'available':True,
            'preparing':False,'phase':7,'done':False,'failed':False,'truncated':False,'resourceCount':3,
            'resources':[{'owners':0,'unavailable':0,'states':[0]*4,'references':0,
                'dependencies':0,'endpointPhases':[0]*8,'endpointFailures':0,'ownerFailures':0} for _ in range(10)],
            'connections':{'available':True,'closed':False,'tasks':2,'physical':0},
            'reference':{'available':True,'started':True,'stopping':True,'busy':False,
                'pauses':0,'quarantined':0,'failed':False,'setupDone':True,'workerDone':True,'stoppedDone':True}}
        raw = b'ERROR runtime cleanup snapshot: '+json.dumps(snapshot).encode()+b'\n'
        self.assertEqual(diagnostic.cleanup_snapshot_observations(raw),([snapshot],0))
        bad=[]
        for key,value in [('phase',9),('schema','secret-user-host'),('atomic',True),('resourceCount',1000001),('phase',True)]:
            mutated=copy.deepcopy(snapshot);mutated[key]=value;bad.append(mutated)
        mutated=copy.deepcopy(snapshot);mutated['private']='secret-user-host';bad.append(mutated)
        mutated=copy.deepcopy(snapshot);mutated['resources'][2]['references']='secret';bad.append(mutated)
        mutated=copy.deepcopy(snapshot);mutated['resources'][2]['states'].append(0);bad.append(mutated)
        mutated=copy.deepcopy(snapshot);mutated['reference']['extra']='secret';bad.append(mutated)
        mutated=copy.deepcopy(snapshot);mutated['connections']['tasks']=-1;bad.append(mutated)
        for value in bad:
            observed,rejected=diagnostic.cleanup_snapshot_observations(b'runtime cleanup snapshot: '+json.dumps(value).encode())
            self.assertEqual(observed,[]);self.assertEqual(rejected,1)
            self.assertNotIn('secret',json.dumps([observed,rejected]))
        self.assertEqual(diagnostic.cleanup_snapshot_observations(b'runtime cleanup snapshot: {"phase":1,"phase":2}'),([],1))
        observed,rejected=diagnostic.cleanup_snapshot_observations(raw*5)
        self.assertEqual(len(observed),4);self.assertEqual(rejected,1)
        self.assertEqual(diagnostic.cleanup_snapshot_observations(b'runtime cleanup snapshot: '+b'x'*16385),([],1))

    def test_close_error_classes_do_not_retain_arbitrary_error_text(self):
        raw=(b'sing-box did not closed properly: runtime resource cleanup remains unconfirmed: context deadline exceeded; secret-host\n'
             b'context canceled; runtime reference observer cleanup incomplete; device shutdown did not complete; secret-token')
        observed=diagnostic.safe_log_observation(raw,ROOT)
        codes={row['category'] for row in observed['categories']}
        self.assertTrue({'native_close_incomplete','runtime_graph_cleanup_incomplete','close_observer_deadline',
            'close_context_canceled','runtime_reference_cleanup_incomplete','runtime_device_close_incomplete'}<=codes)
        self.assertNotIn('secret',json.dumps(observed))

    def test_naive_native_callback_protocol_exact_tokens_and_status(self):
        for kind, token in [('naive-h2','h2'),('naive-h3','quic/1+spdy/3')]:
            raw = ('response received, protocol: '+token+', status: 200\n').encode()
            result = peer.naive_protocol_observation(kind,raw)
            self.assertTrue(result['successfulExpectedProtocolObserved'])
            self.assertEqual(result['observedAllowlistedProtocolAndStatus'],[[token,200]])
            self.assertEqual(result['privateRawLogSHA256'],peer.digest(raw))
        for token in ('h2','h3','h3-29','quic','quic/1+spdy/3-secret'):
            raw=('response received, protocol: '+token+', status: 200\n').encode()
            self.assertFalse(peer.naive_protocol_observation('naive-h3',raw)['successfulExpectedProtocolObserved'])
        for status in ('401','407','500','2000','200SECRET','200 SECRET'):
            raw=('response received, protocol: quic/1+spdy/3, status: '+status+'\n').encode()
            self.assertFalse(peer.naive_protocol_observation('naive-h3',raw)['successfulExpectedProtocolObserved'])
        raw=b'response received, protocol: PRIVATE_TOKEN, status: 200\n'
        result=peer.naive_protocol_observation('naive-h3',raw)
        self.assertEqual(result['unrecognizedObservationCount'],1)
        self.assertNotIn('PRIVATE_TOKEN',str(result))

    def test_h3_proof_retains_exact_listener_fallback_and_two_way_udp(self):
        config,_=peer.configs('naive-h3',1,2,3,'CA','CERT','KEY','PASSWORD',[4,5])
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as reserved:
            reserved.bind(('127.0.0.1',0))
            relay=mock.Mock(port=reserved.getsockname()[1],counts=[4,7])
            self.assertEqual(peer.verify_h3_only_carrier(config,reserved,relay),
                {'listenerNetwork':'udp','serverALPN':['h3'],'tcpFallbackBoundNonListening':True,'carrierDatagrams':[4,7]})
            for key, value in [('network','tcp'),('listen','0.0.0.0'),('tls',{'alpn':['h3','h2']})]:
                wrong=copy.deepcopy(config);wrong['inbounds'][0][key]=value
                with self.assertRaises(RuntimeError):peer.verify_h3_only_carrier(wrong,reserved,relay)
            relay.counts=[4,0]
            with self.assertRaises(RuntimeError):peer.verify_h3_only_carrier(config,reserved,relay)
            relay.counts=[4,7];relay.port+=1
            with self.assertRaises(RuntimeError):peer.verify_h3_only_carrier(config,reserved,relay)
            relay.port-=1;reserved.listen()
            with self.assertRaises(RuntimeError):peer.verify_h3_only_carrier(config,reserved,relay)

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
        first=mock.Mock();first.bind.side_effect=OSError('bind failed')
        with mock.patch.object(peer.socket,'socket',return_value=first), self.assertRaises(OSError):peer.UDPRelay(12346)
        first.close.assert_called_once()


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


class PeerNegativeAndObserverContracts(unittest.TestCase):
    def wait(self, predicate):
        end=time.monotonic()+3
        while not predicate():
            if time.monotonic()>end:self.fail('bounded observer condition not reached')
            time.sleep(.01)

    def owner(self):
        owner=mock.Mock(pid=os.getpid(),pidfd=1,start_identity=peer.process_identity(os.getpid()),bound_sha256='a'*64)
        owner.cleanup={'pid':owner.pid,'startIdentity':owner.start_identity,'boundCoreSHA256':owner.bound_sha256,
                       'exitBeforeTerminate':None,'exitCode':0,'forcedKill':False,'remainingGroup':[],'cleanupErrorLog':False,
                       'terminationActions':[{'signal':'SIGTERM','pidfdBound':True}]}
        owner.inspection_gate=threading.RLock()
        owner.sigterm_observation=None
        owner.process.poll.return_value=None
        return owner

    def recorded_sigterm(self, owner):
        owner.sigterm_observation=peer.event([], 'test.process.signal',signal='SIGTERM',pidfdBound=True,pid=owner.pid,
            startTicks=owner.start_identity['startTicks'],coreSHA256=owner.bound_sha256)
        owner.cleanup['terminationActions']=[owner.sigterm_observation]


    def test_peer_alert_is_exact_remote_complete_new_window(self):
        good=b'2026/10/25 00:00:01 server Closing connection with error: CRYPTO_ERROR 0x12e (remote): SECRET\n'
        baseline=b'healthy-only\n'
        result=peer.peer_certificate_alert(baseline+good,len(baseline))
        self.assertEqual(result['certificateAlert'],'certificate_unknown')
        self.assertEqual(result['origin'],'remote')
        self.assertNotIn('SECRET',json.dumps(result))
        for raw,offset in [(good+b'no new alert\n',len(good)),(good.replace(b'remote',b'local'),0),
                           (good.replace(b'0x12e',b'0x128'),0),(good[:-1],0),
                           (b'ERR_QUIC_PROTOCOL_ERROR timeout\n',0),(baseline+good,1),
                           (b'2026/10/25 00:00:01 server Closing connection with error: INTERNAL_ERROR: '+good,0),
                           (b'arbitrary '+good,0)]:
            with self.assertRaises(RuntimeError):peer.peer_certificate_alert(raw,offset)
        with self.assertRaises(RuntimeError):peer.negative_evidence('naive-h3','wrong-ca',b'',good)
        for mutation in ('wrong-ca','wrong-sni'):
            result=peer.negative_evidence('naive-h3',mutation,b'',good,mutation_proof={'singleFieldMutation':mutation})
            self.assertEqual(result['classificationSource'],'single-variable-fixture-with-healthy-control')
            self.assertNotIn('authority_invalid',json.dumps(result))

    def test_all_negative_configs_require_one_semantic_field(self):
        for kind in ('naive-h2','naive-h3','masque-h3'):
            for mutation in ('wrong-auth','wrong-ca','wrong-sni','wrong-path'):
                if mutation=='wrong-path' and kind.startswith('naive'):continue
                _,healthy=peer.configs(kind,100,101,102,'CA','CERT','KEY','SECRET',[103,104])
                _,bad=peer.configs(kind,100,105,106,'CA','CERT','KEY','SECRET',[103,104],mutation)
                bucket='outbounds' if kind.startswith('naive') else 'endpoints'
                if mutation=='wrong-ca':bad[bucket][0]['tls']['certificate']=['WRONG_CA']
                result=peer.controlled_mutation(healthy,bad,mutation)
                self.assertEqual(result['singleFieldMutation'],mutation)
                self.assertNotIn('SECRET',json.dumps(result))
                extra=copy.deepcopy(bad);extra[bucket][0]['tls']['insecure']=True
                with self.assertRaises(RuntimeError):peer.controlled_mutation(healthy,extra,mutation)
                with self.assertRaises(RuntimeError):peer.controlled_mutation(healthy,healthy,mutation)

    def test_peer_error_env_is_private_peer_only(self):
        source=(ROOT/'scripts/ci/protocol_peer.py').read_text()
        tree=ast.parse(source);core=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='CoreProcess')
        init=next(n for n in core.body if isinstance(n,ast.FunctionDef) and n.name=='__init__')
        guards=[n for n in init.body if isinstance(n,ast.If) and "name == 'peer'"==ast.unparse(n.test)]
        self.assertEqual(len(guards),1)
        self.assertEqual(ast.unparse(guards[0].body[0]),"env['QUIC_GO_LOG_LEVEL'] = 'error'")
        self.assertNotIn('QUIC_GO_LOG_LEVEL',peer.core_environment(Path('/private')))

    def test_on_demand_first_flow_precedes_assignment_for_both_epochs(self):
        source=(ROOT/'scripts/ci/protocol_peer.py').read_text()
        function=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='run_case')
        nested=next(n for n in ast.walk(function) if isinstance(n,ast.FunctionDef) and n.name=='start_client')
        guard=next(n for n in ast.walk(nested) if isinstance(n,ast.If) and any(isinstance(c,ast.Call) and isinstance(c.func,ast.Attribute) and c.func.attr=='wait_assigned' for c in ast.walk(n)))
        self.assertIn("not kind.endswith('on-demand')",ast.unparse(guard.test))
        for role,call in [('healthy','keep=True'),('client',"label='reconnected'")]:
            first=source.index(call,source.index('def run_case'))
            observed=source.index(role+'.wait_assigned()',first)
            self.assertGreater(observed,first)
        self.assertIn("result['onDemandFreshAssignmentAfterFirstFlow'] = True",source)

    def test_actual_relay_owner_gate_two_sources_and_reply_isolation(self):
        echo=peer.Echo(udp=True);relay=peer.UDPRelay(echo.port);sockets=[]
        try:
            for _ in range(2):
                sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('127.0.0.1',0));sock.settimeout(2);sockets.append(sock)
            sockets[0].sendto(b'first',('127.0.0.1',relay.port));time.sleep(.15)
            self.assertEqual(echo.received,0)
            relay.bind_owner(self.owner())
            self.assertEqual(sockets[0].recv(99),b'first')
            sockets[1].sendto(b'second',('127.0.0.1',relay.port));self.assertEqual(sockets[1].recv(99),b'second')
            self.assertEqual(len(relay.sources),2);self.assertEqual(relay.counts,[2,2])
            self.assertEqual(len({slot['socket'].getsockname() for slot in relay.sources.values()}),2)
            relay.close();fact=relay.observation()
            self.assertTrue(fact['threadJoined']);self.assertTrue(fact['terminalAcknowledged']);self.assertEqual(fact['terminal'],'stopped')
        finally:
            for sock in sockets:sock.close()
            with contextlib.suppress(RuntimeError):relay.close()
            echo.close()

    def test_actual_retired_reverse_tail_is_not_sent_to_reusable_port(self):
        server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);server.bind(('127.0.0.1',0));server.settimeout(2)
        relay=peer.UDPRelay(server.getsockname()[1]);client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        try:
            client.bind(('127.0.0.1',0));relay.bind_owner(self.owner())
            client.sendto(b'payload',('127.0.0.1',relay.port));data,back=server.recvfrom(100);self.assertEqual(data,b'payload')
            client.close();server.sendto(b'old reply',back)
            self.wait(lambda:relay.retired_drops[1]==1)
            self.assertEqual(relay.counts,[1,0]);self.assertEqual(relay.received,[1,1])
            self.assertEqual(sum(x['retired'] for x in relay.sources.values()),1)
        finally:
            client.close();relay.close();server.close()

    def test_actual_source_port_reuse_is_sticky_failure(self):
        echo=peer.Echo(udp=True);relay=peer.UDPRelay(echo.port);first=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);second=None
        try:
            first.bind(('127.0.0.1',0));address=first.getsockname();first.settimeout(2);relay.bind_owner(self.owner())
            first.sendto(b'one',('127.0.0.1',relay.port));self.assertEqual(first.recv(99),b'one');first.close()
            second=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);second.bind(address);second.sendto(b'not same inode',('127.0.0.1',relay.port))
            self.wait(relay.finished.is_set)
            with self.assertRaises(RuntimeError):relay.close()
            self.assertEqual(relay.errors[0]['category'],'source_socket_reused');self.assertEqual(relay.counts,[1,1])
        finally:
            first.close()
            if second:second.close()
            with contextlib.suppress(RuntimeError):relay.close()
            echo.close()

    def test_observer_selector_create_register_select_errors_cannot_look_successful(self):
        for operation in ('selector_create','selector_register','selector_select'):
            with self.subTest(operation=operation):
                selector=mock.MagicMock();selector.__enter__.return_value=selector
                if operation=='selector_register':selector.register.side_effect=RuntimeError('SECRET')
                if operation=='selector_select':selector.select.side_effect=OSError(peer.errno.ECONNREFUSED,'SECRET')
                with mock.patch.object(peer.selectors,'DefaultSelector',side_effect=RuntimeError('SECRET') if operation=='selector_create' else None,return_value=selector):
                    relay=peer.UDPRelay(1)
                    if operation=='selector_select':relay.bind_owner(self.owner())
                    self.wait(relay.finished.is_set)
                    with self.assertRaises(RuntimeError):relay.close()
                    result=relay.observation();self.assertEqual(result['terminal'],'failed')
                    self.assertEqual(result['errors'][0]['operation'],operation)
                    self.assertNotIn('SECRET',json.dumps(result));self.assertTrue(result['threadJoined'])

    def test_owner_exit_expectation_cannot_launder_previous_exit_or_reuse(self):
        for failure in ('already_exited','pid_changed','permission'):
            relay=peer.UDPRelay(1);owner=self.owner()
            try:
                relay.bind_owner(owner)
                if failure=='already_exited':owner.process.poll.return_value=0
                context=mock.patch.object(peer,'process_identity',side_effect=PermissionError('SECRET')) if failure=='permission' else \
                        mock.patch.object(peer,'process_identity',return_value=dict(owner.start_identity,startTicks=0)) if failure=='pid_changed' else contextlib.nullcontext()
                with context,self.assertRaises(peer.IdentityFailure):relay.prepare_owner_retirement()
                self.assertTrue(relay.identity_uncertain);self.assertFalse(relay.expected_owner_exit)
                owner.process.poll.return_value=None
                with self.assertRaises(peer.IdentityFailure):relay.prepare_owner_retirement()
                with self.assertRaises(RuntimeError):relay.close()
            finally:
                with contextlib.suppress(RuntimeError):relay.close()

    def test_expected_missing_proc_requires_later_actual_zero_exit(self):
        for exit_code in (None,1,0):
            relay=peer.UDPRelay(1);owner=self.owner()
            try:
                relay.bind_owner(owner);relay.prepare_owner_retirement()
                self.recorded_sigterm(owner)
                with mock.patch.object(peer,'process_identity',side_effect=FileNotFoundError(peer.errno.ENOENT,'PRIVATE')):
                    self.assertIsNone(relay.source_inode(('127.0.0.1',1234),{'inode':'123'}))
                self.assertTrue(relay.owner_exit_pending);self.assertFalse(relay.owner_exit_observed)
                owner.process.poll.return_value=exit_code
                if exit_code==0:
                    relay.close();self.assertTrue(relay.owner_exit_observed)
                else:
                    with self.assertRaises(RuntimeError):relay.close()
            finally:
                with contextlib.suppress(RuntimeError):relay.close()

    def test_back_socket_registration_failure_closes_acquired_socket(self):
        relay=peer.UDPRelay(1);sock=mock.Mock();selector=mock.Mock();selector.register.side_effect=RuntimeError('SECRET')
        try:
            with mock.patch.object(relay,'source_inode',return_value='123'),mock.patch.object(peer.socket,'socket',return_value=sock):
                with self.assertRaises(RuntimeError):relay.current_source(('127.0.0.1',1234),selector,True)
            sock.close.assert_called_once();self.assertEqual(relay.sources,{})
        finally:relay.close()

    def test_source_limit_includes_tombstones_no_lru_eviction(self):
        relay=peer.UDPRelay(1)
        try:
            relay.sources={('127.0.0.1',i):{'inode':str(i),'retired':True,'socket':mock.Mock()} for i in range(16)}
            with mock.patch.object(relay,'source_inode',return_value='new'):
                with self.assertRaisesRegex(RuntimeError,'limit'):relay.current_source(('127.0.0.1',99),mock.Mock(),True)
            self.assertEqual(len(relay.sources),16)
        finally:relay.close()

    def test_cleanup_orders_clients_then_observer_then_peer(self):
        source=(ROOT/'scripts/ci/protocol_peer.py').read_text();cleanup=source[source.index("        errors = list(result.get('observerCleanupErrors',[]))",source.index('def run_case')):]
        self.assertLess(cleanup.index("p.role != 'peer'"),cleanup.index('retire_udp_observer(relay,result)'))
        self.assertLess(cleanup.index('retire_udp_observer(relay,result)'),cleanup.index("p.role == 'peer'"))
        self.assertIn("errors.extend(retire_udp_observer(relay,result))",cleanup)
        self.assertIn("result['status'] = 'FAIL'; result['cleanupErrors'] = errors",cleanup)


class PeerObserverAdditionalBoundaries(unittest.TestCase):
    wait = PeerNegativeAndObserverContracts.wait
    owner = PeerNegativeAndObserverContracts.owner
    def test_actual_foreign_child_udp_source_is_rejected_without_forward(self):
        echo=peer.Echo(udp=True);relay=peer.UDPRelay(echo.port);child=None
        try:
            relay.bind_owner(self.owner())
            code="import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('127.0.0.1',0)); s.sendto(b'foreign',('127.0.0.1',"+str(relay.port)+")); time.sleep(.4); s.close()"
            child=subprocess.Popen([sys.executable,'-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            self.wait(relay.finished.is_set);self.assertEqual(child.wait(3),0)
            with self.assertRaises(RuntimeError):relay.close()
            self.assertEqual(echo.received,0);self.assertEqual(relay.counts,[0,0])
            self.assertEqual(relay.errors[0]['operation'],'source_identity')
        finally:
            if child:
                child.wait(3);child.stdout.close();child.stderr.close()
            with contextlib.suppress(RuntimeError):relay.close()
            echo.close()

    def test_proc_permission_and_pid_change_are_fail_closed_even_during_expected_exit(self):
        relay=peer.UDPRelay(1);owner=self.owner()
        try:
            relay.bind_owner(owner);relay.prepare_owner_retirement()
            for error in (PermissionError('SECRET'),RuntimeError('changed')):
                with mock.patch.object(peer,'process_identity',side_effect=error):
                    with self.assertRaises(type(error)):relay.source_inode(('127.0.0.1',1234))
            with mock.patch.object(peer,'process_identity',return_value=dict(owner.start_identity,startTicks=999)):
                with self.assertRaises(RuntimeError):relay.source_inode(('127.0.0.1',1234))
            self.assertFalse(relay.owner_exit_observed);self.assertFalse(relay.owner_exit_pending)
        finally:
            with self.assertRaises(RuntimeError):relay.close()

    def test_peer_non_h3_window_hash_and_absolute_offset_bind_full_log(self):
        raw=b'healthy\nold line\nunexpected status: 401\n';offset=len(b'healthy\nold line\n')
        result=peer.negative_evidence('masque-h3','wrong-auth',b'',raw,peer_offset=offset)
        self.assertEqual(result['privateRawLogSHA256'],peer.digest(raw))
        self.assertEqual(result['privateRawLogBytes'],len(raw));self.assertEqual(result['byteOffset'],offset)
        with self.assertRaises(RuntimeError):peer.negative_evidence('masque-h3','wrong-auth',b'',raw,peer_offset=len(raw))


class PeerReviewRegressionContracts(unittest.TestCase):
    owner = PeerNegativeAndObserverContracts.owner
    wait = PeerNegativeAndObserverContracts.wait

    def test_actual_wildcard_reuse_cannot_be_tombstoned_as_unoccupied(self):
        server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);server.bind(('127.0.0.1',0));server.settimeout(2)
        relay=peer.UDPRelay(server.getsockname()[1]);client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);replacement=None
        try:
            client.bind(('127.0.0.1',0));port=client.getsockname()[1];relay.bind_owner(self.owner())
            client.sendto(b'first',('127.0.0.1',relay.port));_,back=server.recvfrom(100);client.close()
            replacement=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);replacement.bind(('0.0.0.0',port))
            server.sendto(b'old reply',back);self.wait(relay.finished.is_set)
            with self.assertRaises(RuntimeError):relay.close()
            self.assertEqual(relay.errors[0]['category'],'source_port_occupied_or_unowned')
            self.assertEqual(relay.counts,[1,0]);self.assertEqual(relay.retired_drops,[0,0])
        finally:
            client.close()
            if replacement:replacement.close()
            with contextlib.suppress(RuntimeError):relay.close()
            server.close()

    def test_udp6_port_occupancy_is_not_ignored(self):
        relay=peer.UDPRelay(1);owner=self.owner()
        try:
            relay.bind_owner(owner)
            table='header\n 0: '+('0'*32)+':04D2 '+('0'*32)+':0000 07 0 0 0 0 0 123 0\n'
            real_open=Path.open
            def opened(path,*args,**kwargs):
                return io.StringIO(table) if str(path).endswith('/net/udp6') else real_open(path,*args,**kwargs)
            with mock.patch.object(Path,'open',opened),self.assertRaises(RuntimeError):relay.source_inode(('127.0.0.1',1234))
            self.assertEqual(relay.failure_class,'source_port_occupied_or_unowned')
        finally:relay.close()

    def test_expected_but_unsignaled_zero_exit_cannot_pass_retirement(self):
        relay=peer.UDPRelay(1);owner=self.owner()
        try:
            relay.bind_owner(owner);relay.prepare_owner_retirement();owner.process.poll.return_value=0
            with self.assertRaises(peer.IdentityFailure):relay.source_inode(('127.0.0.1',1234))
            owner.cleanup.update(exitBeforeTerminate=0,terminationActions=[])
            with self.assertRaises(RuntimeError):relay.close()
            self.assertFalse(relay.owner_retirement_confirmed)
            self.assertIn('owner_actual_signaled_retirement_not_proven',relay.close_faults)
        finally:
            with contextlib.suppress(RuntimeError):relay.close()

    def test_each_socket_close_and_observation_fault_is_retained_without_short_circuit(self):
        relay=peer.UDPRelay(1);first=mock.Mock();second=mock.Mock();first.close.side_effect=OSError('SECRET')
        relay.sources={('127.0.0.1',1):{'socket':first},('127.0.0.1',2):{'socket':second}}
        with self.assertRaises(RuntimeError):relay.close()
        first.close.assert_called_once();second.close.assert_called_once()
        self.assertIn('socket_close_failed',relay.close_faults)
        broken=mock.Mock();broken.close.side_effect=RuntimeError('SECRET');broken.observation.side_effect=RuntimeError('SECRET')
        result={};errors=peer.retire_udp_observer(broken,result)
        self.assertEqual(len(errors),2);self.assertNotIn('SECRET',json.dumps(result))
        self.assertTrue(result['udpObservers'][0]['snapshotUnavailable'])

    def test_actual_case_bind_identity_and_observer_failure_stop_and_still_close_peer(self):
        for observation_fails in (False,True):
            with tempfile.TemporaryDirectory() as td:
                root=Path(td);binary=root/'sing-box';binary.write_bytes(b'core');(root/'libcronet.so').write_bytes(b'side')
                row={'core':{'member':'sing-box','bytes':4,'sha256':peer.digest(b'core')},
                     'sidecar':{'member':'libcronet.so','bytes':4,'sha256':peer.digest(b'side')}}
                closed=[]
                class FakeCore:
                    def __init__(self,binary,config,directory,role,core_hash,events):
                        self.role=role;self.pid=123;self.start_identity={'pid':123,'pgrp':123,'session':123,'startTicks':456}
                        self.config_fact={'sha256':peer.digest(json.dumps(config,separators=(',',':')).encode()),'bytes':6}
                        self.process=mock.Mock();self.process.poll.return_value=None
                        self.log_path=directory/(role+'.private.log');self.log_path.write_bytes(b'')
                        self.cleanup={'exitCode':0,'forcedKill':False,'remainingGroup':[],'cleanupErrorLog':False,
                            'pid':self.pid,'startIdentity':self.start_identity,'boundCoreSHA256':core_hash}
                    def wait_tcp(self,port):pass
                    def wait_udp(self,port):pass
                    def close(self):closed.append(self.role)
                relay=mock.Mock(port=peer.free_port(),counts=[0,0]);relay.bind_owner.side_effect=peer.IdentityFailure('UDP observer exact child identity unavailable')
                relay.observation.return_value={'actor':'udp_observer','threadJoined':True}
                if observation_fails:relay.observation.side_effect=RuntimeError('SECRET')
                receipt={'cases':[]}
                with mock.patch.object(peer,'certificate',return_value=('CA','CERT','KEY')),mock.patch.object(peer,'config_check',return_value={}), \
                     mock.patch.object(peer,'CoreProcess',FakeCore),mock.patch.object(peer,'UDPRelay',return_value=relay), \
                     mock.patch.object(peer,'process_snapshot',return_value={}), \
                     mock.patch.object(peer,'drain_owned_children',return_value={'remaining':[],'forcedKill':False,'retired':[]}):
                    peer.execute_cases(receipt,lambda k,m:peer.run_case(binary,row,root,'naive-h3',m),time.monotonic()+30)
                case=receipt['cases'][0]
                self.assertTrue(case['identityUncertain']);self.assertFalse(case['continuationSafe'])
                self.assertEqual(sum(x['status']=='NOT_RUN' for x in receipt['cases']),13)
                self.assertEqual(closed,['healthy','peer'])
                if observation_fails:
                    self.assertTrue(case['cleanupErrors']);self.assertFalse(case['fixturesJoined'])
                    self.assertNotIn('SECRET',json.dumps(case))


class PeerIdentityBoundaryRegression(unittest.TestCase):
    def test_actual_run_case_real_bind_proc_failure_stops_after_complete_cleanup(self):
        for exception in (FileNotFoundError,PermissionError,OSError):
            with self.subTest(exception=exception.__name__),tempfile.TemporaryDirectory() as td:
                root=Path(td);binary=root/'sing-box';binary.write_bytes(b'core');(root/'libcronet.so').write_bytes(b'side')
                row={'core':{'member':'sing-box','bytes':4,'sha256':peer.digest(b'core')},
                     'sidecar':{'member':'libcronet.so','bytes':4,'sha256':peer.digest(b'side')}}
                closed=[]
                class FakeCore:
                    def __init__(self,binary,config,directory,role,core_hash,events):
                        self.role=role;self.pid=123;self.pidfd=1;self.start_identity={'pid':123,'pgrp':123,'session':123,'startTicks':456}
                        self.config_fact={'sha256':peer.digest(json.dumps(config,separators=(',',':')).encode()),'bytes':6}
                        self.process=mock.Mock();self.process.poll.return_value=None
                        self.log_path=directory/(role+'.private.log');self.log_path.write_bytes(b'')
                        self.cleanup={'exitCode':0,'forcedKill':False,'remainingGroup':[],'cleanupErrorLog':False,
                            'pid':self.pid,'startIdentity':self.start_identity,'boundCoreSHA256':core_hash}
                    def wait_tcp(self,port):pass
                    def wait_udp(self,port):pass
                    def close(self):closed.append(self.role)
                receipt={'cases':[]}
                with mock.patch.object(peer,'certificate',return_value=('CA','CERT','KEY')),mock.patch.object(peer,'config_check',return_value={}), \
                     mock.patch.object(peer,'CoreProcess',FakeCore),mock.patch.object(peer,'process_identity',side_effect=exception('SECRET')), \
                     mock.patch.object(peer,'process_snapshot',return_value={}), \
                     mock.patch.object(peer,'drain_owned_children',return_value={'remaining':[],'forcedKill':False,'retired':[]}):
                    peer.execute_cases(receipt,lambda k,m:peer.run_case(binary,row,root,'naive-h3',m),time.monotonic()+30)
                case=receipt['cases'][0]
                self.assertEqual(case['errorType'],'IdentityFailure');self.assertTrue(case['identityUncertain'])
                self.assertFalse(case['continuationSafe']);self.assertEqual(sum(x['status']=='NOT_RUN' for x in receipt['cases']),13)
                self.assertEqual(closed,['healthy','peer'])
                self.assertTrue(case['udpObservers'][0]['identityUncertain']);self.assertTrue(case['udpObservers'][0]['threadJoined'])
                self.assertTrue(case['udpObservers'][0]['allSocketsClosed']);self.assertNotIn('SECRET',json.dumps(case))



class OwnedRetirementLifecycleContracts(unittest.TestCase):
    """Actual Python child/pidfd/UDP regression, not native protocol evidence."""
    wait=PeerNegativeAndObserverContracts.wait
    owner=PeerNegativeAndObserverContracts.owner
    recorded_sigterm=PeerNegativeAndObserverContracts.recorded_sigterm

    @contextlib.contextmanager
    def child_relay(self, exit_code=0, signal_delay=.08):
        with tempfile.TemporaryDirectory() as td:
            directory=Path(td);echo=peer.Echo(udp=True);relay=peer.UDPRelay(echo.port)
            source=r'''
import socket,signal,sys,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));s.settimeout(2)
address=('127.0.0.1',int(sys.argv[1]))
def stop(*_):
    for i in range(4):s.sendto(b'tail',address);time.sleep(.002)
    time.sleep(float(sys.argv[3]));s.close();sys.exit(int(sys.argv[2]))
signal.signal(signal.SIGTERM,stop)
print(s.getsockname()[1],flush=True)
for line in sys.stdin:
    if line.strip()=='send':
        s.sendto(b'healthy',address);print('OK' if s.recv(100)==b'healthy' else 'BAD',flush=True)
    elif line.strip()=='exit':sys.exit(0)
    elif line.strip()=='close':s.close();print('CLOSED',flush=True)
'''
            owner=object.__new__(peer.CoreProcess);owner.events=[];owner.role='fixture';owner.source_root=ROOT
            owner.inspection_gate=threading.RLock();owner.sigterm_observation=None
            owner.log_path=directory/'owned.private.log';owner.log=owner.log_path.open('wb')
            owner.process=subprocess.Popen([sys.executable,'-u','-c',source,str(relay.port),str(exit_code),str(signal_delay)],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=owner.log,start_new_session=True)
            owner.pid=owner.process.pid;owner.pidfd=os.pidfd_open(owner.pid)
            owner.start_identity=peer.process_identity(owner.pid);owner.stopped=False;owner.cleanup=None
            owner.bound_sha256=peer.digest(Path(f'/proc/{owner.pid}/exe').read_bytes())
            try:
                port=int(self.line(owner));relay.bind_owner(owner)
                self.send(owner);self.assertEqual(relay.counts,[1,1])
                yield owner,relay,echo,('127.0.0.1',port)
            finally:
                if not owner.stopped:
                    with contextlib.suppress(Exception):owner.close()
                with contextlib.suppress(Exception):relay.close()
                if owner.process.poll() is None:
                    # Exact test-owned pidfd only, never a naked PID/PGID.
                    self.assertEqual(peer.process_identity(owner.pid),owner.start_identity)
                    fd=os.pidfd_open(owner.pid)
                    try:signal.pidfd_send_signal(fd,signal.SIGKILL);owner.process.wait(3)
                    finally:os.close(fd)
                if owner.pidfd is not None:os.close(owner.pidfd);owner.pidfd=None
                owner.log.close();owner.process.stdin.close();owner.process.stdout.close();echo.close()

    def line(self, owner):
        if not select.select([owner.process.stdout],[],[],3)[0]:self.fail('owned fixture reply deadline')
        value=owner.process.stdout.readline()
        if not value:self.fail('owned fixture unexpectedly closed output')
        return value.decode().strip()

    def send(self,owner):
        owner.process.stdin.write(b'send\n');owner.process.stdin.flush();self.assertEqual(self.line(owner),'OK')

    @contextlib.contextmanager
    def denied_suboperation(self, relay, operation, error):
        identity=peer.process_identity;scandir=os.scandir;readlink=os.readlink;opened=Path.open
        def fail():raise error
        def identity_read(pid):
            if relay.identity_operation==operation:fail()
            return identity(pid)
        def scan(path):
            if relay.identity_operation==operation:fail()
            return scandir(path)
        def link(path,*a,**kw):
            if relay.identity_operation==operation:fail()
            return readlink(path,*a,**kw)
        def file_open(path,*a,**kw):
            if relay.identity_operation==operation:fail()
            stream=opened(path,*a,**kw)
            if operation in ('udp_read','udp6_read') and str(path).endswith('/'+operation[:-5]):
                class FailedRead:
                    def __enter__(self):return self
                    def __exit__(self,*args):stream.close()
                    def read(self,*args):fail()
                return FailedRead()
            return stream
        with mock.patch.object(peer,'process_identity',identity_read),mock.patch.object(os,'scandir',scan), \
             mock.patch.object(os,'readlink',link),mock.patch.object(Path,'open',file_open):yield

    def test_all_proc_suboperations_active_failure_and_post_signal_known_gap(self):
        operations=('owner_stat_before','fd_list','fd_readlink','udp_open','udp_read','udp6_open','udp6_read','owner_stat_after')
        for operation in operations:
            for signaled in (False,True):
                with self.subTest(operation=operation,signaled=signaled):
                    relay=peer.UDPRelay(1);owner=self.owner();client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                    try:
                        client.bind(('127.0.0.1',0));relay.bind_owner(owner);relay.prepare_owner_retirement()
                        if signaled:self.recorded_sigterm(owner)
                        with self.denied_suboperation(relay,operation,PermissionError(peer.errno.EACCES,'PRIVATE')):
                            if signaled:self.assertIsNone(relay.source_inode(client.getsockname(),{'inode':'123'}))
                            else:
                                with self.assertRaises(PermissionError):relay.source_inode(client.getsockname(),{'inode':'123'})
                        if signaled:
                            gap=relay.inspection_gap;self.assertEqual(gap['identityOperation'],operation)
                            self.assertLessEqual(gap['sigtermSucceededMonotonic'],gap['readStartedMonotonic'])
                            self.assertLessEqual(gap['readStartedMonotonic'],gap['readFinishedMonotonic'])
                            self.assertNotIn('PRIVATE',json.dumps(gap));owner.process.poll.return_value=0
                            relay.close();self.assertEqual(gap['resolution'],'verified_owned_retirement')
                        else:self.assertIsNone(relay.inspection_gap)
                    finally:
                        client.close()
                        with contextlib.suppress(RuntimeError):relay.close()

    def test_only_fixed_errno_and_previously_proven_slot_can_quarantine(self):
        for code,known,signaled in [(peer.errno.EACCES,False,True),(peer.errno.EACCES,True,False),
                                    (peer.errno.EIO,True,True),(peer.errno.EBADF,True,True)]:
            with self.subTest(code=code,known=known,signaled=signaled):
                relay=peer.UDPRelay(1);owner=self.owner()
                try:
                    relay.bind_owner(owner);relay.prepare_owner_retirement()
                    if signaled:self.recorded_sigterm(owner)
                    with mock.patch.object(peer,'process_identity',side_effect=OSError(code,'PRIVATE')):
                        with self.assertRaises(OSError):relay.source_inode(('127.0.0.1',1234),{'inode':'123'} if known else None)
                    self.assertIsNone(relay.inspection_gap)
                finally:
                    with contextlib.suppress(RuntimeError):relay.close()

    def test_real_core_close_and_relay_normal_sigterm_retirement(self):
        with self.child_relay() as (owner,relay,echo,address):
            relay.prepare_owner_retirement();self.send(owner) # Marking alone must not stop healthy traffic.
            self.assertEqual(relay.counts,[2,2]);fact=owner.close();relay.close()
            self.assertEqual(fact['exitCode'],0);self.assertFalse(fact['forcedKill'])
            self.assertTrue(relay.owner_retirement_confirmed);self.assertTrue(relay.observation()['threadJoined'])
            self.assertEqual(fact['terminationActions'],[owner.sigterm_observation])

    def test_real_post_signal_permission_quarantines_tails_without_rechecking(self):
        for code in (peer.errno.EACCES,peer.errno.EPERM,peer.errno.ENOENT,peer.errno.ESRCH):
            with self.subTest(code=code),self.child_relay() as (owner,relay,echo,address):
                relay.prepare_owner_retirement();real=os.scandir;calls=[]
                def scan(path):
                    if threading.current_thread() is relay.thread and owner.sigterm_observation:
                        calls.append(time.monotonic());raise OSError(code,'PRIVATE')
                    return real(path)
                before=relay.counts[:]
                with mock.patch.object(os,'scandir',scan):
                    fact=owner.close();self.wait(lambda:relay.quarantined_drops[0]>=1);relay.close()
                self.assertEqual(len(calls),1);self.assertEqual(relay.counts,before)
                self.assertEqual(fact['exitCode'],0);self.assertFalse(fact['forcedKill'])
                self.assertEqual(relay.inspection_gap['resolution'],'verified_owned_retirement')
                self.assertTrue(relay.observation()['allSocketsClosed'])

    def test_real_pre_signal_permission_remains_sticky_after_later_clean_exit(self):
        with self.child_relay() as (owner,relay,echo,address):
            relay.prepare_owner_retirement();real=os.scandir
            def scan(path):
                if threading.current_thread() is relay.thread:raise PermissionError(peer.errno.EACCES,'PRIVATE')
                return real(path)
            with mock.patch.object(os,'scandir',scan):
                owner.process.stdin.write(b'send\n');owner.process.stdin.flush();self.wait(relay.finished.is_set)
            self.assertIsNone(relay.inspection_gap);owner.close()
            with self.assertRaises(RuntimeError):relay.close()
            self.assertIsNone(relay.errors[0]['sigtermSucceededAtReadStart']);self.assertTrue(relay.owner_retirement_confirmed)
            self.assertEqual(relay.errors[0]['identityOperation'],'fd_list')

    def test_real_inspection_signal_overlap_cannot_reclassify_pre_signal_error(self):
        with self.child_relay() as (owner,relay,echo,address):
            relay.prepare_owner_retirement();entered=threading.Event();release=threading.Event();real=os.scandir;result=[]
            def scan(path):
                if threading.current_thread() is relay.thread:
                    entered.set()
                    if not release.wait(.7):raise RuntimeError('test release deadline')
                    raise PermissionError(peer.errno.EACCES,'PRIVATE')
                return real(path)
            def close():
                try:result.append(owner.close())
                except BaseException as error:result.append(error)
            with mock.patch.object(os,'scandir',scan):
                owner.process.stdin.write(b'send\n');owner.process.stdin.flush();self.assertTrue(entered.wait(2))
                worker=threading.Thread(target=close);worker.start();time.sleep(.03)
                self.assertIsNone(owner.sigterm_observation);release.set();worker.join(3)
            self.assertFalse(worker.is_alive());self.assertIsInstance(result[0],dict)
            self.assertIsNone(relay.inspection_gap);self.wait(relay.finished.is_set)
            with self.assertRaises(RuntimeError):relay.close()
            error=relay.errors[0];self.assertIsNone(error['sigtermSucceededAtReadStart'])
            self.assertLessEqual(error['identityReadFinishedMonotonic'],owner.sigterm_observation['monotonicSeconds'])

    def test_real_post_signal_nonzero_exit_does_not_resolve_gap(self):
        with self.child_relay(exit_code=2) as (owner,relay,echo,address):
            relay.prepare_owner_retirement();real=os.scandir
            def scan(path):
                if threading.current_thread() is relay.thread and owner.sigterm_observation:raise PermissionError(peer.errno.EACCES,'PRIVATE')
                return real(path)
            with mock.patch.object(os,'scandir',scan):
                with self.assertRaises(RuntimeError):owner.close()
                with self.assertRaises(RuntimeError):relay.close()
            self.assertEqual(owner.cleanup['exitCode'],2);self.assertFalse(relay.owner_retirement_confirmed)
            self.assertEqual(relay.inspection_gap['resolution'],'pending_owned_retirement')

    def test_real_natural_exit_cannot_be_relabelled_sigterm_retirement(self):
        with self.child_relay() as (owner,relay,echo,address):
            relay.prepare_owner_retirement();owner.process.stdin.write(b'exit\n');owner.process.stdin.flush();owner.process.wait(3)
            fact=owner.close();self.assertEqual(fact['exitBeforeTerminate'],0);self.assertIsNone(owner.sigterm_observation)
            with self.assertRaises(RuntimeError):relay.close()
            self.assertFalse(relay.owner_retirement_confirmed)

    def test_quarantine_rejects_new_sources_and_never_rechecks_bound_sources(self):
        relay=peer.UDPRelay(1);owner=self.owner()
        try:
            relay.bind_owner(owner);relay.prepare_owner_retirement();self.recorded_sigterm(owner)
            slot={'inode':'123','socket':socket.socket(socket.AF_INET,socket.SOCK_DGRAM),'retired':False}
            address=('127.0.0.1',1234);relay.sources[address]=slot
            with mock.patch.object(peer,'process_identity',side_effect=PermissionError(peer.errno.EACCES,'PRIVATE')):
                self.assertIsNone(relay.source_inode(address,slot))
            with mock.patch.object(relay,'source_inode',side_effect=AssertionError('must not retry')):
                self.assertIsNone(relay.current_source(address,mock.Mock()))
                with self.assertRaises(peer.IdentityFailure):relay.current_source(('127.0.0.1',1235),mock.Mock(),True)
            owner.process.poll.return_value=0;relay.close()
        finally:
            with contextlib.suppress(RuntimeError):relay.close()

    def test_cleanup_mutations_never_resolve_permission_gap(self):
        for change in ({'forcedKill':True},{'remainingGroup':[123]},{'cleanupErrorLog':True},{'exitBeforeTerminate':0},
                       {'terminationActions':[]},{'exitCode':2},{'boundCoreSHA256':'b'*64}):
            with self.subTest(change=change):
                relay=peer.UDPRelay(1);owner=self.owner()
                try:
                    relay.bind_owner(owner);relay.prepare_owner_retirement();self.recorded_sigterm(owner)
                    with mock.patch.object(peer,'process_identity',side_effect=PermissionError(peer.errno.EACCES,'PRIVATE')):
                        relay.source_inode(('127.0.0.1',1234),{'inode':'123'})
                    owner.process.poll.return_value=0;owner.cleanup.update(change)
                    with self.assertRaises(RuntimeError):relay.close()
                    self.assertEqual(relay.inspection_gap['resolution'],'pending_owned_retirement')
                finally:
                    with contextlib.suppress(RuntimeError):relay.close()

    def test_gate_timeout_is_sticky_and_never_publishes_signal_success(self):
        owner=self.owner();owner.inspection_gate=mock.Mock();owner.inspection_gate.acquire.return_value=False
        with self.assertRaises(peer.IdentityFailure):
            with peer.process_inspection_gate(owner):self.fail('gate admitted')
        owner.inspection_gate.release.assert_not_called();self.assertIsNone(owner.sigterm_observation)


    def test_real_child_fd_close_while_alive_only_tombstones_existing_slot(self):
        with self.child_relay() as (owner,relay,echo,address):
            back=relay.sources[address]['socket'].getsockname()
            owner.process.stdin.write(b'close\n');owner.process.stdin.flush();self.assertEqual(self.line(owner),'CLOSED')
            echo.socket.sendto(b'late',back);self.wait(lambda:relay.retired_drops[1]==1)
            self.assertIsNone(owner.process.poll());self.assertIsNone(relay.inspection_gap)
            self.assertTrue(relay.sources[address]['retired']);self.assertEqual(relay.counts,[1,1])
            # This fixture intentionally closed its socket; natural exit must
            # remain an unsignaled outcome, not be presented as graceful core.
            owner.process.stdin.write(b'exit\n');owner.process.stdin.flush();owner.process.wait(3);owner.close();relay.close()

    def test_real_unknown_source_during_gap_stops_without_any_forward(self):
        with self.child_relay(signal_delay=.3) as (owner,relay,echo,address):
            relay.prepare_owner_retirement();real=os.scandir;results=[]
            def scan(path):
                if threading.current_thread() is relay.thread and owner.sigterm_observation:raise PermissionError(peer.errno.EACCES,'PRIVATE')
                return real(path)
            def close():
                try:results.append(owner.close())
                except BaseException as error:results.append(error)
            stranger=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            try:
                with mock.patch.object(os,'scandir',scan):
                    worker=threading.Thread(target=close);worker.start();self.wait(lambda:relay.inspection_gap is not None)
                    stranger.bind(('127.0.0.1',0));stranger.sendto(b'unknown',('127.0.0.1',relay.port))
                    self.wait(relay.finished.is_set);worker.join(3)
                self.assertFalse(worker.is_alive());self.assertIsInstance(results[0],dict)
                with self.assertRaises(RuntimeError):relay.close()
                self.assertEqual(relay.errors[0]['category'],'unowned_source_during_quarantine')
                self.assertEqual(relay.errors[0]['identityOperation'],'quarantine_new_source')
                self.assertIsNone(relay.errors[0]['identityReadStartedMonotonic'])
                self.assertEqual(relay.counts,[1,1]);self.assertEqual(relay.inspection_gap['resolution'],'pending_owned_retirement')
            finally:stranger.close()

    def test_pid_identity_mismatch_after_signal_never_becomes_gap(self):
        relay=peer.UDPRelay(1);owner=self.owner()
        try:
            relay.bind_owner(owner);relay.prepare_owner_retirement();self.recorded_sigterm(owner)
            with mock.patch.object(peer,'process_identity',return_value=dict(owner.start_identity,startTicks=0)):
                with self.assertRaises(peer.IdentityFailure):relay.source_inode(('127.0.0.1',1234),{'inode':'123'})
            self.assertIsNone(relay.inspection_gap)
        finally:
            with contextlib.suppress(RuntimeError):relay.close()

    def test_real_signal_failure_publishes_no_success_and_remains_sticky(self):
        with self.child_relay() as (owner,relay,echo,address):
            relay.prepare_owner_retirement()
            with mock.patch.object(signal,'pidfd_send_signal',side_effect=PermissionError(peer.errno.EPERM,'PRIVATE')):
                with self.assertRaises(RuntimeError):owner.close()
            self.assertIsNone(owner.sigterm_observation);self.assertIsNone(owner.process.poll())
            self.assertTrue(owner.log.closed);self.assertIsNone(owner.pidfd)
            self.assertEqual(owner.cleanup['closeOperationFailure']['stage'],'sigterm')
            self.assertFalse(owner.cleanup['privateLogObservedAfterExit'])
            with self.assertRaises(RuntimeError):owner.close()
            with self.assertRaises(RuntimeError):relay.close()
            self.assertFalse(relay.owner_retirement_confirmed)

    def test_real_signal_deadline_force_remains_failure(self):
        with self.child_relay(signal_delay=5) as (owner,relay,echo,address):
            relay.prepare_owner_retirement();real_wait=owner.process.wait;calls=[]
            def shortened_wait(timeout):
                calls.append(timeout)
                if len(calls)==1:raise subprocess.TimeoutExpired('exact test-owned child',timeout)
                return real_wait(timeout)
            with mock.patch.object(owner.process,'wait',shortened_wait):
                with self.assertRaises(RuntimeError):owner.close()
            with self.assertRaises(RuntimeError):relay.close()
            self.assertEqual(calls,[15,5]);self.assertTrue(owner.cleanup['forcedKill'])
            self.assertEqual([a['signal'] for a in owner.cleanup['terminationActions']],['SIGTERM','SIGKILL'])
            self.assertFalse(relay.owner_retirement_confirmed)
            with self.assertRaises(RuntimeError):owner.close()

    def test_actual_gate_timeout_has_no_signal_and_does_not_leak_owned_child(self):
        with self.child_relay() as (owner,relay,echo,address):
            relay.prepare_owner_retirement();gate=owner.inspection_gate;entered=threading.Event();release=threading.Event()
            def hold():
                with gate:entered.set();release.wait(2)
            worker=threading.Thread(target=hold);worker.start();self.assertTrue(entered.wait(1))
            try:
                with self.assertRaises(RuntimeError):owner.close()
                self.assertIsNone(owner.sigterm_observation);self.assertIsNone(owner.process.poll())
                self.assertTrue(owner.log.closed);self.assertIsNone(owner.pidfd)
                self.assertEqual(owner.cleanup['closeOperationFailure']['stage'],'inspection_gate')
            finally:release.set();worker.join(2)
            self.assertFalse(worker.is_alive())
            with self.assertRaises(RuntimeError):owner.close()
            with self.assertRaises(RuntimeError):relay.close()
            self.assertFalse(relay.owner_retirement_confirmed)


    def test_cleanup_budget_is_independent_of_expired_suite(self):
        with self.child_relay() as (owner,relay,echo,address):
            relay.prepare_owner_retirement()
            with mock.patch.object(peer,'SUITE_DEADLINE',time.monotonic()-1):
                fact=owner.close();relay.close()
            self.assertEqual(fact['exitCode'],0);self.assertTrue(owner.log.closed);self.assertIsNone(owner.pidfd)
            self.assertIsNone(fact['closeOperationFailure']);self.assertTrue(relay.owner_retirement_confirmed)

    def test_source_gate_failure_does_not_reuse_previous_read_timestamps(self):
        relay=peer.UDPRelay(1);owner=self.owner()
        try:
            relay.bind_owner(owner);relay.source_inode(('127.0.0.1',1234))
            self.assertIsNotNone(relay.identity_read_start)
            gate=mock.Mock();gate.acquire.return_value=False;owner.inspection_gate=gate
            with self.assertRaises(peer.IdentityFailure):relay.source_inode(('127.0.0.1',1234),{'inode':'123'})
            self.assertEqual(relay.identity_operation,'ordering_gate')
            self.assertIsNone(relay.identity_read_start);self.assertIsNone(relay.identity_read_end)
            self.assertIsNone(relay.identity_signal_at_start)
            self.assertLessEqual(relay.identity_gate_wait_start,relay.identity_gate_wait_end)
        finally:relay.close()

    def test_real_run_case_gate_failure_closes_all_handles_and_drains_child_once(self):
        # Actual run_case cleanup and CoreProcess.close, two real Python children;
        # only product construction/readiness is replaced, never a protocol PASS.
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);binary=root/'sing-box';binary.write_bytes(b'core');(root/'libcronet.so').write_bytes(b'side')
            row={'core':{'member':'sing-box','bytes':4,'sha256':peer.digest(b'core')},
                 'sidecar':{'member':'libcronet.so','bytes':4,'sha256':peer.digest(b'side')}}
            original_core=peer.CoreProcess;original_echo=peer.Echo;original_relay=peer.UDPRelay
            processes=[];fixtures=[];relays=[];threads=[];release=threading.Event();outer=self
            class OwnedFixture(original_core):
                def __init__(self,binary,config,directory,role,expected_hash,events):
                    self.role=role;self.events=events;self.source_root=ROOT;self.inspection_gate=threading.RLock()
                    self.sigterm_observation=None;self.stopped=False;self.cleanup=None
                    self.log_path=directory/(role+'.private.log');self.log=self.log_path.open('wb')
                    self.config_fact={'sha256':peer.digest(json.dumps(config,separators=(',',':')).encode()),'bytes':1}
                    code="import signal,sys,time; signal.signal(signal.SIGTERM,lambda *_:sys.exit(0)); print('READY',flush=True); time.sleep(30)"
                    self.process=subprocess.Popen([sys.executable,'-u','-c',code],stdout=subprocess.PIPE,stderr=self.log,start_new_session=True)
                    self.pid=self.process.pid;self.pidfd=os.pidfd_open(self.pid);self.start_identity=peer.process_identity(self.pid)
                    self.bound_sha256=peer.digest(Path(f'/proc/{self.pid}/exe').read_bytes());processes.append(self)
                    outer.assertEqual(outer.line(self),'READY');self.process.stdout.close()
                def wait_udp(self,port):pass
                def wait_tcp(self,port):
                    entered=threading.Event()
                    def hold():
                        with self.inspection_gate:entered.set();release.wait(5)
                    worker=threading.Thread(target=hold);threads.append(worker);worker.start()
                    outer.assertTrue(entered.wait(1));raise RuntimeError('fixed fixture readiness stop')
            def echo(*a,**kw):
                result=original_echo(*a,**kw);fixtures.append(result);return result
            def relay(*a,**kw):
                result=original_relay(*a,**kw);relays.append(result);return result
            try:
                with mock.patch.object(peer,'certificate',return_value=('CA','CERT','KEY')), \
                     mock.patch.object(peer,'config_check',return_value={}),mock.patch.object(peer,'CoreProcess',OwnedFixture), \
                     mock.patch.object(peer,'Echo',side_effect=echo),mock.patch.object(peer,'UDPRelay',side_effect=relay):
                    result=peer.run_case(binary,row,root,'naive-h3')
                self.assertEqual(result['status'],'FAIL');self.assertFalse(result['continuationSafe'])
                self.assertEqual(len(processes),2);self.assertEqual(len(result['descendantRetirement']['retired']),1)
                self.assertEqual(result['descendantRetirement']['remaining'],[]);self.assertFalse(result['descendantRetirement']['forcedKill'])
                self.assertTrue(any('required recovery' in error for error in result['cleanupErrors']))
                for child in processes:
                    self.assertIsNotNone(child.process.poll());self.assertTrue(child.log.closed);self.assertIsNone(child.pidfd)
                    self.assertIsNotNone(child.cleanup)
                healthy=next(child for child in processes if child.role=='healthy')
                self.assertEqual(healthy.cleanup['closeOperationFailure']['stage'],'inspection_gate')
                self.assertIsNone(healthy.cleanup['exitCode']);self.assertFalse(healthy.cleanup['privateLogObservedAfterExit'])
                self.assertEqual(healthy.cleanup['terminationActions'],[])
                with self.assertRaises(RuntimeError):healthy.close()
                for item in fixtures:self.assertFalse(item.thread.is_alive());self.assertEqual(item.socket.fileno(),-1)
                self.assertTrue(relays[0].observation()['threadJoined']);self.assertTrue(relays[0].observation()['allSocketsClosed'])
            finally:
                release.set()
                for worker in threads:worker.join(2);self.assertFalse(worker.is_alive())
                # This assertion occurs before any emergency cleanup: passing
                # cannot depend on the test finally retrying CoreProcess.close.
                self.assertFalse(any(child.process.poll() is None for child in processes))


    def test_log_snapshot_exit_fact_is_sampled_before_read_not_after(self):
        with tempfile.TemporaryDirectory() as td:
            owner=object.__new__(peer.CoreProcess);owner.role='fixture';owner.events=[];owner.source_root=ROOT
            owner.pid=123;owner.pidfd=None;owner.start_identity={'pid':123,'startTicks':456};owner.bound_sha256='a'*64
            owner.stopped=False;owner.cleanup=None;owner.sigterm_observation=None
            owner.inspection_gate=mock.Mock();owner.inspection_gate.acquire.return_value=False
            owner.process=mock.Mock();owner.process.poll.side_effect=[None,None,0];owner.process.returncode=0
            owner.log_path=Path(td)/'private.log';owner.log_path.write_bytes(b'');owner.log=mock.Mock()
            with mock.patch.object(peer,'process_group_members',return_value=[]):
                with self.assertRaises(RuntimeError):owner.close()
            self.assertEqual(owner.cleanup['exitCode'],0)
            self.assertFalse(owner.cleanup['privateLogObservedAfterExit'])
            self.assertFalse(owner.cleanup['gracefulCleanupProven'])

    def test_log_handle_failure_does_not_skip_pidfd_close_or_become_success(self):
        with tempfile.TemporaryDirectory() as td:
            owner=object.__new__(peer.CoreProcess);owner.role='fixture';owner.events=[];owner.source_root=ROOT
            owner.pid=123;owner.pidfd=987;owner.start_identity={'pid':123,'startTicks':456};owner.bound_sha256='a'*64
            owner.stopped=False;owner.cleanup=None;owner.sigterm_observation=None
            owner.process=mock.Mock();owner.process.poll.return_value=0;owner.process.returncode=0
            owner.log_path=Path(td)/'private.log';owner.log_path.write_bytes(b'');owner.log=mock.Mock()
            owner.log.close.side_effect=OSError(peer.errno.EIO,'PRIVATE')
            with mock.patch.object(peer,'process_group_members',return_value=[]),mock.patch.object(os,'close') as close:
                with self.assertRaises(RuntimeError):owner.close()
            close.assert_called_once_with(987);self.assertIsNone(owner.pidfd)
            self.assertEqual(owner.cleanup['resourceCloseErrors'],['private_log_close'])
            self.assertNotIn('PRIVATE',json.dumps(owner.cleanup))
            with self.assertRaises(RuntimeError):owner.close()


if __name__=='__main__':unittest.main()
