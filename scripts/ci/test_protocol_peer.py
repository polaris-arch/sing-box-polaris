"""Runner controls, not Naive/MASQUE protocol PASS or native-core execution."""
import contextlib
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
from unittest import mock

import protocol_peer as peer

ROOT = Path(__file__).resolve().parents[2]


class ControlledPeerContracts(unittest.TestCase):
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
                endpoint = (client.get('outbounds') or client['endpoints'])[0]
                self.assertEqual(endpoint['server'], '127.0.0.1')
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
        for mutation, text in [('wrong-ca','ERR_CERT_AUTHORITY_INVALID'),('wrong-sni','certificate is valid for localhost, not wrong.invalid'),('wrong-path','unexpected status: 404')]:
            self.assertTrue(peer.negative_evidence('masque-h3',mutation,text,b'')['specificRejectionObserved'])
            with self.assertRaisesRegex(RuntimeError,'lacks actual'):
                peer.negative_evidence('masque-h3',mutation,b'generic timeout',b'')

    def test_exact_read_rejects_drip_beyond_absolute_deadline(self):
        sock=mock.Mock();sock.recv.return_value=b'x'
        with mock.patch.object(peer.time,'monotonic',side_effect=[0,1,9]), mock.patch.object(peer,'SUITE_DEADLINE',None):
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
        sock=mock.Mock();sock.recv.side_effect=socket.timeout()
        with self.assertRaisesRegex(RuntimeError,'unknown after timeout'):peer.retire_old_stream(sock)
        sock.close.assert_called_once()
        for outcome in (b'', ConnectionResetError(), BrokenPipeError()):
            sock=mock.Mock()
            if isinstance(outcome,Exception):sock.recv.side_effect=outcome
            else:sock.recv.return_value=outcome
            self.assertTrue(peer.retire_old_stream(sock)['transportClosed'])
        sock=mock.Mock();sock.recv.return_value=b'late nonce'
        with self.assertRaisesRegex(RuntimeError,'returned a new payload'):peer.retire_old_stream(sock)

    def test_keep_connection_is_closed_when_payload_fails(self):
        sock=mock.Mock();sock.recv.return_value=b''
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

    def test_generated_certificate_is_valid_only_for_declared_localhost(self):
        if not peer.shutil.which('openssl'):self.skipTest('existing OpenSSL absent')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);old=os.umask(0o077)
            try:ca,cert,key=peer.certificate(root,'test')
            finally:os.umask(old)
            self.assertIn('BEGIN CERTIFICATE',ca);self.assertIn('BEGIN PRIVATE KEY',key)
            valid=subprocess.run(['openssl','verify','-CAfile',str(root/'test-ca.pem'),'-verify_hostname','localhost',str(root/'test.pem')],capture_output=True)
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


if __name__=='__main__':unittest.main()
