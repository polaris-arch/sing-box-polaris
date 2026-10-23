import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import github_read_transport as t


class ReadTransportTests(unittest.TestCase):
    path = 'repos/polaris-arch/sing-box-polaris/actions/artifacts/31/zip'

    def fake_child(self, script):
        real = subprocess.Popen
        def start(command, **kwargs):
            self.assertEqual(command, ['gh', 'api', '--include', '--method', 'GET', self.path])
            return real([sys.executable, '-c', script], **kwargs)
        return mock.patch.object(t.subprocess, 'Popen', side_effect=start)

    def test_real_stream_headers_and_digest_no_secret_diagnostics(self):
        body = b'PK\x03\x04binary\x00'
        script = 'import os;os.write(1,' + repr(b'HTTP/2 200 OK\r\nLocation: https://secret.invalid/?sig=secret\r\nSet-Cookie: secret\r\nX-GitHub-Request-Id: safe\r\n\r\n'+body) + ')'
        with self.fake_child(script):
            out=io.BytesIO();r=t._attempt(self.path,out,100,2)
        self.assertEqual(out.getvalue(),body);self.assertEqual(r['sha256'],hashlib.sha256(body).hexdigest())
        self.assertEqual(r['headers'],{'x-github-request-id':'safe'});self.assertNotIn('secret',json.dumps(r))

    def test_non200_response_is_classified_without_retaining_body(self):
        for status in (400,401,403,404,410,429,500,502,503,504,501,302):
            script='import os,sys;os.write(1,'+repr(('HTTP/2 '+str(status)+' error\r\nRetry-After: 2\r\n\r\nsecret').encode())+');os.write(2,b"connection reset by peer https://secret");sys.exit(1)'
            with self.subTest(status=status),self.fake_child(script):
                out=io.BytesIO()
                with self.assertRaises(t.ReadFailure) as caught:t._attempt(self.path,out,100,2)
                self.assertEqual(caught.exception.retryable,status in t.RETRY_STATUS)
                self.assertEqual(out.getvalue(),b'');self.assertNotIn('secret',str(caught.exception))

    def test_4xx_hanging_body_never_retries(self):
        with self.fake_child('import os,time;os.write(1,b"HTTP/2 403 forbidden\\r\\n\\r\\n");time.sleep(10)'):
            with self.assertRaises(t.ReadFailure) as caught:t._attempt(self.path,io.BytesIO(),100,.1)
            self.assertFalse(caught.exception.retryable)

    def test_known_network_exit_and_unknown_exit(self):
        for message,allowed in [(b'connection reset by peer',True),(b'i/o timeout',True),(b'TLS handshake timeout',True),(b'certificate expired',False),(b'authentication required',False)]:
            with self.subTest(message=message),self.fake_child('import os,sys;os.write(2,'+repr(message)+');sys.exit(1)'):
                with self.assertRaises(t.ReadFailure) as caught:t._attempt(self.path,io.BytesIO(),100,2)
                self.assertEqual(caught.exception.retryable,allowed)

    def test_stderr_flood_is_drained_and_not_logged(self):
        with self.fake_child('import os;os.write(2,b"secret"*50000);os.write(1,b"HTTP/2 200 OK\\n\\nhello")'):
            out=io.BytesIO();r=t._attempt(self.path,out,10,2)
        self.assertEqual(out.getvalue(),b'hello');self.assertNotIn('secret',str(r))

    def test_stdout_idle_and_eof_but_child_alive_deadlines_reap(self):
        for script in ['import time;time.sleep(10)','import os,time;os.close(1);os.close(2);time.sleep(10)']:
            with self.subTest(script=script),self.fake_child(script):
                start=time.monotonic()
                with self.assertRaises(t.ReadFailure) as caught:t._attempt(self.path,io.BytesIO(),100,.1)
                self.assertEqual(caught.exception.kind,'read deadline');self.assertLess(time.monotonic()-start,2)

    def test_cleanup_uncertainty_preserves_primary_and_disables_retry(self):
        child=mock.Mock()
        child.stdout=tempfile.TemporaryFile();child.stderr=tempfile.TemporaryFile()
        child.stdout.write(b'HTTP/2 503 unavailable\r\n\r\n');child.stdout.seek(0)
        child.poll.return_value=None
        child.wait.side_effect=subprocess.TimeoutExpired('gh',.01)
        with mock.patch.object(t.subprocess,'Popen',return_value=child):
            with self.assertRaises(t.ReadFailure) as caught:t._attempt(self.path,io.BytesIO(),100,.1)
        self.assertEqual(caught.exception.kind,'read deadline')
        self.assertFalse(caught.exception.retryable)
        self.assertEqual(caught.exception.__notes__,['GitHub GET child cleanup not confirmed'])
        child.kill.assert_called_once()
        self.assertTrue(child.stdout.closed);self.assertTrue(child.stderr.closed)

    def test_size_limit_and_sink_failure_not_retryable(self):
        with self.fake_child('import os;os.write(1,b"HTTP/2 200 OK\\r\\n\\r\\n12345")'):
            with self.assertRaises(t.ReadFailure) as caught:t._attempt(self.path,io.BytesIO(),4,2)
            self.assertFalse(caught.exception.retryable)
        with self.fake_child('import os;os.write(1,b"HTTP/2 200 OK\\r\\n\\r\\n12345")'):
            sink=io.BytesIO()
            with mock.patch.object(sink,'write',side_effect=OSError('quota')),self.assertRaises(OSError):t._attempt(self.path,sink,10,2)

    def test_malformed_duplicate_headers_and_multiblock_fail(self):
        for raw in [b'wrong\r\n\r\n',b'HTTP/2 200 OK\r\nRetry-After: 1\r\nRetry-After: 2\r\n\r\n',b'HTTP/2 302 Found\r\n\r\nHTTP/2 200 OK\r\n\r\nbody',b'X'*65537]:
            with self.subTest(raw=raw[:30]),self.fake_child('import os;os.write(1,'+repr(raw)+')'):
                with self.assertRaises(t.ReadFailure) as caught:t._attempt(self.path,io.BytesIO(),100,2)
                self.assertFalse(caught.exception.retryable)

    def test_retry_restarts_empty_body_and_hash(self):
        calls=[];out=io.BytesIO(b'old');policy=t.RetryBudget();records=[]
        def attempt(path,sink,maximum,timeout):
            calls.append(sink.getvalue());sink.write(b'partial' if len(calls)==1 else b'ok')
            if len(calls)==1:raise t.ReadFailure('HTTP response',503,{'retry-after':'0'},True)
            return {'bytes':2,'sha256':hashlib.sha256(b'ok').hexdigest(),'status':200,'headers':{}}
        with mock.patch.object(t,'_attempt',side_effect=attempt):r=t.read_get(self.path,out,100,budget=policy,record=lambda **kw:records.append(kw))
        self.assertEqual(calls,[b'',b'']);self.assertEqual(out.getvalue(),b'ok');self.assertEqual(r['sha256'],hashlib.sha256(b'ok').hexdigest());self.assertEqual(policy.extra_gets,1);self.assertIsNone(records[-1]['readError'])

    def test_three_attempts_inclusive_and_process_budget_shared(self):
        policy=t.RetryBudget();err=t.ReadFailure('HTTP response',503,{'retry-after':'0'},True)
        with mock.patch.object(t,'_attempt',side_effect=err) as call:
            for _ in range(5):
                with self.assertRaises(t.ReadFailure):t.read_get(self.path,io.BytesIO(),100,budget=policy)
        self.assertEqual(policy.extra_gets,8);self.assertEqual(call.call_count,13)

    def test_retry_after_seconds_dates_and_invalid(self):
        now=1000000000
        self.assertEqual(t.retry_delay('12',1,now),12)
        self.assertEqual(t.retry_delay('Sun, 09 Sep 2001 01:47:00 GMT',1,now),20)
        self.assertEqual(t.retry_delay('Sun, 09 Sep 2001 01:46:00 GMT',1,now),0)
        for value in ('-1','1.5','nonsense','1, 2','Sun, 09 Sep 2001 01:47:00'):
            with self.subTest(value=value),self.assertRaises(t.ReadFailure):t.retry_delay(value,1,now)

    def test_retry_after_total_and_wait_budget_not_truncated(self):
        for delay in ('1321','121'):
            with mock.patch.object(t,'_attempt',side_effect=t.ReadFailure('HTTP response',503,{'retry-after':delay},True)) as call,mock.patch.object(t.time,'sleep') as sleep:
                with self.assertRaisesRegex(t.ReadFailure,'budget'):t.read_get(self.path,io.BytesIO(),100,budget=t.RetryBudget())
                self.assertEqual(call.call_count,1);sleep.assert_not_called()

    def test_total_deadline_and_shared_sleep_budget(self):
        now = [0.0]
        def attempt(*args):
            now[0] += 700
            raise t.ReadFailure('HTTP response',503,{'retry-after':'0'},True)
        with mock.patch.object(t.time,'monotonic',side_effect=lambda:now[0]),mock.patch.object(t,'_attempt',side_effect=attempt) as call:
            with self.assertRaisesRegex(t.ReadFailure,'budget'):t.read_get(self.path,io.BytesIO(),100,budget=t.RetryBudget())
            self.assertEqual(call.call_count,2)
        budget=t.RetryBudget();budget.wait_seconds=119
        with mock.patch.object(t,'_attempt',side_effect=t.ReadFailure('HTTP response',503,{'retry-after':'2'},True)) as call,mock.patch.object(t.time,'sleep') as sleep:
            with self.assertRaisesRegex(t.ReadFailure,'budget'):t.read_get(self.path,io.BytesIO(),100,budget=budget)
            call.assert_called_once();sleep.assert_not_called()

    def test_4xx_integrity_and_unknown_errors_never_retried(self):
        for err in [t.ReadFailure('HTTP response',403,{},False),t.ReadFailure('size mismatch',200),ValueError('hash'),OSError('quota')]:
            with mock.patch.object(t,'_attempt',side_effect=err) as call:
                with self.assertRaises(type(err)):t.read_get(self.path,io.BytesIO(),100,budget=t.RetryBudget())
                self.assertEqual(call.call_count,1)

    def test_no_method_token_or_unapproved_host_and_rate_limit_compatibility(self):
        for path in ['https://api.github.com/repos/x','repos/other/repo/file','repos/polaris-arch/sing-box-polaris/x\n','--method=POST']:
            with self.subTest(path=path),self.assertRaises(t.ReadFailure):t.read_get(path,io.BytesIO(),100)
        with mock.patch.object(t,'_attempt',return_value={'status':200,'headers':{},'bytes':2,'sha256':'x'}) as call:
            t.read_get('rate_limit',io.BytesIO(),100);t.read_get('repos/polaris-arch/sing-box-polaris',io.BytesIO(),100);t.read_get(self.path+'?per_page=100&page=2',io.BytesIO(),100)
            self.assertEqual(call.call_count,3)


if __name__=='__main__':unittest.main()
