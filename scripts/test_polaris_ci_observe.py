import hashlib
import io
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

import polaris_ci_observe as observe

SCRIPT = Path(__file__).with_name('polaris_ci_observe.py')

def budget_env(folder, available=300):
    path = Path(folder) / 'job-budget.json'
    path.write_text(json.dumps({'schema':'polaris-ci-job-budget-v1', 'startedMonotonic':time.monotonic(),
        'jobSeconds':available+61, 'evidenceReserveSeconds':1, 'safetySeconds':60}))
    return dict(os.environ, POLARIS_JOB_BUDGET=str(path))


class ObservationTests(unittest.TestCase):
    def run_child(self, code, timeout=30, expected=0):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'observation'
            env = dict(budget_env(folder), HIDDEN_ENV_TOKEN='do-not-dump-this-marker')
            command = [sys.executable, '-B', str(SCRIPT), '--phase', 'fixture', '--output', str(output),
                       '--timeout-seconds', str(timeout), '--', sys.executable, '-u', '-c', code]
            run = subprocess.run(command, capture_output=True, env=env, timeout=45)
            self.assertEqual(run.returncode, expected, run.stderr.decode())
            row = json.loads((output / 'observation.json').read_text())
            self.assertEqual(row['ciExitCode'], expected)
            self.assertNotIn('do-not-dump-this-marker', json.dumps(row))
            self.assertIsNone(row['memoryObservation']['simultaneousProcessTreePeakBytes'])
            return row, (output / 'command.log').read_bytes(), run.stdout

    def test_success_stream_and_original_failure_code(self):
        row, raw, stdout = self.run_child('import sys; print("out", flush=True); print("err", file=sys.stderr, flush=True)')
        self.assertIn(b'out', raw); self.assertIn(b'err', raw)
        self.assertEqual(row['childMergedStreamSha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(row['outcome'], 'success')
        row, raw, stdout = self.run_child('import sys; print("original-failure"); sys.exit(7)', expected=7)
        self.assertEqual(row['outcome'], 'failure'); self.assertEqual(row['childExitCode'], 7)
        self.assertIn(b'original-failure', raw)

    def test_deadline_fails_and_preserves_original_prefix(self):
        row, raw, stdout = self.run_child('import time; print("before-timeout", flush=True); time.sleep(60)', timeout=0.8, expected=124)
        self.assertEqual(row['outcome'], 'timeout'); self.assertIn(b'before-timeout', raw)

    @unittest.skipIf(os.name == 'nt', 'POSIX signal contract; Windows owns a Job Object')
    def test_cancel_preserves_signal_and_reaps_owned_group(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'observation'; marker = Path(folder) / 'started'
            child_code = 'from pathlib import Path; import time; Path(' + repr(str(marker)) + ').write_text("ready"); print("cancel-prefix", flush=True); time.sleep(60)'
            p = subprocess.Popen([sys.executable, '-B', str(SCRIPT), '--phase', 'cancel', '--output', str(output),
                    '--timeout-seconds', '30', '--', sys.executable, '-u', '-c', child_code], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=budget_env(folder))
            deadline = time.monotonic() + 10
            while not marker.exists() and time.monotonic() < deadline: time.sleep(0.05)
            self.assertTrue(marker.exists()); p.send_signal(signal.SIGTERM)
            stdout, stderr = p.communicate(timeout=20)
            self.assertEqual(p.returncode, 128 + signal.SIGTERM, stderr.decode())
            row = json.loads((output / 'observation.json').read_text()); self.assertEqual(row['receivedSignal'], signal.SIGTERM)
            self.assertEqual(row['outcome'], 'cancelled'); self.assertIn(b'cancel-prefix', (output / 'command.log').read_bytes())

    @unittest.skipIf(os.name == 'nt', 'POSIX producer finally owns its detached session')
    def test_deadline_allows_existing_owner_to_close_detached_guest(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / 'guest.pid'; output = Path(folder) / 'observation'
            code = ('import subprocess,sys,time\nfrom pathlib import Path\n'
                    'guest=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"],start_new_session=True)\n'
                    'Path(' + repr(str(marker)) + ').write_text(str(guest.pid))\n'
                    'try: time.sleep(60)\nfinally: guest.terminate();guest.wait()\n')
            run = subprocess.run([sys.executable, '-B', str(SCRIPT), '--phase', 'guest', '--output', str(output),
                  '--timeout-seconds', '1', '--', sys.executable, '-u', '-c', code], capture_output=True, timeout=30, env=budget_env(folder))
            self.assertEqual(run.returncode,124,run.stderr.decode())
            pid=int(marker.read_text())
            with self.assertRaises(ProcessLookupError): os.kill(pid,0)
            self.assertEqual(json.loads((output/'observation.json').read_text())['outcome'],'timeout')

    def test_leader_exits_descendant_ignores_signal_and_holds_pipe(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); marker = root / 'descendant.pid'; output = root / 'observation'
            descendant = ('import os,signal,time\nfrom pathlib import Path\n'
                'signal.signal(signal.SIGINT,signal.SIG_IGN)\n'
                'Path(' + repr(str(marker)) + ').write_text(str(os.getpid()))\n'
                'print("descendant-holds-pipe",flush=True)\ntime.sleep(60)\n')
            leader = ('import os,subprocess,sys,time\nfrom pathlib import Path\n'
                'subprocess.Popen([sys.executable,"-u","-c",' + repr(descendant) + '])\n'
                'limit=time.monotonic()+5\n'
                'while not Path(' + repr(str(marker)) + ').exists() and time.monotonic()<limit: time.sleep(.02)\n'
                'os._exit(0)\n')
            started = time.monotonic()
            run = subprocess.run([sys.executable, '-B', str(SCRIPT), '--phase', 'held-pipe', '--output', str(output),
                  '--timeout-seconds', '30', '--', sys.executable, '-u', '-c', leader],
                  capture_output=True, timeout=22, env=budget_env(folder))
            self.assertEqual(run.returncode, 1, run.stderr.decode())
            self.assertLess(time.monotonic() - started, 20)
            row = json.loads((output / 'observation.json').read_text())
            self.assertTrue(row['ownedTreeCleanupComplete']); self.assertTrue(row['streamObservedThroughEOF'])
            self.assertEqual(row['outcome'], 'failure')
            self.assertIn(b'descendant-holds-pipe', (output / 'command.log').read_bytes())
            pid = int(marker.read_text())
            if os.name == 'nt':
                import ctypes
                api = ctypes.WinDLL('kernel32', use_last_error=True)
                api.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
                api.OpenProcess.restype = ctypes.c_void_p
                api.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
                api.CloseHandle.argtypes = [ctypes.c_void_p]
                handle = api.OpenProcess(0x100000, False, pid)
                if handle:
                    try: self.assertEqual(api.WaitForSingleObject(handle, 0), 0)
                    finally: api.CloseHandle(handle)
            else:
                proc = Path('/proc') / str(pid) / 'stat'
                if proc.exists(): self.assertEqual(proc.read_text().rsplit(')', 1)[1].split()[0], 'Z')
                else:
                    with self.assertRaises(ProcessLookupError): os.kill(pid, 0)

    def test_two_phases_share_short_job_budget_and_keep_evidence_reserve(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); env = budget_env(folder, available=1.3)
            first = root / 'first'; second = root / 'second'; marker = root / 'must-not-run'
            base = [sys.executable, '-B', str(SCRIPT), '--timeout-seconds', '30', '--phase']
            a = subprocess.run(base + ['first', '--output', str(first), '--', sys.executable, '-u', '-c',
                'import time;print("first-phase",flush=True);time.sleep(60)'], env=env, capture_output=True, timeout=20)
            self.assertEqual(a.returncode, 124)
            b = subprocess.run(base + ['second', '--output', str(second), '--', sys.executable, '-c',
                'from pathlib import Path;Path(' + repr(str(marker)) + ').touch()'], env=env, capture_output=True, timeout=20)
            self.assertNotEqual(b.returncode, 0); self.assertFalse(marker.exists())
            row = json.loads((second / 'observation.json').read_text())
            self.assertEqual(row['memoryObservation']['kind'], 'not-launched')
            self.assertEqual(row['outcome'], 'failure')

    def test_slow_cache_elapsed_cannot_spend_evidence_reserve(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); budget = root / 'budget'; output = root / 'outputs'
            budget.write_text(json.dumps({'schema':'polaris-ci-job-budget-v1','startedMonotonic':100,
                'jobSeconds':5400,'evidenceReserveSeconds':900,'safetySeconds':60}))
            with patch.object(observe.time, 'monotonic', return_value=4400):
                self.assertEqual(observe.cache_window(budget, 2, output), 2)
            # Simulated elapsed time includes checkout/setup/slow restoration.
            with patch.object(observe.time, 'monotonic', return_value=4500):
                self.assertEqual(observe.cache_window(budget, 2, output), 0)
            self.assertIn('allowed=false', output.read_text())
            self.assertEqual(observe.job_window(budget, 4500, now=4500), 40)

    @unittest.skipIf(os.name == 'nt', 'strict Bash gate controls run on the Linux contract runner')
    def test_actual_strict_child_stops_failures_and_wrong_baseline(self):
        for body in ('false\nprintf swallowed', 'false | tee log\nprintf swallowed',
                     'test actual = wrong-baseline\nprintf tests-started'):
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder); script = root / 'command.sh'; output = root / 'observation'
                script.write_text(body)
                run = subprocess.run([sys.executable, '-B', str(SCRIPT), '--phase', 'strict', '--output', str(output),
                    '--timeout-seconds', '20', '--', 'bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', str(script)],
                    cwd=root, env=budget_env(folder), capture_output=True, timeout=30)
                self.assertNotEqual(run.returncode, 0)
                raw=(output / 'command.log').read_bytes()
                self.assertNotIn(b'swallowed', raw); self.assertNotIn(b'tests-started', raw)

    def test_closed_stdout_does_not_bypass_command_deadline(self):
        row, raw, stdout = self.run_child('import os,time;os.close(1);os.close(2);time.sleep(60)', timeout=0.8, expected=124)
        self.assertEqual(row['outcome'], 'timeout');self.assertTrue(row['ownedTreeCleanupComplete'])

    def test_terminal_eof_is_consumed_before_post_exit_classification(self):
        clock = [0.0]
        class SlowOutput(io.BytesIO):
            def flush(self): clock[0] += 2
        sink = io.TextIOWrapper(SlowOutput(), write_through=True)
        child = Mock(); child.poll.return_value = child.wait.return_value = 0
        chunks = Mock(); chunks.get.side_effect = [b'completed-tail\n', None]
        chunks.empty.return_value = True  # Snapshot just before EOF delivery.
        reader = Mock(); reader.is_alive.return_value = False
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            try:
                with patch.object(observe.time, 'monotonic', side_effect=lambda: clock[0]), \
                     patch.object(observe, 'job_window', return_value=20), \
                     patch.object(observe.subprocess, 'Popen', return_value=child), \
                     patch.object(observe, 'WindowsJob', return_value=None), \
                     patch.object(observe.threading, 'Thread', return_value=reader), \
                     patch.object(observe.queue, 'Queue', return_value=chunks), \
                     patch.object(observe, 'group_alive', return_value=False), \
                     patch.object(observe, 'terminate_owned_tree', return_value=True), \
                     patch.object(observe.sys, 'stdout', sink):
                    code = observe.observe(['fixture'], 'terminal-eof', root/'output', 20)
            finally: sink.close()
            row = json.loads((root/'output/observation.json').read_text())
            self.assertEqual(code, 0, row); self.assertTrue(row['streamObservedThroughEOF'])
            self.assertIsNone(row['observerErrorKind'])

    def test_pending_eof_after_leader_exit_is_not_open_stream_failure(self):
        # Pause the reader after actual EOF but before publishing its sentinel.
        # This deterministically exposes the empty-queue/EOF scheduling race.
        release_eof = threading.Event(); eof_read = threading.Event(); cleanup_groups = []
        class DelayedEOFQueue(queue.Queue):
            def put(self, value, *args, **kwargs):
                if value is None:
                    eof_read.set(); release_eof.wait(timeout=10)
                return super().put(value, *args, **kwargs)
        original_cleanup = observe.terminate_owned_tree
        def cleanup(child, job=None):
            cleanup_groups.append(observe.group_alive(child, job))
            complete = original_cleanup(child, job)
            release_eof.set()
            return complete
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); env = budget_env(folder)
            sink = io.TextIOWrapper(io.BytesIO(), write_through=True)
            try:
                with patch.object(observe.queue, 'Queue', DelayedEOFQueue), \
                     patch.object(observe, 'terminate_owned_tree', side_effect=cleanup), \
                     patch.object(observe.sys, 'stdout', sink):
                    code = observe.observe([sys.executable, '-c', 'import sys; sys.stdout.buffer.write(b"completed-tail\\n")'],
                        'pending-eof', root/'output', 20, budget_file=Path(env['POLARIS_JOB_BUDGET']))
            finally:
                release_eof.set(); sink.close()
            row = json.loads((root/'output/observation.json').read_text())
            self.assertTrue(eof_read.is_set()); self.assertEqual(cleanup_groups, [False])
            self.assertEqual(code, 0, row)
            self.assertEqual(row['childExitCode'], 0); self.assertIsNone(row['observerErrorKind'])
            self.assertTrue(row['streamObservedThroughEOF']); self.assertTrue(row['ownedTreeCleanupComplete'])
            self.assertEqual((root/'output/command.log').read_bytes(), b'completed-tail\n')
            self.assertEqual(row['childMergedStreamSha256'], hashlib.sha256(b'completed-tail\n').hexdigest())

    def test_stalled_eof_without_owned_descendants_remains_bounded_failure(self):
        release_eof = threading.Event(); reader_finished = threading.Event()
        original_popen = subprocess.Popen; children = []
        def launch(*args, **kwargs):
            child = original_popen(*args, **kwargs); children.append(child); return child
        class StalledEOFQueue(queue.Queue):
            def put(self, value, *args, **kwargs):
                if value is None:
                    release_eof.wait(timeout=10)
                try: return super().put(value, *args, **kwargs)
                finally:
                    if value is None: reader_finished.set()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); env = budget_env(folder)
            sink = io.TextIOWrapper(io.BytesIO(), write_through=True)
            started = time.monotonic()
            try:
                with patch.object(observe.queue, 'Queue', StalledEOFQueue), \
                     patch.object(observe.subprocess, 'Popen', side_effect=launch), \
                     patch.object(observe.sys, 'stdout', sink):
                    code = observe.observe([sys.executable, '-c', 'pass'], 'stalled-eof',
                        root/'output', 20, budget_file=Path(env['POLARIS_JOB_BUDGET']))
            finally:
                release_eof.set(); reader_finished.wait(timeout=1); sink.close()
                for child in children: child.stdout.close()
            row = json.loads((root/'output/observation.json').read_text())
            self.assertLess(time.monotonic() - started, 7)
            self.assertEqual(code, 1); self.assertEqual(row['childExitCode'], 0)
            self.assertFalse(row['streamObservedThroughEOF']); self.assertTrue(row['ownedTreeCleanupComplete'])
            self.assertEqual(row['observerErrorKind'], 'stream-drain-incomplete')

    @unittest.skipIf(os.name == 'nt', 'POSIX escaped session fixture; Windows owns a Job Object')
    def test_escaped_pipe_holder_later_eof_does_not_clear_failure(self):
        # Keep the escaped pipe open until cleanup classifies it, regardless of
        # scheduling speed. Later EOF must not clear that sticky failure.
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); env = budget_env(folder)
            ready = root/'holder-ready'; release = root/'release-holder'
            holder = ('import time\nfrom pathlib import Path\n'
                      'print("escaped-pipe",flush=True)\n'
                      'Path(' + repr(str(ready)) + ').touch()\n'
                      'deadline=time.monotonic()+10\n'
                      'while not Path(' + repr(str(release)) + ').exists() and time.monotonic()<deadline: time.sleep(.02)\n')
            leader = ('import os,subprocess,sys,time\nfrom pathlib import Path\n'
                      'subprocess.Popen([sys.executable,"-u","-c",' + repr(holder) + '],start_new_session=True)\n'
                      'deadline=time.monotonic()+5\n'
                      'while not Path(' + repr(str(ready)) + ').exists() and time.monotonic()<deadline: time.sleep(.02)\n'
                      'assert Path(' + repr(str(ready)) + ').exists()\n'
                      'os._exit(0)\n')
            original_cleanup = observe.terminate_owned_tree; cleanup_groups = []
            def cleanup(child, job=None):
                cleanup_groups.append(observe.group_alive(child, job))
                complete = original_cleanup(child, job)
                release.touch()
                return complete
            sink = io.TextIOWrapper(io.BytesIO(), write_through=True)
            try:
                with patch.object(observe, 'terminate_owned_tree', side_effect=cleanup), \
                     patch.object(observe.sys, 'stdout', sink):
                    code = observe.observe([sys.executable, '-u', '-c', leader], 'escaped-pipe',
                        root/'output', 20, budget_file=Path(env['POLARIS_JOB_BUDGET']))
            finally: release.touch(); sink.close()
            row = json.loads((root/'output/observation.json').read_text())
            self.assertEqual(cleanup_groups, [False]); self.assertTrue(ready.exists())
            self.assertEqual(code, 1); self.assertEqual(row['childExitCode'], 0)
            self.assertEqual(row['observerErrorKind'], 'leader-exited-with-open-stream')
            self.assertTrue(row['streamObservedThroughEOF']); self.assertTrue(row['ownedTreeCleanupComplete'])
            self.assertIn(b'escaped-pipe', (root/'output/command.log').read_bytes())
            self.assertLess(row['elapsedSeconds'], 7)

    def test_cleanup_incomplete_never_becomes_green(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);env=budget_env(folder)
            with patch.dict(os.environ,env), patch.object(observe,'group_alive',return_value=True), \
                 patch.object(observe,'terminate_owned_tree',return_value=False):
                code=observe.observe([sys.executable,'-c','pass'],'incomplete',root/'output',20,
                    budget_file=Path(env['POLARIS_JOB_BUDGET']))
            self.assertEqual(code,1)
            row=json.loads((root/'output/observation.json').read_text())
            self.assertFalse(row['ownedTreeCleanupComplete']);self.assertEqual(row['outcome'],'failure')

    @unittest.skipUnless(os.name == 'nt', 'actual Git for Windows runner shell control')
    def test_windows_actual_runner_bash_strict_under_wsl_first_path(self):
        shell = Path(os.environ['POLARIS_RUNNER_BASH'])
        self.assertTrue(shell.is_absolute()); self.assertTrue(shell.is_file())
        self.assertEqual(shell.name.lower(), 'bash.exe')
        self.assertIn('git', str(shell.parent).lower())
        for body in ('false; printf swallowed', 'false | tee pipeline.log; printf swallowed',
                     'test actual = wrong-baseline; printf tests-started'):
            with self.subTest(body=body), tempfile.TemporaryDirectory(prefix='polaris runner shell ') as folder:
                root=Path(folder);script=root/'command with spaces.sh';output=root/'observation'
                script.write_text('printf "actual-runner-bash\\n"\n'+body)
                env=budget_env(folder)
                env['PATH']=str(Path(os.environ['SystemRoot'])/'System32')+os.pathsep+env['PATH']
                run=subprocess.run([sys.executable,'-B',str(SCRIPT),'--phase','windows-strict','--output',str(output),
                    '--timeout-seconds','20','--',str(shell),'--noprofile','--norc','-e','-o','pipefail',str(script)],
                    cwd=root,env=env,capture_output=True,timeout=30)
                self.assertNotEqual(run.returncode,0)
                raw=(output/'command.log').read_bytes()
                self.assertIn(b'actual-runner-bash',raw)
                self.assertNotIn(b'swallowed',raw);self.assertNotIn(b'tests-started',raw)
                row=json.loads((output/'observation.json').read_text())
                self.assertTrue(row['ownedTreeCleanupComplete']);self.assertTrue(row['streamObservedThroughEOF'])
                self.assertEqual(row['outcome'],'failure')

    def test_large_output_prefix_budget_does_not_truncate_original_stream(self):
        row, raw, stdout = self.run_child('import sys; sys.stdout.buffer.write(b"x"*(33*1024*1024))')
        self.assertEqual(len(raw), 32 * 1024 * 1024)
        self.assertEqual(row['childMergedStreamBytes'], 33 * 1024 * 1024)
        self.assertTrue(row['artifactLogTruncated']); self.assertGreater(len(stdout), len(raw))


if __name__ == '__main__':
    unittest.main()
