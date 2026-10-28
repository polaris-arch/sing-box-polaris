#!/usr/bin/env python3
"""Stream existing CI commands within one job budget; own and bound child cleanup."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import queue
import re
import signal
import subprocess
import sys
import threading
import time

LOG_LIMIT = 32 * 1024 * 1024
CLEANUP_SECONDS = 15


def job_window(path, cap_seconds, now=None):
    """Every phase/cache uses the original job clock, never a fresh full grant."""
    if path is None:
        raise ValueError('shared job budget required')
    row = json.loads(path.read_bytes())
    if row.get('schema') != 'polaris-ci-job-budget-v1':
        raise ValueError('wrong job budget')
    started, seconds, reserve, safety = (float(row[k]) for k in
        ('startedMonotonic', 'jobSeconds', 'evidenceReserveSeconds', 'safetySeconds'))
    now = time.monotonic() if now is None else now
    if not (0 < seconds <= 6 * 3600 and 0 < reserve < seconds and safety >= CLEANUP_SECONDS
            and 0 <= now - started <= 6 * 3600):
        raise ValueError('invalid or expired job budget')
    return max(0.0, min(cap_seconds, started + seconds - reserve - safety - now))


def cache_window(path, cap_minutes, output):
    minutes = int(job_window(path, cap_minutes * 60) // 60)
    with output.open('a') as stream:
        stream.write(f'allowed={str(minutes >= 1).lower()}\nminutes={max(1, minutes)}\n')
    return minutes


def memory_observation(child):
    if os.name != 'nt':
        import resource
        peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        return {'kind': 'OS-child-rusage-maxrss',
                'bytes': int(peak) * (1 if platform.system() == 'Darwin' else 1024) if peak else None,
                'simultaneousProcessTreePeakBytes': None}
    try:
        import ctypes
        class Counters(ctypes.Structure):
            _fields_ = [('cb', ctypes.c_ulong), ('PageFaultCount', ctypes.c_ulong)] + [
                (name, ctypes.c_size_t) for name in ('PeakWorkingSetSize', 'WorkingSetSize',
                'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage', 'QuotaPeakNonPagedPoolUsage',
                'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage')]
        value = Counters(); value.cb = ctypes.sizeof(value)
        api = ctypes.WinDLL('psapi', use_last_error=True).GetProcessMemoryInfo
        api.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]; api.restype = ctypes.c_int
        if not api(int(child._handle), ctypes.byref(value), value.cb):
            raise OSError('process memory observation unavailable')
        peak = int(value.PeakWorkingSetSize)
    except (OSError, AttributeError, TypeError):
        peak = None
    return {'kind': 'Windows-owned-bootstrap-peak-working-set', 'bytes': peak or None,
            'simultaneousProcessTreePeakBytes': None}


class WindowsJob:
    """Assignment precedes the bootstrap permit; descendants cannot escape by parent exit."""
    def __init__(self):
        import ctypes as c
        self.c = c
        self.api = c.WinDLL('kernel32', use_last_error=True)
        for name, args, restype in [
            ('CreateJobObjectW', [c.c_void_p, c.c_wchar_p], c.c_void_p),
            ('SetInformationJobObject', [c.c_void_p, c.c_int, c.c_void_p, c.c_ulong], c.c_int),
            ('AssignProcessToJobObject', [c.c_void_p, c.c_void_p], c.c_int),
            ('TerminateJobObject', [c.c_void_p, c.c_uint], c.c_int),
            ('QueryInformationJobObject', [c.c_void_p, c.c_int, c.c_void_p, c.c_ulong, c.c_void_p], c.c_int),
            ('CloseHandle', [c.c_void_p], c.c_int)]:
            api = getattr(self.api, name); api.argtypes = args; api.restype = restype
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle: raise c.WinError(c.get_last_error())
        class Basic(c.Structure):
            _fields_ = [('processTime', c.c_longlong), ('jobTime', c.c_longlong), ('flags', c.c_ulong),
                        ('minWorking', c.c_size_t), ('maxWorking', c.c_size_t), ('activeLimit', c.c_ulong),
                        ('affinity', c.c_size_t), ('priority', c.c_ulong), ('scheduling', c.c_ulong)]
        class IO(c.Structure):
            _fields_ = [(name, c.c_ulonglong) for name in ('readOps', 'writeOps', 'otherOps', 'readBytes', 'writeBytes', 'otherBytes')]
        class Extended(c.Structure):
            _fields_ = [('basic', Basic), ('io', IO), ('processMemory', c.c_size_t), ('jobMemory', c.c_size_t),
                        ('peakProcess', c.c_size_t), ('peakJob', c.c_size_t)]
        value = Extended(); value.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.api.SetInformationJobObject(self.handle, 9, c.byref(value), c.sizeof(value)):
            self.close(); raise c.WinError(c.get_last_error())

    def assign(self, child):
        if not self.api.AssignProcessToJobObject(self.handle, int(child._handle)):
            raise self.c.WinError(self.c.get_last_error())

    def alive(self):
        value = self.c.create_string_buffer(48)  # JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
        if not self.api.QueryInformationJobObject(self.handle, 1, value, 48, None):
            raise self.c.WinError(self.c.get_last_error())
        return int.from_bytes(value.raw[40:44], 'little') != 0

    def kill(self):
        if not self.api.TerminateJobObject(self.handle, 1):
            raise self.c.WinError(self.c.get_last_error())

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle); self.handle = None


def group_alive(child, job):
    if job is not None:
        return job.alive()
    try:
        os.killpg(child.pid, 0)
    except ProcessLookupError:
        return False
    return True


def terminate_owned_tree(child, job=None):
    """Do not stop at leader exit. All waits, including forced cleanup, are bounded."""
    limit = time.monotonic() + 9
    if job is not None:
        if group_alive(child, job): job.kill()
    else:
        for number, grace in ((signal.SIGINT, 4), (signal.SIGTERM, 2), (signal.SIGKILL, 2)):
            try: os.killpg(child.pid, number)
            except ProcessLookupError: break
            until = min(limit, time.monotonic() + grace)
            while time.monotonic() < until and group_alive(child, job):
                child.poll(); time.sleep(0.05)
            if not group_alive(child, job): break
    while time.monotonic() < limit and group_alive(child, job):
        child.poll(); time.sleep(0.05)
    try: child.wait(timeout=max(0.01, limit - time.monotonic()))
    except subprocess.TimeoutExpired: return False
    return not group_alive(child, job)


def windows_bootstrap(permit, command):
    deadline = time.monotonic() + 10
    while not permit.exists():
        if time.monotonic() >= deadline: return 125
        time.sleep(0.02)
    # Existing command inherits the assigned job; no breakaway creation flag.
    return subprocess.call(command)


def observe(command, phase, output, timeout, log_limit=LOG_LIMIT, heartbeat=60, budget_file=None):
    if not re.fullmatch(r'[a-z0-9-]{1,64}', phase) or not command or not 0 < timeout <= 6 * 3600:
        raise ValueError('bounded phase, command and deadline required')
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic(); stopped = threading.Event(); chunks = queue.Queue(maxsize=8)
    reader_eof = threading.Event()
    reason = {'signal': None, 'timeout': False}
    child = job = reader = None; assigned = False; count = retained = 0; digest = hashlib.sha256()
    handlers = {}; error = None; eof = False; code = 127; cleanup_complete = True
    granted = 0; next_heartbeat = heartbeat; exited_at = drain_deadline = None
    def cancel(number, _frame): reason['signal'] = number
    for number in (signal.SIGINT, signal.SIGTERM): handlers[number] = signal.signal(number, cancel)
    def enqueue(value):
        while not stopped.is_set():
            try: chunks.put(value, timeout=0.1); return
            except queue.Full: pass
    def read_stream():
        try:
            while block := child.stdout.read1(64 * 1024): enqueue(block)
            reader_eof.set()
            enqueue(None)
        except OSError: enqueue(OSError('stream reader failed'))
    def cleanup():
        nonlocal cleanup_complete, drain_deadline
        cleanup_complete = terminate_owned_tree(child, job)
        drain_deadline = time.monotonic() + 3
    try:
        granted = job_window(budget_file, timeout)
        if granted <= 0: raise ValueError('job work budget exhausted; evidence time reserved')
        print(json.dumps({'schema': 'polaris-ci-phase-start-v1', 'phase': phase,
                          'deadlineSeconds': granted, 'resourcePolicyChanged': False}), flush=True)
        options = {'stdout': subprocess.PIPE, 'stderr': subprocess.STDOUT}
        if os.name == 'nt':
            job = WindowsJob(); permit = output / 'child-permit'
            options['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
            command = [sys.executable, '-B', str(Path(__file__).resolve()), '--windows-bootstrap', str(permit), '--', *command]
        else: options['start_new_session'] = True
        child = subprocess.Popen(command, **options)
        if job is not None:
            job.assign(child); assigned = True; permit.write_bytes(b'assigned\n')
        reader = threading.Thread(target=read_stream, daemon=True); reader.start()
        with (output / 'command.log').open('xb') as log:
            while True:
                now = time.monotonic(); elapsed = now - started
                if drain_deadline is None and (elapsed >= granted or reason['signal'] is not None):
                    reason['timeout'] = elapsed >= granted and reason['signal'] is None
                    cleanup()
                if drain_deadline is not None and now >= drain_deadline:
                    error = error or 'stream-drain-incomplete'; break
                if elapsed >= next_heartbeat:
                    print(json.dumps({'schema': 'polaris-ci-heartbeat-v1', 'phase': phase,
                                      'elapsedSeconds': round(elapsed, 2), 'childRunning': child.poll() is None}), flush=True)
                    next_heartbeat += heartbeat
                try: block = chunks.get(timeout=0.1)
                except queue.Empty: block = b''
                if block is None: eof = True; break
                if child.poll() is not None and drain_deadline is None:
                    exited_at = now if exited_at is None else exited_at
                    if now - exited_at >= 1:
                        descendants_alive = group_alive(child, job)
                        if descendants_alive or not block:
                            # EOF delivery can lag the completed read. Only actual
                            # reader EOF proves an idle queue is not an open pipe;
                            # missing sentinel delivery still has the same drain bound.
                            if descendants_alive or not reader_eof.is_set():
                                error = 'leader-exited-with-open-stream'
                            cleanup()
                if not block: continue
                if isinstance(block, Exception): raise block
                digest.update(block); count += len(block)
                take = max(0, min(len(block), log_limit - retained))
                if take: log.write(block[:take]); retained += take
                sys.stdout.buffer.write(block); sys.stdout.buffer.flush()
        # EOF alone is not process completion. A child can close stdout then hang.
        while child.poll() is None and drain_deadline is None:
            if time.monotonic() - started >= granted or reason['signal'] is not None:
                reason['timeout'] = reason['signal'] is None; cleanup(); break
            time.sleep(0.05)
        code = child.poll()
        if group_alive(child, job):
            error = error or 'owned-descendants-outlived-command'
            if drain_deadline is None: cleanup()
            else: cleanup_complete = False
        code = child.wait(timeout=1)
    except (OSError, ValueError, subprocess.SubprocessError) as failure:
        error = type(failure).__name__
        if child is not None:
            try:
                if job is not None and not assigned:
                    child.kill()  # Unpermitted bootstrap cannot have descendants.
                elif drain_deadline is None:
                    cleanup_complete = terminate_owned_tree(child, job)
                code = child.wait(timeout=1)
            except (OSError, subprocess.SubprocessError): cleanup_complete = False; code = 1
    finally:
        stopped.set()
        if reader is not None:
            reader.join(timeout=0.2)
            if not reader.is_alive(): child.stdout.close()
        if job is not None: job.close()  # kill-on-close even if a query/cleanup failed
        for number, handler in handlers.items(): signal.signal(number, handler)
        memory = memory_observation(child) if child is not None else {
            'kind': 'not-launched', 'bytes': None, 'simultaneousProcessTreePeakBytes': None}
        code = 1 if code is None else code
        exit_code = 124 if reason['timeout'] else 128 + reason['signal'] if reason['signal'] else code if code >= 0 else 128 - code
        if (error or not cleanup_complete or not eof) and exit_code == 0: exit_code = 1
        result = {'schema': 'polaris-ci-command-observation-v1', 'phase': phase,
                  'workflowCommit': os.environ.get('GITHUB_SHA'), 'sourceCommit': os.environ.get('SOURCE_COMMIT'),
                  'outcome': 'timeout' if reason['timeout'] else 'cancelled' if reason['signal'] else 'success' if exit_code == 0 else 'failure',
                  'childExitCode': code, 'ciExitCode': exit_code, 'receivedSignal': reason['signal'],
                  'elapsedSeconds': round(time.monotonic() - started, 3), 'grantedWorkSeconds': granted,
                  'memoryObservation': memory, 'ownedTreeCleanupComplete': cleanup_complete,
                  'cleanupAndDrainBoundSeconds': CLEANUP_SECONDS,
                  'childMergedStreamBytes': count, 'childMergedStreamSha256': digest.hexdigest(),
                  'artifactLogPrefixBytes': retained, 'artifactLogTruncated': count > retained,
                  'fullOriginalStreamLocation': 'original GitHub job log', 'streamObservedThroughEOF': eof, 'resourcePolicyChanged': False,
                  'observerErrorKind': error, 'observerEnvironmentDumped': False, 'observerArgvDumped': False}
        try: (output / 'observation.json').write_text(json.dumps(result, indent=2) + '\n')
        except OSError:
            if exit_code == 0: exit_code = 1
            result.update(ciExitCode=exit_code, outcome='failure', observerErrorKind='observation-write-failure')
        print(json.dumps(result, sort_keys=True), flush=True)
    return exit_code


def main():
    if sys.argv[1:2] == ['--windows-bootstrap']:
        raise SystemExit(windows_bootstrap(Path(sys.argv[2]), sys.argv[4:]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--budget-file', type=Path, default=os.environ.get('POLARIS_JOB_BUDGET'))
    parser.add_argument('--cache-window', action='store_true')
    parser.add_argument('--cache-cap-minutes', type=int, default=2)
    parser.add_argument('--github-output', type=Path)
    parser.add_argument('--phase'); parser.add_argument('--output', type=Path)
    parser.add_argument('--timeout-seconds', type=float)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.cache_window:
        cache_window(args.budget_file, args.cache_cap_minutes, args.github_output); return
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    raise SystemExit(observe(command, args.phase, args.output, args.timeout_seconds, budget_file=args.budget_file))


if __name__ == '__main__': main()
