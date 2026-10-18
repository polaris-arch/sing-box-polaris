#!/usr/bin/env python3
"""Bound work on this runner only; GitHub schedules separate runner machines."""
import argparse
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import time

GIB = 1024 ** 3
# Working-space estimates are admission budgets, not observed peak claims.
GROWTH = {'desktop': 4 * GIB, 'openwrt': 8 * GIB,
          'selfcheck': 3 * GIB, 'contracts': GIB}
MEMORY_PER_PACKAGE = 2 * GIB


def linux_memory(root=Path('/')):
    entries = dict(re.findall(r'^(MemTotal|MemAvailable):\s+(\d+) kB$',
                              (root / 'proc/meminfo').read_text(), re.M))
    total, available = (int(entries[name]) * 1024 for name in ('MemTotal', 'MemAvailable'))
    # Check only the visible root cgroup v2. Nested/v1 groups are not resolved.
    # These measurements do not atomically reserve memory or disk.
    limit = root / 'sys/fs/cgroup/memory.max'
    current = root / 'sys/fs/cgroup/memory.current'
    if limit.exists() and current.exists() and limit.read_text().strip() != 'max':
        cap, used = int(limit.read_text()), int(current.read_text())
        total, available = min(total, cap), min(available, max(0, cap - used))
    return total, available


def windows_memory():
    class MemoryStatus(ctypes.Structure):
        _fields_ = [('length', ctypes.c_ulong), ('load', ctypes.c_ulong),
                    *[(name, ctypes.c_ulonglong) for name in
                      ('totalPhysical', 'availablePhysical', 'totalPageFile',
                       'availablePageFile', 'totalVirtual', 'availableVirtual', 'extended')]]
    value = MemoryStatus()
    value.length = ctypes.sizeof(value)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MemoryStatus)]
    kernel.GlobalMemoryStatusEx.restype = ctypes.c_int
    if not kernel.GlobalMemoryStatusEx(ctypes.byref(value)):
        raise OSError(ctypes.get_last_error(), 'GlobalMemoryStatusEx failed')
    return value.totalPhysical, value.availablePhysical


def darwin_memory(details=None):
    total = int(subprocess.check_output(['sysctl', '-n', 'hw.memsize'], text=True))
    stat = subprocess.check_output(['vm_stat'], text=True)
    page = int(re.search(r'page size of (\d+) bytes', stat).group(1))
    # vm_stat prints free_count minus speculative_count. Add speculative
    # pages back, plus inactive pages; purgeable can overlap and is not added.
    counts = dict(re.findall(r'^(Pages free|Pages inactive|Pages speculative):\s+(\d+)\.', stat, re.M))
    available = sum(int(counts[name]) for name in ('Pages free', 'Pages inactive', 'Pages speculative')) * page
    if details is not None:
        details.update(vmStatSnapshot=stat, memoryAvailableBasis='free+inactive+speculative sample; conservative estimate, not all OS-reclaimable memory')
    return total, min(total, available)


def windows_busy_cpus(cpus):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetSystemTimes.argtypes = [ctypes.POINTER(ctypes.c_ulonglong)] * 3
    kernel.GetSystemTimes.restype = ctypes.c_int
    def read():
        values = [ctypes.c_ulonglong() for _ in range(3)]
        if not kernel.GetSystemTimes(*(ctypes.byref(v) for v in values)):
            raise OSError(ctypes.get_last_error(), 'GetSystemTimes failed')
        return [v.value for v in values]
    before = read()
    time.sleep(0.2)
    after = read()
    idle, system, user = (b - a for a, b in zip(before, after))
    elapsed = system + user  # Windows kernel time includes idle time.
    if elapsed <= 0 or idle < 0 or idle > elapsed:
        raise ValueError('invalid Windows CPU sample')
    return cpus * (1 - idle / elapsed)


def observe(directory):
    system = platform.system()
    details = {}
    cpus = os.cpu_count()
    if not cpus:
        raise ValueError('runner CPU count unavailable')
    if hasattr(os, 'sched_getaffinity'):
        cpus = min(cpus, len(os.sched_getaffinity(0)))
    if system == 'Linux':
        total, available = linux_memory()
        quota = Path('/sys/fs/cgroup/cpu.max')
        if quota.exists():
            amount, period = quota.read_text().split()
            if amount != 'max':
                cpus = min(cpus, max(1, math.floor(int(amount) / int(period))))
    elif system == 'Darwin':
        total, available = darwin_memory(details)
    elif system == 'Windows':
        total, available = windows_memory()
    else:
        raise ValueError('unsupported runner: ' + system)
    busy = windows_busy_cpus(cpus) if system == 'Windows' else os.getloadavg()[0]
    disk = shutil.disk_usage(directory)
    return {**details, 'platform': system, 'effectiveCPUs': cpus, 'busyCPUObservation': busy,
            'cpuObservation': '200ms busy sample' if system == 'Windows' else '1min load average',
            'memoryTotalBytes': total, 'memoryAvailableBytes': available,
            'diskTotalBytes': disk.total, 'diskFreeBytes': disk.free,
            'scratchPath': str(Path(directory).resolve())}


def budget(observation, kind):
    if kind not in GROWTH:
        raise ValueError('unknown resource kind')
    fields = ['effectiveCPUs', 'memoryTotalBytes', 'memoryAvailableBytes',
              'diskTotalBytes', 'diskFreeBytes']
    for name in fields:
        if type(observation[name]) is not int or observation[name] <= 0:
            raise ValueError('invalid resource measurement: ' + name)
    busy = observation['busyCPUObservation']
    if not isinstance(busy, (int, float)) or isinstance(busy, bool) or not math.isfinite(busy) or busy < 0:
        raise ValueError('invalid CPU load measurement')
    if (observation['memoryAvailableBytes'] > observation['memoryTotalBytes'] or
            observation['diskFreeBytes'] > observation['diskTotalBytes']):
        raise ValueError('available resource exceeds total')
    memory_reserve = max(GIB, observation['memoryTotalBytes'] // 5)
    disk_reserve = 2 * GIB
    estimated_memory_slots = (observation['memoryAvailableBytes'] - memory_reserve) // MEMORY_PER_PACKAGE
    memory_pressure = estimated_memory_slots < 1
    disk_pressure = observation['diskFreeBytes'] < disk_reserve + GROWTH[kind]
    # Estimates choose parallelism, not a new capacity gate. A sampled deficit
    # does not prove that a known working serial build cannot safely execute.
    # Preserve the same estimates; reduce to the original single-package lane.
    memory_slots = max(1, estimated_memory_slots)
    if disk_pressure:
        memory_slots = 1
    cpus = observation['effectiveCPUs']
    # Leave one CPU when possible. A busy/single-core runner runs one worker;
    # this is a bounded admission snapshot, not a cross-runner load scheduler.
    cpu_slots = max(1, cpus - (1 if cpus > 1 else 0) - math.ceil(busy))
    threads = min(cpu_slots, memory_slots)
    packages = threads if kind == 'selfcheck' else 1
    return {'schema': 'polaris-runner-resource-budget-v1', 'kind': kind,
            'observation': observation, 'cpuWorkerBudget': threads,
            'compileGOMAXPROCS': 1 if kind == 'selfcheck' else threads, 'goPackageJobs': packages,
            'testRuntimePolicy': 'unchanged; do not export a job-wide GOMAXPROCS or change test -parallel',
            'memoryReserveBytes': memory_reserve, 'memoryPerPackageBytes': MEMORY_PER_PACKAGE,
            'resourceReservationsHeld': False,
            'memoryEstimatePressure': memory_pressure, 'diskEstimatePressure': disk_pressure,
            'estimatedMemorySlots': estimated_memory_slots,
            'singlePackageFallback': memory_pressure or disk_pressure,
            'capacityRejectionBasis': 'none from estimates; actual workload/platform errors remain failures',
            'diskReserveBytes': disk_reserve, 'workingSpaceBudgetBytes': GROWTH[kind],
            'scope': 'this runner; sampled estimates, not reserved resources; Linux root cgroup v2 only, nested/v1 not guaranteed; no account or fleet capacity claim'}


def emit_report(path, result):
    # Fixed resource fields only: never dump environment, GOFLAGS or secrets.
    # Log first, so rejected admission survives even an unwritable scratch file.
    encoded = json.dumps(result, indent=2) + '\n'
    print(encoded, end='', flush=True)
    path.write_text(encoded)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind', choices=GROWTH, required=True)
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--github-env', type=Path)
    args = parser.parse_args()
    measured = None
    try:
        flags = os.environ.get('GOFLAGS', '')
        if args.kind == 'selfcheck' and ('\n' in flags or '\r' in flags):
            raise ValueError('multiline GOFLAGS cannot be exported')
        measured = observe(args.scratch)
        result = budget(measured, args.kind)
        result.update(workflowCommit=os.environ.get('GITHUB_SHA'),
                      sourceCommit=os.environ.get('SOURCE_COMMIT'),
                      toolSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    except (OSError, ValueError, KeyError, AttributeError, subprocess.SubprocessError) as error:
        emit_report(args.output, {'status': 'rejected', 'observation': measured,
                                 'error': str(error)[:2048]})
        raise
    emit_report(args.output, result)
    if args.github_env:
        with args.github_env.open('a') as stream:
            stream.write(f"POLARIS_COMPILE_GOMAXPROCS={result['compileGOMAXPROCS']}\nPOLARIS_GO_JOBS={result['goPackageJobs']}\n")
            if args.kind == 'selfcheck':
                # Source/test tags and ldflags are untouched; cap package jobs
                # for go run/install and gomobile's descendant Go invocations.
                value = (flags + f" -p={result['goPackageJobs']}").strip()
                stream.write(f"GOFLAGS={value}\n")


if __name__ == '__main__':
    main()
