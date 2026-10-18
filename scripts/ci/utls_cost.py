"""Measure whole-migration binary/idle RSS deltas on the same remote Linux Go.

This is not an isolated attribution of every byte to the second TLS library, a
handshake memory benchmark, or an App/mobile size measurement.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import time

from tls_fingerprint_probe import outbound_config, sha
from utls_gate import run_logged

ROOT = Path(__file__).resolve().parents[2]
BASELINE = '55300c55560bcc604fd9675c5526b5713db81cc1'


def idle_samples(core, config, log):
    process = None
    samples = []
    with Path(log).open('wb') as stream:
        try:
            process = subprocess.Popen([str(core), 'run', '-c', str(config)], stdout=stream, stderr=subprocess.STDOUT)
            for _ in range(5):
                time.sleep(1)
                if process.poll() is not None:
                    raise RuntimeError('idle fixture exited before sampling: ' + str(log))
                status = Path('/proc') / str(process.pid) / 'status'
                line = next(x for x in status.read_text().splitlines() if x.startswith('VmRSS:'))
                samples.append(int(line.split()[1]) * 1024)
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill();process.wait()
    return {'samplesBytes': samples, 'medianBytes': statistics.median(samples), 'sampledMaxBytes': max(samples),
            'scope': 'idle process, one uTLS outbound constructed, no inbound or remote handshake'}


def main():
    parser = argparse.ArgumentParser();parser.add_argument('--output', type=Path, required=True);args = parser.parse_args()
    if sys.platform != 'linux' or os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('GITHUB_REPOSITORY') != 'polaris-arch/sing-box-polaris':
        raise RuntimeError('cost measurement is restricted to the existing owned Linux CI job')
    output = args.output.resolve();output.mkdir(parents=True, exist_ok=True)
    os.environ['GOCACHE'] = str(Path(os.environ['RUNNER_TEMP']).resolve() / 'tls-fingerprint-go-cache')
    deadline = time.monotonic() + 20 * 60
    (output / 'cost-input.json').write_text(json.dumps({'baselineSource': BASELINE, 'expectedSource': os.environ['GITHUB_SHA'], 'workBudgetSeconds': 20 * 60}, indent=2) + '\n')
    if shutil.disk_usage(output).free < 10 * 1024**3:
        raise RuntimeError('comparison lacks 4GiB additional growth plus 6GiB headroom')
    slot = Path(os.environ['RUNNER_TEMP']).resolve() / 'tls-fingerprint-baseline'
    if slot.exists():
        raise RuntimeError('comparison slot already exists; do not overwrite source')
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if source != os.environ['GITHUB_SHA']:
        raise RuntimeError('candidate source differs from dispatch')
    scratch = Path(os.environ['RUNNER_TEMP']).resolve() / 'tls-fingerprint-scratch';scratch.mkdir(exist_ok=True)
    env = dict(os.environ, GOTOOLCHAIN='local', GOFLAGS='-mod=readonly', GOMAXPROCS='2', TMPDIR=str(scratch))
    actual_go = subprocess.check_output(['go', 'env', 'GOVERSION'], env=env, text=True).strip()
    if actual_go != 'go' + (ROOT / 'release/GO_VERSION').read_text().strip():
        raise RuntimeError('cost measurement must use the candidate exact Go for both inputs')
    # Fixed worktree is temporary, cache remains one content-addressed Go cache.
    subprocess.run(['git', 'worktree', 'add', '--detach', str(slot), BASELINE], cwd=ROOT, check=True)
    receipt = {'schema': 'polaris-utls-migration-cost-v1', 'baselineSource': BASELINE, 'candidateSource': source,
               'goVersion': actual_go, 'tags': 'with_utls,badlinkname', 'results': {}, 'errors': [],
               'attribution': 'whole source/dependency migration at the same Go, not isolated second-library cost',
               'handshakePeakRSSValidated': False, 'appOrMobileSizeValidated': False, 'productionDefaultTags': False}
    try:
        baseline_flags = (slot / 'release/LDFLAGS').read_text().strip()
        if baseline_flags != (ROOT / 'release/LDFLAGS').read_text().strip():
            raise RuntimeError('comparison linker contract changed; do not silently compare different flags')
        flags = baseline_flags + ' -s -w -buildid= -X github.com/sagernet/sing-box/constant.Version=1.15.0-polaris-alpha.12'
        receipt['ldflags'] = flags
        config = output / 'idle-config.json';config.write_text(json.dumps(outbound_config('chrome')))
        for label, directory in [('baseline', slot), ('candidate', ROOT)]:
            core = output / (label + '-core')
            command = ['go', 'build', '-p=2', '-trimpath', '-tags=with_utls,badlinkname', '-ldflags=' + flags,
                       '-o', str(core), './cmd/sing-box']
            remaining = int(deadline - time.monotonic())
            if remaining <= 0:
                receipt['errors'].append(label + ': comparison budget exhausted; not started')
                continue
            code = run_logged(command, cwd=directory, env=env, logfile=output / (label + '-build.log'), timeout=remaining)
            if code != 0:
                receipt['errors'].append(label + ': comparison build failed; original log retained')
                continue
            info = subprocess.check_output(['go', 'version', '-m', str(core)], env=env, text=True)
            build_id = subprocess.check_output(['go', 'tool', 'buildid', str(core)], env=env, text=True).strip()
            identity = {'sourceCommit': BASELINE if label == 'baseline' else source,
                        'sourceTree': subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=directory, text=True).strip(),
                        'bytes': core.stat().st_size, 'sha256': sha(core), 'buildID': build_id, 'rawBuildInfo': info}
            try:
                identity['idleRSS'] = idle_samples(core, config, output / (label + '-idle.log'))
            except Exception as error:
                receipt['errors'].append(label + ': ' + repr(error))
            receipt['results'][label] = identity
        if all('idleRSS' in receipt['results'].get(x, {}) for x in ['baseline', 'candidate']):
            a, b = receipt['results']['baseline'], receipt['results']['candidate']
            receipt['delta'] = {'binaryBytes': b['bytes'] - a['bytes'],
                                'medianIdleRSSBytes': b['idleRSS']['medianBytes'] - a['idleRSS']['medianBytes']}
    finally:
        result = subprocess.run(['git', 'worktree', 'remove', str(slot)], cwd=ROOT, text=True, capture_output=True)
        receipt['baselineWorktreeRetired'] = result.returncode == 0
        if result.returncode:
            receipt['errors'].append('baseline worktree cleanup failed: ' + result.stderr)
        receipt['diskFreeBytesAfter'] = shutil.disk_usage(output).free
        (output / 'cost.json').write_text(json.dumps(receipt, indent=2) + '\n')
    if receipt['errors']:
        raise RuntimeError('; '.join(receipt['errors']))


if __name__ == '__main__':
    main()
