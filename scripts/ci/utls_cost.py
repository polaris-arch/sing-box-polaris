"""Source CI diagnostics and remote whole-migration binary/idle RSS observation.

An input receipt is not test/native PASS. Partial observations never claim a
measured delta, including when the workflow tolerates the observation's exit.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time

from tls_fingerprint_probe import outbound_config, sha
from utls_gate import run_logged

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = 'polaris-arch/sing-box-polaris'
BASELINE = '55300c55560bcc604fd9675c5526b5713db81cc1'
BASELINE_TREE = '7767ba9a9901a061ff07db7716baed7896cfefbc'
BASELINE_URL = 'https://github.com/polaris-arch/sing-box-polaris.git'
WORK_SECONDS = 20 * 60
FETCH_SECONDS = 90
FETCH_FILE_BYTES = 256 << 20
FETCH_GROWTH_BYTES = 512 << 20


def remaining(deadline, cap=None):
    value = deadline - time.monotonic()
    if value <= 0:
        raise RuntimeError('comparison work budget exhausted')
    return min(value, cap) if cap is not None else value


def write_json(path, value, *, exclusive=False, bound=1 << 20):
    raw = json.dumps(value, ensure_ascii=False, indent=2) + '\n'
    if len(raw.encode('utf-8')) > bound:
        raise ValueError('diagnostic/measurement receipt exceeds byte bound')
    with Path(path).open('x' if exclusive else 'w', encoding='utf-8', newline='\n') as stream:
        stream.write(raw)


def source_context(env):
    if (env.get('GITHUB_ACTIONS') != 'true' or env.get('GITHUB_REPOSITORY') != REPOSITORY
            or env.get('GITHUB_REPOSITORY_ID') != '1421657509'
            or env.get('GITHUB_EVENT_NAME') != 'workflow_dispatch' or env.get('GITHUB_JOB') != 'utls_gate'):
        raise RuntimeError('observation requires the existing owned Source CI job')
    if env.get('SOURCE_BUILD') != 'Source' or env.get('SOURCE_GENERATE_ONLY') != 'false':
        raise RuntimeError('observation requires Source and non-generation')
    numbers = [env.get('GITHUB_RUN_ID', ''), env.get('GITHUB_RUN_ATTEMPT', '')]
    if (not re.fullmatch('[0-9a-f]{40}', env.get('GITHUB_SHA', ''))
            or any(not re.fullmatch('[1-9][0-9]{0,19}', value) for value in numbers)):
        raise ValueError('exact source/run/attempt missing or out of bound')
    inputs = {name: env.get(key, '') for name, key in (
        ('build', 'SOURCE_BUILD'), ('sourceGenerateOnly', 'SOURCE_GENERATE_ONLY'), ('runner', 'SOURCE_RUNNER'))}
    if any(len(value) > 128 for value in inputs.values()):
        raise ValueError('source diagnostic input exceeds bound')
    return {'repository': REPOSITORY, 'repositoryId': 1421657509, 'sourceCommit': env['GITHUB_SHA'],
            'runId': int(numbers[0]), 'runAttempt': int(numbers[1]), 'inputs': inputs,
            'diagnosticOnly': True, 'testOrNativePASS': False, 'executionAuthority': False}


def git_result(args, *, cwd=ROOT, env=None, timeout=20):
    result = subprocess.run(['git', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', *args],
                            cwd=cwd, env=env, capture_output=True, text=True, encoding='utf-8', timeout=timeout)
    if len(result.stdout.encode('utf-8')) + len(result.stderr.encode('utf-8')) > 65536:
        raise ValueError('Git identity diagnostic exceeds byte bound')
    return result


def git_text(args, **kwargs):
    result = git_result(args, **kwargs)
    if result.returncode:
        raise RuntimeError('Git identity/retirement failed: ' + result.stderr[:4096])
    return result.stdout.strip()


def retain_source_input(output, env):
    context = source_context(env)
    output.mkdir(parents=True, exist_ok=True)
    context.update(schema='polaris-source-ci-input-diagnostic-v1', stage='before-compatibility-gates',
                   testExecutionStatus='not-started', measurementsComplete=False)
    path = output / 'source-ci-input.json'
    write_json(path, context, exclusive=True, bound=16384)
    try:
        context['observedSourceCommit'] = git_text(['rev-parse', 'HEAD'])
        context['sourceTree'] = git_text(['rev-parse', 'HEAD^{tree}'])
        if (context['observedSourceCommit'] != context['sourceCommit']
                or not re.fullmatch('[0-9a-f]{40}', context['sourceTree'])
                or git_text(['status', '--porcelain', '--untracked-files=all'])):
            raise RuntimeError('source diagnostic checkout differs from exact clean dispatch')
        context['checkoutIdentityVerified'] = True
    except Exception as error:
        context['checkoutIdentityVerified'] = False
        context['error'] = (type(error).__name__ + ': ' + str(error))[:4096]
        raise
    finally:
        write_json(path, context, bound=16384)
    return context


def object_storage_bytes(directory):
    total = count = 0
    for parent, dirs, files in os.walk(directory, followlinks=False):
        for name in dirs + files:
            if (Path(parent) / name).is_symlink():
                raise RuntimeError('Git object storage has a symlink')
        for name in files:
            count += 1
            if count > 20000:
                raise RuntimeError('Git object storage member budget exceeded')
            total += (Path(parent) / name).stat().st_size
    return total


def fetch_file_limit():
    # Called only in the Linux fetch child, never at import/data-test time.
    import resource
    _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    limit = FETCH_FILE_BYTES if hard == resource.RLIM_INFINITY else min(hard, FETCH_FILE_BYTES)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))


def fetch_baseline(output, env, deadline, acquisition):
    objects = Path(git_text(['rev-parse', '--path-format=absolute', '--git-path', 'objects'], env=env,
                            timeout=remaining(deadline, 20)))
    before = object_storage_bytes(objects)
    acquisition.update(attempted=True, url=BASELINE_URL, commit=BASELINE, timeoutSeconds=FETCH_SECONDS,
                       maxChildFileBytes=FETCH_FILE_BYTES, maxObjectGrowthBytes=FETCH_GROWTH_BYTES,
                       processReaped=False)
    command = ['git', '-c', 'gc.auto=0', '-c', 'fetch.unpackLimit=1', '-c', 'transfer.fsckObjects=true',
               '-c', 'fetch.fsckObjects=true', '-c', 'protocol.file.allow=never', 'fetch', '--no-tags',
               '--no-write-fetch-head', '--no-recurse-submodules', '--no-progress', '--depth=1', BASELINE_URL, BASELINE]
    try:
        budget = remaining(deadline, FETCH_SECONDS)
        with (output / 'baseline-fetch.log').open('xb') as log:
            process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True, preexec_fn=fetch_file_limit)
            try:
                acquisition['exitCode'] = process.wait(timeout=budget)
            finally:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait(timeout=10)
                acquisition['processReaped'] = process.poll() is not None
        if acquisition['exitCode'] != 0 or not acquisition['processReaped']:
            raise RuntimeError('fixed baseline acquisition failed; bounded original fetch log retained')
    finally:
        acquisition['objectGrowthBytes'] = max(0, object_storage_bytes(objects) - before)
        if acquisition['objectGrowthBytes'] > FETCH_GROWTH_BYTES:
            raise RuntimeError('fixed baseline acquisition exceeded object storage growth budget')


def ensure_baseline(output, env, deadline, acquisition):
    found = git_result(['rev-parse', '--verify', '--quiet', BASELINE + '^{commit}'], env=env,
                       timeout=remaining(deadline, 20))
    if found.returncode == 1:
        fetch_baseline(output, env, deadline, acquisition)
    elif found.returncode != 0:
        raise RuntimeError('baseline lookup failed independently of object absence')
    commit = git_text(['rev-parse', '--verify', BASELINE + '^{commit}'], env=env, timeout=remaining(deadline, 20))
    tree = git_text(['rev-parse', '--verify', BASELINE + '^{tree}'], env=env, timeout=remaining(deadline, 20))
    if commit != BASELINE or tree != BASELINE_TREE:
        raise RuntimeError('fixed baseline commit/tree differs')
    acquisition.update(verifiedCommit=commit, verifiedTree=tree)


def idle_samples(core, config, log, deadline):
    process = None
    samples = []
    with Path(log).open('wb') as stream:
        try:
            remaining(deadline)
            process = subprocess.Popen([str(core), 'run', '-c', str(config)], stdout=stream, stderr=subprocess.STDOUT)
            for _ in range(5):
                if remaining(deadline) < 1:
                    raise RuntimeError('idle sample work budget exhausted')
                time.sleep(1)
                if process.poll() is not None:
                    raise RuntimeError('idle fixture exited before sampling: ' + str(log))
                status = Path('/proc') / str(process.pid) / 'status'
                line = next(x for x in status.read_text(encoding='utf-8').splitlines() if x.startswith('VmRSS:'))
                samples.append(int(line.split()[1]) * 1024)
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=10)
    return {'samplesBytes': samples, 'medianBytes': statistics.median(samples), 'sampledMaxBytes': max(samples),
            'scope': 'idle process, one uTLS outbound constructed, no inbound or remote handshake'}


def measure(output, environ):
    context = source_context(environ)
    if sys.platform != 'linux' or environ.get('RUNNER_OS') != 'Linux':
        raise RuntimeError('cost measurement is restricted to the existing owned Linux CI job')
    output.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + WORK_SECONDS
    receipt = dict(context, schema='polaris-utls-migration-cost-v1', baselineSource=BASELINE,
                   baselineTree=BASELINE_TREE, candidateSource=context['sourceCommit'], phase='preflight',
                   status='not-measured', measurementsComplete=False, workBudgetSeconds=WORK_SECONDS,
                   retirementGraceSeconds=60,
                   results={}, errors=[], baselineAcquisition={'attempted': False},
                   baselineWorktree={'creationAttempted': False, 'retirementAttempted': False, 'retired': None},
                   tags='with_utls,badlinkname',
                   attribution='whole source/dependency migration at the same Go, not isolated second-library cost',
                   handshakePeakRSSValidated=False, appOrMobileSizeValidated=False, productionDefaultTags=False)
    write_json(output / 'cost.json', receipt, exclusive=True)
    owner = slot = None
    primary = None
    env = dict(environ)
    try:
        env.update(GOCACHE=str(Path(environ['RUNNER_TEMP']).resolve() / 'tls-fingerprint-go-cache'),
                   GOTOOLCHAIN='local', GOFLAGS='-mod=readonly', GOMAXPROCS='2', GIT_TERMINAL_PROMPT='0',
                   GIT_NO_REPLACE_OBJECTS='1')
        write_json(output / 'cost-input.json', dict(context, baselineSource=BASELINE,
                   baselineTree=BASELINE_TREE, workBudgetSeconds=WORK_SECONDS), exclusive=True)
        if shutil.disk_usage(output).free < 10 * 1024**3:
            raise RuntimeError('comparison lacks 4GiB additional growth plus 6GiB headroom')
        source = git_text(['rev-parse', 'HEAD'], env=env, timeout=remaining(deadline, 20))
        receipt['observedCandidateSource'] = source
        receipt['candidateTree'] = git_text(['rev-parse', 'HEAD^{tree}'], env=env, timeout=remaining(deadline, 20))
        if source != context['sourceCommit'] or git_text(['status', '--porcelain', '--untracked-files=all'], env=env,
                                                       timeout=remaining(deadline, 20)):
            raise RuntimeError('candidate source is not the exact clean dispatch')
        scratch = Path(environ['RUNNER_TEMP']).resolve() / 'tls-fingerprint-scratch'; scratch.mkdir(exist_ok=True)
        env['TMPDIR'] = str(scratch)
        actual_go = subprocess.check_output(['go', 'env', 'GOVERSION'], env=env, text=True,
                                            encoding='utf-8', timeout=remaining(deadline, 20)).strip()
        if actual_go != 'go' + (ROOT / 'release/GO_VERSION').read_text(encoding='utf-8').strip():
            raise RuntimeError('cost measurement must use the candidate exact Go for both inputs')
        receipt['goVersion'] = actual_go
        receipt['phase'] = 'baseline-acquisition'
        ensure_baseline(output, env, deadline, receipt['baselineAcquisition'])
        if shutil.disk_usage(output).free < 10 * 1024**3:
            raise RuntimeError('baseline acquisition left insufficient comparison disk headroom')
        owner = Path(tempfile.mkdtemp(prefix='polaris-utls-cost-', dir=environ['RUNNER_TEMP']))
        slot = owner / 'baseline'
        receipt['baselineWorktree'].update(ownerDirectory=str(owner), path=str(slot), creationAttempted=True)
        write_json(output / 'cost.json', receipt)
        git_text(['worktree', 'add', '--detach', str(slot), BASELINE], env=env, timeout=remaining(deadline, 60))
        if (git_text(['rev-parse', 'HEAD'], cwd=slot, env=env, timeout=remaining(deadline, 20)) != BASELINE
                or git_text(['rev-parse', 'HEAD^{tree}'], cwd=slot, env=env,
                            timeout=remaining(deadline, 20)) != BASELINE_TREE):
            raise RuntimeError('baseline worktree identity differs')
        baseline_flags = (slot / 'release/LDFLAGS').read_text(encoding='utf-8').strip()
        if baseline_flags != (ROOT / 'release/LDFLAGS').read_text(encoding='utf-8').strip():
            raise RuntimeError('comparison linker contract changed; do not silently compare different flags')
        flags = baseline_flags + ' -s -w -buildid= -X github.com/sagernet/sing-box/constant.Version=1.15.0-polaris-alpha.12'
        receipt['ldflags'] = flags
        config = output / 'idle-config.json'; write_json(config, outbound_config('chrome'), exclusive=True)
        for label, directory in [('baseline', slot), ('candidate', ROOT)]:
            receipt['phase'] = label + '-build-and-idle'
            core = output / (label + '-core')
            command = ['go', 'build', '-p=2', '-trimpath', '-tags=with_utls,badlinkname', '-ldflags=' + flags,
                       '-o', str(core), './cmd/sing-box']
            code = run_logged(command, cwd=directory, env=env, logfile=output / (label + '-build.log'),
                              timeout=remaining(deadline))
            if code != 0:
                receipt['errors'].append(label + ': comparison build failed/timed out; original log retained')
                continue
            info = subprocess.check_output(['go', 'version', '-m', str(core)], env=env, text=True,
                                           encoding='utf-8', timeout=remaining(deadline, 20))
            build_id = subprocess.check_output(['go', 'tool', 'buildid', str(core)], env=env, text=True,
                                               encoding='utf-8', timeout=remaining(deadline, 20)).strip()
            identity = {'sourceCommit': BASELINE if label == 'baseline' else source,
                        'sourceTree': git_text(['rev-parse', 'HEAD^{tree}'], cwd=directory, env=env,
                                               timeout=remaining(deadline, 20)),
                        'bytes': core.stat().st_size, 'sha256': sha(core), 'buildID': build_id, 'rawBuildInfo': info}
            try:
                identity['idleRSS'] = idle_samples(core, config, output / (label + '-idle.log'), deadline)
            except Exception as error:
                receipt['errors'].append(label + ': ' + repr(error)[:4096])
            receipt['results'][label] = identity
    except BaseException as error:
        primary = error
        receipt['errors'].append(type(error).__name__ + ': ' + str(error)[:4096])
    finally:
        if owner is not None:
            receipt['baselineWorktree']['retirementAttempted'] = True
            try:
                # Only this invocation's exclusive private workspace is owned.
                # Failed retirement retains its path and reports cleanup debt.
                registered = [line[9:] for line in git_text(['worktree', 'list', '--porcelain'], env=env,
                                                          timeout=20).splitlines() if line.startswith('worktree ')]
                if str(slot) in registered:
                    git_text(['worktree', 'remove', str(slot)], env=env, timeout=20)
                elif slot.exists():
                    raise RuntimeError('unregistered partial checkout retained inside owned workspace')
                owner.rmdir()
                receipt['baselineWorktree']['retired'] = True
            except Exception as error:
                receipt['baselineWorktree']['retired'] = False
                receipt['errors'].append('owned baseline workspace retirement failed: ' + str(error)[:4096])
        receipt['baselineWorktreeRetired'] = receipt['baselineWorktree']['retired'] is True
        receipt['measurementsComplete'] = (not receipt['errors'] and receipt['baselineWorktreeRetired']
            and all('idleRSS' in receipt['results'].get(x, {}) for x in ['baseline', 'candidate']))
        if receipt['measurementsComplete']:
            a, b = receipt['results']['baseline'], receipt['results']['candidate']
            receipt['delta'] = {'binaryBytes': b['bytes'] - a['bytes'],
                              'medianIdleRSSBytes': b['idleRSS']['medianBytes'] - a['idleRSS']['medianBytes']}
        receipt['status'] = 'complete' if receipt['measurementsComplete'] else 'incomplete'
        try:
            receipt['diskFreeBytesAfter'] = shutil.disk_usage(output).free
        except Exception as error:
            receipt['errors'].append('final disk observation failed: ' + str(error)[:4096])
            receipt['measurementsComplete'] = False; receipt['status'] = 'incomplete'; receipt.pop('delta', None)
        try:
            write_json(output / 'cost.json', receipt)
        except Exception as error:
            if primary is None:
                raise
            primary.add_note('final cost receipt also failed: ' + type(error).__name__)
    if primary is not None:
        raise primary
    if not receipt['measurementsComplete']:
        raise RuntimeError('; '.join(receipt['errors']) or 'comparison did not produce both measured inputs')
    return receipt


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--retain-source-input', action='store_true'); args = parser.parse_args()
    if args.retain_source_input:
        retain_source_input(args.output.resolve(), os.environ)
    else:
        measure(args.output.resolve(), os.environ)


if __name__ == '__main__':
    main()
