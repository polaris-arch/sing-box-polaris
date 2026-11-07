"""Offline diagnostic/acquisition rejection controls; no Git, Go or Core executes.

Fixture metadata and mocked subprocesses never stand for actual fetched objects,
measured binary/RSS results, native proof or production acceptance.
"""
import ast
from contextlib import ExitStack
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml
import utls_cost as cost

ROOT = Path(__file__).resolve().parents[2]
SOURCE = 'a' * 40
TREE = 'b' * 40


def fixture_env(temp):
    return {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': cost.REPOSITORY,
            'GITHUB_REPOSITORY_ID': '1421657509', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
            'GITHUB_JOB': 'utls_gate', 'GITHUB_SHA': SOURCE, 'GITHUB_RUN_ID': '12',
            'GITHUB_RUN_ATTEMPT': '2', 'RUNNER_TEMP': str(temp), 'RUNNER_OS': 'Linux',
            'SOURCE_BUILD': 'Source', 'SOURCE_GENERATE_ONLY': 'false', 'SOURCE_WINDOWS_NATIVE_PROOF': 'false',
            'SOURCE_EVIDENCE_MODE': 'staging', 'SOURCE_VERSION': 'fixture-source-input',
            'SOURCE_RUNNER': 'ubuntu-24.04'}


class FetchProcess:
    """Owned process fake; kill/wait API calls are asserted, never executed."""
    pid = 12345

    def __init__(self, waits):
        self.waits = list(waits)
        self.returncode = None

    def wait(self, timeout):
        value = self.waits.pop(0)
        if isinstance(value, BaseException):
            raise value
        self.returncode = value
        return value

    def poll(self):
        return self.returncode


class CostContracts(unittest.TestCase):
    def test_context_rejects_wrong_repo_scope_and_identity_before_execution(self):
        bad = {'GITHUB_ACTIONS': 'false', 'GITHUB_REPOSITORY': 'foreign/repo',
               'GITHUB_REPOSITORY_ID': '1', 'GITHUB_EVENT_NAME': 'push', 'GITHUB_JOB': 'native_windows_proof',
               'SOURCE_BUILD': 'All', 'SOURCE_GENERATE_ONLY': 'true', 'SOURCE_WINDOWS_NATIVE_PROOF': 'true',
               'GITHUB_SHA': 'A' * 40, 'GITHUB_RUN_ID': '0', 'GITHUB_RUN_ATTEMPT': '02',
               'SOURCE_VERSION': 'x' * 129}
        with mock.patch.object(cost.subprocess, 'run') as run, mock.patch.object(cost.subprocess, 'Popen') as popen:
            for key, value in bad.items():
                with self.subTest(field=key), self.assertRaises((ValueError, RuntimeError)):
                    cost.source_context(dict(fixture_env('/fixture'), **{key: value}))
            run.assert_not_called(); popen.assert_not_called()

    def test_early_receipt_binds_actual_checkout_and_is_only_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'evidence'
            with mock.patch.object(cost, 'git_text', side_effect=[SOURCE, TREE, '']) as git:
                data = cost.retain_source_input(output, fixture_env(temp))
            raw = (output / 'source-ci-input.json').read_bytes()
            self.assertEqual(json.loads(raw), data)
            self.assertEqual((data['runId'], data['runAttempt'], data['sourceTree']), (12, 2, TREE))
            self.assertTrue(data['checkoutIdentityVerified']); self.assertTrue(data['diagnosticOnly'])
            self.assertFalse(data['testOrNativePASS']); self.assertFalse(data['executionAuthority'])
            self.assertFalse(data['measurementsComplete']); self.assertEqual(data['testExecutionStatus'], 'not-started')
            self.assertNotIn('goVersion', data); self.assertNotIn('results', data)
            self.assertEqual(git.call_count, 3); self.assertTrue(raw.endswith(b'\n')); self.assertNotIn(b'\r', raw)
            self.assertLessEqual(len(raw), 16384)

    def test_early_wrong_or_dirty_checkout_keeps_failure_receipt(self):
        for commit, status in [('c' * 40, ''), (SOURCE, ' M fixture')]:
            with self.subTest(commit=commit, status=status), tempfile.TemporaryDirectory() as temp:
                output = Path(temp) / 'evidence'
                with mock.patch.object(cost, 'git_text', side_effect=[commit, TREE, status]), self.assertRaises(RuntimeError):
                    cost.retain_source_input(output, fixture_env(temp))
                data = json.loads((output / 'source-ci-input.json').read_bytes())
                self.assertFalse(data['checkoutIdentityVerified']); self.assertIn('error', data)
                self.assertFalse(data['testOrNativePASS']); self.assertFalse(data['measurementsComplete'])

    def test_existing_diagnostic_receipt_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp); path = output / 'source-ci-input.json'; path.write_bytes(b'owned-before')
            with mock.patch.object(cost, 'git_text') as git, self.assertRaises(FileExistsError):
                cost.retain_source_input(output, fixture_env(temp))
            self.assertEqual(path.read_bytes(), b'owned-before'); git.assert_not_called()

    def test_json_bound_counts_utf8_bytes_before_writing(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / 'receipt'
            with self.assertRaises(ValueError):
                cost.write_json(p, {'value': '\u5305' * 12}, bound=20)
            self.assertFalse(p.exists())

    def test_existing_exact_baseline_does_not_fetch(self):
        acquisition = {'attempted': False}
        with mock.patch.object(cost, 'git_result', return_value=mock.Mock(returncode=0)), \
             mock.patch.object(cost, 'git_text', side_effect=[cost.BASELINE, cost.BASELINE_TREE]), \
             mock.patch.object(cost, 'fetch_baseline') as fetch, mock.patch.object(cost.time, 'monotonic', return_value=0):
            cost.ensure_baseline(Path('/unused'), {}, 100, acquisition)
        fetch.assert_not_called(); self.assertFalse(acquisition['attempted'])
        self.assertEqual(acquisition['verifiedTree'], cost.BASELINE_TREE)

    def test_missing_baseline_fetches_once_then_verifies_both_identities(self):
        acquisition = {'attempted': False}
        with mock.patch.object(cost, 'git_result', return_value=mock.Mock(returncode=1)), \
             mock.patch.object(cost, 'git_text', side_effect=[cost.BASELINE, cost.BASELINE_TREE]), \
             mock.patch.object(cost, 'fetch_baseline') as fetch, mock.patch.object(cost.time, 'monotonic', return_value=0):
            cost.ensure_baseline(Path('/unused'), {'fixture': 'env'}, 100, acquisition)
        fetch.assert_called_once_with(Path('/unused'), {'fixture': 'env'}, 100, acquisition)

    def test_nonmissing_lookup_error_never_fetches_or_verifies(self):
        with mock.patch.object(cost, 'git_result', return_value=mock.Mock(returncode=128)), \
             mock.patch.object(cost, 'git_text') as identity, mock.patch.object(cost, 'fetch_baseline') as fetch, \
             mock.patch.object(cost.time, 'monotonic', return_value=0), self.assertRaisesRegex(RuntimeError, 'independently'):
            cost.ensure_baseline(Path('/unused'), {}, 100, {})
        fetch.assert_not_called(); identity.assert_not_called()

    def test_wrong_commit_or_tree_rejects_before_any_build(self):
        for identities in [('f' * 40, cost.BASELINE_TREE), (cost.BASELINE, 'f' * 40)]:
            with self.subTest(identities=identities), mock.patch.object(cost, 'git_result', return_value=mock.Mock(returncode=0)), \
                 mock.patch.object(cost, 'git_text', side_effect=identities), mock.patch.object(cost, 'run_logged') as build, \
                 mock.patch.object(cost.time, 'monotonic', return_value=0), self.assertRaisesRegex(RuntimeError, 'commit/tree'):
                cost.ensure_baseline(Path('/unused'), {}, 100, {})
            build.assert_not_called()

    def fetch_case(self, waits, growth=0):
        stack = ExitStack(); self.addCleanup(stack.close)
        temp = stack.enter_context(tempfile.TemporaryDirectory()); output = Path(temp)
        process = FetchProcess(waits)
        stack.enter_context(mock.patch.object(cost.time, 'monotonic', return_value=0))
        stack.enter_context(mock.patch.object(cost, 'git_text', return_value=str(output / 'objects')))
        stack.enter_context(mock.patch.object(cost, 'object_storage_bytes', side_effect=[10, 10 + growth]))
        stack.enter_context(mock.patch.object(cost.signal, 'SIGKILL', 9, create=True))
        popen = stack.enter_context(mock.patch.object(cost.subprocess, 'Popen', return_value=process))
        kill = stack.enter_context(mock.patch.object(cost.os, 'killpg', create=True))
        return output, process, popen, kill

    def test_fetch_is_one_fixed_url_sha_no_tag_ref_or_submodule_update(self):
        output, process, popen, kill = self.fetch_case([0]); acquisition = {}
        cost.fetch_baseline(output, {}, 100, acquisition)
        command = popen.call_args.args[0]
        self.assertEqual(command[-2:], [cost.BASELINE_URL, cost.BASELINE])
        for arg in ('--no-tags', '--no-write-fetch-head', '--no-recurse-submodules', '--depth=1'):
            self.assertIn(arg, command)
        self.assertNotIn('--force', command); self.assertEqual(popen.call_count, 1)
        self.assertIs(popen.call_args.kwargs['preexec_fn'], cost.fetch_file_limit)
        self.assertTrue(acquisition['processReaped']); kill.assert_not_called()
        self.assertEqual(acquisition['maxObjectGrowthBytes'], 512 << 20)

    def test_fetch_timeout_retires_exact_owned_process_and_does_not_retry(self):
        timeout = subprocess.TimeoutExpired(['fixture-git'], 90)
        output, process, popen, kill = self.fetch_case([timeout, 0]); acquisition = {}
        with self.assertRaises(subprocess.TimeoutExpired):
            cost.fetch_baseline(output, {}, 100, acquisition)
        self.assertTrue(acquisition['processReaped']); self.assertEqual(popen.call_count, 1)
        kill.assert_called_once_with(process.pid, cost.signal.SIGTERM)
        self.assertNotIn('verifiedCommit', acquisition)

    def test_fetch_hard_retirement_is_bounded_and_failure_never_verifies(self):
        timeout = subprocess.TimeoutExpired(['fixture-git'], 90)
        output, process, popen, kill = self.fetch_case([timeout, timeout, -9]); acquisition = {}
        with self.assertRaises(subprocess.TimeoutExpired):
            cost.fetch_baseline(output, {}, 100, acquisition)
        self.assertEqual(kill.call_args_list, [mock.call(process.pid, cost.signal.SIGTERM), mock.call(process.pid, cost.signal.SIGKILL)])
        self.assertTrue(acquisition['processReaped']); self.assertNotIn('verifiedCommit', acquisition)

    def test_fetch_nonzero_and_growth_exhaustion_fail_closed(self):
        for code, growth, error in [(1, 0, 'acquisition failed'), (0, cost.FETCH_GROWTH_BYTES + 1, 'growth budget')]:
            with self.subTest(code=code, growth=growth):
                output, process, popen, kill = self.fetch_case([code], growth)
                with self.assertRaisesRegex(RuntimeError, error):
                    cost.fetch_baseline(output, {}, 100, {})

    def test_budget_expiry_prevents_start_and_git_text_diagnostics_are_bounded(self):
        with mock.patch.object(cost.time, 'monotonic', return_value=10), self.assertRaises(RuntimeError):
            cost.remaining(10)
        with mock.patch.object(cost.subprocess, 'run', return_value=mock.Mock(stdout='x' * 65537, stderr='', returncode=0)), \
             self.assertRaises(ValueError):
            cost.git_result(['rev-parse', 'HEAD'])

    def test_object_storage_rejects_symlink_without_following_it(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp); (p / 'object').write_bytes(b'fixture')
            with mock.patch.object(Path, 'is_symlink', return_value=True), self.assertRaises(RuntimeError):
                cost.object_storage_bytes(p)

    def test_nonlinux_measurement_rejects_before_any_subprocess_or_receipt(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(cost.sys, 'platform', 'win32'), \
             mock.patch.object(cost.subprocess, 'Popen') as process, self.assertRaises(RuntimeError):
            cost.measure(Path(temp) / 'cost', fixture_env(temp))
        process.assert_not_called()

    def test_disk_preflight_failure_keeps_truthful_empty_measurement(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(cost.sys, 'platform', 'linux'), \
             mock.patch.object(cost.shutil, 'disk_usage', return_value=mock.Mock(free=1)), \
             mock.patch.object(cost, 'ensure_baseline') as baseline, mock.patch.object(cost, 'run_logged') as build:
            output = Path(temp) / 'cost'
            with self.assertRaisesRegex(RuntimeError, 'headroom'):
                cost.measure(output, fixture_env(temp))
            data = json.loads((output / 'cost.json').read_bytes())
            self.assertFalse(data['measurementsComplete']); self.assertEqual(data['results'], {})
            self.assertEqual(data['status'], 'incomplete'); self.assertNotIn('delta', data)
            self.assertFalse(data['baselineWorktree']['creationAttempted']); self.assertFalse(data['executionAuthority'])
            baseline.assert_not_called(); build.assert_not_called()

    def measure_case(self, *, dirty=False, wrong_go=False, wrong_flags=False, cleanup_error=False,
                     add_error=False, partial_error=False):
        stack = ExitStack(); self.addCleanup(stack.close)
        temp = stack.enter_context(tempfile.TemporaryDirectory()); root = Path(temp) / 'source'; root.mkdir()
        (root / 'release').mkdir(); (root / 'release/GO_VERSION').write_text('1.27.2\n', encoding='utf-8')
        (root / 'release/LDFLAGS').write_text('-fixture\n', encoding='utf-8')
        slot = [None]
        def git(args, *, cwd=None, **kwargs):
            if args == ['status', '--porcelain', '--untracked-files=all']: return ' M fixture' if dirty else ''
            if args == ['rev-parse', 'HEAD']: return cost.BASELINE if cwd == slot[0] and slot[0] else SOURCE
            if args == ['rev-parse', 'HEAD^{tree}']: return cost.BASELINE_TREE if cwd == slot[0] and slot[0] else TREE
            if args[:2] == ['worktree', 'add']:
                slot[0] = Path(args[3])
                if add_error: raise RuntimeError('fixture add failed before checkout')
                (slot[0] / 'release').mkdir(parents=True)
                (slot[0] / 'release/LDFLAGS').write_text('wrong' if wrong_flags else '-fixture', encoding='utf-8')
                if partial_error: raise RuntimeError('fixture add failed with unregistered partial checkout')
                return ''
            if args == ['worktree', 'list', '--porcelain']:
                if partial_error: return ''
                return 'worktree ' + str(slot[0]) if slot[0] and slot[0].exists() else ''
            if args[:2] == ['worktree', 'remove']:
                if cleanup_error: raise RuntimeError('fixture actual retirement unknown')
                shutil.rmtree(slot[0]); return ''
            raise AssertionError(args)
        stack.enter_context(mock.patch.object(cost, 'ROOT', root))
        stack.enter_context(mock.patch.object(cost.sys, 'platform', 'linux'))
        stack.enter_context(mock.patch.object(cost, 'git_text', side_effect=git))
        stack.enter_context(mock.patch.object(cost.shutil, 'disk_usage', return_value=mock.Mock(free=20 << 30)))
        baseline = stack.enter_context(mock.patch.object(cost, 'ensure_baseline'))
        go = stack.enter_context(mock.patch.object(cost.subprocess, 'check_output', return_value='go1.0' if wrong_go else 'go1.27.2'))
        build = stack.enter_context(mock.patch.object(cost, 'run_logged', return_value=1))
        return Path(temp) / 'cost', fixture_env(temp), baseline, go, build

    def test_candidate_dirty_or_wrong_go_prevents_acquisition_and_measurement(self):
        for option in ('dirty', 'wrong_go'):
            with self.subTest(option=option):
                output, env, baseline, go, build = self.measure_case(**{option: True})
                with self.assertRaises(RuntimeError): cost.measure(output, env)
                data = json.loads((output / 'cost.json').read_bytes())
                self.assertFalse(data['measurementsComplete']); self.assertEqual(data['results'], {})
                baseline.assert_not_called(); build.assert_not_called()

    def test_build_failures_keep_owned_cleanup_and_never_fabricate_delta(self):
        output, env, baseline, go, build = self.measure_case()
        with self.assertRaises(RuntimeError): cost.measure(output, env)
        data = json.loads((output / 'cost.json').read_bytes())
        self.assertTrue(data['baselineWorktreeRetired']); self.assertFalse(data['measurementsComplete'])
        self.assertEqual(data['results'], {}); self.assertNotIn('delta', data); self.assertEqual(build.call_count, 2)
        first, second = [call.args[0] for call in build.call_args_list]
        self.assertEqual(first[:7], second[:7]); self.assertEqual(first[-1], second[-1])
        self.assertNotEqual(first[-2], second[-2])
        self.assertTrue(all(call.kwargs['env']['GOTOOLCHAIN'] == 'local' for call in build.call_args_list))

    def test_wrong_flags_or_add_failure_retire_only_owned_workspace(self):
        for option in ('wrong_flags', 'add_error'):
            with self.subTest(option=option):
                output, env, baseline, go, build = self.measure_case(**{option: True})
                with self.assertRaises(RuntimeError): cost.measure(output, env)
                data = json.loads((output / 'cost.json').read_bytes())
                self.assertTrue(data['baselineWorktreeRetired']); self.assertFalse(data['measurementsComplete'])
                self.assertEqual(data['results'], {}); build.assert_not_called()

    def test_cleanup_error_remains_incomplete_and_keeps_debt_path(self):
        output, env, baseline, go, build = self.measure_case(cleanup_error=True)
        with self.assertRaises(RuntimeError): cost.measure(output, env)
        data = json.loads((output / 'cost.json').read_bytes())
        self.assertFalse(data['baselineWorktreeRetired']); self.assertFalse(data['measurementsComplete'])
        self.assertTrue(Path(data['baselineWorktree']['path']).exists()); self.assertNotIn('delta', data)

    def test_partial_unregistered_checkout_is_retained_without_blind_delete(self):
        output, env, baseline, go, build = self.measure_case(partial_error=True)
        with self.assertRaises(RuntimeError): cost.measure(output, env)
        data = json.loads((output / 'cost.json').read_bytes())
        self.assertFalse(data['baselineWorktreeRetired']); self.assertFalse(data['measurementsComplete'])
        self.assertTrue(Path(data['baselineWorktree']['path']).exists())
        self.assertIn('unregistered partial', '\n'.join(data['errors'])); build.assert_not_called()

    def test_workflow_retains_inputs_before_go_pip_unicode_without_weakening_upload(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/build.yml').read_bytes())
        job = workflow['jobs']['utls_gate']; steps = job['steps']
        self.assertEqual(job['if'], "inputs.build == 'Source' && !inputs.source_generate_only")
        receipt = next(s for s in steps if '--retain-source-input' in s.get('run', ''))
        index = steps.index(receipt)
        for step in steps:
            if step.get('uses') == 'actions/setup-go@v5' or 'pip install' in step.get('run', '') or 'test_client_encoding.py' in step.get('run', ''):
                self.assertLess(index, steps.index(step))
        self.assertNotIn('continue-on-error', receipt)
        self.assertEqual(job['env']['SOURCE_BUILD'], '${{ inputs.build }}')
        self.assertEqual(job['env']['SOURCE_GENERATE_ONLY'], "${{ inputs.source_generate_only && 'true' || 'false' }}")
        self.assertEqual(job['env']['SOURCE_WINDOWS_NATIVE_PROOF'], "${{ inputs.windows_native_proof && 'true' || 'false' }}")
        upload = next(s for s in steps if s.get('uses', '').startswith('actions/upload-artifact@'))
        self.assertEqual(upload['if'], 'always()'); self.assertEqual(upload['with']['if-no-files-found'], 'error')
        observation = next(s for s in steps if 'utls_cost.py --output' in s.get('run', ''))
        self.assertEqual(observation['if'], "always() && matrix.os == 'ubuntu-24.04'")
        self.assertIs(observation['continue-on-error'], True)
        discovery = workflow['jobs']['source_gate']['steps']
        self.assertTrue(any("unittest discover -s scripts/ci -p 'test_*.py'" in s.get('run', '') for s in discovery))

    def test_resource_limit_import_is_lazy_and_touched_text_io_is_explicit_utf8(self):
        tree = ast.parse((ROOT / 'scripts/ci/utls_cost.py').read_bytes())
        self.assertFalse(any(isinstance(node, ast.Import) and any(a.name == 'resource' for a in node.names) for node in tree.body))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ('read_text', 'write_text'):
                self.assertIn('encoding', {k.arg for k in node.keywords})


if __name__ == '__main__':
    unittest.main()
