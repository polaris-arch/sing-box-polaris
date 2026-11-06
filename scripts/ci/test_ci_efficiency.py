"""Contracts for reduced preparation without shrinking product or trust coverage."""
import json
from pathlib import Path
import unittest
import copy
import shlex
import yaml

ROOT = Path(__file__).resolve().parents[2]


def workflow(name):
    return yaml.safe_load((ROOT / '.github/workflows' / (name + '.yml')).read_text())


def native_smoke_go_toolchain_contract(workflow):
    steps = workflow['jobs']['native_smoke']['steps']
    # Darwin's held post-sign observer invokes both go version -m and go tool
    # buildid. A Go installation in the archive-producing job is not inherited
    # by this separate runner; Linux/Windows smoke do not use that observer.
    go_steps = [step for step in steps if step.get('uses', '').startswith('actions/setup-go@')]
    if len(go_steps) != 1:
        raise AssertionError('Darwin metadata requires exactly one source-owned Go setup')
    go = go_steps[0]
    if (go.get('uses') != 'actions/setup-go@v5' or go.get('if') != "startsWith(matrix.id, 'darwin-')"
            or 'continue-on-error' in go or go.get('with') != {'go-version-file':'release/GO_VERSION','cache':False}):
        raise AssertionError('Darwin metadata must use the exact source-owned Go pin without cache drift')
    smoke = next(step for step in steps if step.get('name') == 'Execute final-package Cronet smoke')
    checkout = next(i for i, step in enumerate(steps) if step.get('name') == 'Checkout')
    if not checkout < steps.index(go) < steps.index(smoke) or smoke.get('env', {}).get('GOTOOLCHAIN') != 'local':
        raise AssertionError('Darwin Go must precede metadata and cannot auto-upgrade its toolchain')


def darwin_archive_seal_contract(workflow):
    steps = workflow['jobs']['build_darwin']['steps']
    seals = [step for step in steps if step.get('name') == 'Seal Darwin native candidate before archive']
    if len(seals) != 1:
        raise AssertionError('both modern Darwin archives require an explicit final signature')
    seal = seals[0]
    commands = [shlex.split(line) for line in seal.get('run', '').splitlines() if line.strip()]
    if (seal.get('if') != '${{ ! matrix.legacy_osx }}' or 'continue-on-error' in seal or commands != [
            ['/usr/bin/codesign','--force','--sign','-','--timestamp=none','dist/sing-box'],
            ['/usr/bin/codesign','--verify','--strict','dist/sing-box']]):
        raise AssertionError('modern Darwin seal must be ad-hoc and strictly verified before hashing')
    index = {step.get('name'):i for i,step in enumerate(steps)}
    if not index['Build'] < steps.index(seal) < index['Archive'] < index['Collect actual native archive receipt']:
        raise AssertionError('Darwin archive and receipt must contain only the final signed bytes')
    archive = steps[index['Archive']]
    # macOS tar otherwise emits AppleDouble/PAX host metadata (including
    # com.apple.provenance); the strict native reader accepts only dataforks.
    if (archive.get('env', {}).get('COPYFILE_DISABLE') != '1' or
            'if' in archive or 'continue-on-error' in archive):
        raise AssertionError('both Darwin archives must suppress host copyfile metadata')



class EfficiencyTests(unittest.TestCase):
    def test_darwin_archive_signs_both_modern_targets_before_recording_final_bytes(self):
        for workflow_name in ('build', 'signed-release'):
            with self.subTest(workflow=workflow_name):
                workflow = yaml.safe_load((ROOT/'.github/workflows'/(workflow_name+'.yml')).read_text())
                darwin_archive_seal_contract(workflow)
                rows = workflow['jobs']['build_darwin']['strategy']['matrix']['include']
                self.assertEqual([row['arch'] for row in rows if not row.get('legacy_osx')], ['amd64','arm64'])
                for mutation in ('missing','duplicate','late','only-arm64','skip-failure','no-verify','real-identity'):
                    wrong = copy.deepcopy(workflow)
                    steps = wrong['jobs']['build_darwin']['steps']
                    seal = next(step for step in steps if step.get('name') == 'Seal Darwin native candidate before archive')
                    if mutation == 'missing': steps.remove(seal)
                    elif mutation == 'duplicate': steps.append(copy.deepcopy(seal))
                    elif mutation == 'late': steps.remove(seal); steps.append(seal)
                    elif mutation == 'only-arm64': seal['if'] = "matrix.arch == 'arm64'"
                    elif mutation == 'skip-failure': seal['continue-on-error'] = True
                    elif mutation == 'no-verify': seal['run'] = seal['run'].splitlines()[0]
                    elif mutation == 'real-identity': seal['run'] = seal['run'].replace('--sign - ', '--sign unreviewed ')
                    with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                        darwin_archive_seal_contract(wrong)


    def test_darwin_archives_exclude_host_metadata_for_both_workflows(self):
        for workflow_name in ('build', 'signed-release'):
            original = workflow(workflow_name)
            with self.subTest(workflow=workflow_name):
                darwin_archive_seal_contract(original)
                for mutation in ('missing', 'enabled', 'boolean', 'only-arm64', 'ignore-failure'):
                    wrong = copy.deepcopy(original)
                    archive = next(step for step in wrong['jobs']['build_darwin']['steps']
                                   if step.get('name') == 'Archive')
                    if mutation == 'missing': archive['env'].pop('COPYFILE_DISABLE')
                    elif mutation == 'enabled': archive['env']['COPYFILE_DISABLE'] = '0'
                    elif mutation == 'boolean': archive['env']['COPYFILE_DISABLE'] = True
                    elif mutation == 'only-arm64': archive['if'] = "matrix.arch == 'arm64'"
                    elif mutation == 'ignore-failure': archive['continue-on-error'] = True
                    with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                        darwin_archive_seal_contract(wrong)


    def test_darwin_metadata_go_setup_rejects_missing_drift_late_and_partial_platforms(self):
        for workflow_name in ('build', 'signed-release'):
            with self.subTest(workflow=workflow_name):
                original = yaml.safe_load((ROOT/'.github/workflows'/(workflow_name+'.yml')).read_text())
                native_smoke_go_toolchain_contract(original)
                for mutation in ('missing','duplicate','late','version','latest','cache','wrong-action',
                                 'only-arm64','conditional-success','ignore-failure','auto-toolchain'):
                    workflow = copy.deepcopy(original)
                    steps = workflow['jobs']['native_smoke']['steps']
                    go = next(step for step in steps if step.get('uses', '').startswith('actions/setup-go@'))
                    smoke = next(step for step in steps if step.get('name') == 'Execute final-package Cronet smoke')
                    if mutation == 'missing': steps.remove(go)
                    elif mutation == 'duplicate': steps.append(copy.deepcopy(go))
                    elif mutation == 'late': steps.remove(go); steps.append(go)
                    elif mutation == 'version': go['with'] = {'go-version':'1.27.1','cache':False}
                    elif mutation == 'latest': go['with'] = {'go-version':'stable','cache':False}
                    elif mutation == 'cache': go['with']['cache'] = True
                    elif mutation == 'wrong-action': go['uses'] = 'actions/setup-go@unreviewed'
                    elif mutation == 'only-arm64': go['if'] = "matrix.id == 'darwin-arm64'"
                    elif mutation == 'conditional-success': go['if'] = 'always()'
                    elif mutation == 'ignore-failure': go['continue-on-error'] = True
                    elif mutation == 'auto-toolchain': smoke['env']['GOTOOLCHAIN'] = 'auto'
                    with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                        native_smoke_go_toolchain_contract(workflow)


    def test_win7_prepares_once_without_blocking_other_platforms(self):
        upstream = json.loads((ROOT / 'release/ci/upstream-matrices.json').read_text())['matrices']['build.yml']['build']['include']
        scopes = json.loads((ROOT / 'release/ci/publisher-upstream-scope.json').read_text())
        for name, role in [('build', 'all'), ('signed-release', 'signed')]:
            jobs = workflow(name)['jobs']
            for producer in ('build', 'prepare_windows7', 'build_darwin'):
                self.assertEqual(jobs[producer]['needs'], ['calculate_version'])
                self.assertNotIn('needs.debian_materials', jobs[producer]['if'])
            self.assertEqual(jobs['build_windows7']['needs'], ['calculate_version', 'prepare_windows7'])
            if role == 'signed':
                for job in ['build', 'prepare_windows7', 'build_windows7']:
                    self.assertEqual(jobs[job]['environment'], 'polaris-distribution')
            from test_protocol_peer import normal_build_matrix
            regular = normal_build_matrix(jobs['build']['strategy']['matrix'])['include']
            legacy = jobs['build_windows7']['strategy']['matrix']['include']
            self.assertEqual(len(legacy), 2)
            self.assertTrue(all(row['legacy_win7'] for row in legacy))
            self.assertTrue(all(not row.get('legacy_win7') for row in regular))
            self.assertCountEqual(regular + legacy, upstream)
            self.assertTrue(all(set(row) == {'os', 'arch', 'legacy_win7', 'legacy_name'} for row in legacy))
            # YAML aliases share the complete archive producer, not a second copy.
            self.assertEqual(jobs['build']['steps'], jobs['build_windows7']['steps'])
            prep = jobs['prepare_windows7']['steps']
            self.assertEqual(sum(s.get('run') == '.github/setup_go_for_windows7.sh' for s in prep), 1)
            steps = jobs['build_windows7']['steps']
            restore = next(s for s in steps if s.get('name') == 'Restore complete toolchain files and modes')
            self.assertIn('polaris-toolchain.json', restore['run'])
            self.assertTrue(any(s.get('run') == '.github/setup_go_for_windows7.sh' for s in steps))
            self.assertFalse(any(s.get('uses', '').startswith('actions/cache@') for s in steps))
            for consumer in ['native_smoke', 'native_index', 'publisher_receipt']:
                self.assertIn('build_windows7', jobs[consumer]['needs'])
            self.assertIn('prepare_windows7', jobs['publisher_receipt']['needs'])
            self.assertEqual(scopes[role]['receiptJobs']['prepare_windows7'], 'required')
            if role == 'all':
                self.assertIs(jobs['build']['strategy']['fail-fast'], False)
                for consumer in ('native_index', 'publisher_receipt'):
                    self.assertIn('debian_materials', jobs[consumer]['needs'])
            self.assertIn('go-win7-toolchain', scopes[role]['requiredArtifacts'])
            self.assertEqual(scopes[role]['matrices']['build_windows7'], jobs['build_windows7']['strategy']['matrix'])

    def test_manual_version_jobs_do_not_prepare_go_and_fpm_has_one_owner(self):
        for name in ['build', 'signed-release', 'linux', 'signed-linux']:
            jobs = workflow(name)['jobs']
            for step in jobs['calculate_version']['steps']:
                if step.get('uses', '').startswith(('actions/setup-go@', 'actions/cache/restore@')):
                    self.assertEqual(step['if'], "github.event_name != 'workflow_dispatch'")
            for job in jobs.values():
                commands = [s.get('run', '') for s in job.get('steps', [])]
                consumers = [c for c in commands if 'fpm -t ' in c]
                if consumers:
                    self.assertEqual(sum(c.count('sudo gem install fpm') for c in commands), 1)
        lint = workflow('lint')['jobs']['build']['steps']
        self.assertFalse(any(s.get('uses', '').startswith('actions/cache@') for s in lint))
        setup = next(s for s in lint if s.get('uses', '').startswith('actions/setup-go@'))
        self.assertIn('third_party/metacubex-utls/go.sum', setup['with']['cache-dependency-path'])

    def test_cheap_formatter_is_hash_pinned_and_preserves_the_owned_format_check(self):
        steps = workflow('polaris-selfcheck')['jobs']['classify']['steps']
        commands = '\n'.join(s.get('run', '') for s in steps)
        self.assertNotIn('go install ', commands)
        self.assertIn('9b7fe6a6bf6334b98decf8d86b11415ea7889afdabdd1959fdce23af2a9ebcea', commands)
        self.assertIn('sha256sum -c -', commands)
        self.assertIn('scripts/ci/check_remediation_format.py', commands)
        for s in steps:
            if 'formatter' in s.get('name', '').lower() or s.get('name', '').startswith('Check owned remediation formatting'):
                self.assertEqual(s['if'], "steps.impact.outputs.run_full == 'true'")

    def test_fixed_audits_are_not_cancelled_by_automatic_tips(self):
        for name in ['build', 'linux', 'docker', 'signed-release', 'signed-linux']:
            policy = workflow(name)['concurrency']
            self.assertFalse(policy['cancel-in-progress'])
            self.assertIn('github.run_id', policy['group'])
        for name in ['lint', 'test', 'ci-contract', 'polaris-selfcheck']:
            policy = workflow(name)['concurrency']
            self.assertIn('github.event.pull_request.number', policy['group'])
            self.assertIn('github.run_id', policy['group'])
            self.assertIn("github.event_name == 'pull_request'", policy['cancel-in-progress'])
            self.assertIn("github.ref_type == 'branch'", policy['cancel-in-progress'])
            self.assertNotIn('workflow_dispatch', policy['cancel-in-progress'])


if __name__ == '__main__':
    unittest.main()
