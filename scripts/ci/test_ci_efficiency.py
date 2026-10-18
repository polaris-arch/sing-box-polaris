"""Contracts for reduced preparation without shrinking product or trust coverage."""
import json
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def workflow(name):
    return yaml.safe_load((ROOT / '.github/workflows' / (name + '.yml')).read_text())


class EfficiencyTests(unittest.TestCase):
    def test_win7_prepares_once_without_blocking_other_platforms(self):
        upstream = json.loads((ROOT / 'release/ci/upstream-matrices.json').read_text())['matrices']['build.yml']['build']['include']
        scopes = json.loads((ROOT / 'release/ci/publisher-upstream-scope.json').read_text())
        for name, role in [('build', 'all'), ('signed-release', 'signed')]:
            jobs = workflow(name)['jobs']
            self.assertEqual(jobs['build']['needs'], ['calculate_version'])
            self.assertEqual(jobs['build_windows7']['needs'], ['calculate_version', 'prepare_windows7'])
            regular = jobs['build']['strategy']['matrix']['include']
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
            self.assertEqual(jobs['build_darwin']['needs'], ['calculate_version'])
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
