import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import yaml

import linux_candidate_track as candidate

ROOT = Path(__file__).resolve().parents[2]


class LinuxCandidateTrackTests(unittest.TestCase):
    def fixture(self, root):
        release = json.loads((ROOT / 'release/ci/github-release.json').read_bytes())
        directory = root / 'release/ci'
        directory.mkdir(parents=True)
        (directory / 'github-release.json').write_text(json.dumps(release))
        (directory / 'linux-candidate-track.json').write_text(json.dumps(candidate.POLICY))
        return release, {'GITHUB_EVENT_NAME': 'workflow_dispatch', 'CANDIDATE_VERSION': release['version'],
                         'GITHUB_REF': 'refs/tags/' + release['tag'], 'GITHUB_SHA': 'a' * 40,
                         'GITHUB_WORKFLOW_SHA': 'a' * 40,
                         'GITHUB_WORKFLOW_REF': candidate.REPO + '/.github/workflows/linux.yml@refs/tags/' + release['tag'],
                         'EXPECTED_TAG_OBJECT': 'b' * 40}

    def test_exact_source_tag_and_policy_admit_unsigned_testing_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release, env = self.fixture(root)
            with mock.patch.object(candidate, 'verify_checkout', return_value='b' * 40) as verify:
                result = candidate.bind(root, env)
            verify.assert_called_once_with(release['tag'], 'a' * 40, 'b' * 40)
            self.assertEqual(result, {'tag_object': 'b' * 40, 'TRACK': 'testing', 'NAME': 'sing-box-polaris-testing',
                                      'PACKAGE_NAME': 'sing-box-testing', 'DOCKER_TAG': 'latest-testing'})

    def test_wrong_dispatch_version_ref_policy_and_release_identity_are_rejected(self):
        for mutation in ('event', 'workflow-source', 'workflow-path', 'version', 'ref', 'empty-object', 'track', 'policy-repository',
                         'policy-bool-id', 'policy-extra', 'release-version', 'release-tag', 'publication'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                release, env = self.fixture(root)
                policy = copy.deepcopy(candidate.POLICY)
                if mutation == 'event': env['GITHUB_EVENT_NAME'] = 'push'
                elif mutation == 'workflow-source': env['GITHUB_WORKFLOW_SHA'] = 'c' * 40
                elif mutation == 'workflow-path': env['GITHUB_WORKFLOW_REF'] = env['GITHUB_WORKFLOW_REF'].replace('/linux.yml@', '/signed-linux.yml@')
                elif mutation == 'version': env['CANDIDATE_VERSION'] = 'testing'
                elif mutation == 'ref': env['GITHUB_REF'] = 'refs/heads/fix/candidate'
                elif mutation == 'empty-object': env['EXPECTED_TAG_OBJECT'] = ''
                elif mutation == 'track': policy['track'] = 'beta'
                elif mutation == 'policy-repository': policy['repository'] = 'SagerNet/sing-box'
                elif mutation == 'policy-bool-id': policy['repositoryId'] = True
                elif mutation == 'policy-extra': policy['fallback'] = True
                elif mutation == 'release-version': release['version'] += '0'
                elif mutation == 'release-tag': release['tag'] += '0'
                else: release['publication'] = 'registry'
                (root / 'release/ci/linux-candidate-track.json').write_text(json.dumps(policy))
                (root / 'release/ci/github-release.json').write_text(json.dumps(release))
                with mock.patch.object(candidate, 'verify_checkout') as verify, self.assertRaises(ValueError):
                    candidate.bind(root, env)
                verify.assert_not_called()

    def test_immutable_source_guard_failure_does_not_write_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'env'
            output.write_text('EXISTING=keep\n')
            with mock.patch.object(candidate, 'bind', side_effect=ValueError('source tag object moved')), \
                 mock.patch.dict(candidate.os.environ, {'GITHUB_ENV': str(output)}), self.assertRaises(ValueError):
                candidate.main()
            self.assertEqual(output.read_text(), 'EXISTING=keep\n')

    def test_candidate_workflow_verifies_every_checkout_and_never_retags(self):
        text = (ROOT / '.github/workflows/linux.yml').read_text()
        workflow = yaml.safe_load(text)
        self.assertNotIn('git tag', text)
        self.assertNotIn('detect_track.sh', text)
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        for name in ('calculate_version', 'build'):
            steps = workflow['jobs'][name]['steps']
            checkout = next(s for s in steps if s.get('name') == 'Checkout')
            self.assertEqual(checkout['with'], {'ref': '${{ github.sha }}', 'fetch-depth': 0, 'persist-credentials': False})
            checks = [s for s in steps if s.get('run') == 'python3 scripts/ci/linux_candidate_track.py']
            self.assertEqual(len(checks), 1 if name == 'calculate_version' else 2)
            for step in checks:
                self.assertEqual(step['env']['CANDIDATE_VERSION'], '${{ inputs.version }}')
                self.assertEqual(step['env']['GH_TOKEN'], '${{ github.token }}')
                if name == 'build':
                    self.assertEqual(step['env']['EXPECTED_TAG_OBJECT'], '${{ needs.calculate_version.outputs.tag_object }}')
            if name == 'build':
                self.assertLess(steps.index(checks[0]), next(i for i, s in enumerate(steps) if s.get('name') == 'Setup Go'))
                self.assertLess(steps.index(checks[-1]), next(i for i, s in enumerate(steps) if s.get('name') == 'Upload artifact'))


if __name__ == '__main__':
    unittest.main()
