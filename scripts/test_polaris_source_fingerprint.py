import copy
from pathlib import Path
import unittest
import polaris_source_fingerprint as target

class ReplacementTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path('/tmp/approved-source')
        self.binding = {'module': target.MODULE, 'version': target.VERSION, 'replacementPath': target.REPLACEMENT}
        self.modules = [{'Path': 'github.com/sagernet/sing-box', 'Main': True, 'Dir': str(self.repo), 'GoMod': str(self.repo/'go.mod')},
                        {'Path': target.MODULE, 'Version': target.VERSION, 'Replace': {'Path': target.REPLACEMENT, 'Dir': str(self.repo/'third_party/sing-tun')}}]
    def test_exact_replacement(self):
        target.validate_replacements(self.modules, self.binding, self.repo)
    def test_other_replacements_rejected(self):
        values = copy.deepcopy(self.modules)
        values.append({'Path': 'other', 'Version': 'v1.0.0', 'Replace': {'Path': './other', 'Dir': '/tmp/other'}})
        with self.assertRaises(ValueError): target.validate_replacements(values, self.binding, self.repo)
    def test_missing_or_duplicate_rejected(self):
        for values in [self.modules[:1], self.modules + self.modules[1:]]:
            with self.assertRaises(ValueError): target.validate_replacements(values, self.binding, self.repo)
    def test_wrong_version_path_directory_rejected(self):
        for field, value in [('Version', 'v0.9.6'), ('Path', './other'), ('Dir', '/tmp/other')]:
            values = copy.deepcopy(self.modules)
            if field == 'Version': values[1][field] = value
            else: values[1]['Replace'][field] = value
            with self.assertRaises(ValueError): target.validate_replacements(values, self.binding, self.repo)
    def test_versioned_replacement_rejected(self):
        values = copy.deepcopy(self.modules); values[1]['Replace']['Version'] = 'v0.9.7'
        with self.assertRaises(ValueError): target.validate_replacements(values, self.binding, self.repo)
    def test_binding_identity_rejected(self):
        binding = dict(self.binding, replacementPath='./other')
        with self.assertRaises(ValueError): target.validate_replacements(self.modules, binding, self.repo)
    def test_external_workspace_main_rejected(self):
        values = copy.deepcopy(self.modules)
        values.append({'Path': 'external', 'Main': True, 'Dir': '/tmp/external', 'GoMod': '/tmp/external/go.mod'})
        with self.assertRaises(ValueError): target.validate_replacements(values, self.binding, self.repo)
    def test_wrong_main_path_directory_modfile_rejected(self):
        for field, value in [('Path', 'external'), ('Dir', '/tmp/external'), ('GoMod', '/tmp/external/go.mod')]:
            values = copy.deepcopy(self.modules); values[0][field] = value
            with self.assertRaises(ValueError): target.validate_replacements(values, self.binding, self.repo)
    def test_module_json_stream(self):
        self.assertEqual(target.json_stream(' {"Path":"a"}\n {"Path":"b"}'), [{'Path':'a'}, {'Path':'b'}])



class CheckoutBoundaryTests(unittest.TestCase):
    def test_stale_head_dirty_checkout_extra_source_and_wrong_tree_stop_before_go(self):
        from unittest.mock import patch
        cases = [
            ['different'],
            ['approved', ' M go.mod'],
            ['approved', '', 'third_party/sing-tun/ignored.go'],
            ['approved', '', '', 'wrong-tree'],
        ]
        import json, tempfile
        for outputs in cases:
            with tempfile.TemporaryDirectory() as directory:
                repo = Path(directory)
                binding = repo/'release/dependency-sources/sing-tun-replacement.json'
                binding.parent.mkdir(parents=True)
                binding.write_text(json.dumps({'replacementTree': target.EXPECTED_REPLACEMENT_TREE}))
                with patch.object(target, 'git', side_effect=outputs), patch.object(target.subprocess, 'check_output') as execute:
                    with self.assertRaises(ValueError):
                        target.collect(repo, 'approved', Path('/approved/go'), repo/'actual-module-list.json')
                    execute.assert_not_called()

    def test_wrong_go_version_cannot_refresh_module_evidence(self):
        from unittest.mock import patch
        import json, tempfile
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            binding = repo/'release/dependency-sources/sing-tun-replacement.json'
            binding.parent.mkdir(parents=True)
            binding.write_text(json.dumps({'replacementTree': target.EXPECTED_REPLACEMENT_TREE}))
            with patch.object(target, 'git', side_effect=['approved', '', '', target.EXPECTED_REPLACEMENT_TREE]), patch.object(target.subprocess, 'check_output', return_value='go1.27.1') as execute:
                with self.assertRaises(ValueError): target.collect(repo, 'approved', Path('/approved/go'), repo/'actual-module-list.json')
                self.assertEqual(execute.call_count, 1)
                self.assertFalse((repo/'actual-module-list.json').exists())

class EnvironmentTests(unittest.TestCase):
    def test_collector_and_build_share_environment_factory(self):
        import polaris_go_environment as build
        self.assertIs(target.isolated_go_environment, build.isolated_go_environment)
        hostile = {'GOENV': '/tmp/hostile.env', 'GOWORK': '/tmp/go.work', 'GOFLAGS': '-overlay=/tmp/overlay.json -modfile=/tmp/other.mod', 'GOTOOLCHAIN': 'auto', 'GOMODCACHE': '/tmp/private-cache', 'GOCACHE': '/tmp/private-build-cache', 'GOPROXY': 'off'}
        env = build.isolated_go_environment(hostile)
        for key, value in [('GOENV', 'off'), ('GOWORK', 'off'), ('GOFLAGS', ''), ('GOTOOLCHAIN', 'local')]: self.assertEqual(env[key], value)
        for key in ['GOMODCACHE', 'GOCACHE', 'GOPROXY']: self.assertEqual(env[key], hostile[key])
    def test_explicit_overlay_modfile_and_directory_flags_rejected(self):
        import polaris_go_environment as build
        for arguments in [['build', '-overlay=/tmp/fake'], ['test', '-overlay', '/tmp/fake'], ['build', '-modfile=/tmp/fake.mod'], ['list', '-modfile', '/tmp/fake.mod'], ['build', '-C', '/tmp/external']]:
            with self.assertRaises(ValueError): build.validate_go_arguments(arguments)
        build.validate_go_arguments(['test', '-mod=readonly', '-run', '^TestWindowsDNS', 'github.com/sagernet/sing-tun'])

if __name__ == '__main__': unittest.main()
