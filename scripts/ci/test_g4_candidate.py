"""Pure command/admission controls; no subprocesses or compiler invocation."""
from copy import deepcopy
from pathlib import Path
import unittest
from g4_candidate import SDK, OWNED_SDK, SDK_PACKAGES, FORK_PACKAGES, PRODUCTION_LDFLAGS, commands, require_owned_sdk


class CandidateGates(unittest.TestCase):
    def test_dependency_tests_are_explicit_and_raced(self):
        sdk, fork = commands()
        self.assertEqual(sdk[-len(SDK_PACKAGES):], [SDK + '/' + p for p in SDK_PACKAGES])
        self.assertEqual(fork[-len(FORK_PACKAGES):], list(FORK_PACKAGES))
        for command in (sdk, fork):
            self.assertIn('-race', command)
            self.assertIn('-count=1', command)
        self.assertIn('-tags=with_tailscale', fork)
        self.assertIn('-ldflags=' + PRODUCTION_LDFLAGS, fork)
        self.assertEqual(PRODUCTION_LDFLAGS, (Path(__file__).resolve().parents[2] / 'release/LDFLAGS').read_text().strip())

    def test_only_immutable_owned_sdk_is_admitted(self):
        module = {'Path': SDK, 'Replace': {'Path': OWNED_SDK, 'Version': 'fixture-version', 'Sum': 'h1:fixture'}}
        self.assertEqual(require_owned_sdk(module), module['Replace'])
        for field, value in [('Path', SDK), ('Path', './third_party/tailscale'), ('Version', ''), ('Sum', '')]:
            bad = deepcopy(module)
            bad['Replace'][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(RuntimeError):
                require_owned_sdk(bad)
        with self.assertRaises(RuntimeError):
            require_owned_sdk({'Path': SDK})

    def test_branding_packages_share_the_source_gate(self):
        required = {'./common/badversion', './cmd/internal/read_tag',
                    './cmd/internal/update_android_version', './cmd/internal/update_desktop_version',
                    './cmd/internal/update_apple_version'}
        self.assertTrue(required.issubset(set(FORK_PACKAGES)))
        self.assertEqual(len(FORK_PACKAGES), len(set(FORK_PACKAGES)))

    def test_option_single_value_regressions_share_the_source_gate(self):
        self.assertEqual(FORK_PACKAGES.count('./option'), 1)
        self.assertIn('./option', commands()[1])
        root = Path(__file__).resolve().parents[2]
        workflow = (root / '.github/workflows/build.yml').read_text()
        self.assertIn('python3 scripts/ci/g4_candidate.py', workflow)
        tests = (root / 'option/listable_compat_test.go').read_text()
        for name in ['TestTailcatDERPServersListableJSON', 'TestMASQUEAdvertiseRoutesListableJSON']:
            self.assertIn('func ' + name + '(t *testing.T)', tests)
