"""Pure package-selection fixtures; no Go processes or compilation."""
from pathlib import Path
import tempfile
import unittest

from patch_test_packages import MODULES, selection, write_plan


class PatchModuleSelectionTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        for name, identity in MODULES.items():
            path = root / name
            path.mkdir(parents=True, exist_ok=True)
            (path / 'go.mod').write_text('module ' + identity + '\n\ngo 1.27.0\n')
        return root

    def go_file(self, root, name):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('package fixture\n')
        return name

    def test_root_and_both_nested_modules_are_partitioned_without_loss(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            paths = [self.go_file(root, p) for p in [
                'box.go', 'common/tls/client.go', 'third_party/helper/helper.go',
                'third_party/sing-tun/stack.go', 'third_party/sing-tun/ping/ping_test.go',
                'third_party/metacubex-utls/conn.go',
                'third_party/metacubex-utls/internal/tls13/handshake_test.go']]
            plan = selection(root, paths + [paths[0], 'README.md'])
            modules = plan['modules']
            self.assertEqual(set(modules), set(MODULES))
            self.assertEqual(modules['.']['packages'], ['.', './common/tls', './third_party/helper'])
            self.assertFalse(modules['.']['fullValidation'])
            accounted = []
            for name, entry in modules.items():
                self.assertEqual(entry['module'], MODULES[name])
                accounted += entry['changedPaths']
                if name != '.':
                    self.assertEqual(entry['packages'], ['./...'])
                    self.assertTrue(entry['fullValidation'])
            self.assertCountEqual(accounted, paths)
            write_plan(root / 'plan', plan)
            self.assertEqual((root / 'plan/root-packages.txt').read_text(),
                             '.\n./common/tls\n./third_party/helper\n')
            self.assertEqual((root / 'plan/metacubex-utls-selected').read_text(),
                             MODULES['third_party/metacubex-utls'] + '\n')
            self.assertTrue((root / 'plan/sing-tun-selected').is_file())
            with self.assertRaises(FileExistsError):
                write_plan(root / 'plan', plan)

    def test_module_metadata_only_and_deleted_root_package_fail_closed_to_full_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            plan = selection(root, ['go.sum', 'third_party/sing-tun/go.mod',
                                    'third_party/metacubex-utls/go.sum'])
            self.assertEqual(set(plan['modules']), set(MODULES))
            self.assertTrue(all(e['packages'] == ['./...'] for e in plan['modules'].values()))
            removed = selection(root, ['removed/package/file.go'])
            self.assertEqual(removed['modules']['.']['packages'], ['./...'])
            self.assertEqual(selection(root, ['README.md'])['modules'], {})

    def test_unknown_changed_module_or_identity_cannot_fall_into_root_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            other = root / 'test'
            other.mkdir()
            (other / 'go.mod').write_text('module test\n')
            for name in ['test/fixture.go', 'test/go.mod', 'test/go.sum']:
                with self.subTest(path=name), self.assertRaisesRegex(ValueError, 'no approved test runner'):
                    selection(root, [name])
            for owner in MODULES:
                mod = root / owner / 'go.mod'
                original = mod.read_text()
                mod.write_text('module wrong/identity\n')
                with self.subTest(owner=owner), self.assertRaisesRegex(ValueError, 'identity mismatch'):
                    selection(root, [str(Path(owner) / 'go.mod')])
                mod.write_text(original)

    def test_nested_boundary_removal_and_new_deeper_module_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            meta = root / 'third_party/metacubex-utls'
            (meta / 'go.mod').unlink()
            with self.assertRaisesRegex(ValueError, 'nested module boundary'):
                selection(root, ['third_party/metacubex-utls/conn.go'])
            deeper = root / 'third_party/sing-tun/new-module'
            deeper.mkdir()
            (deeper / 'go.mod').write_text('module another/module\n')
            with self.assertRaisesRegex(ValueError, 'no approved test runner'):
                selection(root, ['third_party/sing-tun/new-module/test.go'])
            with self.assertRaisesRegex(ValueError, 'unaccounted module input boundary'):
                selection(root, ['removed/go.mod'])

    def test_unsafe_paths_and_symlinked_module_boundaries_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            for name in ['../bad.go', '/bad.go', 'a//bad.go', 'a/../bad.go',
                         'line\nbad.go', 'a\\bad.go']:
                with self.subTest(path=name), self.assertRaises(ValueError):
                    selection(root, [name])
            (root / 'alias').symlink_to(root / 'third_party/sing-tun', target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'symlink'):
                selection(root, ['alias/test.go'])


if __name__ == '__main__':
    unittest.main()
