"""Pure package-selection fixtures; no Go processes or compilation."""
from pathlib import Path
import tempfile
import unittest
import subprocess

from g4_candidate import SDK, SDK_PACKAGES
from patch_test_packages import MARKERS, MODULES, selection, write_plan, changed_paths


class PatchModuleSelectionTests(unittest.TestCase):
    def test_divergent_history_is_rejected_until_the_baseline_is_merged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def git(*args):
                return subprocess.check_output(['git', '-c', 'user.name=Fixture', '-c',
                                                'user.email=fixture@example.invalid', *args], cwd=root, text=True).strip()
            git('init', '-q')
            (root / 'base.go').write_text('package fixture\n')
            git('add', '.'); git('commit', '-qm', 'common')
            common = git('rev-parse', 'HEAD')
            (root / 'official.go').write_text('package fixture\n')
            git('add', '.'); git('commit', '-qm', 'official')
            official = git('rev-parse', 'HEAD')
            git('checkout', '-q', '--detach', common)
            (root / 'changed.go').write_text('package fixture\n')
            git('add', '.'); git('commit', '-qm', 'rewritten')
            head = git('rev-parse', 'HEAD')
            with self.assertRaises(subprocess.CalledProcessError) as failure:
                changed_paths(root, official, head)
            self.assertEqual(failure.exception.returncode, 1)
            self.assertEqual(failure.exception.cmd,
                             ['git', 'merge-base', '--is-ancestor', official, head])
            self.assertEqual(changed_paths(root, common, head), (['changed.go'], common))
            git('merge', '--no-ff', '--no-edit', official)
            merged = git('rev-parse', 'HEAD')
            self.assertEqual(changed_paths(root, official, merged), (['changed.go'], official))

    def test_go_nat_selection_keeps_the_product_graph(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(tmp)
            path = self.go_file(fixture, 'third_party/go-nat/mapping_test.go')
            plan = selection(fixture, [path, path, 'third_party/go-nat/go.mod'])
            self.assertEqual(plan['modules'], {'third_party/go-nat': {
                'module': 'github.com/libp2p/go-nat',
                'changedPaths': ['third_party/go-nat/go.mod', path],
                'packages': ['./...'], 'fullValidation': True}})
            write_plan(fixture / 'plan', plan)
            self.assertEqual((fixture / 'plan/go-nat-selected').read_text(),
                             'github.com/libp2p/go-nat\n')
            self.assertEqual((fixture / 'plan/root-packages.txt').read_text(), '')
            deeper = fixture / 'third_party/go-nat/unapproved'
            deeper.mkdir()
            (deeper / 'go.mod').write_text('module unapproved/nested\n')
            with self.assertRaisesRegex(ValueError, 'no approved test runner'):
                selection(fixture, ['third_party/go-nat/unapproved/nat.go'])

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

    def test_root_and_all_nested_modules_are_partitioned_without_loss(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            paths = [self.go_file(root, p) for p in [
                'box.go', 'common/tls/client.go', 'third_party/helper/helper.go',
                'third_party/sing-tun/stack.go', 'third_party/sing-tun/ping/ping_test.go',
                'third_party/metacubex-utls/conn.go',
                'third_party/metacubex-utls/internal/tls13/handshake_test.go',
                'third_party/cronet-go/naive_client_lifecycle_test.go',
                'third_party/fswatch/start_cleanup_test.go',
                'third_party/sing/common/udpnat/runtime_context_test.go',
                'third_party/sing-quic/runtime_test.go',
                'third_party/go-nat/mapping_test.go',
                'third_party/tailscale/net/netmon/runtime_hooks_test.go',
                'third_party/wireguard-go/device/runtime_completion_test.go',
                'third_party/tfo-go/runtime_join_test.go', 'third_party/sing-vmess/vless/vision.go']]
            plan = selection(root, paths + [paths[0], 'README.md'])
            modules = plan['modules']
            self.assertEqual(set(modules), set(MODULES))
            self.assertEqual(modules['.']['packages'], ['.', './common/tls', './third_party/helper'])
            self.assertFalse(modules['.']['fullValidation'])
            accounted = []
            for name, entry in modules.items():
                self.assertEqual(entry['module'], MODULES[name])
                accounted += entry['changedPaths']
                if name == 'third_party/tailscale':
                    self.assertEqual(entry['packages'], [SDK + '/' + p for p in SDK_PACKAGES])
                    self.assertFalse(entry['fullValidation'])
                elif name != '.':
                    self.assertEqual(entry['packages'], ['./...'])
                    self.assertTrue(entry['fullValidation'])
            self.assertCountEqual(accounted, paths)
            write_plan(root / 'plan', plan)
            self.assertEqual((root / 'plan/root-packages.txt').read_text(),
                             '.\n./common/tls\n./third_party/helper\n')
            for owner, marker in MARKERS.items():
                self.assertEqual((root / 'plan' / marker).read_text(), MODULES[owner] + '\n')
            self.assertEqual((root / 'plan/tailscale-packages.txt').read_text(),
                             ''.join(SDK + '/' + p + '\n' for p in SDK_PACKAGES))
            with self.assertRaises(FileExistsError):
                write_plan(root / 'plan', plan)

    def test_module_metadata_only_and_deleted_root_package_fail_closed_to_full_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            plan = selection(root, ['go.sum', 'third_party/sing-tun/go.mod',
                                    'third_party/metacubex-utls/go.sum', 'third_party/cronet-go/go.mod',
                                    'third_party/fswatch/go.mod', 'third_party/sing/go.mod',
                                    'third_party/sing-quic/go.mod', 'third_party/go-nat/go.mod',
                                    'third_party/tailscale/go.mod',
                                    'third_party/wireguard-go/go.sum', 'third_party/tfo-go/go.mod',
                                    'third_party/sing-vmess/go.mod'])
            self.assertEqual(set(plan['modules']), set(MODULES))
            for owner, entry in plan['modules'].items():
                if owner == 'third_party/tailscale':
                    self.assertEqual(entry['packages'], [SDK + '/' + p for p in SDK_PACKAGES])
                    self.assertFalse(entry['fullValidation'])
                else:
                    self.assertEqual(entry['packages'], ['./...'])
                    self.assertTrue(entry['fullValidation'])
            removed = selection(root, ['removed/package/file.go'])
            self.assertEqual(removed['modules']['.']['packages'], ['./...'])
            self.assertEqual(selection(root, ['README.md'])['modules'], {})

    def test_runtime_schema_selects_daemon_without_generated_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            self.go_file(root, 'daemon/runtime_config_test.go')
            path = 'daemon/runtime_config.proto'
            (root / path).write_text('syntax = "proto3";\n')
            for removed in (False, True):
                if removed:
                    (root / path).unlink()
                with self.subTest(removed=removed):
                    plan = selection(root, [path, 'daemon/unrelated.proto'])
                    self.assertEqual(plan['modules'], {
                        '.': {'module': MODULES['.'], 'changedPaths': [path],
                              'packages': ['./daemon'], 'fullValidation': False}})
            with self.assertRaisesRegex(ValueError, 'invalid changed Go/input path'):
                selection(root, ['daemon//runtime_config.proto'])
            (root / 'daemon/go.mod').write_text('module unapproved/daemon\n')
            with self.assertRaisesRegex(ValueError, 'no approved test runner'):
                selection(root, [path])

    def test_removed_schema_package_falls_back_to_root_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            plan = selection(root, ['daemon/runtime_config.proto'])
            self.assertEqual(plan['modules']['.']['packages'], ['./...'])
            self.assertTrue(plan['modules']['.']['fullValidation'])

    def test_tailscale_marker_uses_only_shared_bounded_g4_packages(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            plan = selection(root, ['third_party/tailscale/go.sum'])
            write_plan(root / 'plan', plan)
            self.assertEqual(set(plan['modules']), {'third_party/tailscale'})
            packages = (root / 'plan/tailscale-packages.txt').read_text().splitlines()
            self.assertEqual(packages, [SDK + '/' + p for p in SDK_PACKAGES])
            self.assertTrue(packages)
            self.assertFalse(any('...' in package for package in packages))
            for package in ('net/netmon', 'wgengine/magicsock', 'wgengine'):
                self.assertIn(SDK + '/' + package, packages)
            self.assertEqual((root / 'plan/root-packages.txt').read_text(), '')
            for owner, marker in MARKERS.items():
                self.assertEqual((root / 'plan' / marker).exists(), owner == 'third_party/tailscale')

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

    def test_release_module_admits_only_license_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            name = self.go_file(root, 'release/licenses/module/license_test.go')
            marker = root / 'release/go.mod'
            marker.write_text((Path(__file__).resolve().parents[2] / 'release/go.mod').read_text())
            self.assertEqual(selection(root, ['release/go.mod', name])['modules'], {})
            with self.assertRaisesRegex(ValueError, 'unaccounted release module path'):
                selection(root, [self.go_file(root, 'release/tool/main.go')])
            marker.write_text('module release\n')
            with self.assertRaisesRegex(ValueError, 'unaccounted release module path'):
                selection(root, [name])

    def test_nested_boundary_removal_and_new_deeper_module_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp)
            for owner in MARKERS:
                marker = root / owner / 'go.mod'
                original = marker.read_text()
                marker.unlink()
                with self.subTest(owner=owner), self.assertRaisesRegex(ValueError, 'nested module boundary'):
                    selection(root, [owner + '/fixture.go'])
                marker.write_text(original)
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

