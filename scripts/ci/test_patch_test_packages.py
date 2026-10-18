"""Pure package-selection fixtures; no Go processes or compilation."""
from pathlib import Path
import tempfile
import unittest
import subprocess

from patch_test_packages import MODULES, selection, write_plan, changed_paths


class PatchModuleSelectionTests(unittest.TestCase):
    def test_divergent_rewritten_history_still_selects_every_snapshot_change(self):
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
            paths, ancestor = changed_paths(root, official, head)
            self.assertEqual(ancestor, common)
            self.assertCountEqual(paths, ['official.go', 'changed.go'])
            self.assertEqual(changed_paths(root, common, head), (['changed.go'], common))

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


class ReadOnlyEvidenceBoundaryTests(unittest.TestCase):
    def fixture(self, root):
        import hashlib
        import json
        from patch_test_packages import EVIDENCE_ROOT, EVIDENCE_MODULE, EVIDENCE_MANIFEST
        (root / 'go.mod').write_text('module ' + MODULES['.'] + '\n\ngo 1.27.0\n')
        directory = root / EVIDENCE_ROOT
        directory.mkdir(parents=True)
        (directory / 'go.mod').write_text('module ' + EVIDENCE_MODULE + '\n\ngo 1.27.0\n')
        data = b'package evidence\n'
        (directory / 'snapshot.go').write_bytes(data)
        manifest = {'schema': 'polaris-sing-usbip-source-tar-materials-v1',
                    'baseDirectory': 'release/dependency-sources', 'files': [{
                        'path': 'sing-usbip/sing-box-source-evidence/snapshot.go',
                        'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}]}
        (root / EVIDENCE_MANIFEST).write_text(json.dumps(manifest))
        return directory

    def test_verified_archive_is_reported_separately_and_live_packages_remain_selected(self):
        from patch_test_packages import EVIDENCE_ROOT
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            live = ['service/usbip/client.go', 'cmd/internal/build_boxdd/main.go',
                    'release/dependency-sources/live/helper.go']
            for name in live:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('package live\n')
            evidence = [EVIDENCE_ROOT + '/go.mod', EVIDENCE_ROOT + '/snapshot.go']
            plan = selection(root, live + evidence)
            self.assertEqual(plan['modules']['.']['packages'],
                             ['./cmd/internal/build_boxdd', './release/dependency-sources/live', './service/usbip'])
            self.assertCountEqual(plan['readOnlyEvidence'][EVIDENCE_ROOT]['changedPaths'], evidence)
            self.assertEqual(plan['readOnlyEvidence'][EVIDENCE_ROOT]['verifiedFiles'], 1)

    def test_archive_changes_missing_boundary_and_directives_fail_closed(self):
        from patch_test_packages import EVIDENCE_ROOT
        for mutation in ['bytes', 'extra', 'missing', 'identity', 'replace', 'symlink']:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                directory = self.fixture(root)
                if mutation == 'bytes':
                    (directory / 'snapshot.go').write_text('package changed\n')
                elif mutation == 'extra':
                    (directory / 'new.go').write_text('package hidden\n')
                elif mutation == 'missing':
                    (directory / 'go.mod').unlink()
                elif mutation == 'identity':
                    (directory / 'go.mod').write_text('module wrong/module\n')
                elif mutation == 'replace':
                    with (directory / 'go.mod').open('a') as out:
                        out.write('replace example.org/live => ../../../../..\n')
                else:
                    (directory / 'hidden').symlink_to(root, target_is_directory=True)
                with self.assertRaises(ValueError):
                    selection(root, [EVIDENCE_ROOT + '/snapshot.go'])

    def test_real_archived_files_match_historical_manifest(self):
        from patch_test_packages import EVIDENCE_MODULES, verify_read_only_evidence
        root = Path(__file__).resolve().parents[2]
        for owner in EVIDENCE_MODULES:
            result = verify_read_only_evidence(root, owner)
            self.assertGreater(result['verifiedFiles'], 0)


if __name__ == '__main__':
    unittest.main()
