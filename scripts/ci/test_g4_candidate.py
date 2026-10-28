"""Pure command/admission controls; no subprocesses or compiler invocation."""
from copy import deepcopy
from pathlib import Path
import hashlib
import json
import os
import tempfile
import unittest
from unittest.mock import patch
import g4_candidate
from g4_candidate import SDK, OWNED_SDK, SDK_PACKAGES, FORK_PACKAGES, PRODUCTION_LDFLAGS, commands, require_owned_sdk


class CandidateGates(unittest.TestCase):
    def local_fixture(self, root):
        directory = root / 'third_party/tailscale'
        directory.mkdir(parents=True)
        (directory / 'go.mod').write_text('module ' + SDK + '\n')
        (directory / 'LICENSE').write_text('fixture original license\n')
        (directory / 'tool.sh').write_text('#!/bin/sh\n')
        (directory / 'tool.sh').chmod(0o755)
        (directory / 'license-link').symlink_to('LICENSE')
        files = []
        for path in sorted(directory.iterdir()):
            target = os.readlink(path) if path.is_symlink() else None
            data = target.encode() if target else path.read_bytes()
            files.append({'path': path.name, 'mode': '120000' if target else
                          ('100755' if path.stat().st_mode & 0o111 else '100644'),
                          'sha256': hashlib.sha256(data).hexdigest(),
                          'symlink_target': target})
        manifest = {
            'schema': 'polaris-tailscale-runtime-source-v1',
            'module': SDK, 'directory': 'third_party/tailscale',
            'repository': 'polaris-arch/tailscale',
            'commit': '2f88101070463571831f8fdca7e0d58cbe26cb4b',
            'original_git_tree': '06fbc9361160494eb4625387ea57f35c6b2c1fc5',
            'files': files,
        }
        path = root / g4_candidate.LOCAL_MANIFEST
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(manifest))
        module = {'Path': SDK, 'Replace': {'Path': g4_candidate.LOCAL_SDK,
                                          'Dir': str(directory)}}
        return path, module

    @unittest.skipIf(os.name == 'nt', 'mode and symlink proof executes in existing Linux/macOS G4 jobs')
    def test_exact_local_source_and_rejection_controls(self):
        for mutation in ('none', 'wrong-path', 'wrong-dir', 'extra', 'missing',
                         'bytes', 'mode', 'symlink', 'manifest-layer'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                manifest, module = self.local_fixture(root)
                digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
                directory = root / 'third_party/tailscale'
                if mutation == 'wrong-path':
                    module['Replace']['Path'] = '../tailscale'
                elif mutation == 'wrong-dir':
                    module['Replace']['Dir'] = str(root)
                elif mutation == 'extra':
                    (directory / 'extra.go').write_text('package extra\n')
                elif mutation == 'missing':
                    (directory / 'tool.sh').unlink()
                elif mutation == 'bytes':
                    (directory / 'LICENSE').write_text('changed\n')
                elif mutation == 'mode':
                    (directory / 'tool.sh').chmod(0o644)
                elif mutation == 'symlink':
                    (directory / 'license-link').unlink()
                    (directory / 'license-link').symlink_to('go.mod')
                elif mutation == 'manifest-layer':
                    record = json.loads(manifest.read_text())
                    record['composition_sha256'] = 'unreviewed'
                    manifest.write_text(json.dumps(record))
                with patch.object(g4_candidate, 'LOCAL_MANIFEST_SHA256', digest):
                    if mutation == 'none':
                        self.assertEqual(require_owned_sdk(module, root), module['Replace'])
                    else:
                        with self.assertRaises(RuntimeError):
                            require_owned_sdk(module, root)

    @unittest.skipIf(os.name == 'nt', 'fixture requires symlinks')
    def test_pinned_manifest_still_requires_original_identity(self):
        for field in ('module', 'commit', 'original_git_tree'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                path, module = self.local_fixture(root)
                record = json.loads(path.read_text())
                record[field] = 'different'
                path.write_text(json.dumps(record))
                with patch.object(g4_candidate, 'LOCAL_MANIFEST_SHA256',
                                  hashlib.sha256(path.read_bytes()).hexdigest()):
                    with self.assertRaises(RuntimeError):
                        require_owned_sdk(module, root)

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
