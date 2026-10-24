"""Real Git checkout controls; never normalize the bytes being validated."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import tempfile
import sys
import textwrap
import unittest
from unittest import mock

import vision_source as vision

ROOT = Path(__file__).resolve().parents[2]
EXECUTABLE = '.github/update_dependencies.sh'


def git(root, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME='Source fixture', GIT_AUTHOR_EMAIL='fixture@invalid',
               GIT_COMMITTER_NAME='Source fixture', GIT_COMMITTER_EMAIL='fixture@invalid')
    return subprocess.check_output(['git', '-C', str(root), *args], env=env, stderr=subprocess.PIPE)


def fixture(root, attributes=None):
    for name in ('go.mod', vision.BINDING, 'release/dependency-sources/sing-vmess-vision.patch',
                 'release/licenses/CURRENT44-NOTICE-CANDIDATE.txt'):
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    shutil.copytree(ROOT / 'third_party/sing-vmess', root / 'third_party/sing-vmess')
    (root / '.gitattributes').write_bytes((ROOT / '.gitattributes').read_bytes() if attributes is None else attributes)
    git(root, 'init', '-q')
    git(root, 'config', 'core.autocrlf', 'false')
    git(root, 'add', '--all')
    # Windows cannot infer this reviewed Git mode from its ordinary filesystem.
    git(root, 'update-index', '--chmod=+x', 'third_party/sing-vmess/' + EXECUTABLE)
    git(root, 'commit', '-qm', 'exact source fixture')


class VisionSourcePortability(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        fixture(self.root)
        self.module = self.root / 'third_party/sing-vmess'

    def windows(self, diagnostics=None):
        with mock.patch.object(vision, 'WINDOWS', True):
            return vision.validate(self.root, diagnostics=diagnostics)

    def test_windows_git_mode_accepts_exact_raw_bytes_with_no_executable_stat(self):
        (self.module / EXECUTABLE).chmod(0o644)
        diagnostic = {}
        actual = self.windows(diagnostic)
        self.assertEqual(actual['replacementTree'], 'c06c20c35da9997e56b5f6169143e3c0261da672')
        self.assertEqual(diagnostic['filesystemModes'][EXECUTABLE], '100644')
        self.assertEqual(diagnostic['observed'][EXECUTABLE]['mode'], '100755')
        self.assertEqual(diagnostic['git']['head'], diagnostic['git']['index'])

    @unittest.skipIf(os.name == 'nt', 'POSIX actual executable-bit semantics')
    def test_posix_still_rejects_actual_mode_change(self):
        (self.module / EXECUTABLE).chmod(0o644)
        with mock.patch.object(vision, 'WINDOWS', False), self.assertRaisesRegex(ValueError, 'complete source bytes/modes/tree'):
            vision.validate(self.root)

    def test_windows_rejects_actual_raw_byte_changes_not_only_git_objects(self):
        target = self.module / 'vless/vision.go'
        target.write_bytes(target.read_bytes() + b'\n')
        diagnostic = {}
        with self.assertRaisesRegex(ValueError, 'actual worktree bytes differ'):
            self.windows(diagnostic)
        self.assertNotEqual(diagnostic['observed']['vless/vision.go']['gitBlob'], diagnostic['git']['head']['vless/vision.go']['gitBlob'])

    def test_windows_rejects_changed_index_mode(self):
        git(self.root, 'update-index', '--chmod=-x', 'third_party/sing-vmess/' + EXECUTABLE)
        diagnostic = {}
        with self.assertRaisesRegex(ValueError, 'HEAD/index source identity differs'):
            self.windows(diagnostic)
        self.assertEqual(len(diagnostic['observed']), 36)
        self.assertEqual(len(diagnostic['filesystemStatModes']), 36)
        self.assertIsNone(diagnostic['actualTree'])
        self.assertIn('treeUnavailableReason', diagnostic)

    def test_windows_rejects_changed_index_blob(self):
        target = self.module / 'vless/vision.go'
        target.write_bytes(target.read_bytes() + b'\n')
        git(self.root, 'add', 'third_party/sing-vmess/vless/vision.go')
        with self.assertRaisesRegex(ValueError, 'HEAD/index source identity differs'):
            self.windows()

    def test_windows_rejects_same_head_index_tamper_against_frozen_manifest(self):
        git(self.root, 'update-index', '--chmod=-x', 'third_party/sing-vmess/' + EXECUTABLE)
        git(self.root, 'commit', '-qm', 'tampered executable metadata')
        with self.assertRaisesRegex(ValueError, 'complete source bytes/modes/tree'):
            self.windows()

    def test_windows_missing_and_extra_actual_paths_fail_closed(self):
        target = self.module / 'foreign.go'
        target.write_bytes(b'package vmess\n')
        with self.assertRaisesRegex(ValueError, 'actual worktree bytes differ'):
            self.windows()
        target.unlink()
        (self.module / 'vless/vision.go').unlink()
        with self.assertRaisesRegex(ValueError, 'actual worktree bytes differ'):
            self.windows()

    def test_windows_rejects_unmerged_index_stages(self):
        name = 'third_party/sing-vmess/vless/vision.go'
        blob = git(self.root, 'rev-parse', 'HEAD:' + name).decode().strip()
        git(self.root, 'update-index', '--force-remove', name)
        result = subprocess.run(['git', '-C', str(self.root), 'update-index', '--index-info'],
                                input=('100644 ' + blob + ' 1\t' + name + '\n').encode(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        diagnostic = {}
        with self.assertRaisesRegex(ValueError, 'unique regular stage zero'):
            self.windows(diagnostic)
        self.assertEqual(len(diagnostic['observed']), 36)
        self.assertEqual(diagnostic['invalidGitEntry']['path'], 'vless/vision.go')
        self.assertIn('head', diagnostic['git'])

    def test_windows_rejects_changed_head_and_index_bytes(self):
        target = self.module / 'vless/vision.go'
        target.write_bytes(target.read_bytes() + b'\n')
        git(self.root, 'add', 'third_party/sing-vmess/vless/vision.go')
        git(self.root, 'commit', '-qm', 'tampered source bytes')
        with self.assertRaisesRegex(ValueError, 'complete source bytes/modes/tree'):
            self.windows()

    def test_windows_without_git_metadata_is_rejected(self):
        (self.root / '.git').rename(self.root / 'disabled-git-metadata')
        with self.assertRaisesRegex(ValueError, 'Git source metadata unavailable'):
            self.windows()

    def test_reparse_points_are_rejected_independent_of_symlink_flag(self):
        info = mock.Mock(st_mode=0o100644, st_file_attributes=0x400)
        with mock.patch.object(Path, 'lstat', return_value=info):
            self.assertTrue(vision.redirected(self.module / 'vless/vision.go'))

    def test_crlf_checkout_preserves_all_raw_identity_inputs(self):
        git(self.root, 'config', 'core.autocrlf', 'true')
        paths = ['third_party/sing-vmess', vision.BINDING,
                 'release/dependency-sources/sing-vmess-vision.patch',
                 'release/licenses/CURRENT44-NOTICE-CANDIDATE.txt']
        shutil.rmtree(self.module)
        for name in paths[1:]:
            (self.root / name).unlink()
        git(self.root, 'checkout', 'HEAD', '--', *paths)
        self.windows()
        for name in paths[1:]:
            self.assertEqual((self.root / name).read_bytes(), (ROOT / name).read_bytes())
        attrs = git(self.root, 'check-attr', 'text', '--', 'third_party/sing-vmess/vless/vision.go', *paths[1:]).decode()
        self.assertEqual(attrs.count(': text: unset'), 4)

    def test_old_attributes_reproduce_crlf_raw_byte_failure(self):
        attrs = (self.root / '.gitattributes').read_bytes()
        attrs = attrs[:attrs.index(b'# Source-owned Vision closure')]
        (self.root / '.gitattributes').write_bytes(attrs)
        git(self.root, 'add', '.gitattributes')
        git(self.root, 'commit', '-qm', 'old checkout attributes')
        git(self.root, 'config', 'core.autocrlf', 'true')
        shutil.rmtree(self.module)
        git(self.root, 'checkout', 'HEAD', '--', 'third_party/sing-vmess')
        self.assertIn(b'\r\n', (self.module / 'vless/vision.go').read_bytes())
        with self.assertRaisesRegex(ValueError, 'actual worktree bytes differ'):
            self.windows()

    def test_failure_diagnostic_is_preserved_before_downstream_commands(self):
        source = (ROOT / 'scripts/ci/utls_gate.py').read_text()
        start = source.index('        vision_diagnostics = {}')
        end = source.index("        execute('verify-modules'", start)
        block = source[start:end]
        self.assertIn("receipt['errors'].append('vision-source: ' + str(error))", block)
        self.assertIn("finally:\n            try:\n                (output / 'vision-source.json').write_text", block)
        self.assertIn('if vision_error is None:', block)
        self.assertIn('            raise\n', block)

    def test_diagnostic_write_failure_does_not_hide_original_rejection(self):
        source = (ROOT / 'scripts/ci/utls_gate.py').read_text()
        start = source.index('        vision_diagnostics = {}')
        end = source.index("        execute('verify-modules'", start)
        block = textwrap.dedent(source[start:end])
        output = mock.MagicMock()
        output.__truediv__.return_value.write_text.side_effect = OSError('diagnostic disk full')
        receipt = {'errors': []}
        namespace = {'ROOT': self.root, 'output': output, 'receipt': receipt, 'json': json,
                     'validate_vision_source': mock.Mock(side_effect=ValueError('source sentinel mismatch'))}
        with self.assertRaisesRegex(ValueError, 'source sentinel mismatch'):
            exec(block, namespace)
        self.assertEqual(receipt['errors'], ['vision-source: source sentinel mismatch',
                                            'vision-source diagnostics: diagnostic disk full'])
        namespace['validate_vision_source'] = mock.Mock(return_value={'passed': True})
        with self.assertRaisesRegex(OSError, 'diagnostic disk full'):
            exec(block, namespace)


    def test_outer_final_evidence_failure_preserves_primary_and_attempts_both(self):
        from utls_gate import finalize_evidence
        output = mock.MagicMock()
        output.__truediv__.return_value.write_text.side_effect = OSError('disk full')
        status = mock.Mock(side_effect=OSError('cannot save status'))
        primary = ValueError('source exact identity rejected')
        with self.assertRaises(ValueError) as caught:
            try:
                raise primary
            finally:
                finalize_evidence(output, {'errors': []}, status, sys.exc_info()[1])
        self.assertIs(caught.exception, primary)
        self.assertEqual(len(primary.__notes__), 2)
        output.__truediv__.return_value.write_text.assert_called_once()
        with self.assertRaisesRegex(OSError, 'cannot save status'):
            finalize_evidence(output, {'errors': []}, status, None)



if __name__ == '__main__':
    unittest.main()
