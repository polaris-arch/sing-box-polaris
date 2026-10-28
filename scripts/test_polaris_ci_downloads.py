import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import polaris_ci_downloads as inputs


class Response(io.BytesIO):
    def geturl(self):
        return 'https://dl.google.com/android/repository/fixed.zip'


class AcquisitionTests(unittest.TestCase):
    def test_cold_and_warm_still_verify_exact_bytes(self):
        raw = b'fixed compressed input'; sha = hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'ndk.zip'
            with patch.object(inputs.urllib.request, 'urlopen', return_value=Response(raw)) as fetch:
                seen = inputs.acquire_ndk('https://dl.google.com/android/repository/fixed.zip', sha, target)
                self.assertEqual(seen['sha256'], sha); fetch.assert_called_once()
            with patch.object(inputs.urllib.request, 'urlopen', side_effect=AssertionError('warm must not download')):
                self.assertEqual(inputs.acquire_ndk('https://dl.google.com/android/repository/fixed.zip', sha, target), seen)
                target.write_bytes(b'changed input')
                with self.assertRaises(ValueError): inputs.acquire_ndk('https://dl.google.com/android/repository/fixed.zip', sha, target)
            self.assertEqual(target.read_bytes(), b'changed input')

    def test_bad_cold_partial_is_not_promoted_or_lost(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'ndk.zip'
            with patch.object(inputs.urllib.request, 'urlopen', return_value=Response(b'bad')):
                with self.assertRaises(ValueError): inputs.acquire_ndk('https://dl.google.com/android/repository/fixed.zip', 'a' * 64, path)
            self.assertFalse(path.exists()); self.assertEqual(path.with_suffix('.zip.partial').read_bytes(), b'bad')
            with self.assertRaises(ValueError): inputs.acquire_ndk('https://dl.google.com/android/repository/fixed.zip', 'a' * 64, path)

    def test_missing_is_cold_not_success_and_corruption_blocks_consumer(self):
        raw = b'pin'; sha = hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); file = root / 'archive.zip'; rows = {'tool': {'path': str(file), 'sha256': sha, 'limitBytes': 100}}
            seen = inputs.inspect_inputs(rows, root / 'cold.json'); self.assertFalse(seen['inputs']['tool'].get('valid', False))
            file.write_bytes(raw); self.assertTrue(inputs.inspect_inputs(rows, root / 'warm.json')['inputs']['tool']['valid'])
            file.write_bytes(b'bad')
            with self.assertRaises(ValueError): inputs.inspect_inputs(rows, root / 'bad.json')
            self.assertFalse(json.loads((root / 'bad.json').read_text())['valid'])
            inputs.preserve_bad_inputs(rows, root / 'failure')
            self.assertEqual((root / 'failure/archive.zip').read_bytes(), b'bad')
            file.write_bytes(raw); inputs.preserve_bad_inputs(rows, root / 'valid-not-copied')
            self.assertFalse((root / 'valid-not-copied/archive.zip').exists())

    def test_limits_symlinks_and_url_scope_are_not_bypassed_by_key(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); raw = root / 'raw'; raw.write_bytes(b'1234'); sha = hashlib.sha256(raw.read_bytes()).hexdigest()
            with self.assertRaises(ValueError): inputs.archive_pin(raw, sha, 3)
            link = root / 'link'
            try: link.symlink_to(raw)
            except OSError: pass
            else:
                with self.assertRaises(ValueError): inputs.archive_pin(link, sha, 10)
            for url in ('https://example.invalid/tool.zip', 'https://dl.google.com/android/repository/fixed.zip?token=x',
                        'http://dl.google.com/android/repository/fixed.zip'):
                with self.assertRaises(ValueError): inputs.acquire_ndk(url, sha, root / 'ndk.zip')

    def test_ancestor_symlink_rejection_preserves_metadata_without_target_read(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);outside=root/'outside';outside.mkdir();(outside/'archive.zip').write_bytes(b'external secret')
            link=root/'cache'
            try:link.symlink_to(outside,target_is_directory=True)
            except OSError as error:self.skipTest('host cannot create symlink: '+str(error))
            rows={'tool':{'path':str(link/'archive.zip'),'sha256':'a'*64,'limitBytes':100}}
            with patch.object(inputs,'archive_pin',side_effect=AssertionError('external target must not be read')):
                with self.assertRaises(ValueError):inputs.inspect_inputs(rows,root/'check.json')
                inputs.preserve_bad_inputs(rows,root/'preserved')
            self.assertFalse((root/'preserved/archive.zip').exists())
            kept=json.loads((root/'preserved/bad-input-retention.json').read_text())
            self.assertTrue(kept);self.assertTrue(all(row['retained'] is False for row in kept))
            self.assertTrue(all('unsafe' in row['reason'] for row in kept))
            self.assertEqual((outside/'archive.zip').read_bytes(),b'external secret')

    def test_openwrt_content_shared_not_compiled_or_receipt_cache(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as folder:
            a = inputs.openwrt_inputs(repo, Path(folder), 'x86_64')
            b = inputs.openwrt_inputs(repo, Path(folder), 'aarch64_generic')
            self.assertEqual(a['apk'], b['apk']); self.assertEqual(a['clang'], b['clang'])
            self.assertNotEqual(a['sdk']['sha256'], b['sdk']['sha256'])
            self.assertEqual(len({r['sha256'] for r in [*a.values(), *b.values()]}), 4)
            with self.assertRaises(ValueError): inputs.openwrt_inputs(repo, Path(folder), 'armv7')
            with self.assertRaises(ValueError): inputs.openwrt_inputs(repo, Path(folder + '\nwrong'), 'x86_64')



    def test_output_paths_cannot_escape_via_source_archive_filename(self):
        repo = Path(__file__).resolve().parents[1]
        value = json.loads((repo / 'release/polaris-openwrt-inputs.json').read_text())
        with tempfile.TemporaryDirectory() as folder:
            fake = Path(folder); (fake / 'release').mkdir()
            for name in ('.', '..', '../outside.tar.zst', 'nested/archive.tar.zst', 'bad\nname.tar.zst'):
                altered = json.loads(json.dumps(value)); altered['sdkInputs'][0]['file'] = name
                (fake / 'release/polaris-openwrt-inputs.json').write_text(json.dumps(altered))
                with self.assertRaises(ValueError): inputs.openwrt_inputs(fake, fake / 'cache', 'x86_64')

if __name__ == '__main__':
    unittest.main()
