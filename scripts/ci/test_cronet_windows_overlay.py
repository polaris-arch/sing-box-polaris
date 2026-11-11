"""Source-data controls in the existing ordinary CI/Source discovery gate."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import cronet_windows_overlay as overlay

ROOT = Path(__file__).resolve().parents[2]


class CronetWindowsOverlayTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        for name in (overlay.MANIFEST, overlay.PATCH, *overlay.HISTORICAL):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)
        shutil.copytree(ROOT / overlay.VENDOR, root / overlay.VENDOR)
        return root

    def mutate(self, root, change):
        manifest = json.loads((root / overlay.MANIFEST).read_bytes())
        change(manifest)
        (root / overlay.MANIFEST).write_text(json.dumps(manifest))

    def test_all_overlay_source_inputs_preserve_raw_blob_bytes_on_windows_checkout(self):
        attributes = (ROOT / '.gitattributes').read_text().splitlines()
        for pattern in (overlay.VENDOR + '/**', overlay.MANIFEST, overlay.PATCH, *overlay.HISTORICAL):
            self.assertEqual(attributes.count('/' + pattern + ' -text'), 1)

    def test_cold_source_without_git_validates_complete_read_closure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            self.assertFalse((root / '.git').exists())
            inputs = overlay.validate_overlay(root)
            self.assertEqual(len(inputs), 141)
            self.assertEqual(inputs, overlay.validate_overlay(ROOT))
            self.assertEqual(sum(name.startswith(overlay.VENDOR + '/') for name in inputs), 137)
            self.assertEqual(inputs[overlay.PATCH], '8f386f58494d1f75cccb5646645fa1ca784f84a359b93f721a378f079f7a49fb')
            self.assertEqual(set(inputs) - {p for p in inputs if p.startswith(overlay.VENDOR + '/')},
                             {overlay.MANIFEST, overlay.PATCH, *overlay.HISTORICAL})

    def test_closed_version_shape_base_counts_and_paths_fail(self):
        mutations = [lambda m: m.update(schema='future'), lambda m: m.update(extra=True),
                     lambda m: m.update(nativeBinaryValidated=True), lambda m: m.update(patchContextLines=False),
                     lambda m: m.update(baseTree='f' * 40), lambda m: m.update(replacementPath='../elsewhere'),
                     lambda m: m['baseFiles'].pop(), lambda m: m['changes'].pop(),
                     lambda m: m['baseFiles'].__setitem__(0, m['baseFiles'][1]),
                     lambda m: m['changes'].__setitem__(0, m['changes'][1]),
                     lambda m: m['changes'][0]['after'].update(path='../escape'),
                     lambda m: m['changes'][0].update(operation='add'),
                     lambda m: m['baseFiles'][0].update(bytes=True),
                     lambda m: m['baseFiles'][0].update(mode='120000'),
                     lambda m: m['changes'][0]['before'].update(extra='unknown'),
                     lambda m: m.update(unchangedGitlinks=[{'path':'foreign','gitObject':'f'*40}])]
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            original = (root / overlay.MANIFEST).read_bytes()
            for mutate in mutations:
                with self.subTest(mutation=mutate):
                    (root / overlay.MANIFEST).write_bytes(original)
                    self.mutate(root, mutate)
                    self.assertRaises(ValueError, overlay.validate_overlay, root)

    def test_duplicate_json_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            path = root / overlay.MANIFEST
            raw = path.read_text()
            path.write_text(raw.replace('"schema":', '"schema":"ignored", "schema":', 1))
            self.assertRaisesRegex(ValueError, 'duplicate JSON', overlay.validate_overlay, root)

    def test_missing_extra_changed_and_symlink_vendor_objects_fail(self):
        for mutation in ('missing', 'extra', 'empty-directory', 'bytes', 'symlink-file', 'symlink-directory'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = self.fixture(directory)
                victim = root / overlay.VENDOR / 'loader_observation_types.go'
                if mutation == 'missing': victim.unlink()
                elif mutation == 'extra': (victim.parent / 'extra.go').write_bytes(b'extra')
                elif mutation == 'empty-directory': (victim.parent / 'extra-directory').mkdir()
                elif mutation == 'bytes': victim.write_bytes(victim.read_bytes() + b'tamper')
                else:
                    if mutation == 'symlink-file':
                        victim.unlink(); target = ROOT / overlay.VENDOR / victim.name
                    else:
                        victim = victim.parent / 'extra-directory'; target = ROOT / overlay.VENDOR
                    try: victim.symlink_to(target, target_is_directory=mutation == 'symlink-directory')
                    except (OSError, NotImplementedError): self.skipTest('symlink creation unavailable')
                self.assertRaises(ValueError, overlay.validate_overlay, root)

    def test_merkle_tree_proof_tampering_or_extra_fields_fail(self):
        for mutation in (lambda m: m['baseTreeProof'][0].update(rawBase64='AA=='),
                         lambda m: m['baseTreeProof'][1].update(gitTree='f'*40),
                         lambda m: m['baseTreeProof'][0].update(path='wrong'),
                         lambda m: m['baseTreeProof'][0].update(extra=1),
                         lambda m: m['baseFiles'][0].update(gitBlob='f'*40)):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = self.fixture(directory); self.mutate(root, mutation)
                self.assertRaises(ValueError, overlay.validate_overlay, root)

    def test_historical_materials_remain_exact_original_bytes(self):
        for name in overlay.HISTORICAL:
            with self.subTest(path=name), tempfile.TemporaryDirectory() as directory:
                root = self.fixture(directory); path = root / name
                path.write_bytes(path.read_bytes() + b'tamper')
                self.assertRaisesRegex(ValueError, 'historical', overlay.validate_overlay, root)

    def test_patch_digest_duplicate_missing_path_and_cold_inverse_tamper_fail(self):
        import hashlib
        for mutation in ('hash', 'duplicate', 'missing', 'coordinates', 'body', 'after-identity'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = self.fixture(directory); path = root / overlay.PATCH; raw = path.read_bytes()
                if mutation == 'hash': path.write_bytes(raw + b'bad')
                else:
                    if mutation == 'duplicate': raw += raw
                    elif mutation == 'missing': raw = raw[:raw.rfind(b'--- /dev/null')]
                    elif mutation == 'coordinates': raw = raw.replace(b'@@ -1,2 +0,0 @@', b'@@ -2,2 +0,0 @@', 1)
                    elif mutation == 'body': raw = raw.replace(b'-//go:build with_purego', b'-//go:build with_bogusx', 1)
                    else:
                        self.mutate(root, lambda m: m['changes'][0]['after'].update(sha256='f'*64))
                    path.write_bytes(raw)
                    self.mutate(root, lambda m: m.update(patchSHA256=hashlib.sha256(raw).hexdigest()))
                self.assertRaises(ValueError, overlay.validate_overlay, root)

    def test_current_modes_and_all_bound_identity_fields_are_checked(self):
        for field, value in [('bytes', 0), ('sha256', 'f'*64), ('gitBlob', 'f'*40), ('mode', '100755')]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = self.fixture(directory)
                self.mutate(root, lambda m: m['changes'][0]['after'].update({field: value}))
                self.assertRaises(ValueError, overlay.validate_overlay, root)

    def test_oversized_data_and_missing_material_fail_before_unbounded_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            (root / overlay.PATCH).unlink()
            self.assertRaises(ValueError, overlay.validate_overlay, root)
            path = root / overlay.MANIFEST
            with path.open('wb') as stream: stream.truncate(overlay.MAX_FILE_BYTES + 1)
            self.assertRaisesRegex(ValueError, 'oversized', overlay.validate_overlay, root)

    def test_exact_current_bytes_are_reconstructed_without_external_patch(self):
        # A changed preimage with a refreshed patch SHA still cannot replace the
        # Merkle-bound P2 base; no external patch, Git or network is involved.
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            self.mutate(root, lambda m: m['changes'][0]['before'].update(sha256='f'*64))
            self.assertRaises(ValueError, overlay.validate_overlay, root)


if __name__ == '__main__':
    unittest.main()
