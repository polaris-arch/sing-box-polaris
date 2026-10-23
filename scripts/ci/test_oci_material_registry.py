import copy
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest import mock

import github_release as g
import oci_material_registry as r
import oci_material_supplement as old

ROOT = Path(__file__).resolve().parents[2]
SELECTOR = json.loads((ROOT / r.DIRECTORY / 'selection-manifest.json').read_text())
API = [{'id': row['artifactId'], 'name': name, 'size_in_bytes': row['archiveBytes'],
        'digest': row['artifactAPIDigest'], 'expired': False,
        'workflow_run': {'id': r.RUN_ID, 'head_sha': r.SOURCE, 'repository_id': old.REPOSITORY_ID,
                         'head_repository_id': old.REPOSITORY_ID}} for name, row in SELECTOR['artifacts'].items()]


def load(**changes):
    args = dict(source=r.SOURCE, tree=r.TREE, tag=r.TAG, tag_object=r.TAG_OBJECT, run_id=r.RUN_ID,
                attempt=1, workflow=old.WORKFLOW, artifacts=copy.deepcopy(API), source_root=ROOT, publisher_root=ROOT)
    args.update(changes)
    return r.load_for_run(**args)


class RegistryTests(unittest.TestCase):
    def test_exact_selection_and_materials_stay_separate(self):
        p = load()
        self.assertEqual(p['binding']['sourceCommit'], r.SOURCE)
        self.assertEqual(p['reference_path'], ROOT / r.DIRECTORY / 'reuse-reference.json')
        self.assertEqual(p['selector']['sharedMaterials']['sourceCommit'], old.SOURCE)
        self.assertEqual(p['bundle_tar_bytes'], 7454720)
        self.assertEqual(p['bundle_maximum_bytes'], 8503104)
        self.assertTrue(r.supports_source(r.SOURCE))
        self.assertTrue(r.supports_source(old.SOURCE))
        self.assertFalse(r.supports_source('0' * 40))

    def test_exact_tuple(self):
        for key, value in [('source', '0' * 40), ('tree', '0' * 40), ('tag', old.TAG),
                           ('tag_object', old.TAG_OBJECT), ('run_id', old.RUN_ID), ('run_id', str(r.RUN_ID)),
                           ('attempt', True), ('attempt', 2), ('workflow', '.github/workflows/build.yml')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                load(**{key: value})

    def test_api_negative_matrix(self):
        variants = [API[:-1], API + API[:1], API[:-1] + API[:1]]
        for field, value in [('id', True), ('id', API[1]['id']), ('name', 'foreign'),
                             ('size_in_bytes', 0), ('digest', 'sha256:' + '0' * 64), ('expired', True), ('expired', None)]:
            rows = copy.deepcopy(API)
            rows[0][field] = value
            variants.append(rows)
        for field, value in [('id', old.RUN_ID), ('head_sha', old.SOURCE), ('repository_id', 1), ('head_repository_id', 1)]:
            rows = copy.deepcopy(API)
            rows[0]['workflow_run'][field] = value
            variants.append(rows)
        for rows in variants:
            with self.subTest(rows=rows[0]['id']), self.assertRaises(ValueError):
                load(artifacts=rows)

    def test_current_and_shared_files_fail_closed(self):
        for target in ('current', 'extra', 'symlink', 'shared'):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                shutil.copytree(ROOT / r.DIRECTORY, root / r.DIRECTORY)
                shutil.copytree(ROOT / old.DIRECTORY, root / old.DIRECTORY)
                current = root / r.DIRECTORY / 'selection-manifest.json'
                if target == 'current':
                    current.write_bytes(current.read_bytes() + b' ')
                elif target == 'extra':
                    (current.parent / 'extra').mkdir()
                elif target == 'symlink':
                    current.unlink()
                    current.symlink_to(ROOT / r.DIRECTORY / 'selection-manifest.json')
                else:
                    p = root / old.DIRECTORY / 'reuse-reference.json'
                    p.write_bytes(p.read_bytes() + b' ')
                with self.subTest(target=target), self.assertRaises(ValueError):
                    load(publisher_root=root)

    def test_policy_cannot_redirect_or_increase_budget(self):
        p = load()
        for key, value in [('reference_path', Path('/tmp/other')), ('material_map_path', Path('/tmp/other')),
                           ('bundle_maximum_bytes', 99999999), ('selector_sha256', '0' * 64),
                           ('artifacts', {}), ('binding', {}), ('_unreviewed', True)]:
            q = copy.deepcopy(p)
            q[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.bundle_name(q)

    def test_exact_image_hash_is_required_before_parser(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / 'image.tar'
            image.write_bytes(b'not an image')
            with self.assertRaises(ValueError):
                r.check_image(load(), API[0]['name'], image)

    def test_bundle_deterministic_exact_73_and_receipt(self):
        p = load()
        with tempfile.TemporaryDirectory() as tmp:
            paths = [Path(tmp) / name for name in ('a.tar.gz', 'b.tar.gz')]
            a = r.write_bundle(p, paths[0])
            b = r.write_bundle(p, paths[1])
            self.assertEqual((a['bytes'], a['sha256']), (b['bytes'], b['sha256']))
            with tarfile.open(paths[1]) as archive:
                members = archive.getmembers()
                self.assertEqual(len(members), 73)
                for item in members:
                    expected = ROOT / item.name
                    self.assertEqual(archive.extractfile(item).read(), expected.read_bytes())
                    self.assertEqual((item.mode, item.uid, item.gid, item.mtime), (0o644, 0, 0, 0))
            receipt = r.record(p, 'a' * 40, paths[1])
            self.assertEqual(receipt['sourceCommit'], r.SOURCE)
            self.assertEqual(receipt['sharedMaterials']['sourceCommit'], old.SOURCE)
            self.assertFalse(receipt['legalConclusion'])
            self.assertEqual(receipt['nativeIndexSHA256'], SELECTOR['binding']['nativeIndexSHA256'])
            with self.assertRaises(ValueError):
                r.record(p, 'a' * 40, paths[0])
            with self.assertRaises(ValueError):
                r.record(p, 'not-a-sha', paths[1])
            paths[1].write_bytes(b'changed')
            with self.assertRaises(ValueError):
                r.record(p, 'a' * 40, paths[1])

    def test_writer_cleanup_and_no_overwrite(self):
        p = load()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'bundle'
            path.write_bytes(b'keep')
            with self.assertRaises(ValueError):
                r.write_bundle(p, path)
            self.assertEqual(path.read_bytes(), b'keep')
            path.unlink()
            with mock.patch.object(tarfile.TarFile, 'addfile', side_effect=OSError('write failure')):
                with self.assertRaises(OSError):
                    r.write_bundle(p, path)
            self.assertFalse(path.exists())

    def test_package_delta_is_exactly_two_and_source_notices_are_bound(self):
        p = load()
        root = ROOT / r.DIRECTORY
        selector = p['selector']
        reference = json.loads((root / selector['materialReference']['path']).read_text())
        material_map = json.loads((root / selector['materialMap']['path']).read_text())
        old_reference = json.loads((ROOT / old.DIRECTORY / 'reuse-reference.json').read_text())
        self.assertEqual(len(material_map['sharedPackageAssociations']), 241)
        self.assertEqual(len(material_map['newPackageAssociations']), 2)
        for which in ('shared-package', 'new-checksum', 'base', 'recipe', 'association'):
            ref, mapping = copy.deepcopy(reference), copy.deepcopy(material_map)
            if which == 'shared-package':
                ref['artifacts']['oci-linux-amd64']['packages'][0]['C'] = 'wrong'
            elif which == 'new-checksum':
                next(p for p in ref['artifacts']['oci-linux-loong64']['packages'] if p['P'] == 'libncursesw')['C'] = 'wrong'
            elif which == 'base':
                ref['artifacts']['oci-linux-amd64']['baseDependencies'] = []
            elif which == 'recipe':
                mapping['newRecipe']['commit'] = '0' * 40
            else:
                mapping['newPackageAssociations'] = []
            with self.subTest(which=which), self.assertRaises(ValueError):
                r._delta_materials(root, selector, ref, mapping, old_reference)

    def test_legacy_delegation(self):
        with mock.patch.object(old, 'load_for_run', return_value='legacy') as call:
            self.assertEqual(load(source=old.SOURCE), 'legacy')
            self.assertEqual(call.call_args.args[0], old.SOURCE)
        for name in ('check_image', 'write_bundle', 'record'):
            args = ({'schema': 'legacy'}, 'x', 'y') if name != 'write_bundle' else ({'schema': 'legacy'}, 'x')
            with mock.patch.object(old, name, return_value='legacy') as call:
                self.assertEqual(getattr(r, name)(*args), 'legacy')
                call.assert_called_once_with(*args)

    def test_publisher_actual_parser_uses_current_identity_and_shared_paths(self):
        p = load()
        name = API[0]['name']
        expected = p['artifacts'][name]
        measured = {k: expected[k] for k in ('coreBytes', 'coreSHA256', 'installedSHA256')}
        measured['actualImageManifest'] = expected['imageManifest']
        with mock.patch.object(r, 'check_image', return_value=expected), mock.patch.object(g, 'validate_oci_material_reuse', return_value=measured) as parser:
            result = g.measure_oci_materials(Path('actual'), name, r.SOURCE, str(r.RUN_ID), 1, p)
            parser.assert_called_once_with(Path('actual'), name, r.SOURCE, str(r.RUN_ID), 1,
                reference_paths=(p['reference_path'], p['material_map_path']))
            self.assertEqual(result['supplementSelectorSHA256'], r.SELECTOR_SHA256)


if __name__ == '__main__':
    unittest.main()
