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
import oci_material_selection_12_19 as s19

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
    def load19(self, **changes):
        selector = json.loads((ROOT / s19.DIRECTORY / 'selection-manifest.json').read_bytes())
        api = [{'id': row['artifactId'], 'name': name, 'size_in_bytes': row['archiveBytes'],
                'digest': row['artifactAPIDigest'], 'expired': False,
                'workflow_run': {'id': s19.RUN_ID, 'head_sha': s19.SOURCE,
                                 'repository_id': old.REPOSITORY_ID, 'head_repository_id': old.REPOSITORY_ID}}
               for name, row in selector['artifacts'].items()]
        args = dict(source=s19.SOURCE, tree=s19.TREE, tag=s19.TAG, tag_object=s19.TAG_OBJECT,
                    run_id=s19.RUN_ID, attempt=1, workflow=old.WORKFLOW, artifacts=api,
                    source_root=ROOT, publisher_root=ROOT)
        args.update(changes)
        return r.load_for_run(**args)

    def test_s19_exact_materials_keep_product_and_historical_ownership_separate(self):
        with mock.patch.object(old, 'load_for_run', side_effect=AssertionError('no historical API freshness')):
            policy = self.load19()
        self.assertEqual(policy['schema'], s19.SCHEMA)
        self.assertEqual(policy['binding']['sourceCommit'], 'd8727ed53de26cfd13c95f96d0a69235792d221b')
        self.assertEqual(policy['binding']['producerRunId'], 42315358374)
        self.assertEqual(policy['binding']['producerAttempt'], 1)
        self.assertEqual(policy['selector']['sharedMaterials']['sourceCommit'], s19.previous.SOURCE)
        self.assertEqual(policy['reference_path'], ROOT / s19.DIRECTORY / 'reuse-reference.json')
        self.assertTrue(r.supports_source(s19.SOURCE))
        self.assertTrue(r.supports_source(s19.previous.SOURCE))
        self.assertFalse(r.supports_source('0' * 40))
        mapping = json.loads(policy['material_map_path'].read_bytes())
        self.assertEqual((len(mapping['exactPackageAssociations']), len(mapping['newPackageAssociations']),
                          len(mapping['baseDependencyChanges']), mapping['newRecipeCount']), (214, 29, 8, 3))
        self.assertFalse(mapping['legalConclusion'])

    def test_s19_product_tuple_and_all_nine_native_artifacts_have_no_fallback(self):
        policy = self.load19()
        for key, value in [('source', '0' * 40), ('tree', '0' * 40), ('tag', old.TAG),
                           ('tag_object', old.TAG_OBJECT), ('run_id', s19.previous.RUN_ID),
                           ('attempt', True), ('attempt', 2), ('workflow', '.github/workflows/build.yml')]:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'wrong .*tuple'):
                self.load19(**{key: value})
        api = policy['_api']
        for rows, guard in [(api[:-1], 'requires exact nine OCI APIs'), (api + api[:1], 'requires exact nine OCI APIs')]:
            with self.subTest(count=len(rows)), self.assertRaisesRegex(ValueError, guard):
                self.load19(artifacts=rows)
        for field, value, guard in [('name', 'oci-unlisted', 'unknown/duplicate artifact'),
                                    ('id', True, 'unknown/duplicate artifact'),
                                    ('digest', 'sha256:' + '0' * 64, 'artifact bytes identity changed'),
                                    ('expired', True, 'artifact origin/expiry differs')]:
            changed = copy.deepcopy(api); changed[0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, guard):
                self.load19(artifacts=changed)
        for field, value in [('id', s19.previous.RUN_ID), ('head_sha', s19.previous.SOURCE),
                             ('repository_id', 1), ('head_repository_id', True)]:
            changed = copy.deepcopy(api); changed[0]['workflow_run'][field] = value
            with self.subTest(origin=field), self.assertRaisesRegex(ValueError, 'artifact origin/expiry differs'):
                self.load19(artifacts=changed)

    def test_s19_measured_seven_fields_base_and_recipe_closure_are_strict(self):
        policy = self.load19(); root = policy['directory']; selector = policy['selector']
        reference = json.loads(policy['reference_path'].read_bytes())
        mapping = json.loads(policy['material_map_path'].read_bytes())
        _, historical, historical_root, historical_map, _ = s19._historical_sources(ROOT, ROOT)
        cases = [(field, 'exact measured seven-field package set differs') for field in ('P', 'V', 'A', 'L', 'o', 'c', 'C')]
        cases += [('base', 'exact base dependency differs'), ('repository', 'image/platform/repository differs'),
                  ('association', '214\\+29/base association closure differs'), ('extra-image', 'requires exact nine OCI profiles'),
                  ('recipe', 'official recipe origin/commit differs'), ('recipe-files', 'full recipe directory scope differs')]
        for change, guard in cases:
            ref, data = copy.deepcopy(reference), copy.deepcopy(mapping)
            row = ref['artifacts']['oci-linux-arm64']
            if change in ('P', 'V', 'A', 'L', 'o', 'c', 'C'):
                row['packages'][0][change] += '-unreviewed'
            elif change == 'base': row['baseDependencies'][0]['digest']['sha256'] = '0' * 64
            elif change == 'repository': row['repositories'] += 'foreign\n'
            elif change == 'association': data['newPackageAssociations'].pop()
            elif change == 'extra-image': ref['artifacts']['oci-unlisted'] = copy.deepcopy(row)
            elif change == 'recipe': data['newRecipes'][0]['commit'] = '0' * 40
            else: data['newRecipes'][0]['files'] = []
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, guard):
                s19._reassociation(root, selector, ref, data, historical, historical_root, historical_map)

    def test_s19_actual_get_notice_and_historical_reuse_cannot_be_relabelled(self):
        self.load19()
        root = ROOT / s19.DIRECTORY
        acquisition = (root / 'source-acquisition.json').read_bytes()
        notice = (root / 'notice-inventory.json').read_bytes()
        receipt = (root / 'http/apk-tools-source-get.json').read_bytes()
        original = old._json
        for raw, path, value, guard in [
                (acquisition, ('newDownloads',), True, 'source/notice origin/count differs'),
                (acquisition, ('historicalReceiptsUnmodified',), False, 'historical source/notice ownership differs'),
                (acquisition, ('reusedSources', 0, 'notReacquired'), False, 'historical source ownership differs'),
                (acquisition, ('reusedSources', 0, 'historicalRecord', 'sha512'), '0' * 128, 'historical acquisition record differs'),
                (receipt, ('HTTP',), 403, 'actual upstream GET receipt differs'),
                (receipt, ('actualEOF',), False, 'actual upstream GET receipt differs'),
                (receipt, ('request', 'authSent'), True, 'actual upstream GET receipt differs'),
                (receipt, ('request', 'redirectFollowed'), True, 'actual upstream GET receipt differs'),
                (notice, ('files', 0, 'archiveMember'), 'other', 'exact notice ownership differs')]:
            changed = json.loads(raw); target = changed
            for key in path[:-1]: target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), mock.patch.object(old, '_json', side_effect=lambda data: changed if data == raw else original(data)), \
                 self.assertRaisesRegex(ValueError, guard):
                self.load19()

    def test_s19_source_archive_notice_and_unlisted_files_fail_before_history(self):
        self.load19()
        for change in ('source', 'notice', 'extra'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); current = root / s19.DIRECTORY
                shutil.copytree(ROOT / s19.DIRECTORY, current)
                if change == 'extra':
                    (current / 'unlisted').mkdir()
                    guard = 'unexpected current selection entries'
                else:
                    name = 'sources/apk-tools-v3.0.9.tar.gz' if change == 'source' else 'notices/apk-tools-v3.0.9/LICENSE'
                    path = current / name; path.write_bytes(path.read_bytes() + b'!')
                    guard = 'file size mismatch before hashing'
                with self.assertRaisesRegex(ValueError, guard): self.load19(publisher_root=root)

    def test_s19_bundle_all_136_members_receipt_and_parser_selection(self):
        policy = self.load19()
        self.assertEqual((policy['bundle_tar_bytes'], policy['bundle_maximum_bytes']), (10270720, 11715104))
        self.assertEqual(r.bundle_name(policy), 'polaris-oci-material-supplement-42315358374-attempt1.tar.gz')
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / r.bundle_name(policy)
            r.write_bundle(policy, path)
            with tarfile.open(path) as archive:
                members = archive.getmembers(); self.assertEqual(len(members), 136)
                for member in members:
                    self.assertEqual(archive.extractfile(member).read(), (ROOT / member.name).read_bytes())
            receipt = r.record(policy, 'a' * 40, path)
            self.assertEqual((receipt['sharedPackageAssociationCount'], receipt['newPackageAssociationCount'],
                              receipt['changedBaseDependencyCount']), (214, 29, 8))
            self.assertFalse(receipt['legalConclusion'])
            image = Path(temporary) / 'not-an-image'; image.write_bytes(b'corrupt actual image')
            with mock.patch.object(g, 'validate_oci_material_reuse') as parser, \
                 self.assertRaisesRegex(ValueError, 'file size mismatch before hashing'):
                g.measure_oci_materials(image, 'oci-linux-arm64', s19.SOURCE, str(s19.RUN_ID), 1, policy)
            parser.assert_not_called()
            with self.assertRaisesRegex(ValueError, 'unknown image'):
                r.check_image(policy, 'oci-unlisted', image)
        for name, expected in policy['artifacts'].items():
            measured = {k: expected[k] for k in ('coreBytes', 'coreSHA256', 'installedSHA256')}
            measured['actualImageManifest'] = expected['imageManifest']
            with self.subTest(name=name), mock.patch.object(r, 'check_image', return_value=expected), \
                 mock.patch.object(g, 'validate_oci_material_reuse', return_value=measured) as parser:
                result = g.measure_oci_materials(Path('actual'), name, s19.SOURCE, str(s19.RUN_ID), 1, policy)
                parser.assert_called_once_with(Path('actual'), name, s19.SOURCE, str(s19.RUN_ID), 1,
                    reference_paths=(policy['reference_path'], policy['material_map_path']))
                self.assertEqual(result['supplementSelectorSHA256'], s19.SELECTOR_SHA256)

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
