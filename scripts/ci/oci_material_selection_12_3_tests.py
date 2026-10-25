"""Exact current OCI admission; no images are executed or historical APIs forged."""
import copy
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest import mock

import github_release as g
import oci_material_registry as registry
import oci_material_selection_12_3 as current
import oci_material_supplement as old

ROOT = Path(__file__).resolve().parents[2]
SELECTOR = json.loads((ROOT / current.DIRECTORY / 'selection-manifest.json').read_text())
API = [{'id': row['artifactId'], 'name': name, 'size_in_bytes': row['archiveBytes'],
        'digest': row['artifactAPIDigest'], 'expired': False,
        'workflow_run': {'id': current.RUN_ID, 'head_sha': current.SOURCE,
                         'repository_id': old.REPOSITORY_ID, 'head_repository_id': old.REPOSITORY_ID}}
       for name, row in SELECTOR['artifacts'].items()]


def load(**changes):
    args = dict(source=current.SOURCE, tree=current.TREE, tag=current.TAG, tag_object=current.TAG_OBJECT,
                run_id=current.RUN_ID, attempt=1, workflow=old.WORKFLOW, artifacts=copy.deepcopy(API),
                source_root=ROOT, publisher_root=ROOT)
    args.update(changes)
    return registry.load_for_run(**args)


class CurrentOCISelectionTests(unittest.TestCase):
    def test_exact_current_239_plus_four_source_closure(self):
        policy = load()
        self.assertEqual(policy['schema'], current.SCHEMA)
        self.assertEqual(policy['binding']['sourceCommit'], current.SOURCE)
        self.assertEqual(policy['selector']['sharedMaterials']['sourceCommit'], registry.SOURCE)
        self.assertEqual(policy['selector']['sharedMaterials']['relabelled'], False)
        self.assertTrue(registry.supports_source(current.SOURCE))
        self.assertTrue(registry.supports_source(registry.SOURCE))
        self.assertTrue(registry.supports_source(old.SOURCE))
        self.assertFalse(registry.supports_source('0' * 40))
        mapping = json.loads(policy['material_map_path'].read_text())
        self.assertEqual(len(mapping['exactPackageAssociations']), 239)
        self.assertEqual(len(mapping['crossArchitectureSourceAssociations']), 4)
        self.assertEqual(mapping['newRecipeCount'], 0)

    def test_current_tuple_has_no_alias_or_attempt_fallback(self):
        for key, value in [('source', '0' * 40), ('tree', registry.TREE), ('tag', registry.TAG),
                           ('tag_object', registry.TAG_OBJECT), ('run_id', registry.RUN_ID),
                           ('run_id', str(current.RUN_ID)), ('attempt', True), ('attempt', 2),
                           ('workflow', '.github/workflows/build.yml')]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                load(**{key: value})

    def test_exact_api_identity_expiry_and_scope(self):
        variants = [API[:-1], API + API[:1], API[:-1] + API[:1]]
        for field, value in [('id', True), ('id', API[1]['id']), ('name', 'oci-unreviewed'),
                             ('size_in_bytes', 0), ('digest', 'sha256:' + '0' * 64),
                             ('expired', True), ('expired', None)]:
            rows = copy.deepcopy(API); rows[0][field] = value; variants.append(rows)
        for field, value in [('id', registry.RUN_ID), ('head_sha', registry.SOURCE),
                             ('repository_id', 1), ('head_repository_id', 1)]:
            rows = copy.deepcopy(API); rows[0]['workflow_run'][field] = value; variants.append(rows)
        for i, rows in enumerate(variants):
            with self.subTest(i=i), self.assertRaises(ValueError):
                load(artifacts=rows)

    def test_new_and_historical_bytes_symlinks_and_extra_fail_closed(self):
        for change in ('selector', 'new-map', 'source', 'notice', 'symlink', 'extra'):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                for directory in (old.DIRECTORY, registry.DIRECTORY, current.DIRECTORY):
                    shutil.copytree(ROOT / directory, root / directory)
                selector = root / current.DIRECTORY / 'selection-manifest.json'
                if change == 'symlink':
                    selector.unlink(); selector.symlink_to(ROOT / current.DIRECTORY / 'selection-manifest.json')
                elif change == 'extra':
                    (selector.parent / 'extra').mkdir()
                else:
                    target = {'selector': selector, 'new-map': selector.parent / 'oci-source-notice-map.json',
                              'source': root / old.DIRECTORY / 'source-acquisition.json',
                              'notice': root / registry.DIRECTORY / 'notice-inventory.json'}[change]
                    target.write_bytes(target.read_bytes() + b' ')
                with self.subTest(change=change), self.assertRaises(ValueError):
                    load(publisher_root=root)

    def test_semantic_package_base_recipe_and_association_negatives(self):
        root = ROOT / current.DIRECTORY
        reference = json.loads((root / SELECTOR['materialReference']['path']).read_text())
        mapping = json.loads((root / SELECTOR['materialMap']['path']).read_text())
        _, previous, first_root, first_map, _ = current._historical_sources(ROOT, ROOT)
        for change in ('checksum', 'architecture', 'license', 'commit', 'base', 'base-uri',
                       'repo', 'source-recipe', 'source-package', 'missing', 'duplicate', 'legal'):
            ref, data = copy.deepcopy(reference), copy.deepcopy(mapping)
            changed = data['crossArchitectureSourceAssociations'][0]
            package = next(p for p in ref['artifacts']['oci-linux-riscv64']['packages'] if p == changed['package'])
            if change in ('checksum', 'architecture', 'license', 'commit'):
                package[{'checksum': 'C', 'architecture': 'A', 'license': 'L', 'commit': 'c'}[change]] = 'unreviewed'
            elif change == 'base':
                ref['artifacts']['oci-linux-amd64']['baseDependencies'][0]['digest']['sha256'] = '0' * 64
            elif change == 'base-uri':
                ref['artifacts']['oci-linux-amd64']['baseDependencies'][0]['uri'] += '-foreign'
            elif change == 'repo':
                ref['artifacts']['oci-linux-amd64']['repositories'] = []
            elif change == 'source-recipe':
                changed['recipe']['directoryTreeSHA'] = '0' * 40
            elif change == 'source-package':
                changed['sourceAssociation']['package']['C'] = 'unreviewed'
            elif change == 'missing':
                data['crossArchitectureSourceAssociations'].pop()
            elif change == 'duplicate':
                data['crossArchitectureSourceAssociations'].append(copy.deepcopy(changed))
            else:
                data['legalConclusion'] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                current._reassociation(root, SELECTOR, ref, data, previous, first_root, first_map)

    def test_no_historical_api_freshness_is_synthesized(self):
        with mock.patch.object(old, 'load_for_run', side_effect=AssertionError('no synthetic old API')):
            policy = load()
        self.assertEqual(policy['binding']['producerRunId'], current.RUN_ID)

    def test_policy_mutation_cannot_redirect_or_raise_budget(self):
        policy = load()
        for key, value in [('reference_path', Path('/tmp/foreign')), ('material_map_path', Path('/tmp/foreign')),
                           ('bundle_maximum_bytes', 99999999), ('artifacts', {}), ('binding', {}),
                           ('selector_sha256', '0' * 64), ('extra', True)]:
            altered = copy.deepcopy(policy); altered[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                registry.bundle_name(altered)

    def test_image_bytes_are_checked_before_graph_parser(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / 'image.tar'; image.write_bytes(b'not actual producer image')
            policy = load()
            with mock.patch.object(g, 'validate_oci_material_reuse') as parser:
                with self.assertRaises(ValueError):
                    g.measure_oci_materials(image, API[0]['name'], current.SOURCE, str(current.RUN_ID), 1, policy)
                parser.assert_not_called()
            with self.assertRaises(ValueError):
                registry.check_image(policy, 'foreign', image)

    def test_real_graph_validator_required_and_output_byte_identity_bound(self):
        policy = load(); name = API[0]['name']; expected = policy['artifacts'][name]
        measured = {k: expected[k] for k in ('coreBytes', 'coreSHA256', 'installedSHA256')}
        measured['actualImageManifest'] = expected['imageManifest']
        with mock.patch.object(registry, 'check_image', return_value=expected):
            with mock.patch.object(g, 'validate_oci_material_reuse', return_value=copy.deepcopy(measured)) as parser:
                result = g.measure_oci_materials(Path('actual'), name, current.SOURCE, str(current.RUN_ID), 1, policy)
                parser.assert_called_once_with(Path('actual'), name, current.SOURCE, str(current.RUN_ID), 1,
                    reference_paths=(policy['reference_path'], policy['material_map_path']))
                self.assertEqual(result['supplementSelectorSHA256'], current.SELECTOR_SHA256)
            with mock.patch.object(g, 'validate_oci_material_reuse', side_effect=ValueError('graph mismatch')):
                with self.assertRaisesRegex(ValueError, 'graph mismatch'):
                    g.measure_oci_materials(Path('actual'), name, current.SOURCE, str(current.RUN_ID), 1, policy)
            for key in measured:
                altered = dict(measured); altered[key] = 0
                with self.subTest(key=key), mock.patch.object(g, 'validate_oci_material_reuse', return_value=altered):
                    with self.assertRaises(ValueError):
                        g.measure_oci_materials(Path('actual'), name, current.SOURCE, str(current.RUN_ID), 1, policy)

    def test_exact_78_member_deterministic_bundle_and_separate_publisher(self):
        policy = load()
        self.assertEqual(registry.bundle_name(policy), 'polaris-oci-material-supplement-40164108947-attempt1.tar.gz')
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / 'a.tar.gz', Path(tmp) / 'b.tar.gz'
            first = registry.write_bundle(policy, a); second = registry.write_bundle(policy, b)
            self.assertEqual((first['bytes'], first['sha256']), (second['bytes'], second['sha256']))
            with tarfile.open(b) as archive:
                members = archive.getmembers(); self.assertEqual(len(members), 78)
                for item in members:
                    self.assertTrue(item.isfile())
                    self.assertEqual(archive.extractfile(item).read(), (ROOT / item.name).read_bytes())
                    self.assertEqual((item.mode, item.uid, item.gid, item.mtime), (0o644, 0, 0, 0))
            receipt = registry.record(policy, 'f' * 40, b)
            self.assertEqual(receipt['sourceCommit'], current.SOURCE)
            self.assertEqual(receipt['publisherCommit'], 'f' * 40)
            self.assertEqual(receipt['sharedPackageAssociationCount'], 239)
            self.assertEqual(receipt['crossArchitectureSourceAssociationCount'], 4)
            self.assertFalse(receipt['legalConclusion'])
            self.assertTrue(receipt['publicReleaseAssetSetUnchanged'])
            self.assertEqual(receipt['nativeIndexSHA256'], SELECTOR['binding']['nativeIndexSHA256'])
            with self.assertRaises(ValueError): registry.record(policy, 'not-sha', b)
            with self.assertRaises(ValueError): registry.record(policy, 'f' * 40, a)
            b.write_bytes(b'changed')
            with self.assertRaises(ValueError): registry.record(policy, 'f' * 40, b)

    def test_writer_partial_cleanup_no_overwrite_symlink_or_source_directory(self):
        policy = load()
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'bundle'; target.write_bytes(b'keep')
            with self.assertRaises(ValueError): registry.write_bundle(policy, target)
            self.assertEqual(target.read_bytes(), b'keep'); target.unlink()
            target.symlink_to(Path(tmp) / 'missing')
            with self.assertRaises(ValueError): registry.write_bundle(policy, target)
            target.unlink()
            primary = OSError(122, 'quota')
            with mock.patch.object(tarfile.TarFile, 'addfile', side_effect=primary):
                with self.assertRaises(OSError) as caught: registry.write_bundle(policy, target)
            self.assertIs(caught.exception, primary); self.assertFalse(target.exists())
            self.assertNotIn('_written_bundle', policy)
        with self.assertRaises(ValueError): registry.write_bundle(policy, ROOT / current.DIRECTORY / 'forbidden')
