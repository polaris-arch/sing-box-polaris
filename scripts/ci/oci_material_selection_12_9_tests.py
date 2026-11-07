"""Offline admission regressions; no producer image or repository recipe executes."""
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
import oci_material_selection_12_9 as current
import oci_material_selection_12_7 as previous
import oci_material_supplement as legacy
import publisher_peer_evidence_12_9 as peer

ROOT = Path(__file__).resolve().parents[2]
DIRECTORY = ROOT / current.DIRECTORY
SELECTOR = json.loads((DIRECTORY / 'selection-manifest.json').read_bytes())
REFERENCE = json.loads((DIRECTORY / 'reuse-reference.json').read_bytes())
MAPPING = json.loads((DIRECTORY / 'oci-source-notice-map.json').read_bytes())
API = [{'id': row['artifactId'], 'name': name, 'size_in_bytes': row['archiveBytes'],
        'digest': row['artifactAPIDigest'], 'expired': False,
        'workflow_run': {'id': current.RUN_ID, 'head_sha': current.SOURCE,
                         'repository_id': legacy.REPOSITORY_ID, 'head_repository_id': legacy.REPOSITORY_ID}}
       for name, row in SELECTOR['artifacts'].items()]


def load(**changes):
    args = dict(source=current.SOURCE, tree=current.TREE, tag=current.TAG, tag_object=current.TAG_OBJECT,
                run_id=current.RUN_ID, attempt=1, workflow=legacy.WORKFLOW, artifacts=copy.deepcopy(API),
                source_root=ROOT, publisher_root=ROOT)
    args.update(changes)
    return registry.load_for_run(**args)


class Alpha129OCISelectionTests(unittest.TestCase):
    def test_exact_measured_241_plus_two_package_and_one_base_delta(self):
        with mock.patch.object(legacy, 'load_for_run', side_effect=AssertionError('no historical API freshness')):
            policy = load()
        self.assertTrue(registry.supports_source(current.SOURCE))
        self.assertEqual(policy['schema'], current.SCHEMA)
        self.assertEqual(policy['selector']['schema'], 'polaris-exact-oci-material-delta-selection-v1')
        self.assertNotIn('resolved_reference', policy)
        self.assertEqual(len(MAPPING['exactPackageAssociations']), 241)
        self.assertEqual(MAPPING['newRecipeCount'], 2)
        self.assertEqual(MAPPING['packageAssociationCount'], 243)
        self.assertEqual([r['package'] for r in MAPPING['newPackageAssociations']], current._DELTA_PACKAGES)
        self.assertEqual([r['artifact'] for r in MAPPING['baseDependencyChanges']], ['oci-linux-loong64'])
        self.assertEqual(len(REFERENCE['artifacts']), 9)
        self.assertEqual(sum(len(r['packages']) for r in REFERENCE['artifacts'].values()), 243)
        selected, _ = peer.load(ROOT)
        for key in ('sourceCommit', 'sourceTree', 'tagObject', 'nativeIndexSHA256'):
            self.assertEqual(policy['binding'][key], selected[key])
        self.assertNotEqual(policy['binding']['producerRunId'], selected['runId'])

    def test_predecessor_indexed_profile_resolves_without_relabelling_historical_files(self):
        path = ROOT / previous.DIRECTORY / 'reuse-reference.json'
        raw = path.read_bytes()
        self.assertTrue(all('packages' not in row for row in json.loads(raw)['artifacts'].values()))
        selector, profile, _, _, members = current._historical_sources(ROOT, ROOT)
        self.assertEqual(selector['binding']['sourceCommit'], previous.SOURCE)
        self.assertEqual(sum(len(row['packages']) for row in profile['artifacts'].values()), 243)
        self.assertEqual(len(members), 98)
        self.assertEqual(path.read_bytes(), raw)

    def test_exact_product_tag_run_and_attempt_have_no_fallback(self):
        for key, value in [('source', previous.SOURCE), ('source', 'f' * 40), ('tree', '0' * 40),
                           ('tag', previous.TAG), ('tag_object', previous.TAG_OBJECT),
                           ('run_id', previous.RUN_ID), ('run_id', str(current.RUN_ID)),
                           ('attempt', 2), ('attempt', True), ('attempt', 1.0),
                           ('workflow', '.github/workflows/build.yml')]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                load(**{key: value})

    def test_exact_nine_artifacts_digest_repository_source_expiry_and_types(self):
        variants = [API[:-1], API + API[:1], API[:-1] + API[:1]]
        for field, value in [('id', True), ('id', float(API[0]['id'])), ('id', API[1]['id']),
                             ('name', 'oci-unreviewed'), ('size_in_bytes', 0),
                             ('digest', 'sha256:' + '0' * 64), ('expired', True), ('expired', None)]:
            rows = copy.deepcopy(API); rows[0][field] = value; variants.append(rows)
        for field, value in [('id', previous.RUN_ID), ('id', float(current.RUN_ID)),
                             ('head_sha', previous.SOURCE), ('repository_id', 1), ('head_repository_id', True)]:
            rows = copy.deepcopy(API); rows[0]['workflow_run'][field] = value; variants.append(rows)
        for i, rows in enumerate(variants):
            with self.subTest(variant=i), self.assertRaises(ValueError):
                load(artifacts=rows)

    def test_all_seven_package_fields_base_repository_and_association_controls(self):
        _, historical, historical_root, historical_map, _ = current._historical_sources(ROOT, ROOT)
        for change in ('P', 'V', 'A', 'L', 'o', 'c', 'C', 'base', 'repo', 'missing', 'extra',
                       'duplicate', 'cross', 'count', 'recipe-count', 'legal', 'old-delta'):
            ref, data = copy.deepcopy(REFERENCE), copy.deepcopy(MAPPING)
            if change in ('P', 'V', 'A', 'L', 'o', 'c', 'C'):
                ref['artifacts']['oci-linux-amd64']['packages'][0][change] = 'unreviewed'
            elif change == 'base': ref['artifacts']['oci-linux-loong64']['baseDependencies'][0]['digest']['sha256'] = '0' * 64
            elif change == 'repo': ref['artifacts']['oci-linux-loong64']['repositories'] += 'foreign\n'
            elif change == 'missing': data['exactPackageAssociations'].pop()
            elif change == 'extra': ref['artifacts']['oci-linux-extra'] = copy.deepcopy(ref['artifacts']['oci-linux-amd64'])
            elif change == 'duplicate': ref['artifacts']['oci-linux-loong64']['packages'][-1] = copy.deepcopy(ref['artifacts']['oci-linux-loong64']['packages'][0])
            elif change == 'cross': data['crossArchitectureSourceAssociations'].append({})
            elif change == 'count': data['packageAssociationCount'] = 243.0
            elif change == 'recipe-count': data['newRecipeCount'] = True
            elif change == 'legal': data['legalConclusion'] = True
            else: ref['artifacts']['oci-linux-loong64']['packages'] = copy.deepcopy(historical['artifacts']['oci-linux-loong64']['packages'])
            with self.subTest(change=change), self.assertRaises(ValueError):
                current._reassociation(DIRECTORY, SELECTOR, ref, data, historical, historical_root, historical_map)

    def test_recipe_git_tree_full_directory_and_origin_cannot_drift(self):
        _, historical, historical_root, historical_map, _ = current._historical_sources(ROOT, ROOT)
        for field, value in [('commit', '0' * 40), ('origin', 'other'), ('repositoryHost', 'foreign.example'),
                             ('projectId', True), ('directoryTreeSHA', '0' * 40), ('files', [])]:
            changed = copy.deepcopy(MAPPING); changed['newRecipes'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                current._reassociation(DIRECTORY, SELECTOR, REFERENCE, changed, historical, historical_root, historical_map)
        for field, value in [('gitBlob', '0' * 40), ('gitMode', '120000'), ('path', '../escape')]:
            changed = copy.deepcopy(MAPPING); changed['newRecipes'][0]['files'][0][field] = value
            with self.subTest(file_field=field), self.assertRaises(ValueError):
                current._reassociation(DIRECTORY, SELECTOR, REFERENCE, changed, historical, historical_root, historical_map)
        for value in (True, float(MAPPING['newRecipes'][0]['files'][1]['bytes'])):
            changed = copy.deepcopy(MAPPING); changed['newRecipes'][0]['files'][1]['bytes'] = value
            with self.subTest(shared_recipe_bytes=value), self.assertRaises(ValueError):
                current._reassociation(DIRECTORY, SELECTOR, REFERENCE, changed, historical, historical_root, historical_map)

    def test_real_get_source_notice_and_shared_ownership_negatives(self):
        original = legacy._json
        acquisition_raw = (DIRECTORY / 'source-acquisition.json').read_bytes()
        notice_raw = (DIRECTORY / 'notice-inventory.json').read_bytes()
        receipt_path = json.loads(acquisition_raw)['newSources'][0]['getReceipt']['path']
        receipt_raw = (DIRECTORY / receipt_path).read_bytes()
        for raw, path, value in [
                (acquisition_raw, ('newDownloads',), True),
                (acquisition_raw, ('historicalReceiptsUnmodified',), False),
                (acquisition_raw, ('newSources', 0, 'sha512'), '0' * 128),
                (receipt_raw, ('HTTP',), 403),
                (receipt_raw, ('HTTP',), 200.0),
                (receipt_raw, ('fullGet',), False),
                (receipt_raw, ('openResponseAndBodyClosed',), False),
                (receipt_raw, ('effectiveURL',), 'https://foreign.example/source'),
                (receipt_raw, ('responseHeaders', 'Authorization'), 'never-accepted'),
                (notice_raw, ('files', 0, 'archiveMember'), 'other'),
                (notice_raw, ('files', 0, 'sourceArchiveSHA256'), '0' * 64),
                (notice_raw, ('sharedNotices', 0, 'reextractedNow'), True)]:
            changed = json.loads(raw); target = changed
            for key in path[:-1]: target = target[key]
            target[path[-1]] = value
            with mock.patch.object(legacy, '_json', side_effect=lambda data: changed if data == raw else original(data)):
                with self.subTest(path=path), self.assertRaises(ValueError): load()

    def test_new_source_hash_and_symlink_fail_before_historical_admission(self):
        for change in ('source', 'notice', 'extra', 'symlink'):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); current_root = root / current.DIRECTORY
                shutil.copytree(DIRECTORY, current_root)
                if change == 'extra': (current_root / 'extra').mkdir()
                elif change == 'symlink':
                    path = current_root / 'selection-manifest.json'; path.unlink(); path.symlink_to(DIRECTORY / path.name)
                else:
                    name = 'sources/tzdata2026f.tar.gz' if change == 'source' else 'notices/tzdata2026f.tar.gz/LICENSE'
                    path = current_root / name; path.write_bytes(path.read_bytes() + b'!')
                with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'symlink|unexpected current|file size'):
                    load(publisher_root=root)

    def test_actual_image_hash_precedes_unchanged_graph_and_package_parser(self):
        policy = load(); name = API[0]['name']; expected = policy['artifacts'][name]
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / 'image.tar'; image.write_bytes(b'not an actual producer image')
            with mock.patch.object(g, 'validate_oci_material_reuse') as parser, self.assertRaises(ValueError):
                g.measure_oci_materials(image, name, current.SOURCE, str(current.RUN_ID), 1, policy)
            parser.assert_not_called()
        measured = {key: expected[key] for key in ('coreBytes', 'coreSHA256', 'installedSHA256')}
        measured['actualImageManifest'] = expected['imageManifest']
        with mock.patch.object(registry, 'check_image', return_value=expected), mock.patch.object(g, 'validate_oci_material_reuse', return_value=measured) as parser:
            g.measure_oci_materials(Path('synthetic'), name, current.SOURCE, str(current.RUN_ID), 1, policy)
            parser.assert_called_once_with(Path('synthetic'), name, current.SOURCE, str(current.RUN_ID), 1,
                reference_paths=(policy['reference_path'], policy['material_map_path']))
        for field in ('coreSHA256', 'installedSHA256', 'actualImageManifest', 'coreBytes'):
            bad = dict(measured); bad[field] = measured[field] + 1 if field == 'coreBytes' else '0' * 64
            with mock.patch.object(registry, 'check_image', return_value=expected), mock.patch.object(g, 'validate_oci_material_reuse', return_value=bad):
                with self.subTest(measured=field), self.assertRaises(ValueError):
                    g.measure_oci_materials(Path('synthetic'), name, current.SOURCE, str(current.RUN_ID), 1, policy)

    def test_policy_cannot_redirect_paths_raise_budget_or_relabel_source(self):
        policy = load()
        for key, value in [('reference_path', Path('/foreign')), ('material_map_path', Path('/foreign')),
                           ('bundle_maximum_bytes', 99999999), ('binding', {}), ('artifacts', {}),
                           ('selector_sha256', '0' * 64), ('extra', True)]:
            changed = copy.deepcopy(policy); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): registry.bundle_name(changed)

    def test_exact_118_member_nonpublic_bundle_keeps_product_and_publisher_distinct(self):
        policy = load()
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / registry.bundle_name(policy)
            registry.write_bundle(policy, bundle)
            receipt = registry.record(policy, 'e' * 40, bundle)
            with tarfile.open(bundle, 'r:gz') as archive:
                self.assertEqual(len(archive.getmembers()), 118)
            self.assertEqual(receipt['sourceCommit'], current.SOURCE)
            self.assertEqual(receipt['publisherCommit'], 'e' * 40)
            self.assertEqual(receipt['sharedPackageAssociationCount'], 241)
            self.assertEqual(receipt['newPackageAssociationCount'], 2)
            self.assertEqual(receipt['newRecipeCount'], 2)
            self.assertEqual(receipt['changedBaseDependencyCount'], 1)
            self.assertFalse(receipt['legalConclusion'])
            self.assertTrue(receipt['publicReleaseAssetSetUnchanged'])
            self.assertTrue(receipt['ociSeparateDistributionChannel'])
            self.assertEqual(g.publication('docker', 'oci-linux-loong64', 'image.tar', current.SOURCE),
                             (None, 'separate-distribution-channel'))
