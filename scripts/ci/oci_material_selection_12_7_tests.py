"""Exact alpha.12.7 OCI reassociation and unchanged strict material boundaries."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import github_release as g
import oci_material_registry as registry
import oci_material_selection_12_6 as previous
import oci_material_selection_12_7 as current
import oci_material_supplement as legacy
import publisher_peer_evidence_12_7 as peer

ROOT = Path(__file__).resolve().parents[2]
SELECTOR = json.loads((ROOT / current.DIRECTORY / 'selection-manifest.json').read_text())
API = [{'id': row['artifactId'], 'name': name, 'size_in_bytes': row['archiveBytes'],
        'digest': row['artifactAPIDigest'], 'expired': False,
        'workflow_run': {'id': current.RUN_ID, 'head_sha': current.SOURCE,
                         'repository_id': legacy.REPOSITORY_ID, 'head_repository_id': legacy.REPOSITORY_ID}}
       for name, row in SELECTOR['artifacts'].items()]


def wrong_numeric_type(value, convert):
    return convert(value) if type(value) is not bool else (float(value) if convert is float else int(value))


def load(**changes):
    args = dict(source=current.SOURCE, tree=current.TREE, tag=current.TAG, tag_object=current.TAG_OBJECT,
                run_id=current.RUN_ID, attempt=1, workflow=legacy.WORKFLOW, artifacts=copy.deepcopy(API),
                source_root=ROOT, publisher_root=ROOT)
    args.update(changes)
    return registry.load_for_run(**args)


class Alpha127OCISelectionTests(unittest.TestCase):
    def test_exact_243_reused_associations_and_cross_producer_identity(self):
        with mock.patch.object(legacy, 'load_for_run', side_effect=AssertionError('no synthetic old API')):
            policy = load()
        self.assertTrue(registry.supports_source(current.SOURCE))
        self.assertEqual(policy['schema'], current.SCHEMA)
        self.assertEqual(policy['selector']['sharedMaterials']['sourceCommit'], previous.SOURCE)
        mapping = json.loads(policy['material_map_path'].read_text())
        self.assertEqual(mapping['packageAssociationCount'], 243)
        self.assertEqual(sum(len(row['packageIndices']) for row in mapping['artifactPackageIndices'].values()), 243)
        self.assertNotIn('exactPackageAssociations', mapping)
        self.assertTrue(all('packages' not in row for row in json.loads(policy['reference_path'].read_text())['artifacts'].values()))
        self.assertEqual(len(policy['resolved_reference']['artifacts']), 9)
        self.assertEqual(mapping['crossArchitectureSourceAssociations'], [])
        self.assertEqual(mapping['newRecipeCount'], 0)
        selected, _ = peer.load(ROOT)
        self.assertEqual(policy['binding']['nativeIndexSHA256'], selected['nativeIndexSHA256'])
        self.assertEqual(policy['binding']['sourceCommit'], selected['sourceCommit'])
        self.assertNotEqual(policy['binding']['producerRunId'], selected['runId'])

    def test_exact_tuple_and_api_scope_have_no_fallback(self):
        for key, value in [('source', '0' * 40), ('tree', previous.TREE), ('tag', previous.TAG),
                           ('tag_object', previous.TAG_OBJECT), ('run_id', previous.RUN_ID),
                           ('run_id', str(current.RUN_ID)), ('attempt', True), ('attempt', 2),
                           ('workflow', '.github/workflows/build.yml')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                load(**{key: value})
        variants = [API[:-1], API + API[:1], API[:-1] + API[:1]]
        for field, value in [('id', True), ('id', API[1]['id']), ('name', 'oci-unknown'),
                             ('size_in_bytes', 0), ('digest', 'sha256:' + '0' * 64), ('expired', True)]:
            rows = copy.deepcopy(API); rows[0][field] = value; variants.append(rows)
        for field, value in [('id', previous.RUN_ID), ('head_sha', previous.SOURCE),
                             ('repository_id', 1), ('head_repository_id', 1)]:
            rows = copy.deepcopy(API); rows[0]['workflow_run'][field] = value; variants.append(rows)
        for rows in variants:
            with self.assertRaises(ValueError): load(artifacts=rows)

    def test_reference_mapping_missing_mismatched_dangling_duplicate_and_count_rejected(self):
        root = ROOT / current.DIRECTORY
        reference = json.loads((root / SELECTOR['materialReference']['path']).read_text())
        mapping = json.loads((root / SELECTOR['materialMap']['path']).read_text())
        _, historical, first_root, first_map, _ = current._historical_sources(ROOT, ROOT)
        for change in ('missing', 'extra-artifact', 'wrong-artifact', 'dangling', 'duplicate', 'missing-index',
                       'order', 'bool-index', 'float-index', 'count', 'bool-count', 'ref-version', 'map-version',
                       'ref-path', 'ref-sha', 'ref-bytes', 'extra-field', 'cross', 'recipe', 'bool-recipe', 'legal'):
            ref, data = copy.deepcopy(reference), copy.deepcopy(mapping)
            row = data['artifactPackageIndices']['oci-linux-amd64']
            if change == 'missing': data['artifactPackageIndices'].pop('oci-linux-amd64')
            elif change == 'extra-artifact': data['artifactPackageIndices']['unreviewed'] = copy.deepcopy(row)
            elif change == 'wrong-artifact': row['sourceArtifact'] = 'oci-linux-arm64'
            elif change == 'dangling': row['packageIndices'][-1] = 27
            elif change == 'duplicate': row['packageIndices'][-1] = 0
            elif change == 'missing-index': row['packageIndices'].pop()
            elif change == 'order': row['packageIndices'].reverse()
            elif change == 'bool-index': row['packageIndices'][0] = False
            elif change == 'float-index': row['packageIndices'][0] = 0.0
            elif change == 'count': data['packageAssociationCount'] = 242
            elif change == 'bool-count': data['packageAssociationCount'] = True
            elif change == 'ref-version': ref['schema'] = 'polaris-current-oci-material-reference-v1'
            elif change == 'map-version': data['schema'] = 'polaris-exact-oci-source-reassociation-v3'
            elif change == 'ref-path': ref['sharedReference']['path'] += '-missing'
            elif change == 'ref-sha': ref['sharedReference']['sha256'] = '0' * 64
            elif change == 'ref-bytes': ref['sharedReference']['bytes'] += 1
            elif change == 'extra-field': ref['packages'] = []
            elif change == 'cross': data['crossArchitectureSourceAssociations'].append({})
            elif change == 'recipe': data['newRecipeCount'] = 1
            elif change == 'bool-recipe': data['newRecipeCount'] = False
            else: data['legalConclusion'] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                current._reassociation(root, SELECTOR, ref, data, historical, first_root, first_map)
        for field in ('P', 'V', 'A', 'L', 'o', 'c', 'C'):
            altered = copy.deepcopy(historical)
            altered['artifacts']['oci-linux-amd64']['packages'][0][field] = 'unreviewed'
            with self.subTest(field=field), self.assertRaises(ValueError):
                current._reassociation(root, SELECTOR, reference, mapping, altered, first_root, first_map)

    def test_selector_version_directory_and_distribution_boundary_are_exact(self):
        raw = (ROOT / current.DIRECTORY / 'selection-manifest.json').read_bytes()
        original = legacy._json
        for field, value in [('appendOnlyPublisherDirectory', previous.DIRECTORY),
                             ('ociDistribution', 'public-release'), ('publicReleaseAssetSet', 'changed'),
                             ('auditDelivery', 'publish raw evidence'), ('extra', True), ('schema', 'v1')]:
            changed = copy.deepcopy(SELECTOR)
            if field == 'schema': changed['schema'] = 'polaris-exact-oci-source-reassociation-selection-v1'
            else: changed['distributionBoundary'][field] = value
            with mock.patch.object(legacy, '_json', side_effect=lambda data: changed if data == raw else original(data)):
                with self.subTest(field=field), self.assertRaises(ValueError): load()

    def test_resolved_reference_is_consumed_by_the_unchanged_graph_parser(self):
        policy = load(); name = API[0]['name']; expected = policy['artifacts'][name]
        measured = {key: expected[key] for key in ('coreBytes', 'coreSHA256', 'installedSHA256')}
        measured['actualImageManifest'] = expected['imageManifest']
        with mock.patch.object(registry, 'check_image', return_value=expected), \
             mock.patch.object(g, 'validate_oci_material_reuse', return_value=measured) as parser:
            g.measure_oci_materials(Path('actual'), name, current.SOURCE, str(current.RUN_ID), 1, policy)
            parser.assert_called_once_with(Path('actual'), name, current.SOURCE, str(current.RUN_ID), 1,
                reference_paths=(policy['reference_path'], policy['material_map_path']),
                resolved_reference=policy['resolved_reference'])

    def test_policy_and_actual_image_bytes_cannot_be_redirected(self):
        policy = load()
        for key, value in [('reference_path', Path('/tmp/foreign')), ('material_map_path', Path('/tmp/foreign')),
                           ('bundle_maximum_bytes', 99999999), ('artifacts', {}), ('binding', {}),
                           ('selector_sha256', '0' * 64), ('extra', True)]:
            changed = copy.deepcopy(policy); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): registry.bundle_name(changed)
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / 'image.tar'; image.write_bytes(b'not actual image')
            with mock.patch.object(g, 'validate_oci_material_reuse') as parser, self.assertRaises(ValueError):
                g.measure_oci_materials(image, API[0]['name'], current.SOURCE, str(current.RUN_ID), 1, policy)
            parser.assert_not_called()

    def test_json_reference_graph_selector_api_and_policy_numeric_types_are_strict(self):
        root = ROOT / current.DIRECTORY
        reference = json.loads((root / SELECTOR['materialReference']['path']).read_text())
        mapping = json.loads((root / SELECTOR['materialMap']['path']).read_text())
        _, historical, first_root, first_map, _ = current._historical_sources(ROOT, ROOT)
        for convert in (float, bool):
            ref = copy.deepcopy(reference); ref['sharedReference']['bytes'] = convert(ref['sharedReference']['bytes'])
            with self.subTest(reference=convert.__name__), self.assertRaises(ValueError):
                current._reassociation(root, SELECTOR, ref, mapping, historical, first_root, first_map)
            for field in ('artifactId', 'archiveBytes', 'coreBytes', 'imageBytes'):
                ref = copy.deepcopy(reference)
                ref['artifacts']['oci-linux-amd64'][field] = convert(ref['artifacts']['oci-linux-amd64'][field])
                with self.subTest(graph=field, conversion=convert.__name__), self.assertRaises(ValueError):
                    current._reassociation(root, SELECTOR, ref, mapping, historical, first_root, first_map)
            for path in (('producerRunId',), ('producerAttempt',), ('selector', 'bytes'), ('relabelled',)):
                data = copy.deepcopy(mapping); target = data['sharedMaterials']
                for key in path[:-1]: target = target[key]
                target[path[-1]] = wrong_numeric_type(target[path[-1]], convert)
                with self.subTest(shared=path, conversion=convert.__name__), self.assertRaises(ValueError):
                    current._reassociation(root, SELECTOR, reference, data, historical, first_root, first_map)
            for path in (('binding', 'repositoryId'), ('binding', 'producerRunId'), ('binding', 'producerAttempt'),
                         ('binding', 'sourceArchive', 'bytes'), ('materialReference', 'bytes'), ('materialMap', 'bytes'),
                         ('sourceAcquisition', 'bytes'), ('noticeInventory', 'bytes'), ('files', 0, 'bytes'),
                         ('sharedMaterials', 'selector', 'bytes'),
                         ('sharedMaterials', 'producerRunId'), ('sharedMaterials', 'producerAttempt'),
                         ('sharedMaterials', 'relabelled'), ('artifacts', 'oci-linux-amd64', 'artifactId'),
                         ('artifacts', 'oci-linux-amd64', 'archiveBytes'), ('artifacts', 'oci-linux-amd64', 'coreBytes'),
                         ('artifacts', 'oci-linux-amd64', 'imageBytes')):
                changed = copy.deepcopy(SELECTOR); target = changed
                for key in path[:-1]: target = target[key]
                target[path[-1]] = wrong_numeric_type(target[path[-1]], convert)
                raw = (root / 'selection-manifest.json').read_bytes(); original = legacy._json
                with mock.patch.object(legacy, '_json', side_effect=lambda data: changed if data == raw else original(data)):
                    with self.subTest(selector=path, conversion=convert.__name__), self.assertRaises(ValueError): load()
            for path in (('id',), ('size_in_bytes',), ('workflow_run', 'id'),
                         ('workflow_run', 'repository_id'), ('workflow_run', 'head_repository_id')):
                rows = copy.deepcopy(API); target = rows[0]
                for key in path[:-1]: target = target[key]
                target[path[-1]] = wrong_numeric_type(target[path[-1]], convert)
                with self.subTest(api=path, conversion=convert.__name__), self.assertRaises(ValueError): load(artifacts=rows)
            policy = load()
            for path in (('bundle_maximum_bytes',), ('binding', 'producerAttempt'),
                         ('artifacts', 'oci-linux-amd64', 'archiveBytes'),
                         ('resolved_reference', 'sharedReference', 'bytes')):
                changed = copy.deepcopy(policy); target = changed
                for key in path[:-1]: target = target[key]
                target[path[-1]] = wrong_numeric_type(target[path[-1]], convert)
                with self.subTest(policy=path, conversion=convert.__name__), self.assertRaises(ValueError):
                    registry.bundle_name(changed)

    def test_compatible_v1_api_and_reassociation_reject_equal_float_and_bool_identities(self):
        import oci_material_selection_12_5 as compatible
        selector = json.loads((ROOT / compatible.DIRECTORY / 'selection-manifest.json').read_text())
        rows = [{'id': row['artifactId'], 'name': name, 'size_in_bytes': row['archiveBytes'],
                 'digest': row['artifactAPIDigest'], 'expired': False,
                 'workflow_run': {'id': compatible.RUN_ID, 'head_sha': compatible.SOURCE,
                                  'repository_id': legacy.REPOSITORY_ID, 'head_repository_id': legacy.REPOSITORY_ID}}
                for name, row in selector['artifacts'].items()]
        for convert in (float, bool):
            for path in (('size_in_bytes',), ('workflow_run', 'id'), ('workflow_run', 'repository_id')):
                changed = copy.deepcopy(rows); target = changed[0]
                for key in path[:-1]: target = target[key]
                target[path[-1]] = wrong_numeric_type(target[path[-1]], convert)
                with self.subTest(api=path, conversion=convert.__name__), self.assertRaises(ValueError):
                    registry.load_for_run(compatible.SOURCE, compatible.TREE, compatible.TAG, compatible.TAG_OBJECT,
                        compatible.RUN_ID, 1, legacy.WORKFLOW, changed, ROOT, ROOT)
            reference = json.loads((ROOT / compatible.DIRECTORY / 'reuse-reference.json').read_text())
            mapping = json.loads((ROOT / compatible.DIRECTORY / 'oci-source-notice-map.json').read_text())
            _, historical, first_root, first_map, _ = compatible._historical_sources(ROOT, ROOT)
            for field in ('artifactId', 'archiveBytes', 'coreBytes', 'imageBytes'):
                changed = copy.deepcopy(reference)
                changed['artifacts']['oci-linux-amd64'][field] = convert(changed['artifacts']['oci-linux-amd64'][field])
                with self.subTest(row=field, conversion=convert.__name__), self.assertRaises(ValueError):
                    compatible._reassociation(ROOT / compatible.DIRECTORY, selector, changed, mapping,
                                               historical, first_root, first_map)

    def test_parser_measured_byte_identity_cannot_use_equal_float_or_bool(self):
        policy = load(); name = API[0]['name']; expected = policy['artifacts'][name]
        for convert in (float, bool):
            measured = {key: expected[key] for key in ('coreBytes', 'coreSHA256', 'installedSHA256')}
            measured['actualImageManifest'] = expected['imageManifest']; measured['coreBytes'] = convert(measured['coreBytes'])
            with mock.patch.object(registry, 'check_image', return_value=expected), \
                 mock.patch.object(g, 'validate_oci_material_reuse', return_value=measured), self.assertRaises(ValueError):
                g.measure_oci_materials(Path('actual'), name, current.SOURCE, str(current.RUN_ID), 1, policy)

    def test_exact_98_member_bundle_and_later_publisher(self):
        policy = load()
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / registry.bundle_name(policy)
            record = registry.write_bundle(policy, bundle)
            receipt = registry.record(policy, 'f' * 40, bundle)
            self.assertEqual(receipt['auditBundle'], record)
            self.assertEqual(receipt['publisherCommit'], 'f' * 40)
            self.assertNotEqual(receipt['publisherCommit'], current.SOURCE)
            self.assertEqual(receipt['packageAssociationCount'], 243)
            self.assertEqual(receipt['newRecipeCount'], 0)
            import tarfile
            with tarfile.open(bundle) as archive: self.assertEqual(len(archive.getmembers()), 98)
            with self.assertRaises(ValueError): registry.record(policy, '', bundle)
