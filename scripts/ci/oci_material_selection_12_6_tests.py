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
import oci_material_selection_12_6 as current
import oci_material_selection_12_5 as previous
import oci_material_selection_12_3 as ancestor
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


class Alpha126OCISelectionTests(unittest.TestCase):
    def test_exact_current_242_shared_and_one_new_recipe_closure(self):
        policy = load()
        self.assertEqual(policy['schema'], current.SCHEMA)
        self.assertEqual(policy['binding']['sourceCommit'], current.SOURCE)
        self.assertEqual(policy['selector']['sharedMaterials']['sourceCommit'], previous.SOURCE)
        self.assertEqual(policy['selector']['sharedMaterials']['relabelled'], False)
        self.assertTrue(registry.supports_source(current.SOURCE))
        self.assertTrue(registry.supports_source(registry.SOURCE))
        self.assertTrue(registry.supports_source(old.SOURCE))
        self.assertFalse(registry.supports_source('0' * 40))
        mapping = json.loads(policy['material_map_path'].read_text())
        self.assertEqual(len(mapping['exactPackageAssociations']), 242)
        self.assertEqual(len(mapping['crossArchitectureSourceAssociations']), 0)
        self.assertEqual(mapping['newRecipeCount'], 1)

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
                for directory in (old.DIRECTORY, registry.DIRECTORY, ancestor.DIRECTORY, previous.DIRECTORY, current.DIRECTORY):
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

    def test_semantic_package_base_and_association_negatives(self):
        root = ROOT / current.DIRECTORY
        reference = json.loads((root / SELECTOR['materialReference']['path']).read_text())
        mapping = json.loads((root / SELECTOR['materialMap']['path']).read_text())
        _, historical, first_root, first_map, _ = current._historical_sources(ROOT, ROOT)
        for change in ('P', 'V', 'A', 'L', 'o', 'c', 'C', 'base', 'repo', 'missing', 'duplicate', 'cross', 'legal'):
            ref, data = copy.deepcopy(reference), copy.deepcopy(mapping)
            row = ref['artifacts']['oci-linux-amd64']
            if change in ('P', 'V', 'A', 'L', 'o', 'c', 'C'):
                row['packages'][0][change] = 'unreviewed'
            elif change == 'base': row['baseDependencies'][0]['digest']['sha256'] = '0' * 64
            elif change == 'repo': row['repositories'] += 'foreign'
            elif change == 'missing': data['exactPackageAssociations'].pop()
            elif change == 'duplicate': data['exactPackageAssociations'].append(copy.deepcopy(data['exactPackageAssociations'][0]))
            elif change == 'cross': data['crossArchitectureSourceAssociations'].append({})
            else: data['legalConclusion'] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                current._reassociation(root, SELECTOR, ref, data, historical, first_root, first_map)

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

    def test_exact_93_member_deterministic_bundle_and_separate_publisher(self):
        policy = load()
        self.assertEqual(registry.bundle_name(policy), 'polaris-oci-material-supplement-40478933774-attempt1.tar.gz')
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / 'a.tar.gz', Path(tmp) / 'b.tar.gz'
            first = registry.write_bundle(policy, a); second = registry.write_bundle(policy, b)
            self.assertEqual((first['bytes'], first['sha256']), (second['bytes'], second['sha256']))
            with tarfile.open(b) as archive:
                members = archive.getmembers(); self.assertEqual(len(members), 93)
                for item in members:
                    self.assertTrue(item.isfile())
                    self.assertEqual(archive.extractfile(item).read(), (ROOT / item.name).read_bytes())
                    self.assertEqual((item.mode, item.uid, item.gid, item.mtime), (0o644, 0, 0, 0))
            receipt = registry.record(policy, 'f' * 40, b)
            self.assertEqual(receipt['sourceCommit'], current.SOURCE)
            self.assertEqual(receipt['publisherCommit'], 'f' * 40)
            self.assertEqual(receipt['sharedPackageAssociationCount'], 242)
            self.assertEqual(receipt['crossArchitectureSourceAssociationCount'], 0)
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

    def material_fixture(self):
        root = ROOT / current.DIRECTORY
        ref = json.loads((root / SELECTOR['materialReference']['path']).read_bytes())
        mapping = json.loads((root / SELECTOR['materialMap']['path']).read_bytes())
        _, historical, first_root, first_map, _ = current._historical_sources(ROOT, ROOT)
        return root, ref, mapping, historical, first_root, first_map

    def test_exact_new_jansson_seven_fields_and_architecture(self):
        root, ref, mapping, historical, first_root, first_map = self.material_fixture()
        for field, value in [('P','other'),('V','2.15.0-r0'),('A','riscv64'),('L','BSD'),('o','other'),('c','0'*40),('C','Q1'+('A'*27))]:
            changed = copy.deepcopy(ref)
            package = next(p for p in changed['artifacts']['oci-linux-loong64']['packages'] if p['P']=='jansson')
            package[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                current._reassociation(root, SELECTOR, changed, mapping, historical, first_root, first_map)
        for field, value in [('source',previous.SOURCE),('tree',previous.TREE),('tag',previous.TAG),('tag_object',previous.TAG_OBJECT),('run_id',previous.RUN_ID)]:
            with self.subTest(field=field), self.assertRaises(ValueError): load(**{field:value})

    def test_single_recipe_tree_patch_and_external_input_bounds(self):
        root, ref, mapping, historical, first_root, first_map = self.material_fixture()
        mutations = [lambda r:r.update(commit=previous.SOURCE), lambda r:r.update(directoryTreeSHA='0'*40),
            lambda r:r['files'].append(copy.deepcopy(r['files'][0])), lambda r:r['files'][0].update(gitMode='100755'),
            lambda r:r['files'][0].update(gitBlob='0'*40), lambda r:r['files'][0].update(path='../escape'),
            lambda r:r['externalInputs'].clear(), lambda r:r['externalInputs'][0].update(sha512='0'*128)]
        for i, mutate in enumerate(mutations):
            data=copy.deepcopy(mapping);mutate(data['newRecipe'])
            with self.subTest(i=i), self.assertRaises(ValueError):
                current._reassociation(root, SELECTOR, ref, data, historical, first_root, first_map)

    def altered_document(self, relative, mutation):
        # Deliberately bypass one synthetic file-hash read to exercise semantic
        # guards independently. Production closure/hash gates are not patched.
        root, ref, mapping, historical, first_root, first_map = self.material_fixture()
        original = old._file
        value=json.loads((root/relative).read_bytes());mutation(value)
        def read(directory, row, read=False):
            if Path(directory)==root and row['path']==relative and read:
                return json.dumps(value).encode()
            return original(directory,row,read=read)
        with mock.patch.object(old,'_file',side_effect=read), self.assertRaises(ValueError):
            current._reassociation(root, SELECTOR, ref, mapping, historical, first_root, first_map)

    def test_new_acquisition_cannot_relabel_old_or_invent_download(self):
        mutations=[lambda a:a.update(newDownloads=0),lambda a:a.update(newDownloads=True),lambda a:a.update(historicalReceiptsUnmodified=False),
            lambda a:a['newSources'].clear(),lambda a:a['newSources'][0].update(name='jansson-2.15.0.tar.gz'),
            lambda a:a['newSources'][0].update(requestedURL='https://foreign.example/source'),
            lambda a:a['newSources'][0].update(sha512='0'*128),lambda a:a['references'].clear()]
        for i,mutation in enumerate(mutations):
            with self.subTest(i=i):self.altered_document('source-acquisition.json',mutation)

    def test_actual_get_terminal_redirect_and_secret_boundaries(self):
        mutations=[lambda r:r.update(HTTP=206),lambda r:r.update(fullGet=False),lambda r:r.update(openResponseAndBodyClosed=None),
            lambda r:r.update(status='FAILED'),lambda r:r.update(errorType='TimeoutError'),lambda r:r.update(sha512='0'*128),
            lambda r:r.update(effectiveURLRedacted='https://github.com/other'),lambda r:r['redirects'].clear(),
            lambda r:r['redirects'][0].update(queryOmitted=False),lambda r:r['responseHeaders'].update(Location='https://signed/?token=secret'),
            lambda r:r['redirects'][0].update(to='https://foreign.example/x')]
        for i,mutation in enumerate(mutations):
            with self.subTest(i=i):self.altered_document('http/jansson-source-result.json',mutation)
        for mutation in (lambda r:r.update(url='https://foreign.example/x'),lambda r:r.update(retry=True),lambda r:r.update(expectedSHA256='0'*64)):
            self.altered_document('http/jansson-source-request.json',mutation)

    def test_new_notice_cannot_drop_original_or_switch_archive(self):
        mutations=[lambda n:n.update(newNotices=0),lambda n:n['files'].clear(),lambda n:n['files'][0].update(archiveMember='jansson-2.15.0/LICENSE'),
            lambda n:n['files'][0].update(sourceArchiveSHA256='0'*64),lambda n:n['references'].clear()]
        for i,mutation in enumerate(mutations):
            with self.subTest(i=i):self.altered_document('notice-inventory.json',mutation)
        notice=(ROOT/current.DIRECTORY/'notices/jansson-2.15.1/LICENSE').read_text()
        self.assertIn('Lucent',notice)
        self.assertIn('Permission is hereby granted',notice)

    def test_each_new_original_is_in_checked_file_closure(self):
        expected={'sources/jansson-2.15.1.tar.gz','http/jansson-source-request.json','http/jansson-source-result.json',
                  'notices/jansson-2.15.1/LICENSE','aports/71e8557e8e44bbe04bffec34b6b2693798611f62/main/jansson/APKBUILD'}
        self.assertTrue(expected.issubset({r['path'] for r in SELECTOR['files']}))
        for name in sorted(expected):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                for directory in (old.DIRECTORY,registry.DIRECTORY,ancestor.DIRECTORY,previous.DIRECTORY,current.DIRECTORY):
                    shutil.copytree(ROOT/directory,root/directory)
                p=root/current.DIRECTORY/name;p.write_bytes(p.read_bytes()+b'x')
                with self.assertRaises(ValueError):load(publisher_root=root)
