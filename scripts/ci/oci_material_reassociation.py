"""Exact, immutable OCI reassociation without new recipes or copied historical material."""
import copy
from dataclasses import dataclass
import gzip
import io
import os
from pathlib import Path
import re
import tarfile
from release_identity import same_identity

import oci_material_supplement as legacy
import oci_material_registry as prior

_require = legacy._require


def _image_identity(row):
    _require(type(row) is dict and set(row) == {
        'artifactId', 'archiveBytes', 'archiveSHA256', 'artifactAPIDigest', 'coreBytes', 'coreSHA256',
        'imageBytes', 'imageSHA256', 'imageManifest', 'installedSHA256', 'platform'},
        'OCI graph identity fields differ')
    _require(all(type(row[key]) is int and row[key] > 0
                 for key in ('artifactId', 'archiveBytes', 'coreBytes', 'imageBytes')),
             'OCI graph identity count/type differs')
    _require(all(type(row[key]) is str and re.fullmatch('[0-9a-f]{64}', row[key])
                 for key in ('archiveSHA256', 'coreSHA256', 'imageSHA256', 'installedSHA256'))
             and all(type(row[key]) is str and re.fullmatch('sha256:[0-9a-f]{64}', row[key])
                     for key in ('artifactAPIDigest', 'imageManifest')), 'OCI graph digest identity differs')
    _require(type(row['platform']) is dict and set(row['platform']) in (
        {'os', 'architecture'}, {'os', 'architecture', 'variant'})
        and all(type(value) is str and value for value in row['platform'].values()), 'OCI graph platform identity differs')


@dataclass(frozen=True)
class OCIReassociation:
    source: str
    tree: str
    tag: str
    tag_object: str
    run_id: int
    attempt: int
    directory: str
    selector_bytes: int
    selector_sha256: str
    schema: str
    previous: object
    bundle_members: int
    reference_version: int = 1

    def _selector_record(self):
        return {'path': 'selection-manifest.json', 'bytes': self.selector_bytes, 'sha256': self.selector_sha256}


    def _historical_sources(self, source_root, publisher_root):
        """Validate the complete predecessor closure without inventing historical API freshness."""
        second, second_ref, first_root, first_map, members = self.previous._historical_sources(source_root, publisher_root)
        root = legacy._path(publisher_root, self.previous.DIRECTORY)
        selector = legacy._json(legacy._file(root, self.previous._selector_record(), read=True))
        prior._current_closure(root, selector)
        reference = legacy._json(legacy._file(root, selector['materialReference'], read=True))
        material_map = legacy._json(legacy._file(root, selector['materialMap'], read=True))
        self.previous._reassociation(root, selector, reference, material_map, second_ref, first_root, first_map)
        for key in ('sourceAcquisition', 'noticeInventory'):
            for row in legacy._json(legacy._file(root, selector[key], read=True))['references']:
                legacy._file(publisher_root, row)
        members += [(root, row, self.previous.DIRECTORY + '/' + row['path']) for row in selector['files']]
        members += [(root, self.previous._selector_record(), self.previous.DIRECTORY + '/selection-manifest.json')]
        return selector, reference, root, material_map, members


    def _resolve_reference(self, selector, reference, material_map, historical, historical_root):
        """Resolve only the exact predecessor file and all 243 ordered package references."""
        _require(type(reference) is dict and set(reference) == {
            'schema', 'sourceCommit', 'producerRunId', 'producerAttempt', 'legalConclusion',
            'materialMapSHA256', 'sharedReference', 'artifacts'}, 'OCI v2 reference fields differ')
        _require(type(material_map) is dict and set(material_map) == {
            'schema', 'sourceCommit', 'producerRunId', 'producerAttempt', 'legalConclusion',
            'sharedMaterials', 'newRecipeCount', 'crossArchitectureSourceAssociations',
            'packageAssociationCount', 'artifactPackageIndices'}, 'OCI v2 map fields differ')
        predecessor = legacy._json(legacy._file(historical_root, self.previous._selector_record(), read=True))
        original = predecessor['materialReference']
        expected = dict(original, path=self.previous.DIRECTORY + '/' + original['path'])
        _require(same_identity(reference['sharedReference'], expected), 'OCI v2 predecessor reference differs')
        raw = legacy._file(historical_root, original, read=True)
        _require(len(raw) <= 1024 * 1024 and same_identity(legacy._json(raw), historical),
                 'OCI v2 predecessor bytes/content differ')
        _require(same_identity(historical['schema'], 'polaris-current-oci-material-reference-v1')
                 and set(historical['artifacts']) == legacy.ARTIFACT_NAMES, 'OCI v2 predecessor scope/version differs')
        _require(type(material_map['newRecipeCount']) is int and same_identity(material_map['newRecipeCount'], 0),
                 'OCI v2 recipe count/type differs')
        mappings = material_map['artifactPackageIndices']
        _require(type(mappings) is dict and set(mappings) == legacy.ARTIFACT_NAMES
                 and type(reference['artifacts']) is dict and set(reference['artifacts']) == legacy.ARTIFACT_NAMES,
                 'OCI v2 artifact reference scope differs')
        resolved = dict(reference, artifacts={})
        total = 0
        for name in sorted(mappings):
            mapping = mappings[name]
            _require(type(mapping) is dict and set(mapping) == {'sourceArtifact', 'packageIndices'}
                     and same_identity(mapping['sourceArtifact'], name), 'OCI v2 artifact material reference differs')
            indices = mapping['packageIndices']
            _require(type(indices) is list and all(type(i) is int for i in indices)
                     and indices == list(range(27)), 'OCI v2 missing/duplicate/dangling package reference')
            old = historical['artifacts'][mapping['sourceArtifact']]
            packages = old['packages']
            _require(type(packages) is list and len(packages) == 27, 'OCI v2 predecessor package count differs')
            for package in packages:
                legacy._package(package)
            row = reference['artifacts'][name]
            _image_identity(row)
            _require(type(row) is dict and same_identity(row, selector['artifacts'][name]), 'OCI v2 image identity differs')
            resolved['artifacts'][name] = dict(row, baseDependencies=old['baseDependencies'],
                repositories=old['repositories'], packages=[packages[i] for i in indices])
            total += len(indices)
        _require(type(material_map['packageAssociationCount']) is int
                 and (same_identity(material_map['packageAssociationCount'], total) and same_identity(total, 243)), 'OCI v2 association count differs')
        return resolved


    def _reassociation(self, root, selector, reference, material_map, historical, _first_root, _first_map):
        _require(same_identity(reference['schema'], f'polaris-current-oci-material-reference-v{self.reference_version}')
                 and same_identity(material_map['schema'], f'polaris-exact-oci-source-reassociation-v{self.reference_version}')
                 and same_identity(reference['materialMapSHA256'], selector['materialMap']['sha256']), 'OCI reassociation reference/map mismatch')
        for document in (reference, material_map):
            _require(same_identity((document['sourceCommit'], document['producerRunId'], document['producerAttempt']), (self.source, self.run_id, self.attempt))
                     and type(document['producerRunId']) is int and type(document['producerAttempt']) is int
                     and document['legalConclusion'] is False, 'OCI reassociation material identity mismatch')
        _require(same_identity(material_map['sharedMaterials'], selector['sharedMaterials']) and same_identity(material_map['newRecipeCount'], 0)
                 and same_identity(material_map['crossArchitectureSourceAssociations'], []), 'OCI reassociation source reuse identity mismatch')
        if self.reference_version == 2:
            reference = self._resolve_reference(selector, reference, material_map, historical, _first_root)
        _require(set(reference['artifacts']) == legacy.ARTIFACT_NAMES, 'OCI reassociation exact image scope required')
        exact = []
        for name, row in sorted(reference['artifacts'].items()):
            old = historical['artifacts'][name]
            _require(all(same_identity(row[key], old[key]) for key in ('platform', 'repositories', 'baseDependencies')),
                     'OCI reassociation platform/repository/base drift')
            _require(all(same_identity(row[key], value) for key, value in selector['artifacts'][name].items()), 'OCI reassociation actual image binding differs')
            packages = row['packages']
            for package in packages:
                legacy._package(package)
            _require(len(packages) == len({p['P'] for p in packages}) == 27
                     and packages == sorted(packages, key=lambda p: (p['P'], p['V'], p['A']))
                     and same_identity(packages, old['packages']), 'OCI reassociation exact seven-field package set differs')
            exact += [{'artifact': name, 'package': p} for p in packages]
        _require(len(exact) == 243 and (self.reference_version == 2 or same_identity(exact, material_map['exactPackageAssociations'])),
                 'OCI reassociation association closure differs')
        for key, filename, schema in (
                ('sourceAcquisition', 'source-acquisition.json', 'polaris-reused-source-acquisition-v1'),
                ('noticeInventory', 'notice-inventory.json', 'polaris-reused-notice-inventory-v1')):
            document = legacy._json(legacy._file(root, selector[key], read=True))
            _require(same_identity(document['schema'], schema)
                     and same_identity((document['sourceCommit'], document['producerRunId'], document['producerAttempt']), (self.source, self.run_id, self.attempt))
                     and document['legalConclusion'] is False
                     and same_identity([r['path'] for r in document['references']], [self.previous.DIRECTORY + '/' + filename]),
                     'OCI reassociation historical source/notice references differ')
            _require(same_identity(document.get('newDownloads'), 0) and document.get('historicalReceiptsUnmodified') is True
                     if key == 'sourceAcquisition' else same_identity(document.get('newNotices'), 0), 'OCI reassociation must not invent acquisitions/notices')
        return reference


    def _load(self, artifacts, source_root, publisher_root):
        root = legacy._path(publisher_root, self.directory)
        selector = legacy._json(legacy._file(root, self._selector_record(), read=True))
        prior._current_closure(root, selector)
        _require(self.reference_version in (1, 2) and type(self.reference_version) is int
                 and same_identity(selector['schema'], f'polaris-exact-oci-source-reassociation-selection-v{self.reference_version}')
                 and same_identity(selector['directory'], self.directory) and selector['legalConclusion'] is False, 'OCI reassociation selector schema mismatch')
        _require(same_identity(selector['distributionBoundary'], {
            'appendOnlyPublisherDirectory': self.directory, 'ociDistribution': 'separate-channel',
            'publicReleaseAssetSet': 'unchanged',
            'auditDelivery': 'Existing authorized publisher audit mechanism or immutable GitHub source references to the exact independently reviewed publisher commit; no additional public Release assets.'}),
            'OCI reassociation distribution boundary differs')
        binding = selector['binding']
        _require(same_identity(tuple(binding[k] for k in ('repository', 'repositoryId', 'sourceCommit', 'sourceTree', 'tag', 'tagObject',
                 'producerRunId', 'producerAttempt', 'workflowPath')), (legacy.REPOSITORY, legacy.REPOSITORY_ID,
                 self.source, self.tree, self.tag, self.tag_object, self.run_id, self.attempt, legacy.WORKFLOW)), 'OCI reassociation selection tuple mismatch')
        source_archive = binding['sourceArchive']
        _require(type(source_archive) is dict and set(source_archive) == {'name', 'bytes', 'sha256'}
                 and type(source_archive['bytes']) is int and source_archive['bytes'] > 0
                 and source_archive['name'] == 'sing-box-polaris-source-' + self.source + '.tar.gz'
                 and type(source_archive['sha256']) is str and re.fullmatch('[0-9a-f]{64}', source_archive['sha256'])
                 and type(binding['nativeIndexSHA256']) is str and re.fullmatch('[0-9a-f]{64}', binding['nativeIndexSHA256']),
                 'OCI source/index identity type differs')
        second, historical, first_root, first_map, members = self._historical_sources(source_root, publisher_root)
        expected_shared = {'selector': {'path': self.previous.DIRECTORY + '/selection-manifest.json', 'bytes': self.previous.SELECTOR_BYTES,
            'sha256': self.previous.SELECTOR_SHA256}, 'sourceCommit': self.previous.SOURCE, 'producerRunId': self.previous.RUN_ID,
            'producerAttempt': self.previous.ATTEMPT, 'relabelled': False}
        _require(same_identity(selector['sharedMaterials'], expected_shared) and same_identity(selector['coreBindingPolicy'], second['coreBindingPolicy']),
                 'OCI reassociation historical ownership/core boundary differs')
        reference_path = legacy._file(root, selector['materialReference'])
        map_path = legacy._file(root, selector['materialMap'])
        reference_raw, map_raw = reference_path.read_bytes(), map_path.read_bytes()
        _require(len(reference_raw) <= 1024 * 1024 and len(map_raw) <= 1024 * 1024, 'OCI reassociation JSON budget exceeded')
        reference = legacy._json(reference_raw)
        material_map = legacy._json(map_raw)
        resolved = self._reassociation(root, selector, reference, material_map, historical, first_root, first_map)
        for key in ('sourceAcquisition', 'noticeInventory'):
            for row in legacy._json(legacy._file(root, selector[key], read=True))['references']:
                legacy._file(publisher_root, row)
        rows = selector['artifacts']
        _require(set(rows) == legacy.ARTIFACT_NAMES and isinstance(artifacts, list) and len(artifacts) == 9, 'OCI reassociation requires exact nine OCI APIs')
        names, ids = set(), set()
        for a in artifacts:
            name, ident = a.get('name'), a.get('id')
            _require(name in rows and name not in names and type(ident) is int and ident not in ids, 'OCI reassociation unknown/duplicate artifact')
            names.add(name); ids.add(ident)
            row, run = rows[name], a.get('workflow_run', {})
            _image_identity(row)
            _require(same_identity((ident, a.get('size_in_bytes'), a.get('digest')), (row['artifactId'], row['archiveBytes'], row['artifactAPIDigest']))
                     and same_identity(row['artifactAPIDigest'], 'sha256:' + row['archiveSHA256']), 'OCI reassociation artifact bytes identity changed')
            _require(same_identity((run.get('id'), run.get('head_sha'), run.get('repository_id'), run.get('head_repository_id')), (self.run_id, self.source, legacy.REPOSITORY_ID, legacy.REPOSITORY_ID)) and a.get('expired') is False, 'OCI reassociation artifact origin/expiry differs')
        members += [(root, row, self.directory + '/' + row['path']) for row in selector['files']]
        members += [(root, self._selector_record(), self.directory + '/selection-manifest.json')]
        _require(len(members) == len({name for _, _, name in members}) == self.bundle_members, 'OCI reassociation bundle closure mismatch')
        tar_body = 0
        for _, row, name in members:
            info = tarfile.TarInfo(name); info.size = row['bytes']
            info.tobuf(format=tarfile.USTAR_FORMAT, encoding='ascii', errors='strict')
            tar_body += 512 + ((row['bytes'] + 511) // 512) * 512
        tar_bytes = ((tar_body + 1024 + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE
        bound = tar_bytes + ((tar_bytes + 7) >> 3) + ((tar_bytes + 63) >> 6) + 64
        policy = {'schema': self.schema, 'directory': root, 'publisher_root': Path(publisher_root), 'source_root': Path(source_root),
            'selector': selector, 'selector_sha256': self.selector_sha256, 'binding': binding, 'reference_path': reference_path,
            'material_map_path': map_path, 'artifacts': rows, 'bundle_tar_bytes': tar_bytes, 'bundle_maximum_bytes': bound,
            '_api': copy.deepcopy(artifacts)}
        if self.reference_version == 2:
            policy['resolved_reference'] = resolved
        return policy, members


    def load_for_run(self, source, tree, tag, tag_object, run_id, attempt, workflow, artifacts, source_root, publisher_root):
        _require(type(run_id) is int and type(attempt) is int and same_identity((source, tree, tag, tag_object, run_id, attempt, workflow), (self.source, self.tree, self.tag, self.tag_object, self.run_id, self.attempt, legacy.WORKFLOW)), 'OCI reassociation wrong product/run tuple')
        return self._load(artifacts, source_root, publisher_root)[0]


    def _checked(self, policy):
        _require(isinstance(policy, dict) and same_identity(policy.get('schema'), self.schema), 'OCI reassociation invalid policy')
        actual, members = self._load(policy['_api'], policy['source_root'], policy['publisher_root'])
        _require(same_identity({k: v for k, v in policy.items() if k != '_written_bundle'}, actual), 'OCI reassociation policy changed after validation')
        return actual, members


    def bundle_name(self, policy):
        self._checked(policy)
        return f'polaris-oci-material-supplement-{self.run_id}-attempt{self.attempt}.tar.gz'


    def check_image(self, policy, artifact_name, actual_image_path):
        actual, _ = self._checked(policy)
        _require(artifact_name in actual['artifacts'], 'OCI reassociation unknown image')
        row = actual['artifacts'][artifact_name]
        _require(same_identity(legacy._digest_file(actual_image_path, row['imageBytes']), (row['imageBytes'], row['imageSHA256'])), 'OCI reassociation actual image bytes differ')
        return row


    def write_bundle(self, policy, path):
        actual, members = self._checked(policy)
        path = Path(path)
        _require(not path.exists() and not path.is_symlink() and all(not path.resolve().is_relative_to(root.resolve())
                 for root, _, _ in members), 'OCI reassociation unsafe bundle destination')
        identity = None
        try:
            with path.open('xb') as raw:
                info = os.fstat(raw.fileno()); identity = (info.st_dev, info.st_ino)
                with gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0, compresslevel=9) as compressed:
                    with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT, encoding='ascii') as archive:
                        for root, row, name in sorted(members, key=lambda item: item[2]):
                            data = legacy._file(root, row, read=True)
                            info = tarfile.TarInfo(name); info.size, info.mode, info.mtime = row['bytes'], 0o644, 0
                            info.uid = info.gid = 0; info.uname = info.gname = ''
                            archive.addfile(info, io.BytesIO(data))
            size, hashed = legacy._digest_file(path)
            _require(size <= actual['bundle_maximum_bytes'], 'OCI reassociation bundle exceeds admitted bound')
        except BaseException as primary:
            if identity is not None:
                try:
                    info = path.lstat()
                    if same_identity((info.st_dev, info.st_ino), identity): path.unlink()
                except FileNotFoundError:
                    pass
                except OSError as error:
                    primary.add_note('OCI reassociation partial bundle cleanup failed: ' + str(error))
            raise
        policy['_written_bundle'] = {'path': path.resolve(), 'name': path.name, 'bytes': size, 'sha256': hashed}
        return {k: v for k, v in policy['_written_bundle'].items() if k != 'path'}


    def record(self, policy, publisher_sha, bundle_path):
        _require(re.fullmatch('[0-9a-f]{40}', publisher_sha or '') is not None, 'OCI reassociation publisher SHA required')
        actual, members = self._checked(policy)
        bundle = policy.get('_written_bundle')
        _require(bundle is not None and same_identity(Path(bundle_path).resolve(), bundle['path']), 'OCI reassociation bundle not written by policy')
        _require(same_identity(legacy._digest_file(bundle_path, bundle['bytes']), (bundle['bytes'], bundle['sha256'])), 'OCI reassociation bundle bytes changed')
        expected = {name: row for _, row, name in members}
        with tarfile.open(bundle_path, 'r:gz') as archive:
            entries = archive.getmembers()
            _require(len(entries) == len(expected) and {m.name for m in entries} == set(expected), 'OCI reassociation bundle entries differ')
            for member in entries:
                row = expected[member.name]
                _require(member.isfile() and same_identity(member.size, row['bytes']) and member.mode == 0o644 and member.uid == member.gid == member.mtime == 0
                         and not member.uname and not member.gname, 'OCI reassociation bundle metadata differs')
                data = archive.extractfile(member).read()
                _require(same_identity((len(data), legacy._sha(data)), (row['bytes'], row['sha256'])), 'OCI reassociation bundle member differs')
        s, b = actual['selector'], actual['binding']
        base = f'https://github.com/{legacy.REPOSITORY}/blob/{publisher_sha}/'
        return {'schema': 'polaris-oci-material-supplement-receipt-v1', 'policy': f'exact-{self.run_id}-attempt{self.attempt}-no-fallback',
            'sourceCommit': self.source, 'sourceTree': self.tree, 'tag': self.tag, 'tagObject': self.tag_object, 'producerRunId': self.run_id,
            'producerAttempt': self.attempt, 'publisherCommit': publisher_sha, 'publisherImmutableURL': f'https://github.com/{legacy.REPOSITORY}/tree/{publisher_sha}/{self.directory}',
            'selector': dict(self._selector_record(), path=self.directory + '/selection-manifest.json', url=base + self.directory + '/selection-manifest.json'),
            'sharedMaterials': s['sharedMaterials'], 'materialMap': dict(s['materialMap'], path=self.directory + '/' + s['materialMap']['path']),
            'materialReference': dict(s['materialReference'], path=self.directory + '/' + s['materialReference']['path']),
            'sourceAcquisition': dict(s['sourceAcquisition'], path=self.directory + '/' + s['sourceAcquisition']['path']),
            'noticeInventory': dict(s['noticeInventory'], path=self.directory + '/' + s['noticeInventory']['path']),
            'nativeIndexSHA256': b['nativeIndexSHA256'], 'sourceArchive': b['sourceArchive'],
            'auditBundle': {k: bundle[k] for k in ('name', 'bytes', 'sha256')}, 'artifactCount': 9, 'packageAssociationCount': 243,
            'sharedPackageAssociationCount': 243, 'crossArchitectureSourceAssociationCount': 0, 'newRecipeCount': 0,
            'coreBindingPolicy': s['coreBindingPolicy'], 'publicReleaseAssetSetUnchanged': True, 'ociSeparateDistributionChannel': True, 'legalConclusion': False}
