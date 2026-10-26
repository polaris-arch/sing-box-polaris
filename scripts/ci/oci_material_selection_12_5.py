"""Exact 332935 OCI source reassociation; old source bytes are never new binaries."""
import copy
import gzip
import io
import os
from pathlib import Path
import re
import tarfile

import oci_material_supplement as legacy
import oci_material_registry as prior
import oci_material_selection_12_3 as previous

SOURCE = '332935c310e78e15319d434f33a9103329200931'
TREE = '6a8371b425370326528658e9b0cace926cf76b2d'
TAG = 'v1.15.0-polaris-alpha.12.5'
TAG_OBJECT = '76e4f7db6767472952d09e4cf35b2cf90c223fbf'
RUN_ID = 40320104873
ATTEMPT = 1
DIRECTORY = 'release/dependency-sources/oci/selections/40320104873-attempt1'
SELECTOR_BYTES = 10502
SELECTOR_SHA256 = 'b93cd6b8337e404829cdf804b09c74ff5ae6805b89bc733a2aae1c95cd3d11a4'
SCHEMA = 'polaris-exact-oci-source-reassociation-12.5-policy-v1'
_require = legacy._require


def _selector_record():
    return {'path': 'selection-manifest.json', 'bytes': SELECTOR_BYTES, 'sha256': SELECTOR_SHA256}


def _historical_sources(source_root, publisher_root):
    """Validate source bytes through 12.3 without inventing historical API freshness."""
    second, second_ref, first_root, first_map, members = previous._historical_sources(source_root, publisher_root)
    root = legacy._path(publisher_root, previous.DIRECTORY)
    selector = legacy._json(legacy._file(root, previous._selector_record(), read=True))
    prior._current_closure(root, selector)
    reference = legacy._json(legacy._file(root, selector['materialReference'], read=True))
    material_map = legacy._json(legacy._file(root, selector['materialMap'], read=True))
    previous._reassociation(root, selector, reference, material_map, second_ref, first_root, first_map)
    for key in ('sourceAcquisition', 'noticeInventory'):
        for row in legacy._json(legacy._file(root, selector[key], read=True))['references']:
            legacy._file(publisher_root, row)
    members += [(root, row, previous.DIRECTORY + '/' + row['path']) for row in selector['files']]
    members += [(root, previous._selector_record(), previous.DIRECTORY + '/selection-manifest.json')]
    return selector, reference, root, material_map, members


def _reassociation(root, selector, reference, material_map, historical, _first_root, _first_map):
    _require(reference['schema'] == 'polaris-current-oci-material-reference-v1'
             and material_map['schema'] == 'polaris-exact-oci-source-reassociation-v1'
             and reference['materialMapSHA256'] == selector['materialMap']['sha256'], '332935 reference/map mismatch')
    for document in (reference, material_map):
        _require((document['sourceCommit'], document['producerRunId'], document['producerAttempt']) == (SOURCE, RUN_ID, ATTEMPT)
                 and type(document['producerRunId']) is int and type(document['producerAttempt']) is int
                 and document['legalConclusion'] is False, '332935 material identity mismatch')
    _require(material_map['sharedMaterials'] == selector['sharedMaterials'] and material_map['newRecipeCount'] == 0
             and material_map['crossArchitectureSourceAssociations'] == [], '332935 source reuse identity mismatch')
    _require(set(reference['artifacts']) == legacy.ARTIFACT_NAMES, '332935 exact image scope required')
    exact = []
    for name, row in sorted(reference['artifacts'].items()):
        old = historical['artifacts'][name]
        _require(all(row[key] == old[key] for key in ('platform', 'repositories', 'baseDependencies')),
                 '332935 platform/repository/base drift')
        _require(all(row[key] == value for key, value in selector['artifacts'][name].items()), '332935 actual image binding differs')
        packages = row['packages']
        for package in packages:
            legacy._package(package)
        _require(len(packages) == len({p['P'] for p in packages}) == 27
                 and packages == sorted(packages, key=lambda p: (p['P'], p['V'], p['A']))
                 and packages == old['packages'], '332935 exact seven-field package set differs')
        exact += [{'artifact': name, 'package': p} for p in packages]
    _require(len(exact) == 243 and exact == material_map['exactPackageAssociations'], '332935 association closure differs')
    for key, filename, schema in (
            ('sourceAcquisition', 'source-acquisition.json', 'polaris-reused-source-acquisition-v1'),
            ('noticeInventory', 'notice-inventory.json', 'polaris-reused-notice-inventory-v1')):
        document = legacy._json(legacy._file(root, selector[key], read=True))
        _require(document['schema'] == schema
                 and (document['sourceCommit'], document['producerRunId'], document['producerAttempt']) == (SOURCE, RUN_ID, ATTEMPT)
                 and document['legalConclusion'] is False
                 and [r['path'] for r in document['references']] == [previous.DIRECTORY + '/' + filename],
                 '332935 historical source/notice references differ')
        _require(document.get('newDownloads') == 0 and document.get('historicalReceiptsUnmodified') is True
                 if key == 'sourceAcquisition' else document.get('newNotices') == 0, '332935 must not invent acquisitions/notices')


def _load(artifacts, source_root, publisher_root):
    root = legacy._path(publisher_root, DIRECTORY)
    selector = legacy._json(legacy._file(root, _selector_record(), read=True))
    prior._current_closure(root, selector)
    _require(selector['schema'] == 'polaris-exact-oci-source-reassociation-selection-v1'
             and selector['directory'] == DIRECTORY and selector['legalConclusion'] is False, '332935 selector schema mismatch')
    binding = selector['binding']
    _require(tuple(binding[k] for k in ('repository', 'repositoryId', 'sourceCommit', 'sourceTree', 'tag', 'tagObject',
             'producerRunId', 'producerAttempt', 'workflowPath')) == (legacy.REPOSITORY, legacy.REPOSITORY_ID,
             SOURCE, TREE, TAG, TAG_OBJECT, RUN_ID, ATTEMPT, legacy.WORKFLOW), '332935 selection tuple mismatch')
    second, historical, first_root, first_map, members = _historical_sources(source_root, publisher_root)
    expected_shared = {'selector': {'path': previous.DIRECTORY + '/selection-manifest.json', 'bytes': previous.SELECTOR_BYTES,
        'sha256': previous.SELECTOR_SHA256}, 'sourceCommit': previous.SOURCE, 'producerRunId': previous.RUN_ID,
        'producerAttempt': previous.ATTEMPT, 'relabelled': False}
    _require(selector['sharedMaterials'] == expected_shared and selector['coreBindingPolicy'] == second['coreBindingPolicy'],
             '332935 historical ownership/core boundary differs')
    reference_path = legacy._file(root, selector['materialReference'])
    map_path = legacy._file(root, selector['materialMap'])
    reference = legacy._json(reference_path.read_bytes())
    material_map = legacy._json(map_path.read_bytes())
    _reassociation(root, selector, reference, material_map, historical, first_root, first_map)
    for key in ('sourceAcquisition', 'noticeInventory'):
        for row in legacy._json(legacy._file(root, selector[key], read=True))['references']:
            legacy._file(publisher_root, row)
    rows = selector['artifacts']
    _require(set(rows) == legacy.ARTIFACT_NAMES and isinstance(artifacts, list) and len(artifacts) == 9, '332935 requires exact nine OCI APIs')
    names, ids = set(), set()
    for a in artifacts:
        name, ident = a.get('name'), a.get('id')
        _require(name in rows and name not in names and type(ident) is int and ident not in ids, '332935 unknown/duplicate artifact')
        names.add(name); ids.add(ident)
        row, run = rows[name], a.get('workflow_run', {})
        _require((ident, a.get('size_in_bytes'), a.get('digest')) == (row['artifactId'], row['archiveBytes'], row['artifactAPIDigest'])
                 and row['artifactAPIDigest'] == 'sha256:' + row['archiveSHA256'], '332935 artifact bytes identity changed')
        _require((run.get('id'), run.get('head_sha'), run.get('repository_id'), run.get('head_repository_id')) ==
                 (RUN_ID, SOURCE, legacy.REPOSITORY_ID, legacy.REPOSITORY_ID) and a.get('expired') is False, '332935 artifact origin/expiry differs')
    members += [(root, row, DIRECTORY + '/' + row['path']) for row in selector['files']]
    members += [(root, _selector_record(), DIRECTORY + '/selection-manifest.json')]
    _require(len(members) == len({name for _, _, name in members}) == 83, '332935 bundle closure mismatch')
    tar_body = 0
    for _, row, name in members:
        info = tarfile.TarInfo(name); info.size = row['bytes']
        info.tobuf(format=tarfile.USTAR_FORMAT, encoding='ascii', errors='strict')
        tar_body += 512 + ((row['bytes'] + 511) // 512) * 512
    tar_bytes = ((tar_body + 1024 + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE
    bound = tar_bytes + ((tar_bytes + 7) >> 3) + ((tar_bytes + 63) >> 6) + 64
    return {'schema': SCHEMA, 'directory': root, 'publisher_root': Path(publisher_root), 'source_root': Path(source_root),
        'selector': selector, 'selector_sha256': SELECTOR_SHA256, 'binding': binding, 'reference_path': reference_path,
        'material_map_path': map_path, 'artifacts': rows, 'bundle_tar_bytes': tar_bytes, 'bundle_maximum_bytes': bound,
        '_api': copy.deepcopy(artifacts)}, members


def load_for_run(source, tree, tag, tag_object, run_id, attempt, workflow, artifacts, source_root, publisher_root):
    _require(type(run_id) is int and type(attempt) is int and (source, tree, tag, tag_object, run_id, attempt, workflow) ==
             (SOURCE, TREE, TAG, TAG_OBJECT, RUN_ID, ATTEMPT, legacy.WORKFLOW), '332935 wrong product/run tuple')
    return _load(artifacts, source_root, publisher_root)[0]


def _checked(policy):
    _require(isinstance(policy, dict) and policy.get('schema') == SCHEMA, '332935 invalid policy')
    actual, members = _load(policy['_api'], policy['source_root'], policy['publisher_root'])
    _require({k: v for k, v in policy.items() if k != '_written_bundle'} == actual, '332935 policy changed after validation')
    return actual, members


def bundle_name(policy):
    _checked(policy)
    return 'polaris-oci-material-supplement-40320104873-attempt1.tar.gz'


def check_image(policy, artifact_name, actual_image_path):
    actual, _ = _checked(policy)
    _require(artifact_name in actual['artifacts'], '332935 unknown image')
    row = actual['artifacts'][artifact_name]
    _require(legacy._digest_file(actual_image_path, row['imageBytes']) == (row['imageBytes'], row['imageSHA256']), '332935 actual image bytes differ')
    return row


def write_bundle(policy, path):
    actual, members = _checked(policy)
    path = Path(path)
    _require(not path.exists() and not path.is_symlink() and all(not path.resolve().is_relative_to(root.resolve())
             for root, _, _ in members), '332935 unsafe bundle destination')
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
        _require(size <= actual['bundle_maximum_bytes'], '332935 bundle exceeds admitted bound')
    except BaseException as primary:
        if identity is not None:
            try:
                info = path.lstat()
                if (info.st_dev, info.st_ino) == identity: path.unlink()
            except FileNotFoundError:
                pass
            except OSError as error:
                primary.add_note('332935 partial bundle cleanup failed: ' + str(error))
        raise
    policy['_written_bundle'] = {'path': path.resolve(), 'name': path.name, 'bytes': size, 'sha256': hashed}
    return {k: v for k, v in policy['_written_bundle'].items() if k != 'path'}


def record(policy, publisher_sha, bundle_path):
    _require(re.fullmatch('[0-9a-f]{40}', publisher_sha or '') is not None, '332935 publisher SHA required')
    actual, members = _checked(policy)
    bundle = policy.get('_written_bundle')
    _require(bundle is not None and Path(bundle_path).resolve() == bundle['path'], '332935 bundle not written by policy')
    _require(legacy._digest_file(bundle_path, bundle['bytes']) == (bundle['bytes'], bundle['sha256']), '332935 bundle bytes changed')
    expected = {name: row for _, row, name in members}
    with tarfile.open(bundle_path, 'r:gz') as archive:
        entries = archive.getmembers()
        _require(len(entries) == len(expected) and {m.name for m in entries} == set(expected), '332935 bundle entries differ')
        for member in entries:
            row = expected[member.name]
            _require(member.isfile() and member.size == row['bytes'] and member.mode == 0o644 and member.uid == member.gid == member.mtime == 0
                     and not member.uname and not member.gname, '332935 bundle metadata differs')
            data = archive.extractfile(member).read()
            _require((len(data), legacy._sha(data)) == (row['bytes'], row['sha256']), '332935 bundle member differs')
    s, b = actual['selector'], actual['binding']
    base = f'https://github.com/{legacy.REPOSITORY}/blob/{publisher_sha}/'
    return {'schema': 'polaris-oci-material-supplement-receipt-v1', 'policy': 'exact-40320104873-attempt1-no-fallback',
        'sourceCommit': SOURCE, 'sourceTree': TREE, 'tag': TAG, 'tagObject': TAG_OBJECT, 'producerRunId': RUN_ID,
        'producerAttempt': ATTEMPT, 'publisherCommit': publisher_sha, 'publisherImmutableURL': f'https://github.com/{legacy.REPOSITORY}/tree/{publisher_sha}/{DIRECTORY}',
        'selector': dict(_selector_record(), path=DIRECTORY + '/selection-manifest.json', url=base + DIRECTORY + '/selection-manifest.json'),
        'sharedMaterials': s['sharedMaterials'], 'materialMap': dict(s['materialMap'], path=DIRECTORY + '/' + s['materialMap']['path']),
        'materialReference': dict(s['materialReference'], path=DIRECTORY + '/' + s['materialReference']['path']),
        'sourceAcquisition': dict(s['sourceAcquisition'], path=DIRECTORY + '/' + s['sourceAcquisition']['path']),
        'noticeInventory': dict(s['noticeInventory'], path=DIRECTORY + '/' + s['noticeInventory']['path']),
        'nativeIndexSHA256': b['nativeIndexSHA256'], 'sourceArchive': b['sourceArchive'],
        'auditBundle': {k: bundle[k] for k in ('name', 'bytes', 'sha256')}, 'artifactCount': 9, 'packageAssociationCount': 243,
        'sharedPackageAssociationCount': 243, 'crossArchitectureSourceAssociationCount': 0, 'newRecipeCount': 0,
        'coreBindingPolicy': s['coreBindingPolicy'], 'publicReleaseAssetSetUnchanged': True, 'ociSeparateDistributionChannel': True, 'legalConclusion': False}
