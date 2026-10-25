"""Exact 368 OCI source reassociation; old source bytes are never new binaries."""
import copy
import gzip
import io
import os
from pathlib import Path
import re
import tarfile

import oci_material_supplement as legacy
import oci_material_registry as prior

SOURCE = '368b2489784dbe06498a18e83cc2257f94868c46'
TREE = 'b1881f23288fafffd950084e952ffb46ba0f2533'
TAG = 'v1.15.0-polaris-alpha.12.3'
TAG_OBJECT = 'd8fb7545ae552b3311548624e3576cb8dabd0bc5'
RUN_ID = 40164108947
ATTEMPT = 1
DIRECTORY = 'release/dependency-sources/oci/selections/40164108947-attempt1'
SELECTOR_BYTES = 10502
SELECTOR_SHA256 = '962b390487b40ce7dd370f139d90c02cf963da8e4f16af9bb2df0920af5d3314'
SCHEMA = 'polaris-exact-oci-source-reassociation-policy-v1'
_require = legacy._require


def _selector_record():
    return {'path': 'selection-manifest.json', 'bytes': SELECTOR_BYTES, 'sha256': SELECTOR_SHA256}


def _historical_sources(source_root, publisher_root):
    """Verify immutable source closures only; do not synthesize old API freshness."""
    first_root = legacy._path(publisher_root, legacy.DIRECTORY)
    first = legacy._json(legacy._file(first_root, {'path': 'selection-manifest.json',
        'bytes': legacy.SELECTOR_BYTES, 'sha256': legacy.SELECTOR_SHA256}, read=True))
    legacy._closure(first_root, first)
    first_ref = legacy._json(legacy._file(first_root, first['materialReference'], read=True))
    first_map = legacy._json(legacy._file(first_root, first['materialMap'], read=True))
    legacy._materials(first_root, Path(source_root), first, first_ref, first_map)
    second_root = legacy._path(publisher_root, prior.DIRECTORY)
    second = legacy._json(legacy._file(second_root, prior._selector_record(), read=True))
    prior._current_closure(second_root, second)
    second_ref = legacy._json(legacy._file(second_root, second['materialReference'], read=True))
    second_map = legacy._json(legacy._file(second_root, second['materialMap'], read=True))
    prior._delta_materials(second_root, second, second_ref, second_map, first_ref)
    members = [(first_root, r, legacy.DIRECTORY + '/' + r['path']) for r in first['files']]
    members += [(first_root, {'path': 'selection-manifest.json', 'bytes': legacy.SELECTOR_BYTES,
                              'sha256': legacy.SELECTOR_SHA256}, legacy.DIRECTORY + '/selection-manifest.json')]
    members += [(second_root, r, prior.DIRECTORY + '/' + r['path']) for r in second['files']]
    members += [(second_root, prior._selector_record(), prior.DIRECTORY + '/selection-manifest.json')]
    return second, second_ref, first_root, first_map, members


def _reassociation(root, selector, reference, material_map, previous, first_root, first_map):
    _require(reference['schema'] == 'polaris-current-oci-material-reference-v1'
             and material_map['schema'] == 'polaris-exact-oci-source-reassociation-v1'
             and reference['materialMapSHA256'] == selector['materialMap']['sha256'], '368 reference/map mismatch')
    for document in (reference, material_map):
        _require((document['sourceCommit'], document['producerRunId'], document['producerAttempt']) == (SOURCE, RUN_ID, ATTEMPT)
                 and type(document['producerRunId']) is int and type(document['producerAttempt']) is int
                 and document['legalConclusion'] is False, '368 material identity mismatch')
    _require(material_map['sharedMaterials'] == selector['sharedMaterials'] and material_map['newRecipeCount'] == 0,
             '368 source reuse identity mismatch')
    _require(set(reference['artifacts']) == legacy.ARTIFACT_NAMES, '368 exact image scope required')
    exact, cross, changed_bases = [], [], []
    for name, row in sorted(reference['artifacts'].items()):
        old = previous['artifacts'][name]
        _require(row['platform'] == old['platform'] and row['repositories'] == old['repositories'], '368 platform/repository drift')
        _require(all(row[key] == value for key, value in selector['artifacts'][name].items()), '368 actual image binding differs')
        dependencies = row['baseDependencies']
        _require(len(dependencies) == 1 and dependencies[0]['uri'] == old['baseDependencies'][0]['uri'], '368 base URI drift')
        if dependencies != old['baseDependencies']:
            _require(name != 'oci-linux-loong64' and dependencies[0]['digest'] == {
                'sha256': 'be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a'}, '368 unreviewed base digest')
            changed_bases.append(name)
        packages = row['packages']
        for package in packages:
            legacy._package(package)
        _require(len(packages) == len({p['P'] for p in packages}) == 27
                 and packages == sorted(packages, key=lambda p: (p['P'], p['V'], p['A'])), '368 package set/order mismatch')
        for package in packages:
            association = {'artifact': name, 'package': package}
            if package in old['packages']:
                exact.append(association)
                continue
            _require(name == 'oci-linux-riscv64' and package['A'] == 'riscv64'
                     and package['P'] in {'alpine-release', 'ca-certificates-bundle', 'musl-utils', 'zlib'}, '368 unreviewed package delta')
            matches = [r for r in material_map['crossArchitectureSourceAssociations']
                       if r['artifact'] == name and r['package'] == package]
            _require(len(matches) == 1, '368 cross-architecture source association missing/duplicate')
            record = matches[0]
            old_association = record['sourceAssociation']
            old_package = old_association['package']
            _require(old_package in previous['artifacts'][old_association['artifact']]['packages']
                     and old_package['A'] != package['A']
                     and all(package[k] == old_package[k] for k in ('P', 'V', 'L', 'o', 'c')), '368 recipe identity cannot be reused')
            recipes = [r for r in first_map['newRecipes'] if (r['origin'], r['commit']) == (package['o'], package['c'])]
            _require(len(recipes) == 1, '368 source recipe is not in verified historical closure')
            recipe = recipes[0]
            _require(record['recipe'] == {'selector': legacy.DIRECTORY + '/selection-manifest.json',
                'origin': package['o'], 'commit': package['c'], 'directoryTreeSHA': recipe['directoryTreeSHA']}, '368 recipe tree reference differs')
            apkbuild = [f for f in recipe['files'] if f['path'].endswith('/APKBUILD')]
            _require(len(apkbuild) == 1, '368 ambiguous recipe')
            text = legacy._file(first_root, apkbuild[0], read=True).decode('utf-8')
            _require(re.findall(r'^arch="([^"]+)"$', text, re.M) in (['all'], ['noarch']), '368 recipe architecture not reviewed')
            cross.append(record)
    _require(len(changed_bases) == 8 and len(exact) == 239 and len(cross) == 4
             and exact == material_map['exactPackageAssociations']
             and cross == material_map['crossArchitectureSourceAssociations'], '368 association closure differs')
    expected_refs = {
        'sourceAcquisition': [legacy.DIRECTORY + '/source-acquisition.json', legacy.DIRECTORY + '/http-get-receipts.json', prior.DIRECTORY + '/source-acquisition.json'],
        'noticeInventory': [legacy.DIRECTORY + '/notice-inventory.json', prior.DIRECTORY + '/notice-inventory.json']}
    for key, paths in expected_refs.items():
        document = legacy._json(legacy._file(root, selector[key], read=True))
        _require((document['sourceCommit'], document['producerRunId'], document['producerAttempt']) == (SOURCE, RUN_ID, ATTEMPT)
                 and document['legalConclusion'] is False and [r['path'] for r in document['references']] == paths,
                 '368 source/notice historical references differ')
        _require(document.get('newDownloads') == 0 and document.get('historicalReceiptsUnmodified') is True
                 if key == 'sourceAcquisition' else document.get('newNotices') == 0, '368 must not invent acquisitions/notices')


def _load(artifacts, source_root, publisher_root):
    root = legacy._path(publisher_root, DIRECTORY)
    selector = legacy._json(legacy._file(root, _selector_record(), read=True))
    prior._current_closure(root, selector)
    _require(selector['schema'] == 'polaris-exact-oci-source-reassociation-selection-v1'
             and selector['directory'] == DIRECTORY and selector['legalConclusion'] is False, '368 selector schema mismatch')
    binding = selector['binding']
    _require(tuple(binding[k] for k in ('repository', 'repositoryId', 'sourceCommit', 'sourceTree', 'tag', 'tagObject',
             'producerRunId', 'producerAttempt', 'workflowPath')) == (legacy.REPOSITORY, legacy.REPOSITORY_ID,
             SOURCE, TREE, TAG, TAG_OBJECT, RUN_ID, ATTEMPT, legacy.WORKFLOW), '368 selection tuple mismatch')
    second, previous, first_root, first_map, members = _historical_sources(source_root, publisher_root)
    expected_shared = {'selector': {'path': prior.DIRECTORY + '/selection-manifest.json', 'bytes': prior.SELECTOR_BYTES,
        'sha256': prior.SELECTOR_SHA256}, 'sourceCommit': prior.SOURCE, 'producerRunId': prior.RUN_ID,
        'producerAttempt': prior.ATTEMPT, 'relabelled': False}
    _require(selector['sharedMaterials'] == expected_shared and selector['coreBindingPolicy'] == second['coreBindingPolicy'],
             '368 historical ownership/core boundary differs')
    reference_path = legacy._file(root, selector['materialReference'])
    map_path = legacy._file(root, selector['materialMap'])
    reference = legacy._json(reference_path.read_bytes())
    material_map = legacy._json(map_path.read_bytes())
    _reassociation(root, selector, reference, material_map, previous, first_root, first_map)
    for key in ('sourceAcquisition', 'noticeInventory'):
        for row in legacy._json(legacy._file(root, selector[key], read=True))['references']:
            legacy._file(publisher_root, row)
    rows = selector['artifacts']
    _require(set(rows) == legacy.ARTIFACT_NAMES and isinstance(artifacts, list) and len(artifacts) == 9, '368 requires exact nine OCI APIs')
    names, ids = set(), set()
    for a in artifacts:
        name, ident = a.get('name'), a.get('id')
        _require(name in rows and name not in names and type(ident) is int and ident not in ids, '368 unknown/duplicate artifact')
        names.add(name); ids.add(ident)
        row, run = rows[name], a.get('workflow_run', {})
        _require((ident, a.get('size_in_bytes'), a.get('digest')) == (row['artifactId'], row['archiveBytes'], row['artifactAPIDigest'])
                 and row['artifactAPIDigest'] == 'sha256:' + row['archiveSHA256'], '368 artifact bytes identity changed')
        _require((run.get('id'), run.get('head_sha'), run.get('repository_id'), run.get('head_repository_id')) ==
                 (RUN_ID, SOURCE, legacy.REPOSITORY_ID, legacy.REPOSITORY_ID) and a.get('expired') is False, '368 artifact origin/expiry differs')
    members += [(root, row, DIRECTORY + '/' + row['path']) for row in selector['files']]
    members += [(root, _selector_record(), DIRECTORY + '/selection-manifest.json')]
    _require(len(members) == len({name for _, _, name in members}) == 78, '368 bundle closure mismatch')
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
             (SOURCE, TREE, TAG, TAG_OBJECT, RUN_ID, ATTEMPT, legacy.WORKFLOW), '368 wrong product/run tuple')
    return _load(artifacts, source_root, publisher_root)[0]


def _checked(policy):
    _require(isinstance(policy, dict) and policy.get('schema') == SCHEMA, '368 invalid policy')
    actual, members = _load(policy['_api'], policy['source_root'], policy['publisher_root'])
    _require({k: v for k, v in policy.items() if k != '_written_bundle'} == actual, '368 policy changed after validation')
    return actual, members


def bundle_name(policy):
    _checked(policy)
    return 'polaris-oci-material-supplement-40164108947-attempt1.tar.gz'


def check_image(policy, artifact_name, actual_image_path):
    actual, _ = _checked(policy)
    _require(artifact_name in actual['artifacts'], '368 unknown image')
    row = actual['artifacts'][artifact_name]
    _require(legacy._digest_file(actual_image_path, row['imageBytes']) == (row['imageBytes'], row['imageSHA256']), '368 actual image bytes differ')
    return row


def write_bundle(policy, path):
    actual, members = _checked(policy)
    path = Path(path)
    _require(not path.exists() and not path.is_symlink() and all(not path.resolve().is_relative_to(root.resolve())
             for root, _, _ in members), '368 unsafe bundle destination')
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
        _require(size <= actual['bundle_maximum_bytes'], '368 bundle exceeds admitted bound')
    except BaseException as primary:
        if identity is not None:
            try:
                info = path.lstat()
                if (info.st_dev, info.st_ino) == identity: path.unlink()
            except FileNotFoundError:
                pass
            except OSError as error:
                primary.add_note('368 partial bundle cleanup failed: ' + str(error))
        raise
    policy['_written_bundle'] = {'path': path.resolve(), 'name': path.name, 'bytes': size, 'sha256': hashed}
    return {k: v for k, v in policy['_written_bundle'].items() if k != 'path'}


def record(policy, publisher_sha, bundle_path):
    _require(re.fullmatch('[0-9a-f]{40}', publisher_sha or '') is not None, '368 publisher SHA required')
    actual, members = _checked(policy)
    bundle = policy.get('_written_bundle')
    _require(bundle is not None and Path(bundle_path).resolve() == bundle['path'], '368 bundle not written by policy')
    _require(legacy._digest_file(bundle_path, bundle['bytes']) == (bundle['bytes'], bundle['sha256']), '368 bundle bytes changed')
    expected = {name: row for _, row, name in members}
    with tarfile.open(bundle_path, 'r:gz') as archive:
        entries = archive.getmembers()
        _require(len(entries) == len(expected) and {m.name for m in entries} == set(expected), '368 bundle entries differ')
        for member in entries:
            row = expected[member.name]
            _require(member.isfile() and member.size == row['bytes'] and member.mode == 0o644 and member.uid == member.gid == member.mtime == 0
                     and not member.uname and not member.gname, '368 bundle metadata differs')
            data = archive.extractfile(member).read()
            _require((len(data), legacy._sha(data)) == (row['bytes'], row['sha256']), '368 bundle member differs')
    s, b = actual['selector'], actual['binding']
    base = f'https://github.com/{legacy.REPOSITORY}/blob/{publisher_sha}/'
    return {'schema': 'polaris-oci-material-supplement-receipt-v1', 'policy': 'exact-40164108947-attempt1-no-fallback',
        'sourceCommit': SOURCE, 'sourceTree': TREE, 'tag': TAG, 'tagObject': TAG_OBJECT, 'producerRunId': RUN_ID,
        'producerAttempt': ATTEMPT, 'publisherCommit': publisher_sha, 'publisherImmutableURL': f'https://github.com/{legacy.REPOSITORY}/tree/{publisher_sha}/{DIRECTORY}',
        'selector': dict(_selector_record(), path=DIRECTORY + '/selection-manifest.json', url=base + DIRECTORY + '/selection-manifest.json'),
        'sharedMaterials': s['sharedMaterials'], 'materialMap': dict(s['materialMap'], path=DIRECTORY + '/' + s['materialMap']['path']),
        'materialReference': dict(s['materialReference'], path=DIRECTORY + '/' + s['materialReference']['path']),
        'sourceAcquisition': dict(s['sourceAcquisition'], path=DIRECTORY + '/' + s['sourceAcquisition']['path']),
        'noticeInventory': dict(s['noticeInventory'], path=DIRECTORY + '/' + s['noticeInventory']['path']),
        'nativeIndexSHA256': b['nativeIndexSHA256'], 'sourceArchive': b['sourceArchive'],
        'auditBundle': {k: bundle[k] for k in ('name', 'bytes', 'sha256')}, 'artifactCount': 9, 'packageAssociationCount': 243,
        'sharedPackageAssociationCount': 239, 'crossArchitectureSourceAssociationCount': 4, 'newRecipeCount': 0,
        'coreBindingPolicy': s['coreBindingPolicy'], 'publicReleaseAssetSetUnchanged': True, 'ociSeparateDistributionChannel': True, 'legalConclusion': False}
