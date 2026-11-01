"""Immutable OCI selections; current product identity is not material identity.

The original 814 supplement remains byte-for-byte historical evidence. The c6
selection shares its verified materials, never its product/producer identity.
Actual OCI graph, ordered layers, provenance and packages are still parsed by
our caller. Nothing here runs an image or publishes a Release.
"""
import copy
import gzip
import io
import os
from pathlib import Path
import re
import tarfile

import oci_material_supplement as legacy

SOURCE = 'c6c0d8b3b83ab4d6e7b953dd2dbdb7efe6f8021a'
TREE = '32c0e3d8c59ad5e41f5ccdbc68e14a644b503e94'
TAG = 'v1.15.0-polaris-alpha.12.2'
TAG_OBJECT = 'db094db3498ea6982ccc601289acbd0c8adcecac'
RUN_ID = 39887556943
ATTEMPT = 1
DIRECTORY = 'release/dependency-sources/oci/selections/39887556943-attempt1'
SELECTOR_BYTES = 13304
SELECTOR_SHA256 = '3f4980a25e8f319243ce8a72ba9cf84bc2af8e71d7e57a0ad7fd835effca26fe'
SCHEMA = 'polaris-exact-shared-oci-material-policy-v1'
_require = legacy._require


def supports_source(source):
    from oci_material_selection_12_3 import SOURCE as next_source
    from oci_material_selection_12_5 import SOURCE as latest_source
    from oci_material_selection_12_6 import SOURCE as alpha126_source
    from oci_material_selection_12_7 import SOURCE as alpha127_source
    return source in (legacy.SOURCE, SOURCE, next_source, latest_source, alpha126_source, alpha127_source)


def _selector_record():
    return {'path': 'selection-manifest.json', 'bytes': SELECTOR_BYTES, 'sha256': SELECTOR_SHA256}


def _current_closure(root, selector):
    rows = selector['files']
    names = [row['path'] for row in rows]
    _require(len(names) == len(set(names)) and 'selection-manifest.json' not in names, 'duplicate/current self reference')
    expected = set(names) | {'selection-manifest.json'}
    directories = {'.'}
    for name in expected:
        directories.update(p.as_posix() for p in legacy._relative(name).parents)
    actual, actual_dirs = set(), {'.'}
    for directory, children, files in os.walk(root, followlinks=False):
        parent = Path(directory)
        _require(not parent.is_symlink(), 'symlinked current directory')
        for name in children:
            child = parent / name
            _require(child.is_dir() and not child.is_symlink(), 'non-directory/current symlink')
            actual_dirs.add(child.relative_to(root).as_posix())
        for name in files:
            child = parent / name
            _require(child.is_file() and not child.is_symlink(), 'nonregular current entry')
            actual.add(child.relative_to(root).as_posix())
    _require(actual == expected and actual_dirs == directories, 'unexpected current selection entries')
    for row in rows:
        legacy._file(root, row)
    for key in ('materialReference', 'materialMap', 'sourceAcquisition', 'noticeInventory'):
        _require(selector[key] in rows, 'current index outside closure')


def _delta_materials(root, selector, reference, material_map, shared_reference):
    """Exactly one new ncurses recipe, two packages; other 241 stay exact."""
    _require(reference['schema'] == 'polaris-current-oci-material-reference-v1'
             and material_map['schema'] == 'polaris-current-oci-material-map-v1'
             and reference['materialMapSHA256'] == selector['materialMap']['sha256'], 'current map/reference mismatch')
    for document in (reference, material_map):
        _require((document['sourceCommit'], document['producerRunId'], document['producerAttempt'])
                 == (SOURCE, RUN_ID, ATTEMPT) and document['legalConclusion'] is False, 'current material binding mismatch')
    _require(material_map['sharedMaterials'] == selector['sharedMaterials'], 'shared map identity mismatch')
    _require(set(reference['artifacts']) == legacy.ARTIFACT_NAMES, 'current reference scope mismatch')
    shared, changed = [], []
    for name, row in reference['artifacts'].items():
        old = shared_reference['artifacts'][name]
        _require(all(row[key] == old[key] for key in ('platform', 'baseDependencies', 'repositories')),
                 'unexpected base/platform/repositories delta')
        _require(all(row[key] == value for key, value in selector['artifacts'][name].items()), 'current image binding mismatch')
        packages = row['packages']
        for package in packages:
            legacy._package(package)
        _require(len(packages) == len({p['P'] for p in packages}) == 27
                 and packages == sorted(packages, key=lambda p: (p['P'], p['V'], p['A'])), 'current package set/order mismatch')
        for package in packages:
            association = {'artifact': name, 'package': package}
            if package in old['packages']:
                shared.append(association)
            else:
                _require(name == 'oci-linux-loong64' and package['P'] in ('libncursesw', 'ncurses-terminfo-base')
                         and (package['V'], package['A'], package['L'], package['o'], package['c'])
                         == ('6.6_p20261017-r0', 'loongarch64', 'X11', 'ncurses',
                             '8b3f794ac226c47c66f0900fa1cd44f8d2c4e116'), 'unexpected package delta')
                changed.append(association)
    _require(len(shared) == 241 and len(changed) == 2 and shared == material_map['sharedPackageAssociations']
             and changed == material_map['newPackageAssociations'], 'incomplete current package association')
    recipe = material_map['newRecipe']
    _require((recipe['repository'], recipe['commit'], recipe['origin'])
             == ('alpinelinux/aports', '8b3f794ac226c47c66f0900fa1cd44f8d2c4e116', 'ncurses'), 'wrong new recipe')
    expected_names = {'APKBUILD', 'cleanup-pkgconfig-ldflags.patch'}
    rows = recipe['files']
    _require(len(rows) == 2 and {Path(row['path']).name for row in rows} == expected_names, 'recipe file closure mismatch')
    tree_entries, texts = [], {}
    prefix = 'aports/' + recipe['commit'] + '/main/ncurses/'
    for row in rows:
        name = row['path'].removeprefix(prefix)
        _require(name in expected_names and row['path'] == prefix + name and row['gitMode'] == '100644', 'recipe path/mode changed')
        data = legacy._file(root, row, read=True)
        blob = legacy._sha(b'blob ' + str(len(data)).encode() + b'\0' + data, 'sha1')
        _require(blob == row['gitBlob'], 'recipe Git blob changed')
        tree_entries.append((name, blob))
        texts[name] = data
    body = b''.join(b'100644 ' + name.encode() + b'\0' + bytes.fromhex(blob) for name, blob in sorted(tree_entries))
    _require(legacy._sha(b'tree ' + str(len(body)).encode() + b'\0' + body, 'sha1') == recipe['directoryTreeSHA'], 'recipe tree changed')
    sums = re.findall(r'^([a-f0-9]{128})  (.+)$', texts['APKBUILD'].decode('utf-8'), re.M)
    _require(len(sums) == 2 and {name for _, name in sums} == {'ncurses-6.6-20261017.tgz', 'cleanup-pkgconfig-ldflags.patch'}, 'recipe input scope changed')
    sums = {name: digest for digest, name in sums}
    _require(legacy._sha(texts['cleanup-pkgconfig-ldflags.patch'], 'sha512') == sums['cleanup-pkgconfig-ldflags.patch'], 'recipe patch checksum changed')
    acquisition = legacy._json(legacy._file(root, selector['sourceAcquisition'], read=True))
    _require(len(acquisition) == 1, 'expected one delta archive')
    source = acquisition[0]
    data = legacy._file(root, source, read=True)
    _require(source['name'] == 'ncurses-6.6-20261017.tgz' and legacy._sha(data, 'sha512')
             == source['sha512'] == sums[source['name']], 'delta archive recipe checksum mismatch')
    receipt = legacy._json(legacy._file(root, source['getReceipt'], read=True))
    request = legacy._json(legacy._file(root, source['getRequest'], read=True))
    transfer = legacy._json(legacy._file(root, source['transferReceipt'], read=True))
    headers = legacy._file(root, source['responseHeaders'], read=True).decode('ascii')
    _require(request['method'] == 'GET' and receipt['HTTP'] == 200 and receipt['curlReturnCode'] == 0
             and (receipt['bytes'], receipt['sha256'], receipt['sha512'])
             == (len(data), legacy._sha(data), legacy._sha(data, 'sha512'))
             and transfer['response_code'] == 200 and transfer['size_download'] == len(data)
             and transfer['num_redirects'] == 0 and transfer['ssl_verify_result'] == 0,
             'delta GET receipt mismatch')
    lengths = re.findall(r'^content-length: ([0-9]+)\r?$', headers, re.M | re.I)
    _require(lengths == [str(len(data))] and headers.startswith('HTTP/2 200 '), 'delta HTTP headers mismatch')
    expected_url = 'https://invisible-mirror.net/archives/ncurses/current/ncurses-6.6-20261017.tgz'
    _require(source['requestedURL'] == receipt['requestURL'] == request['url'] == expected_url
             and source['effectiveURL'] == receipt['effectiveURL'] == transfer['url_effective'] == expected_url,
             'delta source URL changed')
    notices = legacy._json(legacy._file(root, selector['noticeInventory'], read=True))
    _require(notices and len({row['path'] for row in notices}) == len(notices), 'missing/duplicate delta notices')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        members = archive.getmembers()
        for row in notices:
            _require(row['sourceArchiveSHA256'] == source['sha256'], 'notice archive association changed')
            matches = [m for m in members if m.name == row['archiveMember']]
            _require(len(matches) == 1 and matches[0].isfile() and matches[0].size == row['bytes'], 'notice member mismatch')
            _require(archive.extractfile(matches[0]).read() == legacy._file(root, row, read=True), 'notice original bytes changed')


def _load(artifacts, source_root, publisher_root):
    root = legacy._path(publisher_root, DIRECTORY)
    selector = legacy._json(legacy._file(root, _selector_record(), read=True))
    _current_closure(root, selector)
    _require(selector['schema'] == 'polaris-shared-oci-material-selection-v1'
             and selector['directory'] == DIRECTORY and selector['legalConclusion'] is False,
             'invalid current selector schema')
    binding = selector['binding']
    _require(tuple(binding[k] for k in ('repository', 'repositoryId', 'sourceCommit', 'sourceTree', 'tag',
                                      'tagObject', 'producerRunId', 'producerAttempt', 'workflowPath'))
             == (legacy.REPOSITORY, legacy.REPOSITORY_ID, SOURCE, TREE, TAG, TAG_OBJECT, RUN_ID, ATTEMPT, legacy.WORKFLOW),
             'current selector identity mismatch')
    shared = selector['sharedMaterials']
    expected_shared = {'selector': {'path': legacy.DIRECTORY + '/selection-manifest.json',
                       'bytes': legacy.SELECTOR_BYTES, 'sha256': legacy.SELECTOR_SHA256},
                       'sourceCommit': legacy.SOURCE, 'producerRunId': legacy.RUN_ID,
                       'producerAttempt': legacy.ATTEMPT, 'relabelled': False}
    _require(shared == expected_shared, 'shared material identity changed')
    shared_root = legacy._path(publisher_root, legacy.DIRECTORY)
    old = legacy._json(legacy._file(publisher_root, shared['selector'], read=True))
    legacy._closure(shared_root, old)
    reference_path = legacy._file(shared_root, old['materialReference'])
    map_path = legacy._file(shared_root, old['materialMap'])
    reference = legacy._json(legacy._file(shared_root, old['materialReference'], read=True))
    material_map = legacy._json(legacy._file(shared_root, old['materialMap'], read=True))
    _require(reference['materialMapSHA256'] == old['materialMap']['sha256'], 'shared reference/map mismatch')
    legacy._materials(shared_root, Path(source_root), old, reference, material_map)
    _require(selector['distributionBoundary'] == old['distributionBoundary']
             and selector['coreBindingPolicy'] == old['coreBindingPolicy'], 'distribution/core policy changed')
    current_reference_path = legacy._file(root, selector['materialReference'])
    current_map_path = legacy._file(root, selector['materialMap'])
    current_reference = legacy._json(legacy._file(root, selector['materialReference'], read=True))
    current_map = legacy._json(legacy._file(root, selector['materialMap'], read=True))
    _delta_materials(root, selector, current_reference, current_map, reference)
    rows = selector['artifacts']
    _require(set(rows) == legacy.ARTIFACT_NAMES and isinstance(artifacts, list) and len(artifacts) == 9,
             'expected exactly nine current OCI artifacts')
    names, ids = set(), set()
    for artifact in artifacts:
        name, artifact_id = artifact.get('name'), artifact.get('id')
        _require(name in rows and name not in names and type(artifact_id) is int and artifact_id not in ids,
                 'unknown/duplicate API artifact identity')
        names.add(name)
        ids.add(artifact_id)
        row, run = rows[name], artifact.get('workflow_run', {})
        _require((artifact_id, artifact.get('size_in_bytes'), artifact.get('digest'))
                 == (row['artifactId'], row['archiveBytes'], row['artifactAPIDigest'])
                 and row['artifactAPIDigest'] == 'sha256:' + row['archiveSHA256'], 'API archive identity mismatch')
        _require((run.get('id'), run.get('head_sha'), run.get('repository_id'), run.get('head_repository_id'))
                 == (RUN_ID, SOURCE, legacy.REPOSITORY_ID, legacy.REPOSITORY_ID)
                 and artifact.get('expired') is False, 'API repository/source/run/expiry mismatch')
        _require(row['platform'] == reference['artifacts'][name]['platform'], 'shared platform mismatch')
    members = [(shared_root, row, legacy.DIRECTORY + '/' + row['path']) for row in old['files']]
    members += [(shared_root, {'path': 'selection-manifest.json', 'bytes': legacy.SELECTOR_BYTES,
                              'sha256': legacy.SELECTOR_SHA256}, legacy.DIRECTORY + '/selection-manifest.json')]
    members += [(root, row, DIRECTORY + '/' + row['path']) for row in selector['files']]
    members += [(root, _selector_record(), DIRECTORY + '/selection-manifest.json')]
    tar_body = 0
    for _, row, name in members:
        info = tarfile.TarInfo(name)
        info.size = row['bytes']
        info.tobuf(format=tarfile.USTAR_FORMAT, encoding='ascii', errors='strict')
        tar_body += 512 + ((row['bytes'] + 511) // 512) * 512
    tar_bytes = ((tar_body + 1024 + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE
    bound = tar_bytes + ((tar_bytes + 7) >> 3) + ((tar_bytes + 63) >> 6) + 64
    return {'schema': SCHEMA, 'directory': root, 'publisher_root': Path(publisher_root),
            'source_root': Path(source_root), 'selector': selector, 'selector_sha256': SELECTOR_SHA256,
            'binding': binding, 'reference_path': current_reference_path, 'material_map_path': current_map_path,
            'artifacts': rows, 'bundle_tar_bytes': tar_bytes, 'bundle_maximum_bytes': bound,
            '_api': copy.deepcopy(artifacts)}, members, old


def load_for_run(source, tree, tag, tag_object, run_id, attempt, workflow, artifacts, source_root, publisher_root):
    import oci_material_selection_12_7 as alpha127
    if source == alpha127.SOURCE:
        return alpha127.load_for_run(source, tree, tag, tag_object, run_id, attempt, workflow, artifacts, source_root, publisher_root)
    import oci_material_selection_12_6 as alpha126
    if source == alpha126.SOURCE:
        return alpha126.load_for_run(source, tree, tag, tag_object, run_id, attempt, workflow, artifacts, source_root, publisher_root)
    import oci_material_selection_12_5 as latest
    import oci_material_selection_12_3 as current
    if source == latest.SOURCE:
        return latest.load_for_run(source, tree, tag, tag_object, run_id, attempt, workflow, artifacts, source_root, publisher_root)
    if source == current.SOURCE:
        return current.load_for_run(source, tree, tag, tag_object, run_id, attempt, workflow, artifacts, source_root, publisher_root)
    if source == legacy.SOURCE:
        return legacy.load_for_run(source, tree, tag, tag_object, run_id, attempt, workflow, artifacts, source_root, publisher_root)
    _require(type(run_id) is int and type(attempt) is int
             and (source, tree, tag, tag_object, run_id, attempt, workflow)
             == (SOURCE, TREE, TAG, TAG_OBJECT, RUN_ID, ATTEMPT, legacy.WORKFLOW), 'wrong current selection tuple')
    return _load(artifacts, source_root, publisher_root)[0]


def _checked(policy):
    _require(isinstance(policy, dict) and policy.get('schema') == SCHEMA, 'invalid current policy')
    actual, members, shared = _load(policy['_api'], policy['source_root'], policy['publisher_root'])
    _require({k: v for k, v in policy.items() if k != '_written_bundle'} == actual,
             'current policy changed after loading')
    return actual, members, shared


def bundle_name(policy):
    import oci_material_selection_12_7 as alpha127
    if policy.get('schema') == alpha127.SCHEMA:
        return alpha127.bundle_name(policy)
    import oci_material_selection_12_6 as alpha126
    if policy.get('schema') == alpha126.SCHEMA:
        return alpha126.bundle_name(policy)
    import oci_material_selection_12_5 as latest
    import oci_material_selection_12_3 as current
    if policy.get('schema') == latest.SCHEMA:
        return latest.bundle_name(policy)
    if policy.get('schema') == current.SCHEMA:
        return current.bundle_name(policy)
    if policy.get('schema') != SCHEMA:
        legacy._checked_policy(policy)
        return 'polaris-oci-material-supplement-39791192772-attempt1.tar.gz'
    _checked(policy)
    return 'polaris-oci-material-supplement-39887556943-attempt1.tar.gz'


def check_image(policy, artifact_name, actual_image_path):
    import oci_material_selection_12_7 as alpha127
    if policy.get('schema') == alpha127.SCHEMA:
        return alpha127.check_image(policy, artifact_name, actual_image_path)
    import oci_material_selection_12_6 as alpha126
    if policy.get('schema') == alpha126.SCHEMA:
        return alpha126.check_image(policy, artifact_name, actual_image_path)
    import oci_material_selection_12_5 as latest
    import oci_material_selection_12_3 as current
    if policy.get('schema') == latest.SCHEMA:
        return latest.check_image(policy, artifact_name, actual_image_path)
    if policy.get('schema') == current.SCHEMA:
        return current.check_image(policy, artifact_name, actual_image_path)
    if policy.get('schema') != SCHEMA:
        return legacy.check_image(policy, artifact_name, actual_image_path)
    actual, _, _ = _checked(policy)
    _require(artifact_name in actual['artifacts'], 'unknown image artifact')
    row = actual['artifacts'][artifact_name]
    _require(legacy._digest_file(actual_image_path, row['imageBytes']) == (row['imageBytes'], row['imageSHA256']),
             'actual current image identity mismatch')
    return row


def write_bundle(policy, path):
    import oci_material_selection_12_7 as alpha127
    if policy.get('schema') == alpha127.SCHEMA:
        return alpha127.write_bundle(policy, path)
    import oci_material_selection_12_6 as alpha126
    if policy.get('schema') == alpha126.SCHEMA:
        return alpha126.write_bundle(policy, path)
    import oci_material_selection_12_5 as latest
    import oci_material_selection_12_3 as current
    if policy.get('schema') == latest.SCHEMA:
        return latest.write_bundle(policy, path)
    if policy.get('schema') == current.SCHEMA:
        return current.write_bundle(policy, path)
    if policy.get('schema') != SCHEMA:
        return legacy.write_bundle(policy, path)
    actual, members, _ = _checked(policy)
    path = Path(path)
    _require(not path.exists() and not path.is_symlink(), 'audit bundle destination already exists')
    _require(all(not path.resolve().is_relative_to(root.resolve()) for root, _, _ in members),
             'bundle cannot be placed in material directory')
    created_identity = None
    try:
        with path.open('xb') as raw:
            created = os.fstat(raw.fileno())
            created_identity = (created.st_dev, created.st_ino)
            with gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0, compresslevel=9) as compressed:
                with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT, encoding='ascii') as archive:
                    for root, row, name in sorted(members, key=lambda item: item[2]):
                        data = legacy._file(root, row, read=True)
                        info = tarfile.TarInfo(name)
                        info.size, info.mode, info.mtime = row['bytes'], 0o644, 0
                        info.uid = info.gid = 0
                        info.uname = info.gname = ''
                        archive.addfile(info, io.BytesIO(data))
        length, digest = legacy._digest_file(path)
        _require(length <= actual['bundle_maximum_bytes'], 'bundle exceeds admitted bound')
    except BaseException as primary:
        if created_identity is not None:
            try:
                current = path.lstat()
                if (current.st_dev, current.st_ino) == created_identity:
                    path.unlink()
            except FileNotFoundError:
                pass
            except OSError as cleanup_error:
                if hasattr(primary, 'add_note'):
                    primary.add_note('OCI selection partial cleanup failed: ' + str(cleanup_error))
        raise
    result = {'name': path.name, 'bytes': length, 'sha256': digest}
    policy['_written_bundle'] = {'path': path.resolve(), **result}
    return result


def record(policy, publisher_sha, bundle_path):
    import oci_material_selection_12_7 as alpha127
    if policy.get('schema') == alpha127.SCHEMA:
        return alpha127.record(policy, publisher_sha, bundle_path)
    import oci_material_selection_12_6 as alpha126
    if policy.get('schema') == alpha126.SCHEMA:
        return alpha126.record(policy, publisher_sha, bundle_path)
    import oci_material_selection_12_5 as latest
    import oci_material_selection_12_3 as current
    if policy.get('schema') == latest.SCHEMA:
        return latest.record(policy, publisher_sha, bundle_path)
    if policy.get('schema') == current.SCHEMA:
        return current.record(policy, publisher_sha, bundle_path)
    if policy.get('schema') != SCHEMA:
        return legacy.record(policy, publisher_sha, bundle_path)
    _require(re.fullmatch('[0-9a-f]{40}', publisher_sha or '') is not None, 'invalid immutable publisher commit')
    actual, members, shared = _checked(policy)
    bundle = policy.get('_written_bundle')
    _require(bundle is not None and Path(bundle_path).resolve() == bundle['path'], 'bundle not written by policy')
    _require(legacy._digest_file(bundle_path, bundle['bytes']) == (bundle['bytes'], bundle['sha256']), 'bundle changed')
    expected = {name: row for _, row, name in members}
    with tarfile.open(bundle_path, 'r:gz') as archive:
        entries = archive.getmembers()
        _require(len(entries) == len(expected) == 53 + len(actual['selector']['files']) + 1 and {m.name for m in entries} == set(expected), 'bundle member set mismatch')
        for member in entries:
            row = expected[member.name]
            _require(member.isfile() and member.size == row['bytes'] and member.mode == 0o644
                     and member.uid == member.gid == member.mtime == 0 and not member.uname and not member.gname,
                     'bundle member metadata mismatch')
            data = archive.extractfile(member).read()
            _require((len(data), legacy._sha(data)) == (row['bytes'], row['sha256']), 'bundle member changed')
    selector, binding = actual['selector'], actual['binding']
    base_url = f'https://github.com/{legacy.REPOSITORY}/blob/{publisher_sha}/'
    return {'schema': 'polaris-oci-material-supplement-receipt-v1', 'policy': 'exact-39887556943-attempt1-no-fallback',
            'sourceCommit': SOURCE, 'sourceTree': TREE, 'tag': TAG, 'tagObject': TAG_OBJECT,
            'producerRunId': RUN_ID, 'producerAttempt': ATTEMPT, 'publisherCommit': publisher_sha,
            'publisherImmutableURL': f'https://github.com/{legacy.REPOSITORY}/tree/{publisher_sha}/{DIRECTORY}',
            'selector': {'path': DIRECTORY + '/selection-manifest.json', 'bytes': SELECTOR_BYTES,
                         'sha256': SELECTOR_SHA256, 'url': base_url + DIRECTORY + '/selection-manifest.json'},
            'sharedMaterials': selector['sharedMaterials'],
            'materialMap': dict(selector['materialMap'], path=DIRECTORY + '/' + selector['materialMap']['path']),
            'materialReference': dict(selector['materialReference'], path=DIRECTORY + '/' + selector['materialReference']['path']),
            'sourceAcquisition': dict(selector['sourceAcquisition'], path=DIRECTORY + '/' + selector['sourceAcquisition']['path']),
            'noticeInventory': dict(selector['noticeInventory'], path=DIRECTORY + '/' + selector['noticeInventory']['path']),
            'historicalAnchors': {k: shared['binding'][k] for k in ('historicalMaterialMap', 'historicalReuseReference', 'historicalAcquisition')},
            'nativeIndexSHA256': binding['nativeIndexSHA256'], 'sourceArchive': binding['sourceArchive'],
            'auditBundle': {k: bundle[k] for k in ('name', 'bytes', 'sha256')},
            'artifactCount': 9, 'packageAssociationCount': 243, 'sharedPackageAssociationCount': 241, 'newPackageAssociationCount': 2, 'coreBindingPolicy': selector['coreBindingPolicy'],
            'publicReleaseAssetSetUnchanged': True, 'ociSeparateDistributionChannel': True, 'legalConclusion': False}
