"""One reviewed, append-only OCI material set; never a general reuse fallback.

The caller retains all original OCI graph/provenance/package gates, validates the
native-index/source-archive anchors against actual bytes, and admits the bundle
budget before write_bundle. This module does not publish or execute an image.
"""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

REPOSITORY = 'polaris-arch/sing-box-polaris'
REPOSITORY_ID = 1421657509
SOURCE = '814da362838e96e54f904836a92c2b0d8c3ae29b'
TREE = 'ad574f93026557b49edecb492bd7ecdb851057c1'
TAG = 'v1.15.0-polaris-alpha.12.1'
TAG_OBJECT = '8ecda357ea755a1295336a35ec7eaf1fe2daebc2'
RUN_ID = 39791192772
ATTEMPT = 1
WORKFLOW = '.github/workflows/docker.yml'
DIRECTORY = 'release/dependency-sources/oci/supplements/39791192772-attempt1'
SELECTOR_SHA256 = '723b6687224eb090b811d7ea820a8827d9f373a5cfe4b8750e7298bae713395d'
SELECTOR_BYTES = 14394
ARTIFACT_NAMES = frozenset(('oci-linux-386', 'oci-linux-amd64', 'oci-linux-arm-v6',
                           'oci-linux-arm-v7', 'oci-linux-arm64', 'oci-linux-loong64',
                           'oci-linux-ppc64le', 'oci-linux-riscv64', 'oci-linux-s390x'))
PACKAGE_KEYS = frozenset(('P', 'V', 'A', 'L', 'o', 'c', 'C'))


def _require(condition, message):
    if not condition:
        raise ValueError('OCI supplement: ' + message)


def _sha(data, algorithm='sha256'):
    return hashlib.new(algorithm, data).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def _json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(data.decode('utf-8'), object_pairs_hook=pairs)


def _relative(name):
    _require(isinstance(name, str) and name and name.isascii() and '\\' not in name
             and '\0' not in name and not name.startswith('/'), 'unsafe material path')
    path = PurePosixPath(name)
    _require(path.as_posix() == name and all(part not in ('', '.', '..') for part in path.parts),
             'noncanonical material path')
    return path


def _path(root, name):
    root = Path(root)
    _require(root.is_dir() and not root.is_symlink(), 'material root is missing or symlinked')
    relative = _relative(name)
    current = root
    for part in relative.parts:
        current = current / part
        _require(not current.is_symlink(), 'symlinked material path')
    return current


def _digest_file(path, expected_bytes=None):
    path = Path(path)
    _require(path.is_file() and not path.is_symlink(), 'missing/nonregular file')
    info = path.stat()
    _require(stat.S_ISREG(info.st_mode), 'nonregular file')
    if expected_bytes is not None:
        _require(info.st_size == expected_bytes, 'file size mismatch before hashing')
    digest = hashlib.sha256()
    length = 0
    with path.open('rb') as source:
        _require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), 'nonregular open file')
        while True:
            remaining = info.st_size + 1 - length
            if remaining <= 0:
                break
            chunk = source.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            digest.update(chunk)
            length += len(chunk)
    _require(length == info.st_size, 'file changed while hashing')
    return length, digest.hexdigest()


def _file(root, record, read=False):
    _require(isinstance(record, dict) and type(record.get('bytes')) is int
             and record['bytes'] >= 0 and re.fullmatch('[0-9a-f]{64}', record.get('sha256', '')),
             'invalid file identity')
    path = _path(root, record['path'])
    _require(_digest_file(path, record['bytes']) == (record['bytes'], record['sha256']), 'file size/hash mismatch: ' + record['path'])
    if read:
        with path.open('rb') as source:
            data = source.read(record['bytes'] + 1)
        _require((len(data), _sha(data)) == (record['bytes'], record['sha256']), 'file changed after hashing')
        return data
    return path


def _closure(root, selector):
    rows = selector['files']
    _require(isinstance(rows, list) and len(rows) == 52, 'expected exactly 52 payload files')
    names = [row['path'] for row in rows]
    _require(len(set(names)) == len(names) and 'selection-manifest.json' not in names, 'duplicate/self-referential payload')
    expected = set(names) | {'selection-manifest.json'}
    expected_dirs = {'.'}
    for name in expected:
        relative = _relative(name)
        expected_dirs.update(parent.as_posix() for parent in relative.parents)
    actual, directories = set(), {'.'}
    for directory, children, files in os.walk(root, followlinks=False):
        current = Path(directory)
        _require(not current.is_symlink(), 'symlinked payload directory')
        for name in children:
            child = current / name
            _require(child.is_dir() and not child.is_symlink(), 'non-directory/symlink payload entry')
            directories.add(child.relative_to(root).as_posix())
        for name in files:
            child = current / name
            _require(not child.is_symlink() and stat.S_ISREG(child.lstat().st_mode), 'nonregular payload entry')
            actual.add(child.relative_to(root).as_posix())
    _require(actual == expected and directories == expected_dirs, 'extra/missing payload files or directories')
    _file(root, {'path': 'selection-manifest.json', 'bytes': SELECTOR_BYTES, 'sha256': SELECTOR_SHA256})
    for row in rows:
        _file(root, row)
    for key in ('materialReference', 'materialMap', 'sourceAcquisition', 'noticeInventory', 'httpGetReceipts'):
        _require(selector[key] in rows, 'index missing from payload closure')


def _package(package):
    _require(isinstance(package, dict) and set(package) == PACKAGE_KEYS
             and all(isinstance(value, str) and value for value in package.values()),
             'incomplete installed package identity')


def _materials(root, source_root, selector, reference, material_map):
    binding = selector['binding']
    old_map = _json(_file(source_root, binding['historicalMaterialMap'], read=True))
    old_reference = _json(_file(source_root, binding['historicalReuseReference'], read=True))
    old_acquisition = _json(_file(source_root, binding['historicalAcquisition'], read=True))
    _require(old_reference['materialMapSHA256'] == binding['historicalMaterialMap']['sha256'], 'historical map/reference mismatch')
    old_recipes = {(row['origin'], row['commit']): row for row in old_map['recipes']}
    _require(len(old_recipes) == len(old_map['recipes']), 'duplicate historical origin/commit')
    new_rows = material_map['newRecipes']
    historical_rows = material_map['historicalRecipeReferences']
    new = {(row['origin'], row['commit']): row for row in new_rows}
    historical = {(row['origin'], row['commit']): row for row in historical_rows}
    _require(len(new_rows) == len(new) == 6 and len(historical_rows) == len(historical) == 31
             and not (new.keys() & historical.keys()), 'recipe partition mismatch')
    for key, row in historical.items():
        _require(key in old_recipes, 'unknown historical recipe')
        old = old_recipes[key]
        _require(row['materialMapSHA256'] == binding['historicalMaterialMap']['sha256']
                 and row['historicalRecordSHA256'] == _sha(_canonical(old)), 'historical recipe record changed')
        expected_files = {(item['path'], item['bytes'], item['sha256']) for item in old['files']}
        actual_files = {(item['path'], item['bytes'], item['sha256']) for item in row['files']}
        _require(len(actual_files) == len(row['files']) and actual_files == expected_files, 'historical recipe file set changed')
        old_files = {item['path']: item for item in old['files']}
        for item in row['files']:
            data = _file(source_root, item, read=True)
            original = old_files[item['path']]
            _require(original['gitMode'] in ('100644', '100755', '120000')
                     and _sha(b'blob ' + str(len(data)).encode() + b'\0' + data, 'sha1') == original['gitBlob'],
                     'historical recipe Git blob/mode mismatch')
        _require(len(row['noticeFiles']) == len({item['path'] for item in row['noticeFiles']})
                 and {item['path'] for item in row['noticeFiles']} == set(old['noticePaths']), 'historical notice set changed')
        for item in row['noticeFiles']:
            _file(source_root, item)
        _require(row['externalInputs'] == old['externalInputs'], 'historical external input changed')
        for item in row['externalInputs']:
            matches = [entry for entry in old_acquisition if entry['name'] == item['name'] and entry['sha512'] == item['sha512']]
            _require(len(matches) == 1 and all(matches[0].get(field) == value for field, value in item.items()),
                     'historical acquisition binding changed')

    acquisition = _json(_file(root, selector['sourceAcquisition'], read=True))
    receipts = _json(_file(root, selector['httpGetReceipts'], read=True))
    notices = _json(_file(root, selector['noticeInventory'], read=True))
    acquired = {item['name']: item for item in acquisition}
    _require(len(acquisition) == len(acquired) == 3 and len(receipts) == 3 and len(notices) == 7,
             'new source/notice inventory count changed')
    for name, item in acquired.items():
        data = _file(root, item, read=True)
        _require(_sha(data, 'sha512') == item['sha512'], 'source archive SHA512 mismatch')
        matches = [entry for entry in receipts if entry['name'] == name]
        _require(len(matches) == 1, 'source GET receipt not unique')
        receipt = matches[0]
        _require(receipt['method'] == 'GET' and receipt['status'] == 200 and receipt['fullGet'] is True
                 and (receipt['bytes'], receipt['sha256'], receipt['sha512'], receipt['bodySaved'])
                     == (len(data), _sha(data), _sha(data, 'sha512'), item['path'])
                 and int(receipt['responseHeaders']['Content-Length']) == len(data), 'source GET receipt mismatch')
        expected_url = 'https://distfiles.alpinelinux.org/distfiles/v3.24/' + name
        _require(item['requestedURL'] == item['effectiveURL'] == receipt['requestedURL'] == receipt['effectiveURL'] == expected_url,
                 'source URL mismatch')
        if 'historicalIdentityReuse' in item:
            reuse = item['historicalIdentityReuse']
            matches = [entry for entry in old_acquisition if entry['name'] == name and entry['sha512'] == item['sha512']]
            _require(reuse['path'] == binding['historicalAcquisition']['path']
                     and reuse['sha256'] == binding['historicalAcquisition']['sha256'] and len(matches) == 1
                     and (matches[0]['bytes'], matches[0]['sha256']) == (len(data), _sha(data)), 'shared source identity mismatch')
    for key, row in new.items():
        origin, commit = key
        _require(row['repository'] == 'alpinelinux/aports'
                 and row['source'] == f'https://api.github.com/repos/alpinelinux/aports/contents/main/{origin}?ref={commit}',
                 'recipe repository/commit mismatch')
        files = row['files']
        directory = f'aports/{commit}/main/{origin}/'
        tree_entries, file_names, file_records, apkbuild = [], set(), {}, None
        for item in files:
            name = item['path'].removeprefix(directory)
            _require(item['path'].startswith(directory) and '/' not in name and name not in file_names
                     and item['gitMode'] == '100644' and item['origin'] == origin and item['commit'] == commit,
                     'new recipe path/mode/identity mismatch')
            file_names.add(name)
            file_records[name] = item
            data = _file(root, item, read=True)
            _require(_sha(b'blob ' + str(len(data)).encode() + b'\0' + data, 'sha1') == item['gitBlob'], 'new recipe Git blob mismatch')
            tree_entries.append((name, item['gitBlob']))
            if name == 'APKBUILD':
                apkbuild = data.decode('utf-8')
        _require(apkbuild is not None, 'missing APKBUILD')
        tree = b''.join(b'100644 ' + name.encode('ascii') + b'\0' + bytes.fromhex(blob) for name, blob in sorted(tree_entries))
        _require(_sha(b'tree ' + str(len(tree)).encode() + b'\0' + tree, 'sha1') == row['directoryTreeSHA'], 'recipe directory tree changed')
        local_inputs, external_names = [], set()
        for digest, name in re.findall(r'^([a-f0-9]{128})  (.+)$', apkbuild, re.M):
            _relative(name)
            if name in file_names:
                data = _file(root, file_records[name], read=True)
                local_inputs.append({'path': directory + name, 'sha512': digest})
            else:
                _require(name in acquired, 'unacquired recipe source')
                data = _file(root, acquired[name], read=True)
                external_names.add(name)
            _require(_sha(data, 'sha512') == digest, 'APKBUILD input SHA512 mismatch')
        _require(local_inputs == row['sha512VerifiedLocalInputs'], 'local source input set mismatch')
        _require(len(row['externalInputs']) == len(external_names)
                 and {item['name'] for item in row['externalInputs']} == external_names, 'external source input set mismatch')
        for item in row['externalInputs']:
            _require(all(acquired[item['name']].get(field) == value for field, value in item.items()), 'recipe acquisition record mismatch')
        _require((origin == 'alpine-base' and row['inTreeOnly'] is True and not local_inputs and not external_names and 'source=' not in apkbuild)
                 or (origin != 'alpine-base' and row['inTreeOnly'] is False and len(external_names) == 1), 'in-tree/external source classification mismatch')
        archive_hashes = {acquired[name]['sha256'] for name in external_names}
        _require(row['noticePaths'] == [item['path'] for item in notices if item['sourceArchiveSHA256'] in archive_hashes], 'recipe notice set mismatch')
    for item in notices:
        data = _file(root, item, read=True)
        matches = [entry for entry in acquisition if entry['sha256'] == item['sourceArchiveSHA256']]
        _require(len(matches) == 1, 'notice source archive not unique')
        _relative(item['sourceMember'])
        with tarfile.open(_path(root, matches[0]['path']), 'r:*') as archive:
            members = [member for member in archive.getmembers() if member.name == item['sourceMember']]
            _require(len(members) == 1 and members[0].isfile() and 0 <= members[0].size <= 8 * 1024**2, 'unsafe/ambiguous notice source member')
            body = archive.extractfile(members[0]).read()
        offset = item['byteOffset']
        _require(type(offset) is int and offset >= 0 and len(body) == item['sourceMemberBytes']
                 and _sha(body) == item['sourceMemberSHA256'] and body[offset:offset + len(data)] == data,
                 'notice original source bytes mismatch')
        _require(_file(source_root, item['identicalHistoricalNotice'], read=True) == data, 'shared notice differs from original source')

    associations, seen, used_new, used_old = material_map['packageAssociations'], set(), set(), set()
    for item in associations:
        name, package = item['artifactName'], item['package']
        _package(package)
        _require(name in reference['artifacts'] and package in reference['artifacts'][name]['packages'], 'unbound current package')
        identity = (name, _canonical(package))
        _require(identity not in seen, 'duplicate current package association')
        seen.add(identity)
        key = (package['o'], package['c'])
        _require(key == (item['origin'], item['commit']), 'package origin/commit association mismatch')
        if item['materialKind'] == 'historical-shared-recipe':
            _require(key in historical and package in old_reference['artifacts'][name]['packages'], 'historical source reuse mismatch')
            used_old.add(key)
        else:
            _require(item['materialKind'] == 'supplement-new-recipe' and key in new, 'new source recipe association mismatch')
            used_new.add(key)
    expected = {(name, _canonical(package)) for name, row in reference['artifacts'].items() for package in row['packages']}
    _require(len(associations) == len(seen) == 243 and seen == expected
             and used_new == set(new) and used_old == set(historical), 'incomplete actual package/source closure')


def load_for_run(source, tree, tag, tag_object, run_id, attempt, workflow, artifacts, source_root, publisher_root):
    """Load only this exact tuple and exactly nine raw GitHub OCI artifact rows.

    Wrong tuples are errors, never None/old-reference fallback. The caller must
    choose its original historical path only when no supplement was requested.
    """
    _require(type(run_id) is int and type(attempt) is int
             and (source, tree, tag, tag_object, run_id, attempt, workflow)
                 == (SOURCE, TREE, TAG, TAG_OBJECT, RUN_ID, ATTEMPT, WORKFLOW), 'wrong source/tree/tag/run/attempt/workflow tuple')
    root = _path(publisher_root, DIRECTORY)
    selector = _json(_file(root, {'path': 'selection-manifest.json', 'bytes': SELECTOR_BYTES, 'sha256': SELECTOR_SHA256}, read=True))
    _require(selector['schema'] == 'polaris-oci-material-supplement-selection-v1'
             and selector['directory'] == DIRECTORY and selector['legalConclusion'] is False,
             'invalid selection schema/scope')
    binding = selector['binding']
    _require((binding['repository'], binding['repositoryId'], binding['sourceCommit'], binding['sourceTree'], binding['tag'],
              binding['tagObject'], binding['producerRunId'], binding['producerAttempt'], binding['workflowPath'])
             == (REPOSITORY, REPOSITORY_ID, SOURCE, TREE, TAG, TAG_OBJECT, RUN_ID, ATTEMPT, WORKFLOW), 'selector product binding mismatch')
    _require(selector['distributionBoundary']['publicReleaseAssetSet'] == 'unchanged'
             and selector['distributionBoundary']['ociDistribution'] == 'separate-channel', 'distribution boundary changed')
    _closure(root, selector)
    reference_path = _file(root, selector['materialReference'])
    material_map_path = _file(root, selector['materialMap'])
    reference = _json(_file(root, selector['materialReference'], read=True))
    material_map = _json(_file(root, selector['materialMap'], read=True))
    _require(reference['schema'] == 'polaris-oci-material-supplement-reference-v1'
             and material_map['schema'] == 'polaris-oci-source-notice-supplement-map-v1'
             and reference['materialMapSHA256'] == selector['materialMap']['sha256'], 'material reference/map mismatch')
    for document in (reference, material_map):
        _require((document['sourceCommit'], document['producerRunId'], document['producerAttempt']) == (SOURCE, RUN_ID, ATTEMPT)
                 and document['legalConclusion'] is False, 'material source/run/attempt mismatch')
    _require(set(reference['artifacts']) == ARTIFACT_NAMES, 'reference OCI artifact set mismatch')
    _require(isinstance(artifacts, list) and len(artifacts) == 9, 'expected exactly nine API artifact records')
    seen_names, seen_ids = set(), set()
    for artifact in artifacts:
        name, artifact_id = artifact.get('name'), artifact.get('id')
        _require(name in ARTIFACT_NAMES and name not in seen_names and type(artifact_id) is int and artifact_id not in seen_ids,
                 'unknown/duplicate API artifact identity')
        seen_names.add(name)
        seen_ids.add(artifact_id)
        row = reference['artifacts'][name]
        run = artifact.get('workflow_run', {})
        _require((artifact_id, artifact.get('size_in_bytes'), artifact.get('digest'))
                 == (row['artifactId'], row['archiveBytes'], row['artifactAPIDigest'])
                 and row['artifactAPIDigest'] == 'sha256:' + row['archiveSHA256'], 'API archive ID/bytes/digest mismatch')
        _require((run.get('id'), run.get('head_sha'), run.get('repository_id'), run.get('head_repository_id'))
                 == (RUN_ID, SOURCE, REPOSITORY_ID, REPOSITORY_ID), 'API artifact repository/source/run mismatch')
        _require(artifact.get('expired') is False, 'API artifact expired or expiry unknown')
        packages = row['packages']
        for package in packages:
            _package(package)
        _require(packages == sorted(packages, key=lambda item: (item['P'], item['V'], item['A']))
                 and len(packages) == len({(item['P'], item['V'], item['A']) for item in packages}) == 27,
                 'unexpected package count/order/duplicates')
    _require(seen_names == ARTIFACT_NAMES and len(seen_ids) == 9, 'incomplete API OCI artifact set')
    _materials(root, Path(source_root), selector, reference, material_map)
    bundle_rows = selector['files'] + [{'path': 'selection-manifest.json', 'bytes': SELECTOR_BYTES, 'sha256': SELECTOR_SHA256}]
    # USTAR has no extended headers for these exact ASCII names. Reject otherwise.
    tar_body = 0
    for row in bundle_rows:
        info = tarfile.TarInfo(DIRECTORY + '/' + row['path'])
        info.size = row['bytes']
        info.tobuf(format=tarfile.USTAR_FORMAT, encoding='ascii', errors='strict')
        tar_body += 512 + ((row['bytes'] + 511) // 512) * 512
    tar_bytes = ((tar_body + 1024 + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE
    # Conservative deflate stored/fixed-block upper bound plus gzip framing.
    gzip_bound = tar_bytes + ((tar_bytes + 7) >> 3) + ((tar_bytes + 63) >> 6) + 64
    return {'schema': 'polaris-exact-oci-material-policy-v1', 'directory': root, 'source_root': Path(source_root),
            'selector': selector, 'selector_sha256': SELECTOR_SHA256, 'binding': binding,
            'reference_path': reference_path, 'material_map_path': material_map_path,
            'artifacts': reference['artifacts'], 'bundle_tar_bytes': tar_bytes,
            'bundle_maximum_bytes': gzip_bound, '_bundle_rows': bundle_rows}


def _checked_policy(policy):
    _require(isinstance(policy, dict) and policy.get('schema') == 'polaris-exact-oci-material-policy-v1'
             and policy.get('selector_sha256') == SELECTOR_SHA256, 'invalid material policy')
    root = Path(policy['directory'])
    selector = _json(_file(root, {'path': 'selection-manifest.json', 'bytes': SELECTOR_BYTES,
                                 'sha256': SELECTOR_SHA256}, read=True))
    reference = _json(_file(root, selector['materialReference'], read=True))
    _require(policy['selector'] == selector and policy['binding'] == selector['binding']
             and policy['artifacts'] == reference['artifacts'], 'material policy changed after loading')
    return root, selector, reference


def check_image(policy, artifact_name, actual_image_path):
    """Hash fixed actual image tar bytes before running the unchanged OCI parser."""
    _, _, reference = _checked_policy(policy)
    _require(artifact_name in ARTIFACT_NAMES, 'invalid image artifact name')
    row = reference['artifacts'][artifact_name]
    _require(_digest_file(actual_image_path, row['imageBytes']) == (row['imageBytes'], row['imageSHA256']), 'actual image size/hash mismatch')
    return row


def write_bundle(policy, path):
    """Write a deterministic 53-file audit bundle after caller budget admission.

    No public Release asset is created. The external publisher receipt binds the
    returned hash; no bundle contains its own hash or a not-yet-existing commit.
    """
    root, selector, _ = _checked_policy(policy)
    path = Path(path)
    _require(not path.exists() and not path.is_symlink(), 'audit bundle destination already exists')
    _require(not path.resolve().is_relative_to(root.resolve()), 'bundle cannot be placed in its own material directory')
    _closure(root, selector)
    bundle_rows = selector['files'] + [{'path': 'selection-manifest.json', 'bytes': SELECTOR_BYTES,
                                      'sha256': SELECTOR_SHA256}]
    created_identity = None
    try:
        with path.open('xb') as raw:
            created = os.fstat(raw.fileno())
            created_identity = (created.st_dev, created.st_ino)
            with gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0, compresslevel=9) as compressed:
                with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT, encoding='ascii') as archive:
                    for row in sorted(bundle_rows, key=lambda item: item['path']):
                        # Bound and verify the exact bytes subsequently handed to tar.
                        data = _file(root, row, read=True)
                        info = tarfile.TarInfo(DIRECTORY + '/' + row['path'])
                        info.size, info.mode, info.mtime = row['bytes'], 0o644, 0
                        info.uid = info.gid = 0
                        info.uname = info.gname = ''
                        archive.addfile(info, io.BytesIO(data))
        length, digest = _digest_file(path)
        _require(length <= policy['bundle_maximum_bytes'], 'bundle exceeds admitted worst-case bound')
    except BaseException as primary:
        # Only remove the file this invocation created, never a pre-existing or
        # concurrently replaced destination. Caller also owns budget cleanup.
        if created_identity is not None:
            try:
                current = path.lstat()
                if (current.st_dev, current.st_ino) == created_identity:
                    path.unlink()
            except FileNotFoundError:
                pass
            except OSError as cleanup_error:
                # Preserve the original validation/write error (e.g. EDQUOT).
                # Cleanup failure is secondary and must not mask that cause.
                if hasattr(primary, 'add_note'):
                    primary.add_note('OCI supplement partial cleanup failed: ' + str(cleanup_error))
        raise
    result = {'name': path.name, 'bytes': length, 'sha256': digest}
    policy['_written_bundle'] = {'path': path.resolve(), **result}
    return result


def record(policy, publisher_sha, bundle_path):
    """Return independent supplemental receipt fields, not legal certification."""
    _require(re.fullmatch('[0-9a-f]{40}', publisher_sha or '') is not None, 'invalid immutable publisher commit')
    root, selector, _ = _checked_policy(policy)
    bundle = policy.get('_written_bundle')
    _require(bundle is not None and Path(bundle_path).resolve() == bundle['path'], 'bundle was not written by this policy')
    _require(_digest_file(bundle_path, bundle['bytes']) == (bundle['bytes'], bundle['sha256']), 'audit bundle changed before receipt')
    _closure(root, selector)
    expected_members = {DIRECTORY + '/' + item['path']: item for item in selector['files']}
    expected_members[DIRECTORY + '/selection-manifest.json'] = {
        'path': 'selection-manifest.json', 'bytes': SELECTOR_BYTES, 'sha256': SELECTOR_SHA256}
    with tarfile.open(bundle_path, 'r:gz') as archive:
        members = archive.getmembers()
        _require(len(members) == len(expected_members) == 53
                 and {item.name for item in members} == set(expected_members), 'audit bundle member set mismatch')
        for member in members:
            expected = expected_members[member.name]
            _require(member.isfile() and member.size == expected['bytes'] and member.mode == 0o644
                     and member.uid == member.gid == member.mtime == 0 and not member.uname and not member.gname,
                     'audit bundle member metadata mismatch')
            data = archive.extractfile(member).read()
            _require(len(data) == expected['bytes'] and _sha(data) == expected['sha256'], 'audit bundle member changed')
    base_url = f'https://github.com/{REPOSITORY}/blob/{publisher_sha}/{DIRECTORY}/'
    return {'schema': 'polaris-oci-material-supplement-receipt-v1', 'policy': 'exact-39791192772-attempt1-no-fallback',
            'sourceCommit': SOURCE, 'sourceTree': TREE, 'tag': TAG, 'tagObject': TAG_OBJECT,
            'producerRunId': RUN_ID, 'producerAttempt': ATTEMPT,
            'publisherCommit': publisher_sha, 'publisherImmutableURL': f'https://github.com/{REPOSITORY}/tree/{publisher_sha}/{DIRECTORY}',
            'selector': {'path': DIRECTORY + '/selection-manifest.json', 'bytes': SELECTOR_BYTES,
                         'sha256': SELECTOR_SHA256, 'url': base_url + 'selection-manifest.json'},
            'materialMap': selector['materialMap'], 'materialReference': selector['materialReference'],
            'sourceAcquisition': selector['sourceAcquisition'], 'noticeInventory': selector['noticeInventory'],
            'historicalAnchors': {key: selector['binding'][key] for key in
                                  ('historicalMaterialMap', 'historicalReuseReference', 'historicalAcquisition')},
            'nativeIndexSHA256': selector['binding']['nativeIndexSHA256'], 'sourceArchive': selector['binding']['sourceArchive'],
            'auditBundle': {key: bundle[key] for key in ('name', 'bytes', 'sha256')},
            'artifactCount': 9, 'packageAssociationCount': 243,
            'coreBindingPolicy': selector['coreBindingPolicy'], 'publicReleaseAssetSetUnchanged': True,
            'ociSeparateDistributionChannel': True, 'legalConclusion': False}
