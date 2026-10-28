"""Exact S6 OCI material selection: 242 shared associations and one jansson recipe."""
import copy
import gzip
import io
import os
from pathlib import Path
import re
import tarfile

import oci_material_supplement as legacy
import oci_material_registry as prior
import oci_material_selection_12_5 as previous

SOURCE = 'bfcdf96b244f63e0fe84736ee4a4edd58f6b209e'
TREE = '4c0fdb31d59967f41c808ea6b63f87ca9661c2cf'
TAG = 'v1.15.0-polaris-alpha.12.6'
TAG_OBJECT = '8a230c1d34cb4855b261944e2935ce36f9cd14de'
RUN_ID = 40478933774
ATTEMPT = 1
DIRECTORY = 'release/dependency-sources/oci/selections/40478933774-attempt1'
SELECTOR_BYTES = 11369
SELECTOR_SHA256 = '961813ad9d3da94e607d113754c380f93d8af6ec951a00655d322ab5e5d772d5'
SCHEMA = 'polaris-exact-oci-single-recipe-delta-12.6-policy-v1'
_require = legacy._require


def _selector_record():
    return {'path': 'selection-manifest.json', 'bytes': SELECTOR_BYTES, 'sha256': SELECTOR_SHA256}


def _historical_sources(source_root, publisher_root):
    """Validate source bytes through 12.5 without inventing historical API freshness."""
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
    """Exactly 242 old associations and the measured loong64 jansson recipe."""
    _require(reference['schema'] == 'polaris-current-oci-material-reference-v1'
             and material_map['schema'] == 'polaris-exact-oci-single-recipe-delta-v1'
             and reference['materialMapSHA256'] == selector['materialMap']['sha256'], 'bfcdf9 reference/map mismatch')
    for document in (reference, material_map):
        _require((document['sourceCommit'], document['producerRunId'], document['producerAttempt']) == (SOURCE, RUN_ID, ATTEMPT)
                 and type(document['producerRunId']) is int and type(document['producerAttempt']) is int
                 and document['legalConclusion'] is False, 'bfcdf9 material identity mismatch')
    _require(material_map['sharedMaterials'] == selector['sharedMaterials']
             and type(material_map['newRecipeCount']) is int and material_map['newRecipeCount'] == 1
             and material_map['crossArchitectureSourceAssociations'] == [], 'bfcdf9 delta ownership differs')
    _require(set(reference['artifacts']) == legacy.ARTIFACT_NAMES, 'bfcdf9 exact image scope required')
    package = {'P': 'jansson', 'V': '2.15.1-r0', 'A': 'loongarch64', 'L': 'MIT', 'o': 'jansson',
               'c': '71e8557e8e44bbe04bffec34b6b2693798611f62', 'C': 'Q1CsgFP2G7tgt57D7tUaJEBnMIeUk='}
    exact, changed = [], []
    for name, row in sorted(reference['artifacts'].items()):
        old = historical['artifacts'][name]
        _require(all(row[key] == old[key] for key in ('platform', 'repositories', 'baseDependencies')),
                 'bfcdf9 platform/repository/base drift')
        _require(all(row[key] == value for key, value in selector['artifacts'][name].items()), 'bfcdf9 actual image binding differs')
        packages = row['packages']
        for item in packages:
            legacy._package(item)
        _require(len(packages) == len({p['P'] for p in packages}) == 27
                 and packages == sorted(packages, key=lambda p: (p['P'], p['V'], p['A'])), 'bfcdf9 package set/order differs')
        for item in packages:
            association = {'artifact': name, 'package': item}
            if item in old['packages']:
                exact.append(association)
            else:
                _require(name == 'oci-linux-loong64' and item == package, 'bfcdf9 unreviewed seven-field package delta')
                changed.append(association)
    _require(len(exact) == 242 and len(changed) == 1 and exact == material_map['exactPackageAssociations']
             and changed == material_map['newPackageAssociations'], 'bfcdf9 exact 242+1 association closure differs')
    recipe = material_map['newRecipe']
    _require((recipe['repository'], recipe['commit'], recipe['origin'], recipe['directoryTreeSHA']) ==
             ('alpinelinux/aports', package['c'], 'jansson', '2fb90ff28e9c883f29deb6fe834f2e094b641b6a'), 'bfcdf9 exact recipe differs')
    rows = recipe['files']
    _require(len(rows) == 1 and rows[0]['path'] == 'aports/' + package['c'] + '/main/jansson/APKBUILD'
             and rows[0]['gitMode'] == '100644', 'bfcdf9 recipe path/mode/patch scope differs')
    raw = legacy._file(root, rows[0], read=True)
    blob = legacy._sha(b'blob ' + str(len(raw)).encode() + b'\0' + raw, 'sha1')
    _require(len(raw) == 820 and blob == rows[0]['gitBlob'] == 'd960e9783e3234446043ddf87485cbda81adb4f4', 'bfcdf9 APKBUILD bytes differ')
    body = b'100644 APKBUILD\0' + bytes.fromhex(blob)
    _require(legacy._sha(b'tree ' + str(len(body)).encode() + b'\0' + body, 'sha1') == recipe['directoryTreeSHA'], 'bfcdf9 recipe tree differs')
    sums = re.findall(r'^([a-f0-9]{128})  (.+)$', raw.decode('utf-8'), re.M)
    archive_name = 'jansson-2.15.1.tar.gz'
    url = 'https://github.com/akheron/jansson/releases/download/v2.15.1/' + archive_name
    archive_sha = '0c7114dc0b2d22a670724a1f95922029d7077c19dbf79a584cb8084d2f267f2f'
    archive_sha512 = 'cb952d51bf0b358f316f36fb925267f3ce7529ef88faca935db73923708269e21733b9682eb64d5478a6d9a3d366b34b42d9b63dd1f510537342c4cc79345740'
    _require(sums == [(archive_sha512, archive_name)], 'bfcdf9 APKBUILD source checksum scope differs')
    acquisition = legacy._json(legacy._file(root, selector['sourceAcquisition'], read=True))
    notices = legacy._json(legacy._file(root, selector['noticeInventory'], read=True))
    for document, schema, filename, count in (
            (acquisition, 'polaris-exact-oci-delta-source-acquisition-v1', 'source-acquisition.json', 'newDownloads'),
            (notices, 'polaris-exact-oci-delta-notice-inventory-v1', 'notice-inventory.json', 'newNotices')):
        _require(document['schema'] == schema and document['legalConclusion'] is False
                 and (document['sourceCommit'], document['producerRunId'], document['producerAttempt']) == (SOURCE, RUN_ID, ATTEMPT)
                 and type(document['producerRunId']) is int and type(document['producerAttempt']) is int
                 and type(document[count]) is int and document[count] == 1
                 and [r['path'] for r in document['references']] == [previous.DIRECTORY + '/' + filename], 'bfcdf9 historical/delta source ownership differs')
    _require(acquisition['historicalReceiptsUnmodified'] is True and len(acquisition['newSources']) == 1, 'bfcdf9 source acquisition scope differs')
    source = acquisition['newSources'][0]
    _require(source['name'] == archive_name and source['path'] == 'sources/' + archive_name
             and source['requestedURL'] == url and type(source['assetId']) is int and source['assetId'] == 463527312,
             'bfcdf9 source URI/asset differs')
    data = legacy._file(root, source, read=True)
    _require((len(data), legacy._sha(data), legacy._sha(data, 'sha512')) == (623952, archive_sha, archive_sha512)
             and source['sha512'] == archive_sha512, 'bfcdf9 source archive double hash differs')
    _require(recipe['externalInputs'] == [{'name': archive_name, 'sha512': archive_sha512,
             'requestedURL': url, 'sourceArchivePath': source['path']}], 'bfcdf9 recipe/external source association differs')
    request = legacy._json(legacy._file(root, source['getRequest'], read=True))
    receipt = legacy._json(legacy._file(root, source['getReceipt'], read=True))
    _require(request['method'] == receipt['method'] == 'GET' and request['url'] == receipt['requestedURL'] == url
             and type(request['assetId']) is int and type(receipt['assetId']) is int
             and request['assetId'] == receipt['assetId'] == 463527312 and request['retry'] is False
             and (request['expectedBytes'], request['expectedSHA256'], request['expectedSHA512']) == (623952, archive_sha, archive_sha512)
             and type(receipt['HTTP']) is int and receipt['HTTP'] == 200 and receipt['status'] == 'VERIFIED'
             and receipt['fullGet'] is True and receipt['openResponseAndBodyClosed'] is True and 'errorType' not in receipt
             and (receipt['bytes'], receipt['sha256'], receipt['sha512']) == (623952, archive_sha, archive_sha512),
             'bfcdf9 actual full GET receipt differs')
    redirects = receipt['redirects']
    final = receipt['effectiveURLRedacted']
    _require(re.fullmatch(r'https://release-assets\.githubusercontent\.com/github-production-release-asset/[0-9]+/[a-f0-9-]+', final)
             and len(redirects) == 1 and redirects[0]['HTTP'] == 302 and redirects[0]['from'] == url
             and redirects[0]['to'] == final and redirects[0]['queryOmitted'] is True
             and receipt['responseHeaders']['Content-Length'] == '623952', 'bfcdf9 explicit redacted redirect/response binding differs')
    for headers in [receipt['responseHeaders'], *[r['headers'] for r in redirects]]:
        _require(all(k.lower() in {'content-length', 'content-type', 'date', 'etag', 'last-modified'} for k in headers),
                 'bfcdf9 unsafe/unreviewed retained HTTP header')
    files = notices['files']
    _require(len(files) == 1 and files[0]['path'] == 'notices/jansson-2.15.1/LICENSE'
             and files[0]['archiveMember'] == 'jansson-2.15.1/LICENSE'
             and files[0]['sourceArchiveSHA256'] == archive_sha, 'bfcdf9 notice source/member differs')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        members = archive.getmembers()
        _require(len(members) == 457 and sum(m.size for m in members) == 2621790
                 and len({m.name.rstrip('/') for m in members}) == len(members), 'bfcdf9 source tar member closure differs')
        for member in members:
            path = legacy._relative(member.name.rstrip('/'))
            _require(path.parts[0] == 'jansson-2.15.1' and (member.isfile() or member.isdir()), 'bfcdf9 unsafe source tar member')
        found = [m for m in members if m.name == files[0]['archiveMember']]
        _require(len(found) == 1 and found[0].isfile() and found[0].size == files[0]['bytes'] == 1912
                 and archive.extractfile(found[0]).read() == legacy._file(root, files[0], read=True), 'bfcdf9 actual notice bytes differ')



def _load(artifacts, source_root, publisher_root):
    root = legacy._path(publisher_root, DIRECTORY)
    selector = legacy._json(legacy._file(root, _selector_record(), read=True))
    prior._current_closure(root, selector)
    _require(selector['schema'] == 'polaris-exact-oci-single-recipe-delta-selection-v1'
             and selector['directory'] == DIRECTORY and selector['legalConclusion'] is False, 'bfcdf9 selector schema mismatch')
    binding = selector['binding']
    _require(tuple(binding[k] for k in ('repository', 'repositoryId', 'sourceCommit', 'sourceTree', 'tag', 'tagObject',
             'producerRunId', 'producerAttempt', 'workflowPath')) == (legacy.REPOSITORY, legacy.REPOSITORY_ID,
             SOURCE, TREE, TAG, TAG_OBJECT, RUN_ID, ATTEMPT, legacy.WORKFLOW), 'bfcdf9 selection tuple mismatch')
    second, historical, first_root, first_map, members = _historical_sources(source_root, publisher_root)
    expected_shared = {'selector': {'path': previous.DIRECTORY + '/selection-manifest.json', 'bytes': previous.SELECTOR_BYTES,
        'sha256': previous.SELECTOR_SHA256}, 'sourceCommit': previous.SOURCE, 'producerRunId': previous.RUN_ID,
        'producerAttempt': previous.ATTEMPT, 'relabelled': False}
    _require(selector['sharedMaterials'] == expected_shared and selector['coreBindingPolicy'] == second['coreBindingPolicy'],
             'bfcdf9 historical ownership/core boundary differs')
    reference_path = legacy._file(root, selector['materialReference'])
    map_path = legacy._file(root, selector['materialMap'])
    reference = legacy._json(reference_path.read_bytes())
    material_map = legacy._json(map_path.read_bytes())
    _reassociation(root, selector, reference, material_map, historical, first_root, first_map)
    for key in ('sourceAcquisition', 'noticeInventory'):
        for row in legacy._json(legacy._file(root, selector[key], read=True))['references']:
            legacy._file(publisher_root, row)
    rows = selector['artifacts']
    _require(set(rows) == legacy.ARTIFACT_NAMES and isinstance(artifacts, list) and len(artifacts) == 9, 'bfcdf9 requires exact nine OCI APIs')
    names, ids = set(), set()
    for a in artifacts:
        name, ident = a.get('name'), a.get('id')
        _require(name in rows and name not in names and type(ident) is int and ident not in ids, 'bfcdf9 unknown/duplicate artifact')
        names.add(name); ids.add(ident)
        row, run = rows[name], a.get('workflow_run', {})
        _require((ident, a.get('size_in_bytes'), a.get('digest')) == (row['artifactId'], row['archiveBytes'], row['artifactAPIDigest'])
                 and row['artifactAPIDigest'] == 'sha256:' + row['archiveSHA256'], 'bfcdf9 artifact bytes identity changed')
        _require((run.get('id'), run.get('head_sha'), run.get('repository_id'), run.get('head_repository_id')) ==
                 (RUN_ID, SOURCE, legacy.REPOSITORY_ID, legacy.REPOSITORY_ID) and a.get('expired') is False, 'bfcdf9 artifact origin/expiry differs')
    members += [(root, row, DIRECTORY + '/' + row['path']) for row in selector['files']]
    members += [(root, _selector_record(), DIRECTORY + '/selection-manifest.json')]
    _require(len(members) == len({name for _, _, name in members}) == 93, 'bfcdf9 bundle closure mismatch')
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
             (SOURCE, TREE, TAG, TAG_OBJECT, RUN_ID, ATTEMPT, legacy.WORKFLOW), 'bfcdf9 wrong product/run tuple')
    return _load(artifacts, source_root, publisher_root)[0]


def _checked(policy):
    _require(isinstance(policy, dict) and policy.get('schema') == SCHEMA, 'bfcdf9 invalid policy')
    actual, members = _load(policy['_api'], policy['source_root'], policy['publisher_root'])
    _require({k: v for k, v in policy.items() if k != '_written_bundle'} == actual, 'bfcdf9 policy changed after validation')
    return actual, members


def bundle_name(policy):
    _checked(policy)
    return 'polaris-oci-material-supplement-40478933774-attempt1.tar.gz'


def check_image(policy, artifact_name, actual_image_path):
    actual, _ = _checked(policy)
    _require(artifact_name in actual['artifacts'], 'bfcdf9 unknown image')
    row = actual['artifacts'][artifact_name]
    _require(legacy._digest_file(actual_image_path, row['imageBytes']) == (row['imageBytes'], row['imageSHA256']), 'bfcdf9 actual image bytes differ')
    return row


def write_bundle(policy, path):
    actual, members = _checked(policy)
    path = Path(path)
    _require(not path.exists() and not path.is_symlink() and all(not path.resolve().is_relative_to(root.resolve())
             for root, _, _ in members), 'bfcdf9 unsafe bundle destination')
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
        _require(size <= actual['bundle_maximum_bytes'], 'bfcdf9 bundle exceeds admitted bound')
    except BaseException as primary:
        if identity is not None:
            try:
                info = path.lstat()
                if (info.st_dev, info.st_ino) == identity: path.unlink()
            except FileNotFoundError:
                pass
            except OSError as error:
                primary.add_note('bfcdf9 partial bundle cleanup failed: ' + str(error))
        raise
    policy['_written_bundle'] = {'path': path.resolve(), 'name': path.name, 'bytes': size, 'sha256': hashed}
    return {k: v for k, v in policy['_written_bundle'].items() if k != 'path'}


def record(policy, publisher_sha, bundle_path):
    _require(re.fullmatch('[0-9a-f]{40}', publisher_sha or '') is not None, 'bfcdf9 publisher SHA required')
    actual, members = _checked(policy)
    bundle = policy.get('_written_bundle')
    _require(bundle is not None and Path(bundle_path).resolve() == bundle['path'], 'bfcdf9 bundle not written by policy')
    _require(legacy._digest_file(bundle_path, bundle['bytes']) == (bundle['bytes'], bundle['sha256']), 'bfcdf9 bundle bytes changed')
    expected = {name: row for _, row, name in members}
    with tarfile.open(bundle_path, 'r:gz') as archive:
        entries = archive.getmembers()
        _require(len(entries) == len(expected) and {m.name for m in entries} == set(expected), 'bfcdf9 bundle entries differ')
        for member in entries:
            row = expected[member.name]
            _require(member.isfile() and member.size == row['bytes'] and member.mode == 0o644 and member.uid == member.gid == member.mtime == 0
                     and not member.uname and not member.gname, 'bfcdf9 bundle metadata differs')
            data = archive.extractfile(member).read()
            _require((len(data), legacy._sha(data)) == (row['bytes'], row['sha256']), 'bfcdf9 bundle member differs')
    s, b = actual['selector'], actual['binding']
    base = f'https://github.com/{legacy.REPOSITORY}/blob/{publisher_sha}/'
    return {'schema': 'polaris-oci-material-supplement-receipt-v1', 'policy': 'exact-40478933774-attempt1-no-fallback',
        'sourceCommit': SOURCE, 'sourceTree': TREE, 'tag': TAG, 'tagObject': TAG_OBJECT, 'producerRunId': RUN_ID,
        'producerAttempt': ATTEMPT, 'publisherCommit': publisher_sha, 'publisherImmutableURL': f'https://github.com/{legacy.REPOSITORY}/tree/{publisher_sha}/{DIRECTORY}',
        'selector': dict(_selector_record(), path=DIRECTORY + '/selection-manifest.json', url=base + DIRECTORY + '/selection-manifest.json'),
        'sharedMaterials': s['sharedMaterials'], 'materialMap': dict(s['materialMap'], path=DIRECTORY + '/' + s['materialMap']['path']),
        'materialReference': dict(s['materialReference'], path=DIRECTORY + '/' + s['materialReference']['path']),
        'sourceAcquisition': dict(s['sourceAcquisition'], path=DIRECTORY + '/' + s['sourceAcquisition']['path']),
        'noticeInventory': dict(s['noticeInventory'], path=DIRECTORY + '/' + s['noticeInventory']['path']),
        'nativeIndexSHA256': b['nativeIndexSHA256'], 'sourceArchive': b['sourceArchive'],
        'auditBundle': {k: bundle[k] for k in ('name', 'bytes', 'sha256')}, 'artifactCount': 9, 'packageAssociationCount': 243,
        'sharedPackageAssociationCount': 242, 'newPackageAssociationCount': 1, 'crossArchitectureSourceAssociationCount': 0, 'newRecipeCount': 1,
        'coreBindingPolicy': s['coreBindingPolicy'], 'publicReleaseAssetSetUnchanged': True, 'ociSeparateDistributionChannel': True, 'legalConclusion': False}
