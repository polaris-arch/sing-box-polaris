#!/usr/bin/env python3
"""Offline repackage fixed native bytes with the complete reviewed material inputs."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile
import zipfile

INPUT_SHA = '372549826169567a168d313f28253d2b4a500d925d651390925189a93f84a043'
SOURCE = 'a01da7a942b3a0dbbfdfda2bba5bd63d5bd9d932'
TREE = '0bd19d8461347887c884f10250a402aa85decfe6'
TARGETS = {f'{os}/{arch}' for os in ('linux', 'windows', 'darwin') for arch in ('amd64', 'arm64')}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_info(path):
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'name': path.name, 'bytes': path.stat().st_size, 'sha256': digest}


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def check_bytes(data, expected, label):
    if len(data) != expected['bytes'] or sha(data) != expected['sha256']:
        raise ValueError(label + ': fixed bytes/hash mismatch')


def safe_name(name):
    if not name or '\\' in name or name.startswith('/') or any(x in ('', '.', '..') for x in name.split('/')):
        raise ValueError('unsafe member: ' + name)
    return name


def read_archive(path, expected):
    # Snapshot once: all subsequent validation and writing use these same bytes.
    data = path.read_bytes()
    check_bytes(data, expected, path.name)
    members = {}
    def add(name, content, mode):
        safe_name(name)
        if name in members:
            raise ValueError('duplicate member: ' + name)
        members[name] = (content, mode & 0o777)
    if path.name.endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    safe_name(member.filename.rstrip('/'))
                    continue
                if member.file_size > 200_000_000 or (member.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError('oversized or linked member')
                add(member.filename, archive.read(member), (member.external_attr >> 16) or 0o644)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            for member in archive:
                if member.isdir():
                    safe_name(member.name.rstrip('/'))
                    continue
                if not member.isfile() or member.size > 200_000_000:
                    raise ValueError('non-regular or oversized member')
                add(member.name, archive.extractfile(member).read(), member.mode)
    if {name: sha(item[0]) for name, item in members.items()} != expected['members']:
        raise ValueError('original member set/hash mismatch')
    return members


def write_archive(path, members):
    if path.name.endswith('.zip'):
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for name, (data, mode) in sorted(members.items()):
                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (0o100000 | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, data)
    else:
        with path.open('wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0, compresslevel=6) as zipped:
            with tarfile.open(fileobj=zipped, mode='w', format=tarfile.PAX_FORMAT) as archive:
                for name, (data, mode) in sorted(members.items()):
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.mtime = len(data), mode, 0
                    archive.addfile(info, io.BytesIO(data))


def material_inputs(repo, inputs):
    root = repo / 'release/desktop-source-candidate'
    index_bytes = (root / 'DESKTOP-SOURCE-NOTICE-INDEX-controlled.json').read_bytes()
    if sha(index_bytes) != inputs['indexSha256']:
        raise ValueError('controlled index drift')
    index = json.loads(index_bytes)
    bundle = (root / 'DESKTOP-SOURCE-NOTICE-SUPERSET.txt').read_bytes()
    check_bytes(bundle, {'bytes': inputs['noticeBytes'], 'sha256': inputs['noticeSha256']}, 'whole notice bundle')
    if len(index['noticeRecords']) != inputs['noticeRecords']:
        raise ValueError('notice record count')
    for record in index['noticeRecords']:
        start = record['byteOffset']
        check_bytes(bundle[start:start + record['bytes']], record, record['sourcePath'])
    if index['sourceCommit'] != SOURCE or index['sourceTree'] != TREE:
        raise ValueError('material source mismatch')
    if {x['platform'] for x in inputs['platforms']} != TARGETS or len(inputs['platforms']) != 6:
        raise ValueError('six exact targets required')
    return {'licenses/DESKTOP-SOURCE-NOTICE-SUPERSET.txt': bundle,
            'source/SOURCE-INDEX.json': index_bytes,
            'source/ACQUIRE-AND-BUILD.md': (repo / 'release/native-publication/ACQUIRE-AND-BUILD.md').read_bytes(),
            'source/COVERAGE-DECISIONS.json': (repo / 'release/native-publication/coverage-decisions.json').read_bytes()}


def repack_one(path, output, item, inputs, additions):
    original = read_archive(path, item['archive'])
    roots = {name.split('/')[0] for name in original}
    if len(roots) != 1:
        raise ValueError('single archive root required')
    root = roots.pop()
    provenance = json.loads(original[root + '/provenance.json'][0])
    if (provenance['sourceCommit'], provenance['sourceTree'], provenance['sourceOverlay']) != (SOURCE, TREE, 0):
        raise ValueError('original source identity mismatch')
    if (provenance['workflowCommit'], int(provenance['workflowRun']), int(provenance['workflowAttempt'])) != (item['producerCommit'], item['run'], 1):
        raise ValueError('original producer/run mismatch')
    core = root + ('/sing-box.exe' if item['platform'].startswith('windows/') else '/sing-box')
    if sha(original[core][0]) != item['coreSha256']:
        raise ValueError('core drift')
    members = dict(original)
    for name, data in additions.items():
        name = root + '/' + name
        if name in members:
            raise ValueError('additional member overwrites original')
        members[name] = (data, 0o644)
    distribution = {'schemaVersion': 1, 'sourceCommit': SOURCE, 'sourceTree': TREE,
                    'proposedTag': inputs['proposedTag'], 'compiledVersion': inputs['compiledVersion'],
                    'originalArchive': item['archive'], 'originalProducerCommit': item['producerCommit'],
                    'originalRun': item['run'], 'originalAttempt': 1,
                    'materialCommit': inputs['materialCommit'], 'noticeRecords': inputs['noticeRecords'],
                    'noticeSha256': inputs['noticeSha256'], 'sourceAsset': inputs['sourceAsset'],
                    'distributionSigningPerformed': False, 'binaryBytesAndOriginalSignaturesPreserved': True,
                    'originalProvenancePreserved': True, 'historicalCandidateFlagsNotRewritten': True,
                    'publicationPerformed': False, 'independentFinalPackagingReview': 'pending'}
    members[root + '/distribution.json'] = (encode(distribution), 0o644)
    sums = ''.join(f'{sha(data)}  {name[len(root)+1:]}\n' for name, (data, _) in sorted(members.items()) if name != root + '/SHA256SUMS')
    members[root + '/SHA256SUMS'] = (sums.encode(), original[root + '/SHA256SUMS'][1])
    target = output / path.name
    write_archive(target, members)
    expected = {**file_info(target), 'members': {n: sha(d) for n, (d, _) in members.items()}}
    verified = read_archive(target, expected)
    if verified != members:
        raise ValueError('final member mode/content mismatch')
    for name, data_mode in original.items():
        if name != root + '/SHA256SUMS' and verified[name] != data_mode:
            raise ValueError('original payload/provenance/mode changed')
    return {'platform': item['platform'], 'archive': expected, 'memberModes': {n: oct(m) for n, (_, m) in members.items()},
            'coreSha256': item['coreSha256'], 'originalProducerCommit': item['producerCommit'],
            'originalRun': item['run'], 'originalArtifactId': item['artifactId'],
            'signatureObservation': item['signatureObservation'], 'signatureChanges': [],
            'binaryBytesPreserved': True, 'wholeNoticeBundleAdopted': True}


def prepare(repo, archive_dir, source, destination):
    raw = (repo / 'release/native-publication/inputs.json').read_bytes()
    if sha(raw) != INPUT_SHA:
        raise ValueError('frozen publication inputs drift')
    inputs = json.loads(raw)
    additions = material_inputs(repo, inputs)
    if destination.exists():
        raise ValueError('destination already exists; preserve prior preparation')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.publication-pending-', dir=destination.parent) as temporary:
        output = Path(temporary)
        packages = [repack_one(archive_dir / x['archive']['name'], output, x, inputs, additions) for x in inputs['platforms']]
        # Copy exact v4 asset once and compare the copied bytes to the initial fixed identity.
        shutil.copyfile(source, output / inputs['sourceAsset']['name'])
        if file_info(output / inputs['sourceAsset']['name']) != inputs['sourceAsset']:
            raise ValueError('exact v4 source asset mismatch')
        receipt = {'schemaVersion': 1, 'repository': inputs['repository'], 'proposedTag': inputs['proposedTag'],
                   'tagTargetCommit': SOURCE, 'sourceTree': TREE, 'inputManifestSha256': INPUT_SHA,
                   'packagerSha256': sha(Path(__file__).read_bytes()), 'materialCommit': inputs['materialCommit'],
                   'sourceAsset': inputs['sourceAsset'], 'packages': packages,
                   'coverageDecisions': json.loads(additions['source/COVERAGE-DECISIONS.json']),
                   'publicUploadPerformed': False, 'publicDownloadVerification': 'pending',
                   'signingTreatment': 'No signing or binary rewrite. Existing signatures are byte-preserved; trust not asserted.'}
        (output / 'polaris-box-release-receipt.json').write_bytes(encode(receipt))
        shutil.copyfile(repo / 'release/native-publication/RELEASE-NOTES.md', output / 'polaris-box-release-notes.md')
        assets = [file_info(p) for p in sorted(output.iterdir())]
        (output / 'SHA256SUMS').write_text(''.join(f"{a['sha256']}  {a['name']}\n" for a in assets))
        assets.append(file_info(output / 'SHA256SUMS'))
        if len(assets) != 10:
            raise ValueError('exact ten release assets required')
        manifest = {'schemaVersion': 1, 'repository': inputs['repository'], 'tag': inputs['proposedTag'],
                    'tagTargetCommit': SOURCE, 'assets': sorted(assets, key=lambda a: a['name']),
                    'publicUploadPerformed': False}
        (output / 'UPLOAD-ASSETS.json').write_bytes(encode(manifest))
        Path(temporary).rename(destination)
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--archive-dir', type=Path, required=True)
    parser.add_argument('--source-asset', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.repo, args.archive_dir, args.source_asset, args.output), indent=2))
