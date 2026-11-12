#!/usr/bin/env python3
"""GitHub-only release gate. Inventory is read-only."""
import argparse
import io
from github_read_transport import read_get
import hashlib
from datetime import datetime
from urllib.parse import quote, urlsplit, urlunsplit

from release_identity import remote_tag_identity, public_product_name, validate_publication_index
from polaris_version import validate as validate_version
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile
import struct
import zlib
from contextlib import contextmanager, closing

IO_CHUNK = 1024 * 1024
SCRATCH_LIMIT = 4 * 1024**3
SPACE_RESERVE = 128 * 1024**2
JSON_LIMIT = 32 * 1024**2
PROPOSAL_LIMIT = 64 * 1024**2


class ScratchBudget:
    """Only invocation-owned bytes; statvfs cannot predict a per-user quota."""
    def __init__(self, root, limit=SCRATCH_LIMIT, reserve=SPACE_RESERVE, audit=None):
        self.root, self.limit, self.reserve = Path(root), limit, reserve
        self.root.mkdir(parents=True, exist_ok=True)
        self.live = self.peak = 0
        self.audit = audit
        self.state = {'phase': 'preflight', 'remoteWriteState': 'none'}

    def admit(self, size, context):
        require(type(size) is int and size >= 0, 'invalid scratch allocation')
        free = shutil.disk_usage(self.root).free
        self.state.update(context=str(context)[:400], requestedBytes=size, liveBytes=self.live,
                          peakBytes=self.peak, freeBytes=free, limitBytes=self.limit, reserveBytes=self.reserve)
        require(self.live + size <= self.limit, 'scratch budget exceeded: ' + str(self.state))
        require(free >= size + self.reserve, 'insufficient free scratch space: ' + str(self.state))
        self.live += size
        self.peak = max(self.peak, self.live)

    def release(self, size):
        self.live -= size
        require(self.live >= 0, 'scratch accounting underflow')

    def record(self, **fields):
        self.state.update(fields, liveBytes=self.live, peakBytes=self.peak)
        # A diagnostic failure must never replace the original quota/network error.
        record = json.dumps(self.state, indent=2) + '\n'
        print('Publisher storage: ' + record)
        if self.audit:
            try:
                self.audit.mkdir(parents=True, exist_ok=True)
                (self.audit / 'storage-status.json').write_text(record, encoding='utf-8', newline='\n')
            except OSError as error:
                print('Unable to retain storage diagnostic: ' + str(error)[:400])

    @contextmanager
    def temporary(self, size, context):
        self.admit(size, context)
        primary = None
        try:
            with tempfile.NamedTemporaryFile(dir=self.root, prefix='publisher-') as f:
                try:
                    yield f
                except BaseException as error:
                    primary = error
                    raise
        except BaseException as error:
            if primary is not None and error is not primary:
                primary.add_note('Temporary file cleanup also failed: ' + str(error)[:300])
                raise primary from error
            raise
        finally:
            self.release(size)

    def copy(self, source, destination):
        size = source.stat().st_size
        self.admit(size, 'audit copy ' + destination.name)
        created = False
        try:
            with source.open('rb') as src, destination.open('xb') as dst:
                created = True
                shutil.copyfileobj(src, dst, IO_CHUNK)
        except BaseException as error:
            if created:
                try:
                    destination.unlink(missing_ok=True)
                except OSError as cleanup:
                    error.add_note('Audit copy cleanup also failed: ' + str(cleanup)[:300])
            self.release(size)
            raise

    def write_json(self, destination, record, limit=JSON_LIMIT):
        data = (json.dumps(record, indent=2) + '\n').encode()
        require(len(data) <= limit, 'serialized evidence exceeds budget')
        self.admit(len(data), 'evidence ' + destination.name)
        created = False
        try:
            with destination.open('xb') as stream:
                created = True
                stream.write(data)
        except BaseException as error:
            if created:
                try:
                    destination.unlink(missing_ok=True)
                except OSError as cleanup:
                    error.add_note('Evidence cleanup also failed: ' + str(cleanup)[:300])
            self.release(len(data))
            raise


def bounded_zip_directory(path):
    """Bound metadata before ZipFile allocates its central directory (including ZIP64)."""
    size = path.stat().st_size
    with path.open('rb') as stream:
        stream.seek(max(0, size - 65557))
        tail = stream.read(65557)
        offset = tail.rfind(b'PK\x05\x06')
        require(offset >= 0 and len(tail) - offset >= 22, 'ZIP end record missing')
        end = struct.unpack('<4s4H2LH', tail[offset:offset+22])
        require(len(tail) - offset == 22 + end[-1] and end[1:3] == (0, 0), 'invalid/multidisk ZIP')
        count, directory_size, directory_offset = end[4:7]
        require(end[3] == count, 'multidisk ZIP entry counts')
        absolute = size - len(tail) + offset
        if absolute >= 20:
            stream.seek(absolute - 20)
            locator = stream.read(20)
            if locator[:4] == b'PK\x06\x07':
                _, disk, position, disks = struct.unpack('<4sLQL', locator)
                require(disk == 0 and disks == 1 and position + 56 <= absolute - 20, 'invalid ZIP64 locator')
                stream.seek(position)
                record = struct.unpack('<4sQ2H2L4Q', stream.read(56))
                require(record[0] == b'PK\x06\x06' and record[1] >= 44 and record[4:6] == (0, 0)
                        and record[6] == record[7], 'invalid/multidisk ZIP64')
                count, directory_size, directory_offset = record[7:10]
        require(0 < count <= 16384 and directory_size <= 32 * 1024**2
                and directory_offset + directory_size <= absolute, 'ZIP directory exceeds evidence budget')


def safe_zip_members(archive):
    members, files = {}, set()
    for item in archive.infolist():
        name = portable(item.filename).as_posix()
        require(item.orig_filename == item.filename and name == item.filename.rstrip('/'), 'noncanonical ZIP path')
        require(name.casefold() not in members, 'duplicate ZIP path')
        kind = stat.S_IFMT(item.external_attr >> 16)
        require(kind in ((0, stat.S_IFDIR) if item.is_dir() else (0, stat.S_IFREG)), 'non-regular archive entry')
        require(not item.flag_bits & 1 and item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), 'unsupported/encrypted Actions ZIP')
        require(item.file_size >= 0 and item.compress_size >= 0 and (not item.is_dir() or item.file_size == 0), 'invalid ZIP member size')
        members[name.casefold()] = item
        if not item.is_dir():
            files.add(name.casefold())
    for name in members:
        require(not any(parent.as_posix() in files for parent in PurePosixPath(name).parents if parent.as_posix() != '.'), 'ZIP file/directory prefix collision')
    return list(members.values())


def member_chunks(archive, item):
    """Count real inflated bytes, not ZipExtFile's declared-size-truncated view."""
    with archive.open(item):  # Validate local name, flags and overlap using stdlib.
        pass
    with open(archive.filename, 'rb') as stream:
        stream.seek(item.header_offset)
        header = struct.unpack('<4s5H3L2H', stream.read(30))
        require(header[0] == b'PK\x03\x04' and header[3] == item.compress_type, 'invalid local ZIP header')
        stream.seek(header[-2] + header[-1], 1)
        remaining, actual, crc = item.compress_size, 0, 0
        decoder = zlib.decompressobj(-15) if item.compress_type == zipfile.ZIP_DEFLATED else None
        while remaining:
            data = stream.read(min(remaining, IO_CHUNK))
            require(data, 'truncated compressed ZIP member')
            remaining -= len(data)
            while data:
                if decoder:
                    chunk = decoder.decompress(data, IO_CHUNK)
                    data = decoder.unconsumed_tail
                    require(not decoder.unused_data, 'trailing compressed ZIP member data')
                else:
                    chunk, data = data, b''
                actual += len(chunk)
                require(actual <= item.file_size, 'actual ZIP member exceeds declared size')
                crc = zlib.crc32(chunk, crc)
                if chunk:
                    yield chunk
        require(decoder is None or decoder.eof, 'truncated deflated ZIP member')
        require(actual == item.file_size and crc == item.CRC, 'ZIP member size/CRC mismatch')


@contextmanager
def artifact_archive(artifact, budget):
    size = artifact.get('size_in_bytes')
    require(type(size) is int and size > 0, 'Actions artifact ZIP size required')
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', artifact.get('digest', '')), 'Actions artifact digest missing')
    budget.state.update(artifactId=artifact['id'], artifact=artifact['name'])
    for key in ('member', 'readAttempt', 'readStatus', 'readHeaders', 'readBytes', 'readError'):
        budget.state.pop(key, None)
    with budget.temporary(size, 'ZIP ' + str(artifact['id']) + ' ' + artifact['name']) as zipped:
        measured = read_get(f'repos/{REPO}/actions/artifacts/{artifact["id"]}/zip', zipped, size,
                            record=budget.record)
        require(measured['bytes'] == size, 'Actions artifact ZIP size differs')
        require(artifact['digest'] == 'sha256:' + measured['sha256'], 'Actions artifact digest missing or mismatched')
        zipped.flush()
        bounded_zip_directory(Path(zipped.name))
        with zipfile.ZipFile(zipped.name) as archive:
            members = safe_zip_members(archive)
            yield archive, members


def measure_member(archive, item, destination=None, json_limit=None, json_decoder=json.loads):
    if json_limit is not None:
        require(item.file_size <= json_limit, 'JSON evidence exceeds serialized budget')
    digest, data, count = hashlib.sha256(), bytearray(), 0
    for chunk in member_chunks(archive, item):
        count += len(chunk)
        digest.update(chunk)
        if destination is not None:
            destination.write(chunk)
        if json_limit is not None:
            data.extend(chunk)
    return {'bytes': count, 'sha256': digest.hexdigest()}, json_decoder(data) if json_limit is not None else None

REPO = 'polaris-arch/sing-box-polaris'
RID = 1421657509
ROOT = Path(__file__).resolve().parents[2]
SCOPE = ROOT / 'release/ci/publisher-upstream-scope.json'
CONFIG = ROOT / 'release/ci/github-release.json'
# Bound once by bind_release() from the validated build run's dispatched tag; never from a committed file.
VERSION = PUBLIC_VERSION = TAG = RECEIPT = None


def bind_release(tag):
    global VERSION, PUBLIC_VERSION, TAG, RECEIPT
    require(isinstance(tag, str) and tag.startswith('v'), 'build run must be dispatched on a version tag')
    VERSION = validate_version(tag[1:])
    PUBLIC_VERSION = VERSION.replace('-polaris-', '-', 1)
    TAG = 'v' + VERSION
    RECEIPT = 'polaris-github-release-receipt-' + VERSION + '.json'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def api(path, method='GET', payload=None):
    if method == 'GET' and payload is None:
        stream = io.BytesIO()
        read_get(path, stream, JSON_LIMIT)
        return json.loads(stream.getvalue()) if stream.getvalue().strip() else None
    args = ['gh', 'api', '--method', method, path]
    if payload is not None:
        args += ['--input', '-']
    output = subprocess.check_output(args, input=json.dumps(payload).encode() if payload is not None else None)
    return json.loads(output) if output.strip() else None


def pages(path, key=None, maximum=None):
    result = []
    for page in range(1, 10001):
        data = api(path + ('&' if '?' in path else '?') + f'per_page=100&page={page}')
        batch = data[key] if key else data
        result.extend(batch)
        if maximum is not None and len(result) > maximum:
            raise ValueError('pagination item bound exceeded')
        if len(batch) < 100:
            return result
    raise ValueError('pagination bound exceeded')


def portable(name):
    p = PurePosixPath(name)
    require(not p.is_absolute() and '..' not in p.parts and '\\' not in name and ':' not in name, 'unsafe artifact path')
    require(p.parts and all(re.fullmatch(r'[A-Za-z0-9_.+ -]+', x) and x not in ('.', '..') for x in p.parts), 'unsafe filename')
    return p


def identity(source, source_dir):
    require(re.fullmatch(r'[0-9a-f]{40}', source), 'full source SHA required')
    require(os.environ.get('GITHUB_REPOSITORY') == REPO and os.environ.get('GITHUB_REPOSITORY_ID') == str(RID), 'wrong workflow repository')
    require(api(f'repos/{REPO}')['id'] == RID, 'remote repository ID mismatch')
    require(command('git', '-C', str(source_dir), 'rev-parse', 'HEAD') == source, 'publisher checkout differs from source')
    require(not command('git', '-C', str(source_dir), 'status', '--porcelain', '--untracked-files=no'), 'tracked source is dirty')
    owned = Path('release/ci/owned-distribution.json')
    if (ROOT / owned).exists() or (source_dir / owned).exists():
        require((ROOT / owned).is_file() and (source_dir / owned).is_file() and sha(ROOT / owned) == sha(source_dir / owned), 'publisher owned identity configuration differs from source')


def tag_identity(source):
    return remote_tag_identity(TAG, source)


def upload_endpoint(release, name):
    require(type(release.get('id')) is int and release['id'] > 0, 'invalid release ID')
    url = release.get('upload_url')
    require(isinstance(url, str), 'release upload URL missing')
    parsed = urlsplit(url.removesuffix('{?name,label}'))
    require(parsed.scheme == 'https' and parsed.netloc == 'uploads.github.com'
            and parsed.path == f'/repos/{REPO}/releases/{release["id"]}/assets'
            and not parsed.query and not parsed.fragment, 'unexpected release upload endpoint')
    require(len(portable(name).parts) == 1, 'upload filename must be a basename')
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, 'name=' + quote(name, safe=''), ''))


def validate_final_index(index, source, tree, tag_object, run_id, attempt, workflow, source_root=ROOT):
    import jsonschema
    jsonschema.Draft202012Validator(json.loads((ROOT / 'release/ci/native-release-index.schema.json').read_text(encoding='utf-8'))).validate(index)
    for key, value in [('repository', REPO), ('repositoryId', RID), ('version', VERSION), ('tag', TAG),
                       ('tagObject', tag_object), ('sourceCommit', source), ('sourceTree', tree)]:
        require(index[key] == value, 'final native index binding mismatch: ' + key)
    producer = index['producer']
    require((producer['repository'], producer['repositoryId'], producer['workflow'], producer['workflowCommit'],
             producer['runId'], producer['runAttempt']) == (REPO, RID, workflow, source, int(run_id), attempt),
            'final native producer identity mismatch')
    from native_release_index import expected_native, validate_trusted_execution, select_native_jobs
    expected = expected_native(VERSION)
    require(len(index['platforms']) == len(expected) and {x['id'] for x in index['platforms']} == set(expected), 'exact native identities required')
    for row in index['platforms']:
        validate_trusted_execution(row, producer, source_root)
        require((row['sourceCommit'], row['sourceTree'], row['version'], row['tag']) == (source, tree, VERSION, TAG), 'mixed source native row')
        require((row['target'], row['variant']) == (expected[row['id']]['target'], expected[row['id']]['variant']), 'native row matrix mismatch')
        require(row['archive'].get('releaseName') == public_product_name(row['archive']['name']), 'native public archive name mismatch')
        suffix = '.zip' if row['target'].startswith('windows/') else '.tar.gz'
        require(row['archive']['root'] == row['id'] and row['archive']['name'] == row['id'] + suffix, 'native archive identity mismatch')
    jobs = pages(f'repos/{REPO}/actions/runs/{run_id}/attempts/{attempt}/jobs', 'jobs', maximum=1000)
    require(producer['nativeJobs'] == select_native_jobs(jobs, source, int(run_id), attempt),
            'native producer job mapping differs from retained proof/API evidence')
    require(index['sourceArchive']['name'] == 'sing-box-polaris-source-' + source + '.tar.gz', 'immutable source archive basename required')
    from native_release_index import distribution_materials
    require(index['distributionMaterials'] == distribution_materials(index, source_root),
            'source/notice bindings differ from actual index or committed inputs')


def producer_publication(role, artifact, relative):
    """Producer scope remains exhaustive; only upstream All binary products are public."""
    require(role == 'all', 'unknown publication role')
    basename = PurePosixPath(relative).name
    if basename.startswith(('polaris-candidate-manifest-', 'native-row-')) or artifact in (
            'publisher-run-receipt', 'native-controlled-peer'):
        return None, 'producer-evidence'
    if artifact == 'binary-native-index':
        return None, 'audited-source-and-index'
    require(artifact.startswith('binary-'), 'unknown public artifact')
    return public_product_name(basename), 'upstream-public-product'


def public_asset_name(name):
    """Outer GitHub filename only; never alter producer/archive/native-index identity."""
    name = public_product_name(name)
    require(name.startswith('sing-box-polaris-'), 'unknown public product filename')
    require(name.count(VERSION) == 1, 'public producer filename lacks exact Polaris version')
    return name.replace(VERSION, PUBLIC_VERSION, 1)


def publication(role, artifact, relative):
    name, disposition = producer_publication(role, artifact, relative)
    return (public_asset_name(name) if name is not None else None), disposition


def default_name(role, artifact, relative):
    return publication(role, artifact, relative)[0]


def release_scope(version):
    # Only the current source-owned release contract selects a version. Escape
    # it as regex data; never guess it from artifact names or accept old mixes.
    require(validate_version(version) == VERSION, 'scope version differs from reviewed release version')
    scope = json.loads(SCOPE.read_text(encoding='utf-8'))
    for role in scope.values():
        for rules in role['payloadRules'].values():
            for rule in rules:
                pattern = rule['pattern']
                require(isinstance(pattern, str) and pattern.count('{version}') <= 1, 'invalid version template')
                require(not re.search(r'polaris\\?-(?:alpha|beta|rc)\\?\.\d+', pattern), 'literal branded version in scope template')
                require(not re.search(r'\{[A-Za-z_]\w*\}', pattern.replace('{version}', '')), 'unknown scope template token')
                require(type(rule['count']) is int and rule['count'] > 0, 'invalid exact payload count')
                rule['pattern'] = pattern.replace('{version}', re.escape(version))
                re.compile(rule['pattern'])
    return scope


def verify_artifact_names(names, required, role):
    require(len(names) == len(set(names)), 'duplicate Actions artifact names')
    require(set(names) == set(required), f'{role}: incomplete or unexpected artifact scope: missing={set(required)-set(names)}, extra={set(names)-set(required)}')


def verify_payloads(files, rules, artifact):
    payloads = {p for p in files if not PurePosixPath(p).name.startswith(('polaris-candidate-manifest-', 'native-row-'))}
    if artifact.startswith('smoke-'):
        require(not payloads and len(files) == 1, 'smoke evidence scope mismatch')
        return
    matched = set()
    for rule in rules:
        found = {p for p in payloads if re.fullmatch(rule['pattern'], p)}
        require(len(found) == rule['count'] and not matched.intersection(found), 'required package/file scope mismatch: '+artifact)
        matched.update(found)
    require(matched == payloads, 'unlisted payload file in '+artifact)


def associate_distribution_materials(result, index, index_sha):
    """Associate every public payload with the same existing immutable source/legal assets."""
    require(index['sourceCommit'] == result['sourceCommit'] and index['sourceTree'] == result['sourceTree'],
            'mixed source shared materials')
    shared = {'sourceArchive': index['sourceArchive'],
              'noticeIndex': {'name': 'polaris-upstream-native-assets.json', 'sha256': index_sha},
              'bindingSHA256': hashlib.sha256(json.dumps(index['distributionMaterials'], sort_keys=True,
                                                        separators=(',', ':')).encode()).hexdigest()}
    result['distributionMaterials'] = shared
    for role, run in result['runs'].items():
        for artifact, item in run['artifacts'].items():
            for relative, record in item['files'].items():
                if record['releaseName'] is None:
                    continue
                record['distributionMaterials'] = dict(shared)
    return result


def inventory(runs, source, work, source_tree, tag_object, source_root=ROOT, budget=None):
    budget = budget or ScratchBudget(work)
    scope = release_scope(VERSION)
    require(set(runs) == {'all'}, 'exactly the all run is mandatory')
    result = {'repository': REPO, 'repositoryId': RID, 'version': VERSION, 'sourceCommit': source,
              'scopeSha256': sha(SCOPE), 'reviewed': False, 'runs': {},
              'sourceTree': source_tree, 'tag': TAG, 'tagObject': tag_object}
    for role, rid in runs.items():
        require(re.fullmatch(r'[1-9][0-9]*', rid), 'invalid run ID')
        run = api(f'repos/{REPO}/actions/runs/{rid}')
        require(run['repository']['id'] == RID and run['head_repository']['id'] == RID, 'foreign run')
        require(run['head_sha'] == source and run['path'] == scope[role]['workflow'], 'wrong source or workflow')
        require(run['status'] == 'completed' and run['conclusion'] == 'success', 'unsuccessful input run')
        require(run['event'] == 'workflow_dispatch', 'explicit build dispatch required')
        artifacts = pages(f'repos/{REPO}/actions/runs/{rid}/artifacts', 'artifacts')
        names = [x['name'] for x in artifacts]
        require(len({x['id'] for x in artifacts}) == len(artifacts), 'duplicate Actions artifact IDs')
        verify_artifact_names(names, scope[role]['payloadRules'], role)
        entry = {'id': rid, 'attempt': run['run_attempt'], 'workflow': run['path'], 'artifacts': {}}
        receipt = None
        for a in artifacts:
            require(not a['expired'], 'expired artifact')
            require(datetime.fromisoformat(a['created_at'].replace('Z', '+00:00')) >= datetime.fromisoformat(run['run_started_at'].replace('Z', '+00:00')), 'artifact predates current run attempt')
            arun = a.get('workflow_run', {})
            require(arun.get('id') == int(rid) and arun.get('head_sha') == source, 'artifact source mismatch')
            files = {}
            with artifact_archive(a, budget) as (archive, members):
                for item in members:
                    if item.is_dir():
                        measure_member(archive, item)
                        continue
                    relative = item.filename
                    budget.state.update(artifactId=a['id'], artifact=a['name'], member=relative)
                    name = PurePosixPath(relative).name
                    public_name, disposition = publication(role, a['name'], relative)
                    candidate = name.startswith('polaris-candidate-manifest-')
                    evidence = candidate or (a['name'], relative) in {
                        ('publisher-run-receipt', 'publisher-run-receipt.json'),
                        ('binary-native-index', 'polaris-upstream-native-assets.json')}
                    limit = JSON_LIMIT if evidence else None
                    if a['name'] == 'binary-native-index':
                        target = work / role / a['name'] / relative
                        target.parent.mkdir(parents=True, exist_ok=True)
                        budget.admit(item.file_size, 'retained ' + relative)
                        try:
                            with target.open('xb') as stream:
                                measured_file, provenance = measure_member(archive, item, stream, limit)
                        except BaseException as error:
                            try:
                                target.unlink(missing_ok=True)
                            except OSError as cleanup:
                                error.add_note('Retained member cleanup also failed: ' + str(cleanup)[:300])
                            budget.release(item.file_size)
                            raise
                    else:
                        measured_file, provenance = measure_member(archive, item, json_limit=limit)
                    files[relative] = dict(measured_file, releaseName=public_name, publicationDisposition=disposition)
                    if (a['name'], relative) == ('publisher-run-receipt', 'publisher-run-receipt.json'):
                        receipt = provenance
                    if candidate:
                        require(provenance['sourceCommit'] == source and str(provenance['workflowRunId']) == rid and int(provenance['workflowAttempt']) == run['run_attempt'], 'candidate manifest source/run mismatch')
            require(files, 'empty artifact')
            verify_payloads(files, scope[role]['payloadRules'][a['name']], a['name'])
            entry['artifacts'][a['name']] = {'id': a['id'], 'archiveBytes': a['size_in_bytes'], 'archiveSha256': a['digest'], 'files': files}
        expected_receipt = {'repository': REPO, 'repositoryId': RID, 'sourceCommit': source, 'runId': rid,
                            'attempt': run['run_attempt'], 'version': VERSION, 'build': 'All', 'role': role}
        require(receipt == expected_receipt, 'producer scope/input receipt missing or inconsistent')
        entry['artifacts']['publisher-run-receipt']['files']['publisher-run-receipt.json']['releaseName'] = None
        result['runs'][role] = entry
        if role == 'all':
            index = json.loads((work / role / 'binary-native-index' / 'polaris-upstream-native-assets.json').read_text(encoding='utf-8'))
            validate_final_index(index, source, source_tree, tag_object, rid, run['run_attempt'], scope[role]['workflow'], source_root)
            indexed_names = set()
            for record in [x['archive'] for x in index['platforms']] + [index['sourceArchive']]:
                require(record['name'] not in indexed_names, 'duplicate native index name')
                indexed_names.add(record['name'])
                matches = [f for a in entry['artifacts'].values() for name, f in a['files'].items() if name == record['name']]
                require(len(matches) == 1 and matches[0]['sha256'] == record['sha256'] and matches[0]['bytes'] == record['bytes'], 'native index actual hash mismatch')
    shared_index_path = work / 'all' / 'binary-native-index' / 'polaris-upstream-native-assets.json'
    return associate_distribution_materials(result, json.loads(shared_index_path.read_text(encoding='utf-8')), sha(shared_index_path))


def assemble(actual, config, work, output, audit=None, materialize=True, budget=None):
    require(config.get('reviewed') is True, 'public release file scope is not reviewed')
    require(actual.get('distributionMaterials') == config.get('distributionMaterials'), 'reviewed shared materials differ')
    for field in ('repository', 'repositoryId', 'version', 'sourceCommit', 'sourceTree', 'tag', 'tagObject', 'scopeSha256'):
        require(actual[field] == config[field], 'release contract differs: ' + field)
    require(set(actual['runs']) == set(config['runs']), 'run scope differs')
    # Every generated path is reviewed, including typed non-public outputs.
    audit = audit or output.with_name(output.name + '-audit')
    require(audit.resolve() != output.resolve() and output.resolve() not in audit.resolve().parents, 'audit must be outside public dist')
    output.mkdir(exist_ok=False)
    audit.mkdir(parents=True, exist_ok=True)
    destinations = set()
    receipt = dict(actual, signatureState='unsigned-builds', fullSignedRelease=False)
    receipt['assets'] = []
    for role, run in actual['runs'].items():
        expected = config['runs'][role]
        require(run['id'] == expected['id'] and run['attempt'] == expected['attempt'], 'run/attempt differs from reviewed contract')
        require(set(run['artifacts']) == set(expected['artifacts']), 'artifact scope differs')
        for artifact, a in run['artifacts'].items():
            contract = expected['artifacts'][artifact]
            require(a['id'] == contract['id'] and a['archiveSha256'] == contract['archiveSha256'], 'artifact identity changed')
            require(a.get('archiveBytes') == contract.get('archiveBytes'), 'artifact ZIP size changed')
            require(set(a['files']) == set(contract['files']), 'file scope differs')
            for relative, f in a['files'].items():
                review = contract['files'][relative]
                require(f['bytes'] == review['bytes'] and f['sha256'] == review['sha256'], 'actual file hash differs')
                require(f.get('distributionMaterials') == review.get('distributionMaterials'), 'reviewed per-payload materials differ')
                name, disposition = publication(role, artifact, relative)
                require(review['releaseName'] == f['releaseName'] == name, 'public filename differs from source-owned mapping')
                require(review.get('publicationDisposition') == f.get('publicationDisposition') == disposition,
                        'publication disposition differs from source-owned mapping')
                if name is None:
                    if disposition == 'audited-source-and-index':
                        source_file, target = work / role / artifact / relative, audit / PurePosixPath(relative).name
                        if budget:
                            budget.copy(source_file, target)
                        else:
                            shutil.copyfile(source_file, target)
                    continue
                require(len(portable(name).parts) == 1 and name.casefold() not in destinations, 'duplicate release filename')
                require(PUBLIC_VERSION in name, 'public filename lacks upstream version')
                require(name != RECEIPT, 'receipt name reserved')
                destinations.add(name.casefold())
                if materialize:
                    shutil.copyfile(work / role / artifact / relative, output / name)
                receipt['assets'].append(dict(f, releaseName=name, role=role, artifact=artifact, artifactPath=relative,
                    signatureState='unsigned-candidate'))
    require(receipt['assets'], 'empty release')
    if budget:
        budget.write_json(audit / RECEIPT, receipt, PROPOSAL_LIMIT)
    else:
        (audit / RECEIPT).write_text(json.dumps(receipt, indent=2)+'\n', encoding='utf-8', newline='\n')
    return receipt


def public_asset_stream(actual, budget):
    """Second immutable ZIP pass; at most one public member exists on disk."""
    for role, run in actual['runs'].items():
        for name, expected in run['artifacts'].items():
            for relative, reviewed in expected['files'].items():
                require(publication(role, name, relative) ==
                        (reviewed['releaseName'], reviewed['publicationDisposition']), 'public ZIP mapping changed')
            if not any(f['releaseName'] is not None for f in expected['files'].values()):
                continue
            metadata = api(f'repos/{REPO}/actions/artifacts/{expected["id"]}')
            require((metadata['id'], metadata['name'], metadata.get('digest'), metadata.get('size_in_bytes')) ==
                    (expected['id'], name, expected['archiveSha256'], expected['archiveBytes']), 'public ZIP identity changed')
            require(metadata.get('expired') is False and metadata.get('workflow_run', {}).get('id') == int(run['id'])
                    and metadata['workflow_run'].get('head_sha') == actual['sourceCommit'], 'public ZIP expired or source changed')
            with artifact_archive(metadata, budget) as (archive, members):
                require({i.filename for i in members if not i.is_dir()} == set(expected['files']), 'public ZIP member scope changed')
                for item in members:
                    budget.state.update(artifactId=metadata['id'], artifact=name, member=item.filename)
                    if item.is_dir():
                        measure_member(archive, item)
                        continue
                    reviewed = expected['files'][item.filename]
                    public_name, disposition = publication(role, name, item.filename)
                    require((public_name, disposition) == (reviewed['releaseName'], reviewed['publicationDisposition']), 'public ZIP mapping changed')
                    if public_name is None:
                        measured, _ = measure_member(archive, item)
                        require(measured == {k: reviewed[k] for k in ('bytes', 'sha256')}, 'discarded ZIP member changed')
                        continue
                    with budget.temporary(item.file_size, 'upload ' + public_name) as staged:
                        measured, _ = measure_member(archive, item, staged)
                        require(measured == {k: reviewed[k] for k in ('bytes', 'sha256')}, 'public member bytes changed')
                        staged.flush()
                        yield public_name, Path(staged.name)


def publish(output, source, audit=None, measured=None, budget=None):
    before = tag_identity(source)
    audit = audit or output.with_name(output.name + '-audit')
    index = json.loads((audit / 'polaris-upstream-native-assets.json').read_text(encoding='utf-8'))
    validate_publication_index(index, source, TAG, before)
    # Listing includes drafts visible to the token; no 404-as-absence shortcut.
    require(not any(r['tag_name'] == TAG for r in pages(f'repos/{REPO}/releases')), 'existing Release (including draft) will never be changed')
    if measured is None:
        expected = {p.name: {'size': p.stat().st_size, 'digest': 'sha256:'+sha(p)} for p in output.iterdir() if p.is_file()}
    else:
        receipt = json.loads((audit / RECEIPT).read_text(encoding='utf-8'))
        expected = {f['releaseName']: {'size': f['bytes'], 'digest': 'sha256:' + f['sha256']} for f in receipt['assets']}
        require(expected and len(expected) == len(receipt['assets']), 'empty/duplicate public receipt')
        require(budget is not None, 'streamed publication requires bounded scratch')
        staging_peak = max(a['archiveBytes'] + max(f['bytes'] for f in a['files'].values()
                                                  if f['releaseName'] is not None)
                           for run in measured['runs'].values() for a in run['artifacts'].values()
                           if any(f['releaseName'] is not None for f in a['files'].values()))
        budget.admit(staging_peak, 'maximum single ZIP plus public member before draft creation')
        budget.release(staging_peak)
    notes = 'GitHub-only unsigned native core prerelease from '+source+'.\n\nsing-box-polaris is a derivative of the fixed SagerNet upstream, not an official SagerNet release. Original authors and license texts are retained. The validated producer inventory, source index and publication mapping are retained in the publisher Actions audit artifact.\n\nAudit: https://github.com/'+REPO+'/actions/runs/'+os.environ['GITHUB_RUN_ID']
    if budget:
        budget.record(phase='draft', remoteWriteState='draft-create-outcome-unknown')
    release = api(f'repos/{REPO}/releases', 'POST', {'tag_name': TAG, 'target_commitish': source, 'name': TAG, 'body': notes, 'draft': True, 'prerelease': True})
    release_id = release['id']
    if budget:
        budget.record(phase='upload', remoteWriteState='draft-created', releaseId=release_id)
    # No --clobber. Any upload/validation error leaves this newly created draft intact.
    supplier = ((p.name, p) for p in sorted(output.iterdir())) if measured is None else public_asset_stream(measured, budget)
    with closing(supplier):
        for name, path in supplier:
            require(tag_identity(source) == before, 'tag changed before upload; retained as draft')
            if budget:
                budget.record(remoteWriteState='upload-outcome-unknown', member=name)
            subprocess.run(['gh', 'api', '--method', 'POST', upload_endpoint(release, name),
                            '-H', 'Content-Type: application/octet-stream', '--input', str(path)], check=True, stdout=subprocess.DEVNULL)
            if budget:
                budget.record(remoteWriteState='draft-uploaded-member', member=name)
    checked = api(f'repos/{REPO}/releases/{release_id}')
    assets = pages(f'repos/{REPO}/releases/{release_id}/assets')
    require(checked['draft'] is True and checked['tag_name'] == TAG, 'draft state changed')
    require(len(assets) == len(expected) and {a['name'] for a in assets} == set(expected), 'remote asset scope mismatch; retained as draft')
    for a in assets:
        require(a['state'] == 'uploaded' and a['size'] == expected[a['name']]['size'] and a.get('digest') == expected[a['name']]['digest'], 'remote bytes/hash mismatch; retained as draft')
    require(tag_identity(source) == before, 'tag changed; retained as draft')
    require([r['id'] for r in pages(f'repos/{REPO}/releases') if r['tag_name'] == TAG] == [release_id], 'competing release; retained as draft')
    if budget:
        budget.record(phase='finalize', remoteWriteState='finalization-outcome-unknown')
    try:
        published = api(f'repos/{REPO}/releases/{release_id}', 'PATCH', {'draft': False, 'make_latest': 'false'})
    except BaseException:
        if budget:
            try:
                observed = api(f'repos/{REPO}/releases/{release_id}')
                budget.record(remoteWriteState='finalization-readback', observedDraft=observed.get('draft'), observedTag=observed.get('tag_name'))
            except Exception:
                budget.record(remoteWriteState='finalization-outcome-unknown')
        raise
    require(published['draft'] is False, 'publication not confirmed')
    if budget:
        budget.record(phase='complete', remoteWriteState='published')
    print(published['html_url'])


def reviewed_contract(run_id, digest, source, budget=None):
    require(re.fullmatch(r'[1-9][0-9]*', run_id or ''), 'inventory run ID required')
    require(re.fullmatch(r'[0-9a-f]{64}', digest or ''), 'explicit reviewed inventory SHA-256 required')
    run = api(f'repos/{REPO}/actions/runs/{run_id}')
    require(run['repository']['id'] == RID and run['head_repository']['id'] == RID, 'foreign inventory run')
    require(run['path'] == '.github/workflows/publish-github.yml' and run['head_sha'] == os.environ['GITHUB_SHA'], 'inventory publisher revision mismatch')
    require(run['conclusion'] == 'success' and run['status'] == 'completed', 'inventory run failed')
    candidates = [a for a in pages(f'repos/{REPO}/actions/runs/{run_id}/artifacts', 'artifacts') if a['name'] == 'github-release-validation']
    require(len(candidates) == 1 and not candidates[0]['expired'], 'inventory artifact missing/ambiguous/expired')
    with tempfile.TemporaryDirectory() as temp:
        budget = budget or ScratchBudget(Path(temp))
        contract = None
        with artifact_archive(candidates[0], budget) as (archive, members):
            for item in members:
                if item.filename == 'release-inventory-proposal.json' and not item.is_dir():
                    measured, contract = measure_member(archive, item, json_limit=PROPOSAL_LIMIT)
                    require(measured['sha256'] == digest, 'inventory differs from explicitly reviewed hash')
                else:
                    measure_member(archive, item)
        require(contract is not None, 'reviewed proposal missing')
        require(contract['sourceCommit'] == source, 'inventory source mismatch')
        contract['reviewed'] = True
        return contract


@contextmanager
def publisher_scratch(audit):
    primary = budget = None
    try:
        with tempfile.TemporaryDirectory(prefix='polaris-publisher-', dir=os.environ.get('RUNNER_TEMP')) as temp:
            budget = ScratchBudget(Path(temp), audit=audit)
            try:
                yield budget
            except BaseException as error:
                primary = error
                raise
    except BaseException as error:
        if primary is not None and error is not primary:
            primary.add_note('Scratch directory cleanup also failed: ' + str(error)[:300])
        if budget is not None and error is not primary:
            original = primary if primary is not None else error
            budget.record(result='failed', scratchCleanupFailed=True,
                          errorType=type(original).__name__, error=str(original)[:600],
                          cleanupNotes=[str(note)[:400] for note in getattr(original, '__notes__', [])[:8]])
        if primary is not None and error is not primary:
            raise primary from error
        raise


def bounded_release(args, runs):
    args.audit.mkdir(parents=True, exist_ok=False)
    with publisher_scratch(args.audit) as budget:
        work = budget.root
        try:
            budget.admit(16 * 1024, 'bounded storage diagnostic')
            budget.record(phase='inventory')
            source_tree = command('git', '-C', str(args.source_dir), 'rev-parse', 'HEAD^{tree}')
            tag_object = tag_identity(args.source)
            contract = None
            if args.mode != 'inventory':
                budget.record(phase='reviewed-contract')
                contract = reviewed_contract(args.inventory_run, args.inventory_sha256, args.source, budget=budget)
                require({role: str(run['id']) for role, run in contract['runs'].items()} == runs,
                        'reviewed inventory producer inputs differ')
            budget.record(phase='inventory')
            actual = inventory(runs, args.source, work, source_tree, tag_object, args.source_dir, budget=budget)
            require(tag_identity(args.source) == tag_object, 'tag changed while collecting release inventory')
            if args.mode == 'inventory':
                require(not args.output.exists(), 'inventory output already exists')
                for material in (work / 'all' / 'binary-native-index').iterdir():
                    if material.is_file():
                        budget.copy(material, args.audit / material.name)
                budget.write_json(args.output, actual, PROPOSAL_LIMIT)
                budget.record(phase='complete', result='inventory')
                print('Inventory SHA-256: ' + sha(args.output))
                return
            budget.record(phase='reviewed-contract')
            assemble(actual, contract, work, args.output, args.audit, materialize=False, budget=budget)
            require(tag_identity(args.source) == tag_object, 'tag changed while validating release contract')
            if args.mode == 'publish':
                require(os.environ.get('POLARIS_GITHUB_PUBLISH_ENABLED') == 'true', 'GitHub publication disabled')
                publish(args.output, args.source, args.audit, measured=actual, budget=budget)
            else:
                budget.record(phase='complete', result='validated-without-public-payload-copy')
        except BaseException as error:
            budget.record(result='failed', errorType=type(error).__name__, error=str(error)[:600],
                          cleanupNotes=[str(note)[:400] for note in getattr(error, '__notes__', [])[:8]])
            raise


def main():
    p = argparse.ArgumentParser()
    p.add_argument('mode', choices=['inventory', 'validate', 'publish'])
    p.add_argument('--source', required=True)
    p.add_argument('--source-dir', type=Path, default=Path('reviewed-source'))
    p.add_argument('--all-run', required=True)
    p.add_argument('--audit', type=Path, default=Path('github-release-audit'))
    p.add_argument('--inventory-run')
    p.add_argument('--inventory-sha256')
    p.add_argument('--output', type=Path, default=Path('github-release-dist'))
    args = p.parse_args()
    public = json.loads(CONFIG.read_text(encoding='utf-8'))
    require(public == {'repository': REPO, 'repositoryId': RID, 'publication': 'github-only-unsigned-prerelease'}, 'public GitHub release configuration mismatch')
    identity(args.source, args.source_dir)
    require(re.fullmatch(r'[1-9][0-9]*', args.all_run), 'invalid run ID')
    # The build run is dispatched on the release tag; its tag is bound to the source by tag_identity().
    bind_release(api(f'repos/{REPO}/actions/runs/{args.all_run}')['head_branch'])
    return bounded_release(args, {'all': args.all_run})


if __name__ == '__main__':
    main()
