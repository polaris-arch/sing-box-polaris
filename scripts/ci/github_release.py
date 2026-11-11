#!/usr/bin/env python3
"""GitHub-only release gate. Inventory is read-only; alpha.12 reconciliation is ID-bound."""
import argparse
import io
from github_read_transport import read_get
import hashlib
from datetime import datetime
from urllib.parse import quote, urlsplit, urlunsplit

from release_identity import remote_tag_identity, public_product_name, validate_publication_index, same_identity
from polaris_version import validate as validate_version
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import time
import zipfile
import struct
import zlib
import publisher_peer_registry as peer_evidence
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
RECONCILIATION = ROOT / 'release/ci/github-release-reconciliation.json'
CANONICAL_METADATA = 'SFA-version-metadata.json'
NAME_ALIGNMENT = ROOT / 'release/ci/github-release-name-alignment.json'
NAME_ALIGNMENT_SHA256 = 'c77f674bddbd0f6f77ee636b1bd93643faf8e6cd62d5d9ce7a6a667c789d8064'
# One reviewed Apple-only manifest transition, not a general migration allowlist.
ANDROID_OVERLAY_TRANSITION_SHA256 = '06fdfb3e24a0a6a934ad1ba8660bac3452955894d627d792f0a7317b47d6cd6f'
VERSION = validate_version(json.loads(CONFIG.read_text(encoding='utf-8'))['version'])
PUBLIC_VERSION = VERSION.replace('-polaris-', '-', 1)
TAG = 'v' + VERSION
RECEIPT = 'polaris-github-release-receipt-' + VERSION + '.json'
BLOCKED = [
    'Signed installable iOS and tvOS IPA exports require owned signing and provisioning.',
    'Signed macOS App Store PKG and Developer ID signed/notarized standalone PKG require owned signing.',
    'Store/TestFlight submissions and registry pushes are outside this GitHub-only release.',
]


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


def extract(archive, directory):
    seen = set()
    with zipfile.ZipFile(archive) as z:
        for item in z.infolist():
            p = portable(item.filename)
            if item.is_dir():
                continue
            require(stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG), 'non-regular archive entry')
            require(p.as_posix().casefold() not in seen, 'duplicate ZIP path')
            seen.add(p.as_posix().casefold())
            target = directory.joinpath(*p.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(item) as src, target.open('xb') as dst:
                shutil.copyfileobj(src, dst)


def identity(source, source_dir):
    require(re.fullmatch(r'[0-9a-f]{40}', source), 'full source SHA required')
    require(os.environ.get('GITHUB_REPOSITORY') == REPO and os.environ.get('GITHUB_REPOSITORY_ID') == str(RID), 'wrong workflow repository')
    require(api(f'repos/{REPO}')['id'] == RID, 'remote repository ID mismatch')
    require(command('git', '-C', str(source_dir), 'rev-parse', 'HEAD') == source, 'publisher checkout differs from source')
    require(not command('git', '-C', str(source_dir), 'status', '--porcelain', '--untracked-files=no'), 'tracked source is dirty')
    require(sha(ROOT / 'release/ci/client-overlays.json') == sha(source_dir / 'release/ci/client-overlays.json'), 'publisher client overlay contract differs from actual build source')
    for path in ('release/ci/apple-swift-package-overlays.json', 'scripts/ci/apple_package_overlays.py', 'scripts/ci/client_source.py'):
        require((ROOT / path).is_file() and (source_dir / path).is_file()
                and sha(ROOT / path) == sha(source_dir / path), 'publisher Apple package policy differs from actual build source: ' + path)
    material_plan = Path(DEBIAN_POLICY['profilePlan'])
    if (ROOT / material_plan).exists() or (source_dir / material_plan).exists():
        from cronet_material_supply import profile_plan_sha256
        module = Path('scripts/ci/cronet_material_supply.py')
        require((ROOT / module).is_file() and (source_dir / module).is_file()
                and sha(ROOT / module) == sha(source_dir / module)
                and profile_plan_sha256(ROOT) == profile_plan_sha256(source_dir),
                'publisher Debian material contract differs from actual build source')
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


def validate_final_index(index, source, tree, tag_object, run_id, attempt, workflow, source_root=ROOT, *, debian_raw=None):
    # A staging index is useful evidence, but never a production publication input.
    require(index.get('schema') == 'polaris-upstream-native-assets-v1', 'final native index schema required; staging forbidden')
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
    require(len(index['platforms']) == 44 and {x['id'] for x in index['platforms']} == set(expected), 'exact 44 native identities required')
    for row in index['platforms']:
        validate_trusted_execution(row, producer, source_root)
        require((row['sourceCommit'], row['sourceTree'], row['version'], row['tag']) == (source, tree, VERSION, TAG), 'mixed source native row')
        require((row['target'], row['variant']) == (expected[row['id']]['target'], expected[row['id']]['variant']), 'native row matrix mismatch')
        require(row['archive'].get('releaseName') == public_product_name(row['archive']['name']), 'native public archive name mismatch')
        suffix = '.zip' if row['target'].startswith('windows/') else '.tar.gz'
        require(row['archive']['root'] == row['id'] and row['archive']['name'] == row['id'] + suffix, 'native archive identity mismatch')
    jobs = pages(f'repos/{REPO}/actions/runs/{run_id}/attempts/{attempt}/jobs', 'jobs', maximum=1000)
    require(producer['nativeJobs'] == select_native_jobs(index['platforms'], jobs, source, int(run_id), attempt),
            'native producer job mapping differs from retained proof/API evidence')
    require(index['sourceArchive']['name'] == 'sing-box-polaris-source-' + source + '.tar.gz', 'immutable source archive basename required')
    from native_release_index import distribution_materials
    expected_materials = (distribution_materials(index, source_root) if debian_raw is None
                         else distribution_materials(index, source_root, debian_raw=debian_raw))
    require(index['distributionMaterials'] == expected_materials, 'source/notice bindings differ from actual index or committed inputs')


def producer_publication(role, artifact, relative):
    """Producer scope remains exhaustive; only upstream All binary products are public."""
    if artifact in (DEBIAN_RAW, DEBIAN_READY):
        require(role in ('all', 'linux', 'docker'), 'private Debian artifact in wrong role')
        if artifact == DEBIAN_RAW:
            require(relative == DEBIAN_MANIFEST or re.fullmatch(r'objects/[0-9a-f]{64}', relative),
                    'unlisted private Debian raw member')
            return None, 'private-debian-raw'
        require(relative == DEBIAN_POLICY['readyMember'], 'unlisted private Debian READY member')
        return None, 'private-debian-ready'
    if PurePosixPath(relative).name == DEBIAN_USE:
        from cronet_material_supply import expected_use
        require(relative == DEBIAN_USE and role in ('all', 'linux', 'docker') and expected_use(role, artifact) is not None,
                'private Debian use in nonconsumer/nested artifact')
        return None, 'private-debian-use'

    basename = PurePosixPath(relative).name
    if basename.startswith(('polaris-candidate-manifest-', 'native-row-')) or artifact in ('publisher-run-receipt', 'go-win7-toolchain'):
        return None, 'producer-evidence'
    if role in ('linux', 'docker'):
        return None, 'separate-distribution-channel'
    if role == 'signed':
        return None, 'separate-signed-distribution'
    require(role == 'all', 'unknown publication role')
    if artifact.startswith('libbox-'):
        return None, 'internal-sdk'
    if artifact.startswith('unsigned-apple-'):
        return None, 'internal-unsigned-archive'
    if artifact == 'binary-native-index':
        return None, 'audited-source-and-index'
    require(artifact.startswith('binary-'), 'unknown public artifact')
    if artifact in ('binary-android-apks-other', 'binary-android-apks-other-legacy') and basename.endswith('-version-metadata.json'):
        if artifact.endswith('other-legacy'):
            return None, 'identical-android-metadata'
        return 'sing-box-polaris-SFA-version-metadata.json', 'upstream-public-product'
    if artifact.startswith(('binary-android-apks-', 'binary-windows-client-',
                            'binary-linux-client-', 'binary-apple-')):
        return branded_client_name(basename), 'upstream-public-product'
    return public_product_name(basename), 'upstream-public-product'


def public_asset_name(name):
    """Outer GitHub filename only; never alter producer/archive/native-index identity."""
    name = public_product_name(name)
    if name.startswith('sing-box-polaris-SF'):
        name = name.removeprefix('sing-box-polaris-')
    if name == CANONICAL_METADATA:
        return name
    require(name.startswith(('sing-box-polaris-', 'sing-box-polaris_',
                             'SFA-', 'SFI-', 'SFL-', 'SFM-', 'SFW-')),
            'unknown public product filename')
    require(name.count(VERSION) == 1, 'public producer filename lacks exact Polaris version')
    name = name.replace(VERSION, PUBLIC_VERSION, 1)
    if name.startswith('SFA-') and name.endswith('-unsigned.apk'):
        name = name.removesuffix('-unsigned.apk') + '.apk'
    return name


def publication(role, artifact, relative, source=None):
    private = peer_evidence.mapping(ROOT, role, artifact, relative, source)
    if private is not None:
        return private
    name, disposition = producer_publication(role, artifact, relative)
    return (public_asset_name(name) if name is not None else None), disposition


def default_name(role, artifact, relative):
    return publication(role, artifact, relative)[0]


def verify_metadata_pair(result):
    artifacts = result['runs']['all']['artifacts']
    names = ('binary-android-apks-other', 'binary-android-apks-other-legacy')
    rows = []
    for name in names:
        require(name in artifacts, 'missing Android metadata producer')
        matches = [f for path, f in artifacts[name]['files'].items() if path.endswith('-version-metadata.json')]
        require(len(matches) == 1, 'Android metadata scope mismatch')
        rows.append(matches[0])
    require((rows[0]['bytes'], rows[0]['sha256']) == (rows[1]['bytes'], rows[1]['sha256']),
            'Android flavor metadata differs; cannot collapse')


def branded_client_name(name):
    """Public derivative name only; exact upstream candidate paths stay in the receipt."""
    if name.startswith('sing-box-polaris-'):
        return name
    if name.startswith(('sing-box-', 'sing-box_')):
        return public_product_name(name)
    return 'sing-box-polaris-' + name



DEBIAN_RAW = 'debian-candidate-raw'
DEBIAN_READY = 'debian-material-ready'
DEBIAN_MANIFEST = 'candidate-manifest.json'
DEBIAN_USE = 'debian-material-use.json'
DEBIAN_POLICY = {'family': 'debian_materials', 'rawArtifact': DEBIAN_RAW,
                 'readyArtifact': DEBIAN_READY, 'manifest': DEBIAN_MANIFEST,
                 'readyMember': 'debian-material-ready.json',
                 'profilePlan': 'release/ci/cronet-material-profiles.json',
                 'supplierJob': 'Supply verified Debian raw inputs'}
DEBIAN_REF_ENV = ('POLARIS_DEBIAN_RAW_ID', 'POLARIS_DEBIAN_RAW_DIGEST',
                  'POLARIS_DEBIAN_READY_ID', 'POLARIS_DEBIAN_READY_DIGEST')


def debian_policy(scope, role):
    policy = scope[role].get('debianMaterials')
    if policy is not None:
        require(role in ('all', 'linux', 'docker') and policy == DEBIAN_POLICY,
                'unknown Debian material family or policy')
        require(all(name in scope[role]['requiredArtifacts'] for name in (DEBIAN_RAW, DEBIAN_READY)),
                'Debian family lacks its two exact private artifacts')
        require(scope[role]['payloadRules'][DEBIAN_RAW] == [{'pattern': r'candidate-manifest\.json', 'count': 1}]
                and scope[role]['payloadRules'][DEBIAN_READY] == [{'pattern': r'debian-material-ready\.json', 'count': 1}],
                'Debian private member contract changed')
    return policy


def debian_artifact_ref(artifact):
    return {'id': artifact['id'], 'name': artifact['name'],
            'digest': artifact['digest'], 'size': artifact['size_in_bytes']}


def debian_consumer_artifact(artifact, ready_artifact):
    require(datetime.fromisoformat(artifact['created_at'].replace('Z', '+00:00'))
            >= datetime.fromisoformat(ready_artifact['created_at'].replace('Z', '+00:00')),
            'Debian consumer artifact predates READY')


def debian_context(role, run, source, tree, tag_object):
    require(role in ('all', 'linux', 'docker'), 'not a Debian producer role')
    require(run['repository']['id'] == RID and run['head_repository']['id'] == RID
            and run['head_sha'] == source and run['event'] == 'workflow_dispatch'
            and run['head_branch'] == TAG, 'Debian input run is not this source tag')
    workflow = release_scope(VERSION)[role]['workflow']
    require(run['path'] == workflow, 'Debian input workflow mismatch')
    require(type(run['id']) is int and run['id'] > 0
            and type(run['run_attempt']) is int and run['run_attempt'] > 0,
            'Debian run identity is not an exact positive integer')
    require(isinstance(tree, str) and re.fullmatch(r'[0-9a-f]{40}', tree)
            and isinstance(tag_object, str) and re.fullmatch(r'[0-9a-f]{40}', tag_object),
            'Debian source tree/tag object missing')
    return {'repository': REPO, 'repositoryID': RID, 'sourceCommit': source, 'sourceTree': tree,
            'tag': TAG, 'tagObject': tag_object, 'workflow': workflow,
            'runID': run['id'], 'runAttempt': run['run_attempt'], 'role': role}


def debian_api_artifact(artifact, context, run):
    require(type(artifact.get('id')) is int and artifact['id'] > 0
            and artifact.get('expired') is False
            and type(artifact.get('size_in_bytes')) is int
            and 0 < artifact['size_in_bytes'] <= 1075838976
            and isinstance(artifact.get('digest'), str)
            and re.fullmatch(r'sha256:[0-9a-f]{64}', artifact['digest']),
            'invalid bounded Debian API artifact')
    arun = artifact.get('workflow_run', {})
    require(arun.get('id') == context['runID'] and arun.get('head_sha') == context['sourceCommit'],
            'Debian artifact is from another source/run')
    require(datetime.fromisoformat(artifact['created_at'].replace('Z', '+00:00'))
            >= datetime.fromisoformat(run['run_started_at'].replace('Z', '+00:00')),
            'Debian artifact predates this attempt')


def read_debian_artifacts(artifacts, context, run, supplier_job, budget):
    """Measure the exact data-only CAS once; preserve the 4 GiB shared scratch cap."""
    from cronet_material_supply import decode_json, validate_manifest, validate_ready
    selected = {}
    for name in (DEBIAN_RAW, DEBIAN_READY):
        found = [a for a in artifacts if a['name'] == name]
        require(len(found) == 1, 'missing or duplicate exact Debian artifact: ' + name)
        selected[name] = found[0]
        debian_api_artifact(found[0], context, run)
    require(selected[DEBIAN_RAW]['id'] != selected[DEBIAN_READY]['id'], 'Debian artifacts share an ID')
    require(datetime.fromisoformat(selected[DEBIAN_RAW]['created_at'].replace('Z', '+00:00'))
            <= datetime.fromisoformat(selected[DEBIAN_READY]['created_at'].replace('Z', '+00:00')),
            'Debian READY artifact predates its raw candidate')
    measured = {}
    with artifact_archive(selected[DEBIAN_RAW], budget) as (archive, members):
        regular = [m for m in members if not m.is_dir()]
        require(1 <= len(regular) <= 513 and all(
            m.filename == 'objects/' and m.file_size == 0 for m in members if m.is_dir()),
            'invalid Debian CAS member/directory count')
        require(sum(m.file_size for m in regular) <= 1073741824 + 1048576, 'Debian CAS exceeds union budget')
        manifest_members = [m for m in regular if m.filename == DEBIAN_MANIFEST]
        require(len(manifest_members) == 1, 'Debian CAS manifest member missing/duplicate')
        manifest_measure, manifest = measure_member(archive, manifest_members[0], json_limit=1048576,
                                                     json_decoder=decode_json)
        measured[DEBIAN_MANIFEST] = manifest_measure
        for member in regular:
            if member.filename == DEBIAN_MANIFEST:
                continue
            require(re.fullmatch(r'objects/[0-9a-f]{64}', member.filename)
                    and 0 < member.file_size <= 67108864, 'unlisted/non-bounded Debian CAS member')
            fact, _ = measure_member(archive, member)
            measured[member.filename] = fact
        validate_manifest(manifest, context=context, measurements=measured)
    raw_files = {name: dict(fact, releaseName=None, publicationDisposition='private-debian-raw')
                 for name, fact in measured.items()}
    ready_artifact = selected[DEBIAN_READY]
    require(ready_artifact['size_in_bytes'] <= 1048576 + 65536, 'oversized Debian READY ZIP')
    with artifact_archive(ready_artifact, budget) as (archive, members):
        require(len(members) == 1 and not members[0].is_dir()
                and members[0].filename == DEBIAN_POLICY['readyMember'], 'unexpected Debian READY members')
        ready_fact, ready = measure_member(archive, members[0], json_limit=1048576, json_decoder=decode_json)
        binding = validate_ready(ready, context=context, manifest=manifest,
                                 raw_artifact=debian_artifact_ref(selected[DEBIAN_RAW]),
                                 supplier_job=supplier_job)
    require(datetime.fromisoformat(ready_artifact['created_at'].replace('Z', '+00:00'))
            <= datetime.fromisoformat(supplier_job['completed_at'].replace('Z', '+00:00')),
            'Debian READY artifact postdates its completed supplier')
    binding = dict(binding, readyArtifact=debian_artifact_ref(ready_artifact))
    entries = {
        DEBIAN_RAW: {'id': selected[DEBIAN_RAW]['id'],
                     'archiveBytes': selected[DEBIAN_RAW]['size_in_bytes'],
                     'archiveSha256': selected[DEBIAN_RAW]['digest'], 'files': raw_files},
        DEBIAN_READY: {'id': ready_artifact['id'], 'archiveBytes': ready_artifact['size_in_bytes'],
                       'archiveSha256': ready_artifact['digest'],
                       'files': {DEBIAN_POLICY['readyMember']: dict(ready_fact, releaseName=None,
                                     publicationDisposition='private-debian-ready')}}}
    return binding, entries, manifest, ready_artifact


def debian_supplier_job(context, jobs=None):
    rows = pages(f'repos/{REPO}/actions/runs/{context["runID"]}/attempts/{context["runAttempt"]}/jobs', 'jobs', maximum=1000) if jobs is None else jobs
    jobs = [job for job in rows if job['name'] == DEBIAN_POLICY['supplierJob']]
    require(len(jobs) == 1, 'missing/ambiguous Debian supplier job')
    job = jobs[0]
    require(job['status'] == 'completed' and job['conclusion'] == 'success'
            and job['head_sha'] == context['sourceCommit'] and job['run_id'] == context['runID']
            and job['run_attempt'] == context['runAttempt'], 'Debian supplier did not succeed in this attempt')
    return job


def producer_debian_materials(role, source, tree, *, env=None):
    """Same-run receipts/index: supplier success is enough; never await our own run."""
    env = os.environ if env is None else env
    required = env.get('POLARIS_DEBIAN_REQUIRED', 'false')
    require(required in ('true', 'false'), 'invalid Debian required mode')
    refs = [env.get(name, '') for name in DEBIAN_REF_ENV]
    if required == 'false':
        require(not any(refs), 'optional Debian mode carries unexpected references')
        return None
    require(all(refs), 'required Debian material reference missing')
    require(role in ('all', 'linux', 'docker') and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and env.get('GITHUB_REF') == 'refs/tags/' + TAG and env.get('GITHUB_SHA') == source
            and env.get('GITHUB_WORKFLOW_SHA') == source, 'required Debian producer context mismatch')
    scope = release_scope(VERSION)
    require(debian_policy(scope, role) is not None, 'required Debian producer has no source-owned policy')
    require(env.get('GITHUB_WORKFLOW_REF') == f'{REPO}/{scope[role]["workflow"]}@refs/tags/{TAG}',
            'required Debian producer workflow ref differs')
    require(re.fullmatch(r'[1-9][0-9]*', env.get('GITHUB_RUN_ID', ''))
            and re.fullmatch(r'[1-9][0-9]*', env.get('GITHUB_RUN_ATTEMPT', '')), 'invalid Debian producer run/attempt')
    run = api(f'repos/{REPO}/actions/runs/{env["GITHUB_RUN_ID"]}')
    require(run['id'] == int(env['GITHUB_RUN_ID']) and run['run_attempt'] == int(env['GITHUB_RUN_ATTEMPT'])
            and run['status'] in ('queued', 'in_progress', 'completed')
            and (run['status'] != 'completed' or run['conclusion'] == 'success'),
            'Debian producer run/attempt changed or failed')
    tag_object = tag_identity(source)
    context = debian_context(role, run, source, tree, tag_object)
    artifacts = []
    for name, ident, digest in ((DEBIAN_RAW, refs[0], refs[1]), (DEBIAN_READY, refs[2], refs[3])):
        require(re.fullmatch(r'[1-9][0-9]*', ident) and re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}', digest),
                'invalid exact Debian output reference')
        artifact = api(f'repos/{REPO}/actions/artifacts/{ident}')
        expected_digest = digest if digest.startswith('sha256:') else 'sha256:' + digest
        require(artifact['id'] == int(ident) and artifact['name'] == name
                and artifact['digest'] == expected_digest, 'Debian job output/API mismatch')
        artifacts.append(artifact)
    with tempfile.TemporaryDirectory(prefix='polaris-debian-receipt-') as directory:
        binding, _, _, _ = read_debian_artifacts(artifacts, context, run, debian_supplier_job(context),
                                           ScratchBudget(Path(directory)))
    require(tag_identity(source) == tag_object, 'Debian producer tag moved during verification')
    return binding


def validate_debian_use(files, candidates, artifact, binding, *, jobs=None,
                        canonical_manifest=None, artifact_metadata=None, ready_metadata=None):
    from cronet_material_supply import expected_use, validate_use_ref, LOCAL_USE, BINDING_KEYS
    if binding is not None:
        require(type(binding) is dict and set(binding) == BINDING_KEYS, 'complete Debian material binding')
    expected = expected_use(binding['context']['role'], artifact) if binding is not None else None
    use = files.get(DEBIAN_USE, {}).get('debianRawUse')
    require((use is not None) == (expected is not None), 'missing/unexpected Debian consumer sidecar')
    if expected is None:
        require(all('debianMaterialUse' not in item for item in candidates), 'unexpected candidate Debian useRef')
        return False
    ref = use.get('consumerJob') if isinstance(use, dict) else None
    require(isinstance(ref, dict) and type(ref.get('id')) is int and ref['id'] > 0
            and isinstance(jobs, list), 'Debian use lacks actual consumer job identity')
    consumers = [job for job in jobs if job['id'] == ref['id']]
    require(len(consumers) == 1, 'missing/ambiguous actual Debian consumer job')
    validate_use_ref(use, binding=binding, ready_artifact=binding['readyArtifact'],
                     artifact_name=artifact, consumer_job=consumers[0], canonical_manifest=canonical_manifest)
    if use['schema'] != LOCAL_USE:
        if artifact_metadata is not None:
            require(type(ready_metadata) is dict
                    and {'id', 'name', 'digest', 'size_in_bytes', 'created_at'} <= set(ready_metadata)
                    and type(ready_metadata['created_at']) is str
                    and same_identity(debian_artifact_ref(ready_metadata), binding['readyArtifact']),
                    'legacy authenticated READY metadata missing or mismatched')
            debian_consumer_artifact(artifact_metadata, ready_metadata)
        supplier = debian_supplier_job(binding['context'], jobs=jobs)
        require(supplier['id'] == binding['supplierJob']['id']
                and datetime.fromisoformat(consumers[0]['started_at'].replace('Z', '+00:00'))
                    >= datetime.fromisoformat(supplier['completed_at'].replace('Z', '+00:00')),
                'Debian consumer started before its actual supplier completed')
    if binding['context']['role'] == 'all':
        require(len(candidates) == 1, 'All Debian consumer needs its existing exact candidate receipt')
        record = candidates[0]
        expected_ref = dict(member=DEBIAN_USE, bytes=files[DEBIAN_USE]['bytes'], sha256=files[DEBIAN_USE]['sha256'])
        require(record.get('debianMaterialUse') == expected_ref, 'candidate Debian useRef mismatch')
        listed = [f for f in record['files'] if f['path'] == DEBIAN_USE]
        require(listed == [dict(path=DEBIAN_USE, bytes=expected_ref['bytes'], sha256=expected_ref['sha256'])],
                'candidate did not measure its Debian use sidecar')
        require(record['job'] == ref['key'],
                'candidate Debian consumer job mismatch')
    return True


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


def verify_payloads(files, rules, artifact, *, debian_use=False):
    require((DEBIAN_USE in files) == debian_use, 'missing/unexpected exact private Debian use member')
    payloads = {p for p in files if p != DEBIAN_USE and not PurePosixPath(p).name.startswith(('polaris-candidate-manifest-', 'native-row-'))}
    if artifact.startswith('smoke-'):
        require(not payloads and len(files) == 1, 'smoke evidence scope mismatch')
        return
    matched = set()
    for rule in rules:
        found = {p for p in payloads if re.fullmatch(rule['pattern'], p)}
        require(len(found) == rule['count'] and not matched.intersection(found), 'required package/file scope mismatch: '+artifact)
        matched.update(found)
    require(matched == payloads, 'unlisted payload file in '+artifact)


def client_platform(artifact):
    for prefix, platform in [('binary-android-apks-', 'android'), ('binary-windows-client-', 'windows'),
                             ('binary-linux-client-', 'linux'), ('binary-apple-', 'apple'),
                             ('unsigned-apple-', 'apple'), ('signed-apple-store-', 'apple')]:
        if artifact.startswith(prefix):
            return platform
    return None


def validate_client_source(provenance, artifact, role, source):
    from client_source import validate
    platform = client_platform(artifact)
    record = provenance.get('clientSource')
    if platform is None:
        require(record is None, 'unexpected client source receipt in core/library artifact')
    else:
        require(isinstance(record, dict), 'client artifact lacks actual client source evidence')
        validate(record, platform, source, role != 'signed')
    return record


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
            clients = [f['clientSource'] for f in item['files'].values() if 'clientSource' in f]
            require(len(clients) <= 1, 'duplicate client material record')
            for relative, record in item['files'].items():
                if record['releaseName'] is None:
                    continue
                record['distributionMaterials'] = dict(shared)
                if clients:
                    c = clients[0]
                    require(c['coreSourceCommit'] == result['sourceCommit'], 'mixed client material source')
                    sources = json.loads((ROOT / 'release/dependency-sources/clients/current-client-sources.json').read_text(encoding='utf-8'))['clients']
                    acquired = [x for x in sources if x['repository'] == c['repository'] and x['baseCommit'] == c['baseCommit']]
                    require(len(acquired) == 1 and acquired[0]['fullSourceGetVerified'] is True, 'actual client base differs from acquired shared source')
                    record['distributionMaterials']['clientSource'] = {
                        'repository': c['repository'], 'baseCommit': c['baseCommit'],
                        'sourceURL': 'https://github.com/'+c['repository']+'/tree/'+c['baseCommit'],
                        'overlayManifestSHA256': c['overlayManifestSHA256'],
                        'diffSHA256': c['diffSHA256'],
                        'sourceArchiveURL': acquired[0]['sourceURL'],
                        'sourceArchiveSHA256': acquired[0]['sourceArchiveSHA256'],
                        'receiptArtifactPath': next(k for k,v in item['files'].items() if 'clientSource' in v)}
                    if 'swiftPackageOverlays' in c:
                        packages = c['swiftPackageOverlays']
                        record['distributionMaterials']['clientSource']['swiftPackageOverlays'] = {
                            'manifestSHA256': packages['manifestSHA256'],
                            'lockSHA256': packages['lockSHA256'],
                            'evidenceSHA256': hashlib.sha256(json.dumps(packages, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
    return result


def validate_android_material_reuse(record, configuration, client_source, root=ROOT):
    """Reuse reviewed dependency materials only for identical actual runtime artifacts."""
    from android_runtime_materials import validate as validate_android_runtime
    root = Path(root)
    directory = root / 'release/dependency-sources/clients/runtime/android-resolved'
    reference_path = directory / 'reuse-reference.json'
    reference = json.loads(reference_path.read_text(encoding='utf-8'))
    require(reference.get('schema') == 'polaris-android-material-reuse-v1', 'invalid Android material reference schema')
    material_map = directory / 'source-notice-map.json'
    require(sha(material_map) == reference.get('materialMapSHA256'), 'Android source/notice map changed')
    materials = json.loads(material_map.read_text(encoding='utf-8'))
    require(materials.get('concreteUnresolvedMaterials') == [], 'Android source/notice materials remain unresolved')
    identity_keys = ('repository', 'baseCommit', 'baseTree', 'overlayManifestSHA256', 'platform', 'unsigned')
    require(isinstance(client_source, dict) and all(key in client_source for key in identity_keys), 'missing Android client material identity')
    actual_identity = {key: client_source[key] for key in identity_keys}
    expected_identity = reference.get('clientSource')
    transition_sha = None
    if actual_identity != expected_identity:
        # A separate reviewed Apple-only edit may change the whole overlay manifest.
        # Never relabel the historical reference or relax Android/runtime byte identity.
        require(isinstance(expected_identity, dict) and
                all(actual_identity[key] == expected_identity.get(key) for key in identity_keys if key != 'overlayManifestSHA256'),
                'Android client source material reference drift')
        transition_path = root / 'release/ci/android-material-overlay-transition.json'
        require(transition_path.is_file(), 'Android overlay material reference drift: transition missing')
        require(sha(transition_path) == ANDROID_OVERLAY_TRANSITION_SHA256, 'Android overlay material reference drift: transition changed')
        transition = json.loads(transition_path.read_text(encoding='utf-8'))
        manifest_path = root / 'release/ci/client-overlays.json'
        require(transition.get('schema') == 'polaris-android-material-overlay-transition-v1' and
                transition.get('referenceSHA256') == sha(reference_path) and
                transition.get('previousOverlayManifestSHA256') == expected_identity['overlayManifestSHA256'] and
                transition.get('currentOverlayManifestSHA256') == actual_identity['overlayManifestSHA256'] == sha(manifest_path) and
                transition.get('changedPlatforms') == ['apple'] and transition.get('requiresActualRuntimeArtifactComparison') is True,
                'Android overlay material reference drift: transition identity changed')
        android = json.loads(manifest_path.read_text(encoding='utf-8'))['platforms']['android']
        definition_sha = hashlib.sha256(json.dumps(android, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        require(definition_sha == transition.get('unchangedAndroidDefinitionSHA256'),
                'Android overlay material reference drift: Android definition changed')
        transition_sha = sha(transition_path)
    actual = validate_android_runtime(record, configuration)
    expected = reference.get('variants', {}).get(configuration)
    require(isinstance(expected, dict), 'missing Android configuration material reference')
    # Root-project coordinates and version injection are not external distributed bytes.
    # Only the selected external artifact identities and their exact bytes are reused.
    fields = ('module', 'name', 'artifactIdentity', 'artifactName', 'type', 'extension',
              'classifier', 'componentSelectedVariants', 'bytes', 'sha256')
    def canonical(artifacts):
        values = []
        for artifact in artifacts:
            item = {key: artifact[key] for key in fields}
            item['componentSelectedVariants'] = sorted(item['componentSelectedVariants'], key=lambda v: json.dumps(v, sort_keys=True))
            values.append(json.dumps(item, sort_keys=True, separators=(',', ':')))
        return sorted(values)
    require(canonical(actual['artifacts']) == canonical(expected['artifacts']), 'Android actual runtime artifact material drift')
    mapped = set(canonical([item['artifact'] for item in materials['components']]))
    require(set(canonical(actual['artifacts'])) <= mapped, 'Android actual artifact lacks exact source/notice mapping')
    evidence = {'referenceSHA256': sha(reference_path), 'materialMapSHA256': sha(material_map),
                'configuration': configuration, 'actualArtifactCount': len(actual['artifacts']),
                'sourceMaterialsReusable': True, 'legalConclusion': False}
    if transition_sha is not None:
        evidence['overlayTransitionSHA256'] = transition_sha
    return evidence


def inventory(runs, source, work, source_tree, tag_object, source_root=ROOT, budget=None, materialize=False):
    budget = budget or ScratchBudget(work)
    peer_policy = peer_evidence.select(ROOT, source, VERSION, TAG, source_tree, tag_object)
    scope = peer_evidence.scoped(release_scope(VERSION), peer_policy, runs)
    peer_receipt = None
    require(set(runs) in ({'all', 'linux', 'docker'}, {'all', 'linux', 'docker', 'signed'}), 'all, linux and docker runs are mandatory')
    result = {'repository': REPO, 'repositoryId': RID, 'version': VERSION, 'sourceCommit': source,
              'scopeSha256': sha(SCOPE), 'reviewed': False, 'runs': {}, 'signedOnlyBlockers': BLOCKED,
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
        verify_artifact_names(names, scope[role]['requiredArtifacts'], role)
        entry = {'id': rid, 'attempt': run['run_attempt'], 'workflow': run['path'], 'artifacts': {}}
        receipt = None
        binding = None
        canonical_manifest = None
        ready_metadata = None
        private_entries = {}
        material_jobs = []
        if debian_policy(scope, role) is not None:
            context = debian_context(role, run, source, source_tree, tag_object)
            require(context['runID'] == int(rid), 'Debian input run ID mismatch')
            material_jobs = pages(f'repos/{REPO}/actions/runs/{context["runID"]}/attempts/{context["runAttempt"]}/jobs',
                                  'jobs', maximum=1000)
            binding, private_entries, canonical_manifest, ready_metadata = read_debian_artifacts(
                artifacts, context, run, debian_supplier_job(context, jobs=material_jobs), budget)
            entry['distributionMaterials'] = {'debianRaw': binding}
        for a in artifacts:
            if a['name'] in private_entries:
                entry['artifacts'][a['name']] = private_entries[a['name']]
                continue
            is_peer = peer_policy is not None and a['name'] == peer_policy['selection']['artifact']['name']
            if is_peer:
                peer_evidence.check_api(peer_policy, role, run, a)
            require(not a['expired'], 'expired artifact')
            require(datetime.fromisoformat(a['created_at'].replace('Z', '+00:00')) >= datetime.fromisoformat(run['run_started_at'].replace('Z', '+00:00')), 'artifact predates current run attempt')
            arun = a.get('workflow_run', {})
            require(arun.get('id') == int(rid) and arun.get('head_sha') == source, 'artifact source mismatch')
            files = {}
            client_sources = []
            candidate_records = []
            with artifact_archive(a, budget) as (archive, members):
                if is_peer:
                    peer_evidence.members(peer_policy, members)
                for item in members:
                    if item.is_dir():
                        measure_member(archive, item)
                        continue
                    relative = item.filename
                    budget.state.update(artifactId=a['id'], artifact=a['name'], member=relative)
                    name = PurePosixPath(relative).name
                    public_name, disposition = publication(role, a['name'], relative, source)
                    candidate = name.startswith('polaris-candidate-manifest-')
                    evidence = is_peer or candidate or relative == DEBIAN_USE or (a['name'], relative) in {
                        ('publisher-run-receipt', 'publisher-run-receipt.json'),
                        ('binary-native-index', 'polaris-upstream-native-assets.json')}
                    limit = (3 * 1024**2 if candidate and client_platform(a['name']) else JSON_LIMIT) if evidence else None
                    if is_peer or relative == DEBIAN_USE:
                        limit = peer_evidence.JSON_LIMIT
                    decoder = peer_evidence.strict_json if is_peer or relative == DEBIAN_USE else json.loads
                    retained = (materialize and relative != DEBIAN_USE) or a['name'] == 'binary-native-index'
                    if retained:
                        target = work / role / a['name'] / relative
                        target.parent.mkdir(parents=True, exist_ok=True)
                        budget.admit(item.file_size, 'retained ' + relative)
                        try:
                            with target.open('xb') as stream:
                                measured_file, provenance = measure_member(archive, item, stream, limit, json_decoder=decoder)
                        except BaseException as error:
                            try:
                                target.unlink(missing_ok=True)
                            except OSError as cleanup:
                                error.add_note('Retained member cleanup also failed: ' + str(cleanup)[:300])
                            budget.release(item.file_size)
                            raise
                    else:
                        measured_file, provenance = measure_member(archive, item, json_limit=limit, json_decoder=decoder)
                    files[relative] = dict(measured_file, releaseName=public_name, publicationDisposition=disposition)
                    if is_peer:
                        peer_receipt = provenance
                        files[relative]['controlledPeerEvidence'] = peer_evidence.validate_receipt(peer_policy, measured_file, provenance)
                    if (a['name'], relative) == ('publisher-run-receipt', 'publisher-run-receipt.json'):
                        receipt = provenance
                    if relative == DEBIAN_USE:
                        files[relative]['debianRawUse'] = provenance
                    if candidate:
                        candidate_records.append(provenance)
                        require(provenance['sourceCommit'] == source and str(provenance['workflowRunId']) == rid and int(provenance['workflowAttempt']) == run['run_attempt'], 'candidate manifest source/run mismatch')
                        measured = validate_client_source(provenance, a['name'], role, source)
                        if measured is not None:
                            client_sources.append(measured)
                            # Retained in reviewed inventory and audit receipt,
                            # rather than only in a discarded metadata ZIP member.
                            files[relative]['clientSource'] = measured
                            if client_platform(a['name']) == 'android':
                                from android_runtime_materials import validate as validate_android_runtime
                                configuration = 'otherLegacyReleaseRuntimeClasspath' if a['name'].endswith('other-legacy') else 'otherReleaseRuntimeClasspath'
                                files[relative]['androidRuntimeMaterials'] = validate_android_runtime(provenance.get('androidRuntimeMaterials'), configuration)
                                files[relative]['androidMaterialReuse'] = validate_android_material_reuse(provenance.get('androidRuntimeMaterials'), configuration, measured)
            require(len(client_sources) == (1 if client_platform(a['name']) else 0), 'missing/duplicate client source evidence')
            require(files, 'empty artifact')
            has_debian_use = validate_debian_use(files, candidate_records, a['name'], binding, jobs=material_jobs,
                                                canonical_manifest=canonical_manifest, artifact_metadata=a,
                                                ready_metadata=ready_metadata)
            verify_payloads(files, scope[role]['payloadRules'][a['name']], a['name'], debian_use=has_debian_use)
            entry['artifacts'][a['name']] = {'id': a['id'], 'archiveBytes': a['size_in_bytes'], 'archiveSha256': a['digest'], 'files': files}
        expected_receipt = {'repository': REPO, 'repositoryId': RID, 'sourceCommit': source, 'runId': rid,
                            'attempt': run['run_attempt'], 'version': VERSION, 'build': 'All', 'role': role,
                            'publishStores': False, 'publishRegistry': False}
        if binding is not None:
            expected_receipt['distributionMaterials'] = {'debianRaw': binding}
        require(receipt == expected_receipt, 'producer scope/input receipt missing or inconsistent')
        entry['artifacts']['publisher-run-receipt']['files']['publisher-run-receipt.json']['releaseName'] = None
        result['runs'][role] = entry
        if role in ('all', 'signed'):
            index = json.loads((work / role / 'binary-native-index' / 'polaris-upstream-native-assets.json').read_text(encoding='utf-8'))
            args = (index, source, source_tree, tag_object, rid, run['run_attempt'], scope[role]['workflow'], source_root)
            debian_raw = entry.get('distributionMaterials', {}).get('debianRaw')
            if debian_raw is None:
                validate_final_index(*args)
            else:
                validate_final_index(*args, debian_raw=debian_raw)
            if role == 'all' and peer_policy is not None:
                require(peer_receipt is not None, 'required controlled peer receipt missing')
                peer_evidence.cross_bind(peer_policy, index, sha(work / role / 'binary-native-index' / 'polaris-upstream-native-assets.json'), entry)
                result['controlledPeerEvidence'] = peer_evidence.record(peer_policy, os.environ.get('GITHUB_SHA'))
            indexed_names = set()
            for record in [x['archive'] for x in index['platforms']] + [index['sourceArchive']]:
                require(record['name'] not in indexed_names, 'duplicate native index name')
                indexed_names.add(record['name'])
                matches = [f for a in entry['artifacts'].values() for name, f in a['files'].items() if name == record['name']]
                require(len(matches) == 1 and matches[0]['sha256'] == record['sha256'] and matches[0]['bytes'] == record['bytes'], 'native index actual hash mismatch')
    verify_metadata_pair(result)
    shared_index_path = work / 'all' / 'binary-native-index' / 'polaris-upstream-native-assets.json'
    return associate_distribution_materials(result, json.loads(shared_index_path.read_text(encoding='utf-8')), sha(shared_index_path))


def assemble(actual, config, work, output, audit=None, materialize=True, budget=None):
    require(config.get('reviewed') is True, 'public release file scope is not reviewed')
    peer_evidence.check_inventory(ROOT, actual, os.environ.get('GITHUB_SHA'))
    require(actual.get('controlledPeerEvidence') == config.get('controlledPeerEvidence'), 'reviewed controlled peer selection differs')
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
    receipt = dict(actual, signatureState='unsigned-builds-with-explicit-signed-only-blockers', fullSignedRelease=False)
    receipt['assets'] = []
    for role, run in actual['runs'].items():
        expected = config['runs'][role]
        require(run['id'] == expected['id'] and run['attempt'] == expected['attempt'], 'run/attempt differs from reviewed contract')
        require(run.get('distributionMaterials') == expected.get('distributionMaterials'),
                'reviewed role Debian material binding differs')
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
                require(f.get('androidRuntimeMaterials') == review.get('androidRuntimeMaterials'), 'reviewed Android runtime evidence differs')
                require(f.get('androidMaterialReuse') == review.get('androidMaterialReuse'), 'reviewed Android material reuse evidence differs')
                require(f.get('controlledPeerEvidence') == review.get('controlledPeerEvidence'), 'reviewed controlled peer evidence differs')
                require(f.get('debianRawUse') == review.get('debianRawUse'), 'reviewed Debian use differs')
                name, disposition = publication(role, artifact, relative, actual['sourceCommit'])
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
                require(PUBLIC_VERSION in name or name == CANONICAL_METADATA, 'public filename lacks upstream version')
                require(name != RECEIPT, 'receipt name reserved')
                destinations.add(name.casefold())
                if materialize:
                    shutil.copyfile(work / role / artifact / relative, output / name)
                receipt['assets'].append(dict(f, releaseName=name, role=role, artifact=artifact, artifactPath=relative,
                    signatureState='unverified-signed-build' if role == 'signed' else 'unsigned-candidate'))
    require(receipt['assets'], 'empty release')
    if budget:
        budget.write_json(audit / RECEIPT, receipt, PROPOSAL_LIMIT)
    else:
        (audit / RECEIPT).write_text(json.dumps(receipt, indent=2)+'\n', encoding='utf-8', newline='\n')
    return receipt


def public_asset_stream(actual, budget):
    """Second immutable ZIP pass; at most one public member exists on disk."""
    peer_evidence.check_inventory(ROOT, actual, os.environ.get('GITHUB_SHA'))
    for role, run in actual['runs'].items():
        for name, expected in run['artifacts'].items():
            for relative, reviewed in expected['files'].items():
                require(publication(role, name, relative, actual['sourceCommit']) ==
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
                    public_name, disposition = publication(role, name, item.filename, actual['sourceCommit'])
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
    notes = 'GitHub-only unsigned build/package prerelease from '+source+'. Not a complete signed installable release.\n\nClients are sing-box-polaris derivatives of the fixed SagerNet upstream clients, not official SagerNet releases. Original authors and license texts are retained. The validated producer inventory, source index and publication mapping are retained in the publisher Actions audit artifact.\n\n'+'\n'.join('- '+x for x in BLOCKED)+'\n\nAudit: https://github.com/'+REPO+'/actions/runs/'+os.environ['GITHUB_RUN_ID']
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


def reconciliation_plan(actual):
    plan = json.loads(RECONCILIATION.read_text(encoding='utf-8'))
    require((plan['schema'], plan['repository'], plan['releaseId'], plan['tag'], plan['tagObject'], plan['sourceCommit']) ==
            ('polaris-alpha12-release-reconciliation-v1', REPO, 416392475, 'v1.15.0-polaris-alpha.12',
             'a85a5332432a92e1de502cfc9c680206371540b8', 'c0023dbc6dcd7b6eb2f54dd036ae150168bd8e6e'),
            'reconciliation is limited to the reviewed existing alpha.12 release')
    require((actual['sourceCommit'], actual['tag'], actual['tagObject']) ==
            (plan['sourceCommit'], plan['tag'], plan['tagObject']), 'reconciliation source/tag differs')
    rows = plan['operations']
    require(len(rows) == 228 and len({r['id'] for r in rows}) == 228 and
            len({r['oldName'].casefold() for r in rows}) == 228, 'invalid reconciliation baseline')
    require({op: sum(r['operation'] == op for r in rows) for op in ('keep', 'rename', 'remove')} ==
            plan['counts'] == {'keep': 145, 'rename': 23, 'remove': 60}, 'reconciliation scope changed')
    require(plan['deferRemovalIds'] in ([653244600, 653251914], []), 'invalid consumer material deferral')
    if not plan['deferRemovalIds']:
        # Reuse the existing consumer audit reports, never a flag claiming readiness.
        require(plan['consumerEvidence'], 'consumer verification reports required before sidecar removal')
        for evidence in plan['consumerEvidence']:
            path = ROOT.joinpath(*portable(evidence['path']).parts)
            require(sha(path) == evidence['sha256'], 'consumer verification report changed')
    public = {}
    for row in rows:
        require(type(row['id']) is int and row['id'] > 0 and type(row['bytes']) is int and row['bytes'] > 0 and
                re.fullmatch(r'sha256:[0-9a-f]{64}', row['digest']), 'invalid baseline asset identity')
        require(len(portable(row['oldName']).parts) == 1, 'baseline asset name must be a basename')
        producer = row.get('producer')
        if not producer:
            require(row['oldName'] == RECEIPT and row['operation'] == 'remove', 'unknown non-producer asset')
            continue
        role, artifact, relative = (producer[k] for k in ('role', 'artifact', 'path'))
        record = actual['runs'][role]['artifacts'][artifact]['files'][relative]
        require((record['bytes'], 'sha256:' + record['sha256']) == (row['bytes'], row['digest']), 'baseline differs from original producer bytes')
        # The immutable c002 recovery contract retains its historical outer names.
        name = producer_publication(role, artifact, relative)[0]
        require((name is None) == (row['operation'] == 'remove'), 'reconciliation differs from public selection')
        if name:
            require(name == row.get('newName', row['oldName']), 'reconciliation differs from public naming')
            require(name.casefold() not in {x.casefold() for x in public}, 'duplicate final public name')
            public[name] = row
    require(len(public) == 168, 'exact upstream public set required')
    return plan


def reconciliation_snapshot(plan, final_body):
    release_id = plan['releaseId']
    require(tag_identity(plan['sourceCommit']) == plan['tagObject'], 'reconciliation tag moved')
    require([r['id'] for r in pages(f'repos/{REPO}/releases') if r['tag_name'] == TAG] == [release_id], 'competing release')
    release = api(f'repos/{REPO}/releases/{release_id}')
    require(release['id'] == release_id, 'reconciliation release identity changed')
    for field, original in plan['release'].items():
        require(release.get(field) in (original, final_body) if field == 'body' else release.get(field) == original,
                'release metadata changed: ' + field)
    assets = pages(f'repos/{REPO}/releases/{release_id}/assets')
    by_id = {a['id']: a for a in assets}
    require(len(by_id) == len(assets) and len({a['name'].casefold() for a in assets}) == len(assets), 'duplicate remote asset')
    rows = {r['id']: r for r in plan['operations']}
    require(set(by_id) <= set(rows), 'unknown concurrent release asset')
    normalized = {}
    for ident, row in rows.items():
        asset = by_id.get(ident)
        if asset is None:
            require(row['operation'] == 'remove' and ident not in plan['deferRemovalIds'], 'required asset disappeared')
            continue
        require(asset['name'] in {row['oldName'], row.get('newName', row['oldName'])}, 'asset name changed outside plan')
        require(asset['state'] == 'uploaded' and (asset['size'], asset.get('digest')) == (row['bytes'], row['digest']),
                'remote bytes/hash changed')
        normalized[ident] = (asset['name'], asset['size'], asset['digest'])
    return release['body'], normalized


def recovery_references(actual, plan):
    """Reuse already downloaded and verified producer artifacts, without copying GBs again."""
    references, originals = {}, {}
    for row in plan['operations']:
        if row['operation'] != 'remove' or not row.get('producer'):
            continue
        producer = row['producer']
        artifact = actual['runs'][producer['role']]['artifacts'][producer['artifact']]
        if artifact['id'] not in originals:
            originals[artifact['id']] = api(f'repos/{REPO}/actions/artifacts/{artifact["id"]}')
        original = originals[artifact['id']]
        require(original['id'] == artifact['id'] and original['name'] == producer['artifact'] and
                original.get('digest') == artifact['archiveSha256'] and original.get('expired') is False,
                'original producer artifact is unavailable for recovery')
        expires = datetime.fromisoformat(original['expires_at'].replace('Z', '+00:00'))
        require(expires > datetime.now(expires.tzinfo), 'original producer recovery copy expired')
        references[str(row['id'])] = {'artifactId': original['id'], 'archiveDigest': original['digest'],
                                    'expiresAt': original['expires_at'], 'producer': producer,
                                    'bytes': row['bytes'], 'digest': row['digest']}
    return references


def reconciliation_notes(plan):
    return ('GitHub-only unsigned build/package prerelease from ' + plan['sourceCommit'] + '.\n\n'
            'Public products follow the upstream All Release selection. Client packages are sing-box-polaris '
            'derivatives, not official SagerNet releases. Original authors, license texts and package contents '
            'are retained. APK/EXE/PKG and DEB/RPM signing and macOS notarization are not supplied by this repair.\n\n' +
            '\n'.join('- ' + x for x in BLOCKED) + '\n\n'
            'Producer inventory, original source/index and recoverable asset references are retained in the '
            'reviewed publisher Actions audit: https://github.com/' + REPO + '/actions/workflows/publish-github.yml')


def prepare_reconciliation(actual, audit):
    plan = reconciliation_plan(actual)
    state = reconciliation_snapshot(plan, reconciliation_notes(plan))
    original = {r['id']: (r['oldName'], r['bytes'], r['digest']) for r in plan['operations']}
    require(state == (plan['release']['body'], original), 'prepare requires the complete reviewed initial snapshot; reuse prior recovery artifact after interruption')
    references = recovery_references(actual, plan)
    receipt = next(r for r in plan['operations'] if not r.get('producer'))
    destination = audit / 'original-public-receipt.json'
    with destination.open('xb') as stream:
        subprocess.run(['gh', 'api', f'repos/{REPO}/releases/assets/{receipt["id"]}',
                        '-H', 'Accept: application/octet-stream'], stdout=stream, check=True)
    require((destination.stat().st_size, 'sha256:' + sha(destination)) == (receipt['bytes'], receipt['digest']),
            'original public receipt backup mismatch')
    record = {'planSHA256': sha(RECONCILIATION), 'sourceCommit': plan['sourceCommit'],
              'publisherCommit': os.environ['GITHUB_SHA'], 'assets': references}
    (audit / 'reconciliation-recovery.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8', newline='\n')
    return record


def load_recovery(run_id, audit):
    require(re.fullmatch(r'[1-9][0-9]*', run_id or ''), 'successful recovery preparation run required')
    run = api(f'repos/{REPO}/actions/runs/{run_id}')
    require(run['repository']['id'] == RID and run['head_repository']['id'] == RID and
            run['path'] == '.github/workflows/publish-github.yml' and run['head_sha'] == os.environ['GITHUB_SHA'] and
            run['status'] == 'completed' and run['conclusion'] == 'success', 'recovery run identity/status differs')
    artifacts = [a for a in pages(f'repos/{REPO}/actions/runs/{run_id}/artifacts', 'artifacts')
                 if a['name'] == 'github-release-recovery']
    require(len(artifacts) == 1 and not artifacts[0]['expired'], 'recovery artifact missing/ambiguous/expired')
    with tempfile.TemporaryDirectory() as temp:
        archive = Path(temp) / 'recovery.zip'
        with archive.open('wb') as stream:
            subprocess.run(['gh', 'api', f'repos/{REPO}/actions/artifacts/{artifacts[0]["id"]}/zip'], stdout=stream, check=True)
        require(artifacts[0].get('digest') == 'sha256:' + sha(archive), 'recovery archive digest differs')
        extracted = Path(temp) / 'extracted'
        extract(archive, extracted)
        require({p.relative_to(extracted).as_posix() for p in extracted.rglob('*') if p.is_file()} ==
                {'original-public-receipt.json', 'reconciliation-recovery.json'}, 'unexpected recovery scope')
        for name in ('original-public-receipt.json', 'reconciliation-recovery.json'):
            shutil.copyfile(extracted / name, audit / name)


def reviewed_recovery(run_id, actual, audit):
    load_recovery(run_id, audit)
    plan = reconciliation_plan(actual)
    record = json.loads((audit / 'reconciliation-recovery.json').read_text(encoding='utf-8'))
    require((record['planSHA256'], record['sourceCommit'], record['publisherCommit']) ==
            (sha(RECONCILIATION), plan['sourceCommit'], os.environ['GITHUB_SHA']), 'recovery contract differs')
    require(record['assets'] == recovery_references(actual, plan), 'recovery producer copies changed')
    receipt = next(r for r in plan['operations'] if not r.get('producer'))
    path = audit / 'original-public-receipt.json'
    require((path.stat().st_size, 'sha256:' + sha(path)) == (receipt['bytes'], receipt['digest']), 'recovery receipt differs')
    return plan


def reconcile(plan):
    """Only bounded name changes/removals. No uploads, tag writes or arbitrary clobber."""
    final_body = reconciliation_notes(plan)
    current = reconciliation_snapshot(plan, final_body)
    rows = {r['id']: r for r in plan['operations']}

    def mutate(ident, name=None):
        nonlocal current
        require(reconciliation_snapshot(plan, final_body) == current, 'concurrent change before mutation')
        expected = dict(current[1])
        if name is None:
            require(rows[ident]['operation'] == 'remove' and ident not in plan['deferRemovalIds'], 'unapproved removal')
            api(f'repos/{REPO}/releases/assets/{ident}', 'DELETE')
            expected.pop(ident)
        else:
            require(rows[ident]['operation'] == 'rename' and rows[ident]['newName'] == name, 'unapproved rename')
            api(f'repos/{REPO}/releases/assets/{ident}', 'PATCH', {'name': name})
            expected[ident] = (name, rows[ident]['bytes'], rows[ident]['digest'])
        current = (current[0], expected)
        require(reconciliation_snapshot(plan, final_body) == current, 'mutation readback mismatch; stop and inspect')

    for row in plan['operations']:
        if row['operation'] != 'rename' or current[1][row['id']][0] == row['newName']:
            continue
        conflicts = [ident for ident, asset in current[1].items() if asset[0] == row['newName']]
        for ident in conflicts:
            require(rows[ident]['operation'] == 'remove', 'rename target belongs to retained asset')
            mutate(ident)  # Exact Linux-channel ID; original All ID and bytes are kept.
        mutate(row['id'], row['newName'])
    for row in plan['operations']:
        if row['operation'] == 'remove' and row['id'] not in plan['deferRemovalIds'] and row['id'] in current[1]:
            mutate(row['id'])
    require(reconciliation_snapshot(plan, final_body) == current, 'concurrent change before final notes')
    if current[0] != final_body:
        api(f'repos/{REPO}/releases/{plan["releaseId"]}', 'PATCH', {'body': final_body})
        current = (final_body, current[1])
    require(reconciliation_snapshot(plan, final_body) == current, 'final reconciliation readback mismatch')
    expected = {r['id']: (r.get('newName', r['oldName']), r['bytes'], r['digest']) for r in plan['operations']
                if r['operation'] != 'remove' or r['id'] in plan['deferRemovalIds']}
    require(current[1] == expected, 'final reconciliation set differs')
    return {'releaseId': plan['releaseId'], 'assetCount': len(expected),
            'complete': not plan['deferRemovalIds'], 'deferredAssetIds': plan['deferRemovalIds']}


def reviewed_contract(run_id, digest, source, publisher_commit=None, artifact_identity=None, budget=None):
    require(re.fullmatch(r'[1-9][0-9]*', run_id or ''), 'inventory run ID required')
    require(re.fullmatch(r'[0-9a-f]{64}', digest or ''), 'explicit reviewed inventory SHA-256 required')
    run = api(f'repos/{REPO}/actions/runs/{run_id}')
    require(run['repository']['id'] == RID and run['head_repository']['id'] == RID, 'foreign inventory run')
    require(run['path'] == '.github/workflows/publish-github.yml' and run['head_sha'] == (publisher_commit or os.environ['GITHUB_SHA']), 'inventory publisher revision mismatch')
    require(run['conclusion'] == 'success' and run['status'] == 'completed', 'inventory run failed')
    candidates = [a for a in pages(f'repos/{REPO}/actions/runs/{run_id}/artifacts', 'artifacts') if a['name'] == 'github-release-validation']
    require(len(candidates) == 1 and not candidates[0]['expired'], 'inventory artifact missing/ambiguous/expired')
    if artifact_identity is not None:
        require((candidates[0]['id'], candidates[0].get('digest')) == artifact_identity, 'original inventory artifact identity changed')
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


# This is a one-shot replacement of the original alpha.12 Release, not --clobber.
# The historical reconciliation file is used ONLY as an immutable old-asset
# snapshot. Its old keep/rename/remove decisions never select rebuilt uploads.
REPLACEMENT_ORIGINAL = {
    'snapshotSHA256': '262d6d17c916e6f771c6bb50bdfa5eddae844bbf1318f31d0b7bea87ff600b20',
    'publisherCommit': '388db8964afc4686f07e284fea5ef27185bd6daf',
    'inventoryRun': '39124650790',
    'inventorySHA256': 'a493800dca182ed527ba8b1959f6e2257b19f876c4e2036600f27079bbc2c711',
    'artifactId': 12135921586,
    'artifactDigest': 'sha256:ef48b2218d85b0b000d56bf55f1be91807fb7428c8a10453aaaf9d074a67c9c1',
    'sourceCommit': 'c0023dbc6dcd7b6eb2f54dd036ae150168bd8e6e',
    'tagObject': 'a85a5332432a92e1de502cfc9c680206371540b8',
}


def replacement_baseline():
    lock = REPLACEMENT_ORIGINAL
    require(sha(RECONCILIATION) == lock['snapshotSHA256'], 'replacement original snapshot changed')
    plan = json.loads(RECONCILIATION.read_text(encoding='utf-8'))
    require((plan['repository'], plan['releaseId'], plan['sourceCommit'], plan['tag'], plan['tagObject']) ==
            (REPO, 416392475, lock['sourceCommit'], TAG, lock['tagObject']), 'replacement baseline identity differs')
    # All original assets are retired after all rebuilt public files are staged.
    # No old consumer report or old public-selection decision approves new bytes.
    for row in plan['operations']:
        row['operation'] = 'remove'
        row.pop('newName', None)
    plan['deferRemovalIds'] = []
    return plan


def replacement_original_inventory(plan):
    lock = REPLACEMENT_ORIGINAL
    actual = reviewed_contract(lock['inventoryRun'], lock['inventorySHA256'], lock['sourceCommit'],
                               publisher_commit=lock['publisherCommit'],
                               artifact_identity=(lock['artifactId'], lock['artifactDigest']))
    require((actual['repository'], actual['repositoryId'], actual['tag'], actual['tagObject']) ==
            (REPO, RID, TAG, plan['tagObject']), 'original inventory identity differs')
    for row in plan['operations']:
        if not row.get('producer'):
            require(row['oldName'] == RECEIPT, 'unknown original non-producer asset')
            continue
        origin = row['producer']
        record = actual['runs'][origin['role']]['artifacts'][origin['artifact']]['files'][origin['path']]
        require((record['bytes'], 'sha256:' + record['sha256']) == (row['bytes'], row['digest']),
                'original inventory no longer proves baseline asset bytes')
    return actual


def replacement_recovery(audit, run_id=None):
    plan = replacement_baseline()
    actual = replacement_original_inventory(plan)
    references = recovery_references(actual, plan)
    expected = {'schema': 'polaris-alpha12-replacement-recovery-v1',
                'planSHA256': REPLACEMENT_ORIGINAL['snapshotSHA256'],
                'oldInventorySHA256': REPLACEMENT_ORIGINAL['inventorySHA256'],
                'publisherCommit': os.environ['GITHUB_SHA'], 'sourceCommit': plan['sourceCommit'],
                'assets': references}
    receipt = next(row for row in plan['operations'] if not row.get('producer'))
    destination = audit / 'original-public-receipt.json'
    if run_id is None:
        original = {r['id']: (r['oldName'], r['bytes'], r['digest']) for r in plan['operations']}
        require(reconciliation_snapshot(plan, plan['release']['body']) == (plan['release']['body'], original),
                'replacement preparation requires the complete original snapshot before moving the tag')
        with destination.open('xb') as stream:
            subprocess.run(['gh', 'api', f'repos/{REPO}/releases/assets/{receipt["id"]}',
                            '-H', 'Accept: application/octet-stream'], stdout=stream, check=True)
        (audit / 'reconciliation-recovery.json').write_text(json.dumps(expected, indent=2) + '\n', encoding='utf-8', newline='\n')
    else:
        load_recovery(run_id, audit)
        require(json.loads((audit / 'reconciliation-recovery.json').read_text(encoding='utf-8')) == expected,
                'replacement recovery does not bind this publisher and all original assets')
    require((destination.stat().st_size, 'sha256:' + sha(destination)) == (receipt['bytes'], receipt['digest']),
            'replacement original receipt recovery mismatch')
    return plan


def replacement_target(source):
    require(source == os.environ['GITHUB_SHA'] and source != REPLACEMENT_ORIGINAL['sourceCommit'],
            'rebuilt source must be this new publisher revision, never original binaries')
    require(os.environ.get('GITHUB_REF') == 'refs/tags/' + TAG, 'replacement writes require the exact protected tag ref')
    return tag_identity(source)


def replacement_notes(source, inventory_sha=None):
    if inventory_sha is None:
        return ('Rebuilding this unsigned alpha.12 prerelease from ' + source + '.\n\n'
                'The original assets from ' + REPLACEMENT_ORIGINAL['sourceCommit'] +
                ' are retained for recovery. This Release remains draft until the complete reviewed replacement is verified.')
    return (reconciliation_notes({'sourceCommit': source}) +
            '\n\nChanges in this alpha.12 rebuild:\n'
            '- Fix GitHub public-product selection to match the upstream All release: 168 uploaded products.\n'
            '- Restore canonical DEB/RPM filenames and a single Android version-metadata file.\n'
            '- Keep SDK, container, unsigned xcarchive and source/index/receipt audit outputs out of public Assets.\n'
            '- Replace the same-name release from one reviewed source, with verified staging and interrupted-run recovery.\n'
            'These publication fixes do not claim new device/runtime acceptance or signing.\n\n'
            'Rebuilt inventory SHA-256: ' + inventory_sha +
            '. All public files were freshly validated for this source; original asset IDs are retired.')


def replacement_expected(actual, digest):
    require(actual.get('reviewed') is True and re.fullmatch(r'[0-9a-f]{64}', digest or ''), 'reviewed rebuilt inventory required')
    require(actual['sourceCommit'] == os.environ['GITHUB_SHA'] and actual['tag'] == TAG and
            actual['tagObject'] == replacement_target(actual['sourceCommit']), 'rebuilt inventory source/tag mismatch')
    expected = {}
    for role, run in actual['runs'].items():
        for artifact, item in run['artifacts'].items():
            for path, record in item['files'].items():
                name, disposition = publication(role, artifact, path, actual['sourceCommit'])
                require((record['releaseName'], record['publicationDisposition']) == (name, disposition),
                        'rebuilt inventory public mapping differs')
                if name is None:
                    continue
                require(name not in expected and len(portable(name).parts) == 1, 'duplicate rebuilt public name')
                expected[name] = {'size': record['bytes'], 'digest': 'sha256:' + record['sha256'],
                                  'stagedName': 'replacement-' + actual['sourceCommit'][:12] + '-' + digest[:12] + '-' + name}
    require(len(expected) == 168 and len({name.casefold() for name in expected}) == 168,
            'exact 168 rebuilt public products required')
    return expected


def replacement_snapshot(plan, source, tag_object, expected=None, digest=None):
    require(replacement_target(source) == tag_object, 'replacement tag moved')
    release_id = plan['releaseId']
    require([r['id'] for r in pages(f'repos/{REPO}/releases') if r['tag_name'] == TAG] == [release_id], 'competing replacement release')
    release = api(f'repos/{REPO}/releases/{release_id}')
    require(release['id'] == release_id, 'replacement release identity changed')
    metadata = {key: release.get(key) for key in plan['release']}
    original = plan['release']
    staged = dict(original, draft=True, target_commitish=source, body=replacement_notes(source))
    final = dict(staged, draft=False, body=replacement_notes(source, digest)) if expected is not None else None
    require(metadata in (original, staged, final), 'replacement release metadata changed outside plan')
    assets = pages(f'repos/{REPO}/releases/{release_id}/assets')
    require(len({a['id'] for a in assets}) == len(assets) and
            len({a['name'].casefold() for a in assets}) == len(assets), 'duplicate replacement asset')
    old = {row['id']: row for row in plan['operations']}
    targets = {n: n for n in (expected or {})}
    targets.update({r['stagedName']: n for n, r in (expected or {}).items()})
    normalized, new = {}, {}
    label = 'polaris-alpha12-replacement:' + source + ':' + (digest or '')
    for asset in assets:
        ident, name = asset['id'], asset['name']
        require(asset['state'] == 'uploaded', 'incomplete replacement upload; retain draft and inspect')
        if ident in old:
            row = old[ident]
            require((name, asset['size'], asset.get('digest')) == (row['oldName'], row['bytes'], row['digest']),
                    'original asset changed outside replacement plan')
            normalized[ident] = (name, asset['size'], asset['digest'], None)
        else:
            require(name in targets, 'unknown concurrent replacement asset')
            canonical = targets[name]
            row = expected[canonical]
            require(canonical not in new and asset.get('label') == label and
                    (asset['size'], asset.get('digest')) == (row['size'], row['digest']),
                    'unreviewed replacement asset identity/hash')
            new[canonical] = ident
            normalized[ident] = (name, asset['size'], asset['digest'], label)
    remaining = set(normalized) & set(old)
    complete = expected is not None and len(new) == len(expected)
    require(len(remaining) == len(old) or complete, 'old assets disappeared before all replacements were verified')
    require(not remaining or all(normalized[ident][0] == expected[name]['stagedName'] for name, ident in new.items()),
            'new public names appeared before original assets retired')
    if metadata == original:
        require(len(remaining) == len(old) and not new, 'public original Release cannot contain replacement mutations')
    if metadata == final:
        require(not remaining and complete and all(normalized[ident][0] == name for name, ident in new.items()),
                'public replacement is incomplete')
    return metadata, normalized


def replacement_budget(writes):
    # One authenticated core-budget read, no anonymous fallback or reset waiting.
    # Include bounded full snapshots and a reserve for concurrent read activity.
    core = api('rate_limit')['resources']['core']
    needed = writes + ((writes + 79) // 80 + 5) * 9 + 32
    require(type(core.get('remaining')) is int and core['remaining'] >= needed,
            f"replacement API budget insufficient: remaining={core.get('remaining')}, required={needed}, reset={core.get('reset')}; stop before mutation")


def stage_replacement(plan, source):
    tag_object = replacement_target(source)
    current = replacement_snapshot(plan, source, tag_object)
    staged = dict(plan['release'], draft=True, target_commitish=source, body=replacement_notes(source))
    if current[0] != staged:
        replacement_budget(1)
        require(replacement_snapshot(plan, source, tag_object) == current, 'concurrent change before replacement staging')
        api(f'repos/{REPO}/releases/{plan["releaseId"]}', 'PATCH',
            {'draft': True, 'target_commitish': source, 'body': staged['body']})
        current = (staged, current[1])
    require(replacement_snapshot(plan, source, tag_object) == current, 'replacement staging readback mismatch')
    return {'releaseId': plan['releaseId'], 'draft': True, 'assetCount': len(current[1]), 'sourceCommit': source}


def replace_release(plan, actual, digest, output, audit=None):
    source, tag_object = actual['sourceCommit'], actual['tagObject']
    expected = replacement_expected(actual, digest)
    audit = audit or output.with_name(output.name + '-audit')
    index_path = audit / 'polaris-upstream-native-assets.json'
    # Inventory distributionMaterials is a three-field binding summary, not the
    # native index's eligibility object. Preserve that actual evidence schema.
    require(actual['distributionMaterials']['noticeIndex']['name'] == index_path.name and
            sha(index_path) == actual['distributionMaterials']['noticeIndex']['sha256'],
            'assembled replacement native index differs from reviewed inventory')
    index = json.loads(index_path.read_text(encoding='utf-8'))
    validate_publication_index(index, source, TAG, tag_object, actual['sourceTree'])
    require({p.name for p in output.iterdir()} == set(expected), 'assembled replacement file set differs')
    for name, row in expected.items():
        require(((output / name).stat().st_size, 'sha256:' + sha(output / name)) == (row['size'], row['digest']),
                'assembled replacement bytes differ')
    snapshot = lambda: replacement_snapshot(plan, source, tag_object, expected, digest)
    current = snapshot()
    staged = dict(plan['release'], draft=True, target_commitish=source, body=replacement_notes(source))
    final = dict(staged, draft=False, body=replacement_notes(source, digest))
    if current[0] == final:
        return {'releaseId': plan['releaseId'], 'sourceCommit': source, 'tagObject': tag_object,
                'inventorySHA256': digest, 'assetCount': 168, 'complete': True, 'assets': current[1]}
    require(current[0] == staged, 'stage the original Release as draft before rebuilding/replacing')
    old = {r['id'] for r in plan['operations']}
    replacement_budget(168 - len(set(current[1]) - old) + len(old & set(current[1])) +
                       sum(a[0] not in expected for ident, a in current[1].items() if ident not in old) +
                       (168 - len(set(current[1]) - old)) + 1)
    label = 'polaris-alpha12-replacement:' + source + ':' + digest

    writes = 0

    def checkpoint():
        require(snapshot() == current, 'concurrent replacement change; retain draft and inspect')

    def completed_write():
        nonlocal writes
        writes += 1
        # GitHub recommends no more than one content-creation request per second.
        time.sleep(1)
        if writes % 80 == 0:
            checkpoint()

    def mutate(path, method, payload, after):
        nonlocal current
        response = api(path, method, payload)
        if '/releases/assets/' in path and method == 'PATCH':
            ident = int(path.rsplit('/', 1)[-1])
            require((response.get('id'), response.get('state'), response.get('name'), response.get('size'),
                     response.get('digest'), response.get('label')) ==
                    (ident, 'uploaded', *after[1][ident]), 'replacement rename response mismatch; retain draft and inspect')
        current = after
        completed_write()

    release = api(f'repos/{REPO}/releases/{plan["releaseId"]}')
    require(release.get('id') == plan['releaseId'], 'replacement upload destination changed')
    for name, row in sorted(expected.items()):
        if any(ident not in old and asset[0] in (name, row['stagedName']) for ident, asset in current[1].items()):
            continue
        url = upload_endpoint(release, row['stagedName']) + '&label=' + quote(label, safe='')
        uploaded = json.loads(command('gh', 'api', '--method', 'POST', url,
                                     '-H', 'Content-Type: application/octet-stream', '--input', str(output / name)))
        ident = uploaded['id']
        require(type(ident) is int and ident > 0 and ident not in current[1] and
                (uploaded.get('state'), uploaded.get('name'), uploaded.get('size'), uploaded.get('digest'), uploaded.get('label')) ==
                ('uploaded', row['stagedName'], row['size'], row['digest'], label), 'replacement upload response mismatch; retain draft and inspect')
        after = dict(current[1]);after[ident] = (row['stagedName'], row['size'], row['digest'], label)
        current = (current[0], after)
        completed_write()
    checkpoint()
    replacement_budget(len(old & set(current[1])) + sum(a[0] not in expected for ident, a in current[1].items() if ident not in old) + 1)
    # The snapshot forbids any removal until all 168 new byte identities exist.
    for ident in sorted(old & set(current[1])):
        after = dict(current[1]);after.pop(ident)
        mutate(f'repos/{REPO}/releases/assets/{ident}', 'DELETE', None, (current[0], after))
    checkpoint()
    for name, row in sorted(expected.items()):
        ident = next(ident for ident, asset in current[1].items() if asset[0] in (name, row['stagedName']))
        if current[1][ident][0] == name:
            continue
        after = dict(current[1]);after[ident] = (name, row['size'], row['digest'], label)
        mutate(f'repos/{REPO}/releases/assets/{ident}', 'PATCH', {'name': name}, (current[0], after))
    checkpoint()
    replacement_budget(1)
    mutate(f'repos/{REPO}/releases/{plan["releaseId"]}', 'PATCH',
           {'draft': False, 'target_commitish': source, 'body': final['body'], 'make_latest': 'false'}, (final, current[1]))
    checkpoint()
    return {'releaseId': plan['releaseId'], 'sourceCommit': source, 'tagObject': tag_object,
            'inventorySHA256': digest, 'assetCount': 168, 'complete': True, 'assets': current[1]}


def public_name_plan():
    """One reviewed metadata-only repair; never a general rename/clobber input."""
    require(sha(NAME_ALIGNMENT) == NAME_ALIGNMENT_SHA256, 'public-name snapshot changed')
    plan = json.loads(NAME_ALIGNMENT.read_text(encoding='utf-8'))
    require((plan['schema'], plan['repository'], plan['repositoryId'], plan['releaseId'],
             plan['sourceCommit'], plan['sourceTree'], plan['tag'], plan['tagObject']) ==
            ('polaris-alpha12-public-name-alignment-v1', REPO, RID, 416392475,
             'a4d0858605b51b7f5b3c29a9969a6f2c3ae5a0ae', '830f7256af499e5ad3e7da9a79f0a377ca38fc77',
             'v1.15.0-polaris-alpha.12', '916d9533ba0a6092e34bc53f63dace63e11fa85e'),
            'public-name repair identity changed')
    rows = plan['operations']
    require(len(rows) == len({r['id'] for r in rows}) == 168 and
            len({r['oldName'].casefold() for r in rows}) == len({r['newName'].casefold() for r in rows}) == 168,
            'public-name repair requires exactly 168 distinct identities/names')
    require(not ({r['oldName'].casefold() for r in rows} & {r['newName'].casefold() for r in rows}),
            'public-name repair has a name collision')
    for row in rows:
        require(type(row['id']) is int and row['id'] > 0 and type(row['bytes']) is int and row['bytes'] > 0 and
                re.fullmatch(r'sha256:[0-9a-f]{64}', row['digest']) and
                row['newName'] == public_asset_name(row['oldName']), 'public-name repair differs from source mapping')
    require(plan['release']['draft'] is False and plan['release']['prerelease'] is True and
            plan['release']['target_commitish'] == plan['sourceCommit'] and
            plan['release']['tag_name'] == plan['tag'] == TAG and
            'unsigned' in plan['release']['body'] and 'signing and macOS notarization are not supplied' in plan['release']['body'],
            'public-name repair must preserve unsigned release disclosure')
    return plan


def public_name_snapshot(plan):
    require(plan == public_name_plan(), 'public-name plan was modified')
    require(api(f'repos/{REPO}')['id'] == RID, 'public-name repository ID changed')
    require(tag_identity(plan['sourceCommit']) == plan['tagObject'], 'public-name tag moved')
    commit = api(f'repos/{REPO}/git/commits/{plan["sourceCommit"]}')
    require(commit['sha'] == plan['sourceCommit'] and commit['tree']['sha'] == plan['sourceTree'],
            'public-name source tree changed')
    require([r['id'] for r in pages(f'repos/{REPO}/releases') if r['tag_name'] == TAG] == [plan['releaseId']],
            'competing public-name Release')
    release = api(f'repos/{REPO}/releases/{plan["releaseId"]}')
    require(release['id'] == plan['releaseId'] and
            {k: release.get(k) for k in plan['release']} == plan['release'], 'public-name Release metadata changed')
    assets = pages(f'repos/{REPO}/releases/{plan["releaseId"]}/assets')
    rows = {r['id']: r for r in plan['operations']}
    require(len(assets) == 168 and {a['id'] for a in assets} == set(rows) and
            len({a['name'].casefold() for a in assets}) == 168, 'unknown/missing/concurrent public-name asset')
    current = {}
    for asset in assets:
        row = rows[asset['id']]
        require(asset['name'] in (row['oldName'], row['newName']) and asset.get('state') == 'uploaded' and
                (asset['size'], asset.get('digest'), asset.get('label')) ==
                (row['bytes'], row['digest'], plan['assetLabel']), 'public-name asset identity changed')
        current[asset['id']] = (asset['name'], asset['size'], asset['digest'], asset['label'])
    return current


def rename_public_assets(plan, execute=False):
    current = public_name_snapshot(plan)
    pending = [r for r in plan['operations'] if current[r['id']][0] != r['newName']]
    if execute and pending:
        # Existing authenticated budget gate. Include one GET immediately before
        # each PATCH plus bounded full snapshots; no anonymous fallback or waiting.
        replacement_budget(2 * len(pending))
        require(public_name_snapshot(plan) == current, 'concurrent public-name change before first write')
        for count, row in enumerate(pending, 1):
            ident = row['id']
            path = f'repos/{REPO}/releases/assets/{ident}'
            before = api(path)
            require((before.get('id'), before.get('state'), before.get('name'), before.get('size'),
                     before.get('digest'), before.get('label')) == (ident, 'uploaded', *current[ident]),
                    'concurrent public-name change before rename')
            after = (row['newName'], row['bytes'], row['digest'], plan['assetLabel'])
            response = api(path, 'PATCH', {'name': row['newName']})
            require((response.get('id'), response.get('state'), response.get('name'), response.get('size'),
                     response.get('digest'), response.get('label')) == (ident, 'uploaded', *after),
                    'public-name PATCH response mismatch; stop and inspect before resuming')
            current[ident] = after
            time.sleep(1)
            if count % 80 == 0:
                require(public_name_snapshot(plan) == current, 'concurrent public-name change during rename')
        require(public_name_snapshot(plan) == current, 'public-name final readback differs')
    remaining = sum(current[r['id']][0] != r['newName'] for r in plan['operations'])
    return {'releaseId': plan['releaseId'], 'sourceCommit': plan['sourceCommit'], 'tagObject': plan['tagObject'],
            'planSHA256': NAME_ALIGNMENT_SHA256, 'assetCount': len(current), 'remaining': remaining,
            'complete': remaining == 0, 'assets': current}


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
    p.add_argument('mode', choices=['inventory', 'validate', 'publish', 'prepare-reconcile', 'check-reconcile', 'reconcile', 'prepare-replacement', 'check-stage-replacement', 'stage-replacement', 'check-replacement', 'replace', 'check-names', 'rename-names'])
    p.add_argument('--source', required=True)
    p.add_argument('--source-dir', type=Path, default=Path('reviewed-source'))
    for role in ['all', 'linux', 'docker', 'signed']:
        p.add_argument('--'+role+'-run')
    p.add_argument('--recovery-run')
    p.add_argument('--audit', type=Path, default=Path('github-release-audit'))
    p.add_argument('--inventory-run')
    p.add_argument('--inventory-sha256')
    p.add_argument('--output', type=Path, default=Path('github-release-dist'))
    args = p.parse_args()
    public = json.loads(CONFIG.read_text(encoding='utf-8'))
    require(public == {'repository': REPO, 'repositoryId': RID, 'version': VERSION, 'tag': TAG, 'publication': 'github-only-unsigned-prerelease'}, 'public GitHub release configuration mismatch')
    # Old ID-bound maintenance plans are historical, not a patch-release migration.
    require(args.mode in ('inventory', 'validate', 'publish') or TAG == 'v1.15.0-polaris-alpha.12',
            'historical alpha.12 maintenance is unavailable for the current release plan')
    if args.mode in ('check-names', 'rename-names'):
        plan = public_name_plan()
        require(args.source == plan['sourceCommit'], 'public-name source differs from fixed snapshot')
        if args.mode == 'rename-names':
            require(os.environ.get('POLARIS_GITHUB_PUBLISH_ENABLED') == 'true', 'GitHub publication disabled')
        result = rename_public_assets(plan, execute=args.mode == 'rename-names')
        args.audit.mkdir(parents=True, exist_ok=True)
        (args.audit / 'public-name-result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
        print(json.dumps(result))
        return
    identity(args.source, args.source_dir)
    runs = {role: getattr(args, role+'_run') for role in ['all', 'linux', 'docker', 'signed'] if getattr(args, role+'_run')}
    if args.mode in ('prepare-replacement', 'check-stage-replacement', 'stage-replacement', 'check-replacement'):
        args.audit.mkdir(parents=True, exist_ok=False)
        if args.mode == 'prepare-replacement':
            require(args.source == REPLACEMENT_ORIGINAL['sourceCommit'], 'prepare must use the original source')
            replacement_recovery(args.audit)
        else:
            require(args.recovery_run, 'successful replacement recovery preparation required')
            if args.mode == 'stage-replacement':
                plan = replacement_recovery(args.audit, args.recovery_run)
            else:
                load_recovery(args.recovery_run, args.audit)
                plan = replacement_baseline()
            tag_object = replacement_target(args.source)
            if args.mode == 'check-replacement':
                actual = reviewed_contract(args.inventory_run, args.inventory_sha256, args.source)
                require(set(actual['runs']) == set(runs) and all(actual['runs'][role]['id'] == rid for role, rid in runs.items()),
                        'replacement producer inputs differ from reviewed inventory')
                replacement_expected(actual, args.inventory_sha256)
                # Read-only tokens need not expose private drafts. The protected
                # write job checks full snapshots at phase boundaries and every 80 writes.
            else:
                if args.mode == 'stage-replacement':
                    require(os.environ.get('POLARIS_GITHUB_PUBLISH_ENABLED') == 'true', 'GitHub publication disabled')
                    result = stage_replacement(plan, args.source)
                    (args.audit / 'replacement-stage.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
        return
    # Reconciliation consumes the already reviewed same-revision inventory. Its existing
    # producer artifacts and exact remote Release hashes are rechecked, not re-downloaded.
    if args.mode in ('prepare-reconcile', 'check-reconcile', 'reconcile'):
        actual = reviewed_contract(args.inventory_run, args.inventory_sha256, args.source)
        require(actual['scopeSha256'] == sha(SCOPE) and actual['repository'] == REPO and actual['repositoryId'] == RID and
                actual['version'] == VERSION and actual['sourceTree'] == command('git', '-C', str(args.source_dir), 'rev-parse', 'HEAD^{tree}'),
                'reviewed reconciliation inventory binding changed')
        require(set(actual['runs']) == set(runs) and all(actual['runs'][role]['id'] == rid for role, rid in runs.items()),
                'reconciliation producer inputs differ from reviewed inventory')
        verify_metadata_pair(actual)
        args.audit.mkdir(parents=True, exist_ok=False)
        if args.mode == 'prepare-reconcile':
            prepare_reconciliation(actual, args.audit)
        else:
            plan = reviewed_recovery(args.recovery_run, actual, args.audit)
            reconciliation_snapshot(plan, reconciliation_notes(plan))
            if args.mode == 'reconcile':
                require(os.environ.get('POLARIS_GITHUB_PUBLISH_ENABLED') == 'true', 'GitHub publication disabled')
                result = reconcile(plan)
                (args.audit / 'reconciliation-result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
                print(json.dumps(result))
        return
    if args.mode in ('inventory', 'validate', 'publish'):
        return bounded_release(args, runs)
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        source_tree = command('git', '-C', str(args.source_dir), 'rev-parse', 'HEAD^{tree}')
        tag_object = tag_identity(args.source)
        actual = inventory(runs, args.source, work, source_tree, tag_object, args.source_dir, materialize=True)
        require(tag_identity(args.source) == tag_object, 'tag changed while collecting release inventory')
        if args.mode == 'inventory':
            require(not args.output.exists(), 'inventory output already exists')
            args.output.write_text(json.dumps(actual, indent=2)+'\n', encoding='utf-8', newline='\n')
            args.audit.mkdir(parents=True, exist_ok=False)
            for material in (work / 'all' / 'binary-native-index').iterdir():
                if material.is_file():
                    shutil.copyfile(material, args.audit / material.name)
            print('Inventory SHA-256: '+sha(args.output))
            return
        tag_identity(args.source)
        assemble(actual, reviewed_contract(args.inventory_run, args.inventory_sha256, args.source), work, args.output, args.audit)
        if args.mode == 'replace':
            require(os.environ.get('POLARIS_GITHUB_PUBLISH_ENABLED') == 'true', 'GitHub publication disabled')
            require(args.recovery_run, 'successful replacement recovery preparation required')
            plan = replacement_recovery(args.audit, args.recovery_run)
            actual['reviewed'] = True
            result = replace_release(plan, actual, args.inventory_sha256, args.output, args.audit)
            (args.audit / 'replacement-result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
            print(json.dumps(result))
        if args.mode == 'publish':
            require(os.environ.get('POLARIS_GITHUB_PUBLISH_ENABLED') == 'true', 'GitHub publication disabled')
            publish(args.output, args.source, args.audit)


if __name__ == '__main__':
    main()
