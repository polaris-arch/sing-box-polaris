#!/usr/bin/env python3
"""GitHub-only release gate. Inventory is read-only; alpha.12 reconciliation is ID-bound."""
import argparse
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
import time
import zipfile

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
ANDROID_OVERLAY_TRANSITION_SHA256 = '68a5b52a4768ecf1534cb48b99285c21b365b815fcf985d7303994b1664b3b11'
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
    args = ['gh', 'api', '--method', method, path]
    if payload is not None:
        args += ['--input', '-']
    output = subprocess.check_output(args, input=json.dumps(payload).encode() if payload is not None else None)
    return json.loads(output) if output.strip() else None


def pages(path, key=None):
    result = []
    for page in range(1, 10001):
        data = api(path + ('&' if '?' in path else '?') + f'per_page=100&page={page}')
        batch = data[key] if key else data
        result.extend(batch)
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
    from native_release_index import expected_native
    expected = expected_native(VERSION)
    require(len(index['platforms']) == 44 and {x['id'] for x in index['platforms']} == set(expected), 'exact 44 native identities required')
    for row in index['platforms']:
        require((row['sourceCommit'], row['sourceTree'], row['version'], row['tag']) == (source, tree, VERSION, TAG), 'mixed source native row')
        require((row['target'], row['variant']) == (expected[row['id']]['target'], expected[row['id']]['variant']), 'native row matrix mismatch')
        require(row['archive'].get('releaseName') == public_product_name(row['archive']['name']), 'native public archive name mismatch')
        suffix = '.zip' if row['target'].startswith('windows/') else '.tar.gz'
        require(row['archive']['root'] == row['id'] and row['archive']['name'] == row['id'] + suffix, 'native archive identity mismatch')
    require(index['sourceArchive']['name'] == 'sing-box-polaris-source-' + source + '.tar.gz', 'immutable source archive basename required')
    from native_release_index import distribution_materials
    require(index['distributionMaterials'] == distribution_materials(index, source_root), 'source/notice bindings differ from actual index or committed inputs')


def producer_publication(role, artifact, relative):
    """Producer scope remains exhaustive; only upstream All binary products are public."""
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


def publication(role, artifact, relative):
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


def validate_oci_material_reuse(path, artifact, source, run_id, attempt, root=ROOT):
    """Read OCI bytes, never execute an image; require exact reviewed source-material identities."""
    import io
    import tarfile
    reference_path = root / 'release/dependency-sources/oci/reuse-reference.json'
    reference = json.loads(reference_path.read_text(encoding='utf-8'))
    require(reference['materialMapSHA256'] == sha(root / 'release/dependency-sources/oci/oci-source-notice-map.json'), 'OCI source material map changed')
    require(artifact in reference['artifacts'], 'OCI material reference lacks expected artifact')
    expected = reference['artifacts'][artifact]
    index_type = 'application/vnd.oci.image.index.v1+json'
    manifest_type = 'application/vnd.oci.image.manifest.v1+json'
    config_type = 'application/vnd.oci.image.config.v1+json'
    layer_types = {'application/vnd.oci.image.layer.v1.tar', 'application/vnd.oci.image.layer.v1.tar+gzip'}
    intoto_type = 'application/vnd.in-toto+json'
    protected = ('lib/apk/db/installed', 'etc/apk/repositories', 'usr/local/bin/sing-box')
    actual_files = {}
    images, attestations, referenced = [], [], set()
    with tarfile.open(path, 'r:*') as archive:
        members = {}
        for member in archive:
            name = member.name.removeprefix('./')
            require(name and not name.startswith('/') and '..' not in PurePosixPath(name).parts, 'unsafe OCI member path')
            name = PurePosixPath(name).as_posix()
            require(name not in members, 'duplicate OCI archive member')
            require(member.isfile() or member.isdir(), 'nonregular OCI archive member')
            require(member.size <= 512 * 1024**2, 'OCI member exceeds evidence budget')
            members[name] = member
            require(len(members) <= 256, 'OCI archive member budget exceeded')
        def read(name, limit):
            require(name in members and members[name].isfile() and members[name].size <= limit, 'missing/oversized OCI evidence member')
            data = archive.extractfile(members[name]).read(limit + 1)
            require(len(data) == members[name].size, 'OCI member truncated')
            return data
        require(json.loads(read('oci-layout', 1024)) == {'imageLayoutVersion': '1.0.0'}, 'unsupported OCI layout')
        def blob(descriptor, allowed, limit=512 * 1024**2):
            require(isinstance(descriptor, dict) and descriptor.get('mediaType') in allowed, 'unsupported OCI descriptor media type')
            digest = descriptor.get('digest', '')
            require(isinstance(digest, str) and re.fullmatch('sha256:[0-9a-f]{64}', digest), 'invalid OCI blob digest')
            require(type(descriptor.get('size')) is int and 0 <= descriptor['size'] <= limit, 'invalid OCI blob size')
            name = 'blobs/sha256/' + digest[7:]
            data = read(name, limit)
            require(len(data) == descriptor['size'] and hashlib.sha256(data).hexdigest() == digest[7:], 'OCI blob size/hash mismatch')
            referenced.add(name)
            return data
        def walk(document, descriptor=None, depth=0):
            require(depth <= 4 and document.get('schemaVersion') == 2, 'invalid OCI graph depth/schema')
            if 'manifests' in document:
                require(document.get('mediaType') == index_type and 1 <= len(document['manifests']) <= 8, 'invalid OCI index')
                for child in document['manifests']:
                    walk(json.loads(blob(child, {index_type, manifest_type}, 4 * 1024**2)), child, depth + 1)
                return
            require(descriptor is not None and document.get('mediaType') == manifest_type, 'invalid OCI image manifest')
            is_attestation = descriptor.get('annotations', {}).get('vnd.docker.reference.type') == 'attestation-manifest'
            config = json.loads(blob(document['config'], {'application/vnd.oci.empty.v1+json'} if is_attestation else {config_type}, 4 * 1024**2))
            layers = document.get('layers')
            require(isinstance(layers, list) and 1 <= len(layers) <= 32, 'invalid OCI layer count')
            if descriptor.get('annotations', {}).get('vnd.docker.reference.type') == 'attestation-manifest':
                require(config == {}, 'OCI attestation empty config is not empty')
                require(descriptor.get('platform') == {'architecture': 'unknown', 'os': 'unknown'}, 'invalid OCI attestation platform')
                for layer in layers:
                    attestations.append((descriptor, document, json.loads(blob(layer, {intoto_type}, 16 * 1024**2))))
            else:
                require(descriptor.get('platform') == expected['platform'], 'OCI descriptor platform mismatch')
                require({k: config[k] for k in ('os', 'architecture', 'variant') if k in config} == expected['platform'], 'OCI config platform mismatch')
                images.append((descriptor, document, config))
        walk(json.loads(read('index.json', 4 * 1024**2)))
        require(len(images) == 1, 'OCI requires exactly one expected platform image')
        descriptor, manifest, config = images[0]
        labels = config.get('config', {}).get('Labels', {})
        require(labels.get('org.opencontainers.image.revision') == source and labels.get('org.opencontainers.image.source') == 'https://github.com/' + REPO, 'OCI image source mismatch')
        provenance = []
        for att_descriptor, att_manifest, statement in attestations:
            require(att_manifest.get('artifactType') == 'application/vnd.docker.attestation.manifest.v1+json', 'unsupported OCI attestation storage format')
            require(att_manifest.get('subject') == {key: descriptor[key] for key in ('mediaType','digest','size')}, 'OCI artifact subject does not bind actual image')
            require(att_descriptor['annotations'].get('vnd.docker.reference.digest') == descriptor['digest'], 'OCI attestation does not bind actual image')
            if statement.get('predicateType') == 'https://slsa.dev/provenance/v1':
                require(statement.get('_type') == 'https://in-toto.io/Statement/v1', 'invalid OCI provenance statement')
                # Current BuildKit OCI artifact format binds the image via the
                # attestation manifest subject; all nine measured statements use [].
                require(statement.get('subject') == [], 'unsupported in-toto subject representation')
                provenance.append(statement['predicate'])
        require(len(provenance) == 1, 'OCI requires unique SLSA v1 provenance')
        provenance = provenance[0]
        details = provenance.get('runDetails', {})
        require(details.get('builder', {}).get('id') == f'https://github.com/{REPO}/actions/runs/{run_id}/attempts/{attempt}', 'OCI builder run/attempt mismatch')
        vcs = details.get('metadata', {}).get('buildkit_metadata', {}).get('vcs', {})
        require(vcs.get('revision') == source and vcs.get('source') == 'https://github.com/' + REPO, 'OCI provenance source mismatch')
        definition = provenance['buildDefinition']
        require(definition.get('buildType') == 'https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md', 'unsupported OCI provenance build type')
        require(definition.get('resolvedDependencies') == expected['baseDependencies'], 'OCI base changed; refresh source materials')
        require(definition.get('externalParameters', {}).get('configSource', {}).get('path') == 'Dockerfile.binary', 'OCI build recipe mismatch')
        for layer in manifest['layers']:
            data = blob(layer, layer_types)
            require((layer['mediaType'].endswith('+gzip') and data.startswith(b'\x1f\x8b')) or (layer['mediaType'].endswith('.tar') and not data.startswith(b'\x1f\x8b')), 'OCI layer compression differs from media type')
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as content:
                seen = set()
                expanded_bytes = 0
                for member in content:
                    name = member.name.removeprefix('./').rstrip('/')
                    require(name and not name.startswith('/') and '..' not in PurePosixPath(name).parts, 'unsafe OCI layer path')
                    name = PurePosixPath(name).as_posix()
                    require(name not in seen, 'duplicate OCI layer path')
                    seen.add(name)
                    expanded_bytes += member.size
                    require(len(seen) <= 100000 and 0 <= member.size <= 512 * 1024**2 and expanded_bytes <= 2 * 1024**3, 'OCI expanded layer exceeds evidence budget')
                    if name == '.': require(member.isdir(), 'OCI root must be a directory')
                    path_parts = PurePosixPath(name)
                    if path_parts.name.startswith('.wh.'):
                        parent = path_parts.parent.as_posix()
                        affected = parent if path_parts.name == '.wh..wh..opq' else str(path_parts.parent / path_parts.name[4:])
                        affected = affected.removeprefix('./')
                        require(not any(affected in ('', '.') or target == affected or target.startswith(affected + '/') for target in protected), 'OCI whiteout affects required material evidence')
                    if any(target.startswith(name + '/') for target in protected):
                        require(member.isdir(), 'OCI non-directory shadows material evidence path')
                    if name in protected:
                        require(member.isfile() and 0 < member.size <= (256 * 1024**2 if name.endswith('sing-box') else 4 * 1024**2), 'OCI material evidence is missing/nonregular/oversized')
                        value = content.extractfile(member).read()
                        require(len(value) == member.size, 'truncated OCI material evidence')
                        actual_files[name] = value
        require(all(name in actual_files for name in protected), 'OCI required files missing')
        require({name for name, member in members.items() if member.isfile()} == referenced | {'index.json','oci-layout'}, 'OCI unreferenced or alternate-format file inventory')
    repositories = actual_files['etc/apk/repositories'].decode('utf-8')
    require(repositories == expected['repositories'], 'OCI repositories changed; refresh source materials')
    packages = []
    for paragraph in actual_files['lib/apk/db/installed'].decode('utf-8').strip().split('\n\n'):
        package = {}
        for line in paragraph.splitlines():
            if ':' not in line:
                continue
            key, value = line.split(':', 1)
            if key in ('P', 'V', 'A', 'L', 'o', 'c', 'C'):
                require(key not in package, 'duplicate OCI installed package field')
                package[key] = value
        require(set(package) == {'P', 'V', 'A', 'L', 'o', 'c', 'C'} and all(package.values()), 'incomplete OCI installed source identity')
        packages.append(package)
    packages.sort(key=lambda item: (item['P'], item['V'], item['A']))
    require(packages == expected['packages'], 'OCI installed packages changed; refresh source materials')
    return {'referenceSHA256': sha(reference_path), 'materialMapSHA256': reference['materialMapSHA256'],
            'platform': expected['platform'], 'baseDependencies': expected['baseDependencies'],
            'packageCount': len(packages), 'installedSHA256': hashlib.sha256(actual_files['lib/apk/db/installed']).hexdigest(),
            'coreSHA256': hashlib.sha256(actual_files['usr/local/bin/sing-box']).hexdigest(),
            'actualImageManifest': descriptor['digest'], 'sourceCommit': source,
            'sourceMaterialsReusable': True, 'legalConclusion': False}


def inventory(runs, source, work, source_tree, tag_object, source_root=ROOT):
    scope = release_scope(VERSION)
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
        verify_artifact_names(names, scope[role]['requiredArtifacts'], role)
        entry = {'id': rid, 'attempt': run['run_attempt'], 'workflow': run['path'], 'artifacts': {}}
        for a in artifacts:
            require(not a['expired'], 'expired artifact')
            require(datetime.fromisoformat(a['created_at'].replace('Z', '+00:00')) >= datetime.fromisoformat(run['run_started_at'].replace('Z', '+00:00')), 'artifact predates current run attempt')
            arun = a.get('workflow_run', {})
            require(arun.get('id') == int(rid) and arun.get('head_sha') == source, 'artifact source mismatch')
            directory = work / role / a['name']
            directory.mkdir(parents=True)
            with tempfile.NamedTemporaryFile() as zipped:
                subprocess.run(['gh', 'api', f'repos/{REPO}/actions/artifacts/{a["id"]}/zip'], stdout=zipped, check=True)
                zipped.flush()
                digest = 'sha256:' + sha(zipped.name)
                require(a.get('digest') == digest, 'Actions artifact digest missing or mismatched')
                extract(zipped.name, directory)
            files = {}
            client_sources = []
            for p in sorted(directory.rglob('*')):
                if p.is_file():
                    relative = p.relative_to(directory).as_posix()
                    public_name, disposition = publication(role, a['name'], relative)
                    files[relative] = {'bytes': p.stat().st_size, 'sha256': sha(p), 'releaseName': public_name,
                                       'publicationDisposition': disposition}
                    if role == 'docker' and a['name'].startswith('oci-') and relative == 'image.tar':
                        files[relative]['ociMaterialReuse'] = validate_oci_material_reuse(p, a['name'], source, rid, run['run_attempt'])
                    if p.name.startswith('polaris-candidate-manifest-'):
                        require(not client_platform(a['name']) or p.stat().st_size <= 3 * 1024**2, 'client source evidence exceeds its 3MiB serialized budget')
                        provenance = json.loads(p.read_text(encoding='utf-8'))
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
            verify_payloads(files, scope[role]['payloadRules'][a['name']], a['name'])
            entry['artifacts'][a['name']] = {'id': a['id'], 'archiveSha256': digest, 'files': files}
        receipt = json.loads((work / role / 'publisher-run-receipt' / 'publisher-run-receipt.json').read_text(encoding='utf-8'))
        require(receipt == {'repository': REPO, 'repositoryId': RID, 'sourceCommit': source, 'runId': rid,
                            'attempt': run['run_attempt'], 'version': VERSION, 'build': 'All', 'role': role,
                            'publishStores': False, 'publishRegistry': False}, 'explicit All/version/run-attempt receipt mismatch')
        entry['artifacts']['publisher-run-receipt']['files']['publisher-run-receipt.json']['releaseName'] = None
        result['runs'][role] = entry
        if role in ('all', 'signed'):
            index = json.loads((work / role / 'binary-native-index' / 'polaris-upstream-native-assets.json').read_text(encoding='utf-8'))
            validate_final_index(index, source, source_tree, tag_object, rid, run['run_attempt'], scope[role]['workflow'], source_root)
            indexed_names = set()
            for record in [x['archive'] for x in index['platforms']] + [index['sourceArchive']]:
                require(record['name'] not in indexed_names, 'duplicate native index name')
                indexed_names.add(record['name'])
                matches = [f for a in entry['artifacts'].values() for name, f in a['files'].items() if name == record['name']]
                require(len(matches) == 1 and matches[0]['sha256'] == record['sha256'] and matches[0]['bytes'] == record['bytes'], 'native index actual hash mismatch')
    verify_metadata_pair(result)
    shared_index_path = work / 'all' / 'binary-native-index' / 'polaris-upstream-native-assets.json'
    return associate_distribution_materials(result, json.loads(shared_index_path.read_text(encoding='utf-8')), sha(shared_index_path))


def assemble(actual, config, work, output, audit=None):
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
    receipt = dict(actual, signatureState='unsigned-builds-with-explicit-signed-only-blockers', fullSignedRelease=False)
    receipt['assets'] = []
    for role, run in actual['runs'].items():
        expected = config['runs'][role]
        require(run['id'] == expected['id'] and run['attempt'] == expected['attempt'], 'run/attempt differs from reviewed contract')
        require(set(run['artifacts']) == set(expected['artifacts']), 'artifact scope differs')
        for artifact, a in run['artifacts'].items():
            contract = expected['artifacts'][artifact]
            require(a['id'] == contract['id'] and a['archiveSha256'] == contract['archiveSha256'], 'artifact identity changed')
            require(set(a['files']) == set(contract['files']), 'file scope differs')
            for relative, f in a['files'].items():
                review = contract['files'][relative]
                require(f['bytes'] == review['bytes'] and f['sha256'] == review['sha256'], 'actual file hash differs')
                require(f.get('distributionMaterials') == review.get('distributionMaterials'), 'reviewed per-payload materials differ')
                require(f.get('ociMaterialReuse') == review.get('ociMaterialReuse'), 'reviewed OCI material reuse evidence differs')
                require(f.get('androidRuntimeMaterials') == review.get('androidRuntimeMaterials'), 'reviewed Android runtime evidence differs')
                require(f.get('androidMaterialReuse') == review.get('androidMaterialReuse'), 'reviewed Android material reuse evidence differs')
                name, disposition = publication(role, artifact, relative)
                require(review['releaseName'] == f['releaseName'] == name, 'public filename differs from source-owned mapping')
                require(review.get('publicationDisposition') == f.get('publicationDisposition') == disposition,
                        'publication disposition differs from source-owned mapping')
                if name is None:
                    if disposition == 'audited-source-and-index':
                        shutil.copyfile(work / role / artifact / relative, audit / PurePosixPath(relative).name)
                    continue
                require(len(portable(name).parts) == 1 and name.casefold() not in destinations, 'duplicate release filename')
                require(PUBLIC_VERSION in name or name == CANONICAL_METADATA, 'public filename lacks upstream version')
                require(name != RECEIPT, 'receipt name reserved')
                destinations.add(name.casefold())
                shutil.copyfile(work / role / artifact / relative, output / name)
                receipt['assets'].append(dict(f, releaseName=name, role=role, artifact=artifact, artifactPath=relative,
                    signatureState='unverified-signed-build' if role == 'signed' else 'unsigned-candidate'))
    require(receipt['assets'], 'empty release')
    (audit / RECEIPT).write_text(json.dumps(receipt, indent=2)+'\n', encoding='utf-8', newline='\n')
    return receipt


def publish(output, source, audit=None):
    before = tag_identity(source)
    audit = audit or output.with_name(output.name + '-audit')
    index = json.loads((audit / 'polaris-upstream-native-assets.json').read_text(encoding='utf-8'))
    validate_publication_index(index, source, TAG, before)
    # Listing includes drafts visible to the token; no 404-as-absence shortcut.
    require(not any(r['tag_name'] == TAG for r in pages(f'repos/{REPO}/releases')), 'existing Release (including draft) will never be changed')
    expected = {p.name: {'size': p.stat().st_size, 'digest': 'sha256:'+sha(p)} for p in output.iterdir() if p.is_file()}
    notes = 'GitHub-only unsigned build/package prerelease from '+source+'. Not a complete signed installable release.\n\nClients are sing-box-polaris derivatives of the fixed SagerNet upstream clients, not official SagerNet releases. Original authors and license texts are retained. The validated producer inventory, source index and publication mapping are retained in the publisher Actions audit artifact.\n\n'+'\n'.join('- '+x for x in BLOCKED)+'\n\nAudit: https://github.com/'+REPO+'/actions/runs/'+os.environ['GITHUB_RUN_ID']
    release = api(f'repos/{REPO}/releases', 'POST', {'tag_name': TAG, 'target_commitish': source, 'name': TAG, 'body': notes, 'draft': True, 'prerelease': True})
    release_id = release['id']
    # No --clobber. Any upload/validation error leaves this newly created draft intact.
    for p in sorted(output.iterdir()):
        subprocess.run(['gh', 'api', '--method', 'POST', upload_endpoint(release, p.name),
                        '-H', 'Content-Type: application/octet-stream', '--input', str(p)], check=True, stdout=subprocess.DEVNULL)
    checked = api(f'repos/{REPO}/releases/{release_id}')
    assets = pages(f'repos/{REPO}/releases/{release_id}/assets')
    require(checked['draft'] is True and checked['tag_name'] == TAG, 'draft state changed')
    require(len(assets) == len(expected) and {a['name'] for a in assets} == set(expected), 'remote asset scope mismatch; retained as draft')
    for a in assets:
        require(a['state'] == 'uploaded' and a['size'] == expected[a['name']]['size'] and a.get('digest') == expected[a['name']]['digest'], 'remote bytes/hash mismatch; retained as draft')
    require(tag_identity(source) == before, 'tag changed; retained as draft')
    require([r['id'] for r in pages(f'repos/{REPO}/releases') if r['tag_name'] == TAG] == [release_id], 'competing release; retained as draft')
    published = api(f'repos/{REPO}/releases/{release_id}', 'PATCH', {'draft': False, 'make_latest': 'false'})
    require(published['draft'] is False, 'publication not confirmed')
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


def reviewed_contract(run_id, digest, source, publisher_commit=None, artifact_identity=None):
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
        archive = Path(temp)/'inventory.zip'
        with archive.open('wb') as f:
            subprocess.run(['gh', 'api', f'repos/{REPO}/actions/artifacts/{candidates[0]["id"]}/zip'], stdout=f, check=True)
        require(candidates[0].get('digest') == 'sha256:'+sha(archive), 'inventory archive digest mismatch')
        extract(archive, Path(temp)/'extracted')
        proposal = Path(temp)/'extracted/release-inventory-proposal.json'
        require(sha(proposal) == digest, 'inventory differs from explicitly reviewed hash')
        contract = json.loads(proposal.read_text(encoding='utf-8'))
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
                name, disposition = publication(role, artifact, path)
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
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        source_tree = command('git', '-C', str(args.source_dir), 'rev-parse', 'HEAD^{tree}')
        tag_object = tag_identity(args.source)
        actual = inventory(runs, args.source, work, source_tree, tag_object, args.source_dir)
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
