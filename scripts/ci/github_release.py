#!/usr/bin/env python3
"""GitHub-only, create-only release gate. Inventory is read-only; never auto-review it."""
import argparse
import hashlib
from datetime import datetime
from urllib.parse import quote, urlsplit, urlunsplit

from release_identity import remote_tag_identity, public_product_name
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

REPO = 'polaris-arch/sing-box-polaris'
RID = 1421657509
ROOT = Path(__file__).resolve().parents[2]
SCOPE = ROOT / 'release/ci/publisher-upstream-scope.json'
CONFIG = ROOT / 'release/ci/github-release.json'
VERSION = validate_version(json.loads(CONFIG.read_text())['version'])
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
    return json.loads(subprocess.check_output(args, input=json.dumps(payload).encode() if payload is not None else None))


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


def validate_final_index(index, source, tree, tag_object, run_id, attempt, workflow):
    # A staging index is useful evidence, but never a production publication input.
    require(index.get('schema') == 'polaris-upstream-native-assets-v1', 'final native index schema required; staging forbidden')
    import jsonschema
    jsonschema.Draft202012Validator(json.loads((ROOT / 'release/ci/native-release-index.schema.json').read_text())).validate(index)
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
    require(index['distributionMaterials'] == distribution_materials(index, ROOT), 'source/notice bindings differ from actual index or committed inputs')


def default_name(role, artifact, relative):
    if role == 'signed' and not artifact.startswith('signed-apple-store-'):
        return None
    p = PurePosixPath(relative)
    if artifact.startswith('libbox-android-') and p.name in ('libbox.aar', 'libbox-legacy.aar'):
        return p.stem + '-' + VERSION + '-android-' + artifact.removeprefix('libbox-android-') + '.aar'
    if artifact.startswith('libbox-apple-') and p.name.startswith('Libbox-'):
        return 'Libbox-' + VERSION + '-' + artifact.removeprefix('libbox-apple-') + '.tar'
    if role == 'docker' and artifact.startswith('oci-') and p.name == 'image.tar':
        return public_product_name('sing-box-' + VERSION + '-' + artifact + '.tar')
    if role == 'docker' and artifact.startswith('binary-'):
        return public_product_name('sing-box-' + VERSION + '-container-' + artifact.removeprefix('binary-'))
    # Provenance remains in the aggregate receipt; do not flatten repeated metadata.
    if p.name.startswith(('polaris-candidate-manifest-', 'native-row-')):
        return None
    if artifact.startswith(('binary-android-apks-', 'binary-windows-client-',
                            'binary-linux-client-', 'binary-apple-',
                            'unsigned-apple-', 'signed-apple-store-')):
        return branded_client_name(p.name)
    # build.yml and linux.yml intentionally deliver distinct distro package bytes.
    # Preserve both original outputs without a branding-induced basename collision.
    if role == 'all' and p.name.startswith('sing-box_') and p.suffix in ('.deb', '.rpm'):
        return public_product_name(p.stem) + '-build' + p.suffix
    return public_product_name(p.name)


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
    scope = json.loads(SCOPE.read_text())
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
                    sources = json.loads((ROOT / 'release/dependency-sources/clients/current-client-sources.json').read_text())['clients']
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
    reference = json.loads(reference_path.read_text())
    require(reference.get('schema') == 'polaris-android-material-reuse-v1', 'invalid Android material reference schema')
    material_map = directory / 'source-notice-map.json'
    require(sha(material_map) == reference.get('materialMapSHA256'), 'Android source/notice map changed')
    materials = json.loads(material_map.read_text())
    require(materials.get('concreteUnresolvedMaterials') == [], 'Android source/notice materials remain unresolved')
    identity_keys = ('repository', 'baseCommit', 'baseTree', 'overlayManifestSHA256', 'platform', 'unsigned')
    require(isinstance(client_source, dict) and all(key in client_source for key in identity_keys), 'missing Android client material identity')
    require({key: client_source[key] for key in identity_keys} == reference.get('clientSource'), 'Android client source material reference drift')
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
    return {'referenceSHA256': sha(reference_path), 'materialMapSHA256': sha(material_map),
            'configuration': configuration, 'actualArtifactCount': len(actual['artifacts']),
            'sourceMaterialsReusable': True, 'legalConclusion': False}


def validate_oci_material_reuse(path, artifact, source, run_id, attempt, root=ROOT):
    """Read OCI bytes, never execute an image; require exact reviewed source-material identities."""
    import io
    import tarfile
    reference_path = root / 'release/dependency-sources/oci/reuse-reference.json'
    reference = json.loads(reference_path.read_text())
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


def inventory(runs, source, work, source_tree, tag_object):
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
                    files[relative] = {'bytes': p.stat().st_size, 'sha256': sha(p), 'releaseName': default_name(role, a['name'], relative)}
                    if role == 'docker' and a['name'].startswith('oci-') and relative == 'image.tar':
                        files[relative]['ociMaterialReuse'] = validate_oci_material_reuse(p, a['name'], source, rid, run['run_attempt'])
                    if p.name.startswith('polaris-candidate-manifest-'):
                        require(not client_platform(a['name']) or p.stat().st_size <= 3 * 1024**2, 'client source evidence exceeds its 3MiB serialized budget')
                        provenance = json.loads(p.read_text())
                        require(provenance['sourceCommit'] == source and str(provenance['workflowRunId']) == rid and int(provenance['workflowAttempt']) == run['run_attempt'], 'candidate manifest source/run mismatch')
                        measured = validate_client_source(provenance, a['name'], role, source)
                        if measured is not None:
                            client_sources.append(measured)
                            # Retained in reviewed inventory and final public receipt,
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
        receipt = json.loads((work / role / 'publisher-run-receipt' / 'publisher-run-receipt.json').read_text())
        require(receipt == {'repository': REPO, 'repositoryId': RID, 'sourceCommit': source, 'runId': rid,
                            'attempt': run['run_attempt'], 'version': VERSION, 'build': 'All', 'role': role,
                            'publishStores': False, 'publishRegistry': False}, 'explicit All/version/run-attempt receipt mismatch')
        entry['artifacts']['publisher-run-receipt']['files']['publisher-run-receipt.json']['releaseName'] = None
        result['runs'][role] = entry
        if role in ('all', 'signed'):
            index = json.loads((work / role / 'binary-native-index' / 'polaris-upstream-native-assets.json').read_text())
            validate_final_index(index, source, source_tree, tag_object, rid, run['run_attempt'], scope[role]['workflow'])
            indexed_names = set()
            for record in [x['archive'] for x in index['platforms']] + [index['sourceArchive']]:
                require(record['name'] not in indexed_names, 'duplicate native index name')
                indexed_names.add(record['name'])
                matches = [f for a in entry['artifacts'].values() for name, f in a['files'].items() if name == record['name']]
                require(len(matches) == 1 and matches[0]['sha256'] == record['sha256'] and matches[0]['bytes'] == record['bytes'], 'native index actual hash mismatch')
    shared_index_path = work / 'all' / 'binary-native-index' / 'polaris-upstream-native-assets.json'
    return associate_distribution_materials(result, json.loads(shared_index_path.read_text()), sha(shared_index_path))


def assemble(actual, config, work, output):
    require(config.get('reviewed') is True, 'public release file scope is not reviewed')
    require(actual.get('distributionMaterials') == config.get('distributionMaterials'), 'reviewed shared materials differ')
    for field in ('repository', 'repositoryId', 'version', 'sourceCommit', 'sourceTree', 'tag', 'tagObject', 'scopeSha256'):
        require(actual[field] == config[field], 'release contract differs: ' + field)
    require(set(actual['runs']) == set(config['runs']), 'run scope differs')
    # Every artifact and every path must be reviewed. No globs or silent exclusions.
    output.mkdir(exist_ok=False)
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
                name = review['releaseName']
                if name is None:
                    require(artifact == 'publisher-run-receipt' or relative.startswith(('polaris-candidate-manifest-', 'native-row-')) or role == 'signed', 'payload omission forbidden')
                    continue
                require(len(portable(name).parts) == 1 and name.casefold() not in destinations, 'duplicate release filename')
                require(VERSION in name or name == 'polaris-upstream-native-assets.json' or name == 'sing-box-polaris-source-'+actual['sourceCommit']+'.tar.gz', 'public filename lacks exact Polaris version')
                require(name != RECEIPT, 'receipt name reserved')
                # Native index/source public names are immutable protocol names too.
                basename = PurePosixPath(relative).name
                if basename in ('polaris-upstream-native-assets.json', 'sing-box-polaris-source-'+actual['sourceCommit']+'.tar.gz'):
                    require(name == basename, 'native index/source rename forbidden')
                # Public names are the exact source-owned mapping, never arbitrary reviewed redirects.
                require(name == default_name(role, artifact, relative), 'public filename differs from source-owned mapping')
                destinations.add(name.casefold())
                shutil.copyfile(work / role / artifact / relative, output / name)
                receipt['assets'].append(dict(f, releaseName=name, role=role, artifact=artifact, artifactPath=relative,
                    signatureState='unverified-signed-build' if role == 'signed' else 'unsigned-candidate'))
    require(receipt['assets'], 'empty release')
    (output / RECEIPT).write_text(json.dumps(receipt, indent=2)+'\n')
    return receipt


def publish(output, source):
    before = tag_identity(source)
    index = json.loads((output / 'polaris-upstream-native-assets.json').read_text())
    require(index['schema'] == 'polaris-upstream-native-assets-v1' and index['tag'] == TAG
            and index['tagObject'] == before and index['sourceCommit'] == source, 'assembled final index no longer matches source tag')
    require(index['distributionMaterials']['publicationEligible'] is True, 'current source/notice review remains unresolved')
    # Listing includes drafts visible to the token; no 404-as-absence shortcut.
    require(not any(r['tag_name'] == TAG for r in pages(f'repos/{REPO}/releases')), 'existing Release (including draft) will never be changed')
    expected = {p.name: {'size': p.stat().st_size, 'digest': 'sha256:'+sha(p)} for p in output.iterdir() if p.is_file()}
    notes = 'GitHub-only unsigned build/package prerelease from '+source+'. Not a complete signed installable release.\n\nClients are sing-box-polaris derivatives of the fixed SagerNet upstream clients, not official SagerNet releases. Original authors and license texts are retained. Candidate paths and renamed public assets are mapped in the receipt.\n\n'+'\n'.join('- '+x for x in BLOCKED)+'\n\nSee '+RECEIPT+' for actual hashes, run IDs, scope and signature states.'
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


def reviewed_contract(run_id, digest, source):
    require(re.fullmatch(r'[1-9][0-9]*', run_id or ''), 'inventory run ID required')
    require(re.fullmatch(r'[0-9a-f]{64}', digest or ''), 'explicit reviewed inventory SHA-256 required')
    run = api(f'repos/{REPO}/actions/runs/{run_id}')
    require(run['repository']['id'] == RID and run['head_repository']['id'] == RID, 'foreign inventory run')
    require(run['path'] == '.github/workflows/publish-github.yml' and run['head_sha'] == os.environ['GITHUB_SHA'], 'inventory publisher revision mismatch')
    require(run['conclusion'] == 'success' and run['status'] == 'completed', 'inventory run failed')
    candidates = [a for a in pages(f'repos/{REPO}/actions/runs/{run_id}/artifacts', 'artifacts') if a['name'] == 'github-release-validation']
    require(len(candidates) == 1 and not candidates[0]['expired'], 'inventory artifact missing/ambiguous/expired')
    with tempfile.TemporaryDirectory() as temp:
        archive = Path(temp)/'inventory.zip'
        with archive.open('wb') as f:
            subprocess.run(['gh', 'api', f'repos/{REPO}/actions/artifacts/{candidates[0]["id"]}/zip'], stdout=f, check=True)
        require(candidates[0].get('digest') == 'sha256:'+sha(archive), 'inventory archive digest mismatch')
        extract(archive, Path(temp)/'extracted')
        proposal = Path(temp)/'extracted/release-inventory-proposal.json'
        require(sha(proposal) == digest, 'inventory differs from explicitly reviewed hash')
        contract = json.loads(proposal.read_text())
        require(contract['sourceCommit'] == source, 'inventory source mismatch')
        contract['reviewed'] = True
        return contract


def main():
    p = argparse.ArgumentParser()
    p.add_argument('mode', choices=['inventory', 'validate', 'publish'])
    p.add_argument('--source', required=True)
    p.add_argument('--source-dir', type=Path, default=Path('reviewed-source'))
    for role in ['all', 'linux', 'docker', 'signed']:
        p.add_argument('--'+role+'-run', required=role != 'signed')
    p.add_argument('--inventory-run')
    p.add_argument('--inventory-sha256')
    p.add_argument('--output', type=Path, default=Path('github-release-dist'))
    args = p.parse_args()
    public = json.loads(CONFIG.read_text())
    require(public == {'repository': REPO, 'repositoryId': RID, 'version': VERSION, 'tag': TAG, 'publication': 'github-only-unsigned-prerelease'}, 'public GitHub release configuration mismatch')
    identity(args.source, args.source_dir)
    runs = {role: getattr(args, role+'_run') for role in ['all', 'linux', 'docker', 'signed'] if getattr(args, role+'_run')}
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        source_tree = command('git', '-C', str(args.source_dir), 'rev-parse', 'HEAD^{tree}')
        tag_object = tag_identity(args.source)
        actual = inventory(runs, args.source, work, source_tree, tag_object)
        require(tag_identity(args.source) == tag_object, 'tag changed while collecting release inventory')
        if args.mode == 'inventory':
            require(not args.output.exists(), 'inventory output already exists')
            args.output.write_text(json.dumps(actual, indent=2)+'\n')
            print('Inventory SHA-256: '+sha(args.output))
            return
        tag_identity(args.source)
        assemble(actual, reviewed_contract(args.inventory_run, args.inventory_sha256, args.source), work, args.output)
        if args.mode == 'publish':
            require(os.environ.get('POLARIS_GITHUB_PUBLISH_ENABLED') == 'true', 'GitHub publication disabled')
            publish(args.output, args.source)


if __name__ == '__main__':
    main()
