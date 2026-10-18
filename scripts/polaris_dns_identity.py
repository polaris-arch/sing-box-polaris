"""Fixed DNS technical candidate identities; no App admission or publication."""
import hashlib
import json
from pathlib import Path
import subprocess

SOURCE = 'aafc521b745e0d1a8f50a6a3f41169433f1c2194'
TREE = '4ae424d8a99b16a02442d7b2eac1d5e24e938d8e'
# Go 1.25.5 stamps root versions using available tags. Fixed-source shallow CI
# has no semver ancestor tag; a full checkout has upstream alpha.11.
ROOT_MODULE_VERSIONS = (
    'v0.0.0-20261010200656-aafc521b745e',
    'v1.15.0-alpha.11.0.20261010200656-aafc521b745e',
)
SOURCE_TIME = '2026-10-10T20:06:56Z'
TARGETS = [('linux', 'amd64'), ('windows', 'amd64'), ('darwin', 'amd64'), ('darwin', 'arm64')]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def check_source(source, manifest):
    def git(*args):
        return subprocess.check_output(['git', '-C', str(source), *args], text=True).strip()
    if git('rev-parse', 'HEAD') != SOURCE or git('rev-parse', 'HEAD^{tree}') != TREE:
        raise ValueError('fixed DNS product source SHA/tree differs')
    if git('status', '--porcelain', '--untracked-files=all') or git('ls-files', '--others'):
        raise ValueError('source contains tracked, untracked or ignored changes')
    for path, digest in manifest['sourceFileSha256'].items():
        if sha((source / path).read_bytes()) != digest:
            raise ValueError('frozen source input differs: ' + path)


def source_identity(fingerprint, manifest):
    if (fingerprint['schema'], fingerprint['sourceCommit'], fingerprint['sourceTree'],
            fingerprint['sourceOverlay'], fingerprint['goVersion']) != (
            'fork-source-fingerprint-v1', SOURCE, TREE, 0, 'go1.25.5'):
        raise ValueError('actual collected source identity differs')
    if fingerprint['goModSha256'] != manifest['sourceFileSha256']['go.mod'] or fingerprint['goSumSha256'] != manifest['sourceFileSha256']['go.sum']:
        raise ValueError('actual Go source hashes differ')
    expected = dict(manifest['replacementBinding'], bindingSha256=manifest['sourceFileSha256']['release/dependency-sources/sing-tun-replacement.json'])
    if fingerprint['replacement'] != expected or fingerprint['replacementFilesVerified'] != 256:
        raise ValueError('actual exact replacement binding differs')
    if fingerprint['isolatedGoSettings'] != {'GOENV': 'off', 'GOWORK': 'off', 'GOFLAGS': '', 'GOTOOLCHAIN': 'local'}:
        raise ValueError('collector Go isolation differs')
    # Absolute module cache paths, native Go executable hash and evidence hashes
    # are measured separately. They cannot enter a shared four-platform identity.
    facts = {key: fingerprint[key] for key in ('sourceCommit', 'sourceTree', 'sourceOverlay', 'goVersion', 'goModSha256', 'goSumSha256', 'replacement')}
    return {'schema': 'polaris-dns-technical-source-v1', 'facts': facts,
            'fingerprint': sha(canonical(facts).encode())}


def platform_identity(identity, manifest, os_name, arch, tags):
    if (os_name, arch) not in TARGETS:
        raise ValueError('only the four consuming desktop targets are allowed')
    facts = {'sourceFingerprint': identity['fingerprint'], 'os': os_name, 'arch': arch,
             'CGO_ENABLED': '1' if os_name == 'darwin' else '0',
             'tags': sorted(tags.split(',')), 'version': manifest['candidateVersion'],
             'goVersion': manifest['Go'], 'sourceOverlay': 0}
    digest = sha(canonical(facts).encode())
    return {**facts, 'fingerprint': digest, 'buildID': 'polaris-dns-technical-v1-' + digest}


def validate_build_info(text, manifest, platform, actual_build_id, actual_version):
    if ': go1.25.5\n' not in text:
        raise ValueError('actual binary Go version differs')
    settings = {}; replacements = []; pending = None; module = None; dependency = None
    for line in text.splitlines()[1:]:
        parts = line.lstrip('\t').split('\t')
        if parts[0] in ('dep', 'mod') and len(parts) >= 3:
            pending = (parts[1], parts[2])
            if parts[0] == 'mod': module = pending
            if parts[1] == manifest['replacementBinding']['module']: dependency = pending
        elif parts[0] == '=>' and len(parts) >= 3:
            replacements.append((pending, parts[1], parts[2]))
        elif parts[0] == 'build' and len(parts) == 2 and '=' in parts[1]:
            key, value = parts[1].split('=', 1)
            if key in settings: raise ValueError('duplicate actual BuildInfo setting')
            settings[key] = value
    binding = manifest['replacementBinding']
    expected_dep = (binding['module'], binding['version'])
    if module is None or module[0] != 'github.com/sagernet/sing-box' or module[1] not in ROOT_MODULE_VERSIONS or dependency != expected_dep or replacements != [(expected_dep, binding['replacementPath'], '(devel)')]:
        raise ValueError('actual binary root/module replacement identity differs')
    expected = {'vcs': 'git', 'vcs.time': SOURCE_TIME, 'vcs.revision': SOURCE, 'vcs.modified': 'false', 'GOOS': platform['os'],
                'GOARCH': platform['arch'], 'CGO_ENABLED': platform['CGO_ENABLED'],
                '-trimpath': 'true', '-buildmode': 'exe', '-compiler': 'gc'}
    if any(settings.get(key) != value for key, value in expected.items()) or sorted(settings.get('-tags', '').split(',')) != platform['tags']:
        raise ValueError('actual binary VCS/build parameters differ')
    if actual_build_id.strip() != platform['buildID'] or actual_version.splitlines()[0] != 'sing-box version ' + manifest['candidateVersion']:
        raise ValueError('actual binary BuildID/version differs')
    return {'module': module[0], 'moduleVersion': module[1], 'dependency': list(expected_dep),
            'replacement': binding['replacementPath'], 'settings': settings,
            'buildInfoSha256': sha(text.encode()), 'validatedAgainstActualBinary': True}
