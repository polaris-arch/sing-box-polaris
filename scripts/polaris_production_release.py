#!/usr/bin/env python3
"""Build and assemble a fixed production-version candidate. No GitHub writes."""
import argparse
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
# Entry-point imports must not dirty the source being measured.
sys.dont_write_bytecode = True
import tarfile
from types import SimpleNamespace
import urllib.request

from polaris_go_environment import isolated_go_environment, verify_source
from polaris_native_candidate import build_native, digest, run
from polaris_native_distribution import read_archive, write_archive, file_info, encode, check_bytes
from polaris_native_matrix import TARGETS
from polaris_source_fingerprint import collect, MODULE, VERSION, REPLACEMENT
from polaris_dns_identity import canonical

CONFIG = 'release/polaris-production-release.json'
UPSTREAM_DELTA = {'.github/workflows/build.yml', 'docs/changelog.md'}
CHANGES = {'.github/workflows/polaris-production-native.yml',
           '.github/workflows/polaris-native-candidate.yml', '.github/workflows/polaris-dns-native-candidate.yml',
           'scripts/polaris_ci_impact.py', 'scripts/test_polaris_ci_impact.py',
           'scripts/polaris_ci_downloads.py', 'scripts/test_polaris_ci_downloads.py',
           'scripts/polaris_ci_observe.py', 'scripts/test_polaris_ci_observe.py',
           'scripts/polaris_runner_resources.py', 'scripts/test_polaris_runner_resources.py',
           '.github/workflows/polaris-selfcheck.yml', 'release/POLARIS_ASSETS.md',
           'release/polaris-fork-maintenance.json', 'release/POLARIS_FORK_MAINTENANCE.md',
           'scripts/polaris_fork_maintenance.py', 'scripts/test_polaris_fork_maintenance.py', CONFIG, 'release/POLARIS_PRODUCTION_RELEASE.md',
           '.github/workflows/polaris-production-release.yml',
           'scripts/polaris_native_candidate.py', 'scripts/polaris_production_release.py',
           'scripts/test_polaris_production_release.py',
           'scripts/polaris_production_publish.py', 'scripts/test_polaris_production_publish.py',
           'third_party/sing-tun/internal/winipcfg/winipcfg_test.go',
           'release/dependency-sources/sing-tun-test-printf.patch',
           'release/dependency-sources/sing-tun-replacement.json',
           'scripts/polaris_source_fingerprint.py',
           'release/polaris-openwrt-inputs.json',
           'release/polaris-public-source-inputs.json',
           'release/POLARIS_OPENWRT.md',
           'release/POLARIS_RELEASE_NOTES.md',
           'release/licenses/GCC-RUNTIME-LIBRARY-EXCEPTION-3.1.txt',
           'release/licenses/MUSL-COPYRIGHT.txt',
           'scripts/polaris_openwrt.py',
           'scripts/polaris_openwrt_guest.py',
           'scripts/polaris_naive_loopback.py',
           'scripts/polaris_public_sources.py',
           'scripts/test_polaris_openwrt.py',
           'scripts/test_polaris_public_sources.py',
           'release/openwrt/config.json',
           'release/openwrt/sing-box.uci',
           'release/openwrt/sing-box.init',
           'release/openwrt/preinst',
           'release/openwrt/postinst',
           'release/openwrt/prerm',
           'release/openwrt/postrm',
           }


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def plan(repo):
    config = json.loads((repo / CONFIG).read_bytes())
    require(config['repository'] == 'polaris-arch/polaris-box', 'wrong repository')
    require(config['version'] == '1.15.0-alpha.12'
            and config['tag'] == 'v' + config['version'], 'frozen latest-release Polaris version required')
    require(config['upstreamTag'] == 'v1.15.0-alpha.12'
            and config['upstreamCommit'] == '25b0d5ea3e466d246c708ac0f20d0448110e566c', 'upstream migration forbidden')
    require(config['assetPrefix'] == 'polaris-box' and config['prerelease'] is True, 'wrong product identity')
    expected = {x['os'] + '/' + x['arch'] for x in TARGETS}
    require(len(config['desktop']) == 6 and {x['target'] for x in config['desktop']} == expected,
            'exact six native desktop targets required')
    for row in config['desktop']:
        win = row['target'].startswith('windows/')
        mac = row['target'].startswith('darwin/')
        require(row['suffix'] == ('.zip' if win else '.tar.gz'), 'wrong archive format')
        require(row['executable'] == ('sing-box.exe' if win else 'sing-box'), 'internal executable changed')
        require(row['sidecar'] == (None if mac else 'libcronet.dll' if win else 'libcronet.so'), 'wrong library layout')
        require(row['cronetLinkage'] == ('static-cgo' if mac else 'shared-purego'), 'wrong linkage')
    require(digest(repo / config['inputPinsPath']) == config['inputPinsSha256'], 'immutable library/toolchain inputs drift')
    require(digest(repo / 'release/desktop-source-candidate/DESKTOP-SOURCE-NOTICE-INDEX-controlled.json')
            == config['noticeIndexSha256'], 'notice index drift')
    require(digest(repo / 'release/desktop-source-candidate/DESKTOP-SOURCE-NOTICE-SUPERSET.txt')
            == config['noticeSha256'], 'notice bytes drift')
    for key in ['publicSourceInputs', 'openwrtInputs']:
        require(digest(repo / config[key]['path']) == config[key]['sha256'], 'source-owned input map drift: ' + key)
    return config


def frozen_source(repo, expected):
    require(re.fullmatch('[0-9a-f]{40}', expected) is not None, 'full source SHA required')
    verify_source(repo, expected)
    config = plan(repo)
    run(['git', 'merge-base', '--is-ancestor', config['sourceBaseCommit'], expected], repo)
    run(['git', 'merge-base', '--is-ancestor', config['upstreamCommit'], expected], repo)
    changed = set(run(['git', 'diff', '--name-only', config['sourceBaseCommit'], expected], repo).splitlines())
    require(changed <= CHANGES | UPSTREAM_DELTA, 'changes outside release batch: ' + repr(sorted(changed - CHANGES - UPSTREAM_DELTA)))
    for name in UPSTREAM_DELTA:
        require(run(['git', 'rev-parse', expected + ':' + name], repo)
                == run(['git', 'rev-parse', config['upstreamCommit'] + ':' + name], repo), 'latest upstream blob differs: ' + name)
    require(not run(['git', 'ls-files', '--others'], repo), 'extra source files, including ignored inputs')
    return config, run(['git', 'rev-parse', 'HEAD^{tree}'], repo).strip()


def target(config, key):
    rows = [row for row in config['desktop'] if row['target'] == key]
    require(len(rows) == 1, 'unknown target')
    return rows[0]


def basename(config, key):
    return 'polaris-box-' + config['version'] + '-' + key.replace('/', '-')


def portable_source_identity(fingerprint):
    # Same stable fact projection and canonical hashing as the existing DNS/App
    # contract. Keep the original collector schema and host observations intact.
    require(fingerprint['schema'] == 'fork-source-fingerprint-v1', 'collector schema differs')
    facts = {key: fingerprint[key] for key in ('sourceCommit', 'sourceTree', 'sourceOverlay',
        'goVersion', 'goModSha256', 'goSumSha256', 'replacement')}
    return {'schema': 'polaris-production-source-v1', 'facts': facts,
            'fingerprint': sha(canonical(facts).encode())}


def verify_fingerprint(repo, fingerprint, expected, tree):
    binding_path = repo / 'release/dependency-sources/sing-tun-replacement.json'
    binding = {**json.loads(binding_path.read_bytes()), 'bindingSha256': digest(binding_path)}
    facts = {'sourceCommit': expected, 'sourceTree': tree, 'sourceOverlay': 0, 'goVersion': 'go1.25.5',
             'goModSha256': digest(repo / 'go.mod'), 'goSumSha256': digest(repo / 'go.sum'), 'replacement': binding}
    require(portable_source_identity(fingerprint)['facts'] == facts
            and fingerprint['replacementFilesVerified'] == 256
            and fingerprint['isolatedGoSettings'] == {'GOENV': 'off', 'GOWORK': 'off', 'GOFLAGS': '', 'GOTOOLCHAIN': 'local'},
            'actual source fingerprint facts differ')


def platform_identity(fingerprint, key, version, tags, tag):
    identity = portable_source_identity(fingerprint)
    os_name, arch = key.split('/')
    facts = {'sourceFingerprint': identity['fingerprint'], 'os': os_name, 'arch': arch,
             'CGO_ENABLED': '1' if os_name == 'darwin' else '0', 'tags': sorted(tags.split(',')),
             'version': version, 'tag': tag, 'goVersion': fingerprint['goVersion'], 'sourceOverlay': 0}
    value = sha(canonical(facts).encode())
    return {'schema': 'polaris-production-platform-v1', 'facts': facts,
            'fingerprint': value, 'buildID': 'polaris-production-v1-' + value}


def provider_identity(repo, fingerprint):
    files = ['scripts/polaris_production_release.py', 'scripts/polaris_native_candidate.py',
             'scripts/polaris_source_fingerprint.py', 'scripts/polaris_dns_identity.py',
             'scripts/polaris_go_environment.py', 'scripts/polaris_native_distribution.py',
             'release/polaris-production-release.json', 'release/polaris-candidate-inputs.json']
    facts = {'providerContract': 'polaris-box-release-v1', 'sourceCommit': fingerprint['sourceCommit'],
             'fileSha256': {name: digest(repo / name) for name in files}}
    return {'schema': 'polaris-production-provider-v1', 'facts': facts,
            'fingerprint': sha(canonical(facts).encode())}


def build_identity(fingerprint, key, version, tags, tag):
    return platform_identity(fingerprint, key, version, tags, tag)['buildID']


def production_notice(repo, config, fingerprint, key):
    pins = json.loads((repo / config['inputPinsPath']).read_bytes())
    library = next(row for row in pins['libraries'] if row['target'] == key.replace('/', '_'))
    return (f"Polaris-box {config['version']} / planned tag {config['tag']} / target {key}\n"
        f"Product source: https://github.com/{config['repository']}/tree/{fingerprint['sourceCommit']}\n"
        f"Product tree: {fingerprint['sourceTree']}; sourceOverlay: 0\n"
        "sing-box: GPL-3.0-or-later. Root LICENSE, SING-BOX-COPYING and GPL-3.0.txt accompany this archive.\n"
        "Go dependency versions/checksums: actual product source go.mod/go.sum; exact local sing-tun source is included.\n"
        "Corresponding source: automatic GitHub Source code archives plus fixed public sourceDelivery in polaris-box-assets.json\n"
        f"Cronet Go wrapper: GPL-3.0-or-later; https://github.com/SagerNet/cronet-go/tree/{pins['wrapperCommit']}\n"
        f"Cronet version: {pins['cronetVersion']}; library module: {library['module']}@{library['moduleVersion']}\n"
        f"Library origin: {library['moduleOrigin']}; library SHA256: {library['sha256']}\n"
        "Pinned library licenses/source inputs and the retained notice superset accompany this product.\n"
        "Corresponding-source/notice applicability and compiler runtime approvals are recorded in the release index.\n"
        "Native CLI diagnostics do not prove App/mobile/final carrier or device acceptance.\n").encode()


def validate_build_command(repo, config, receipt, key, build_id):
    preset = 'DEFAULT_BUILD_TAGS_WINDOWS' if key.startswith('windows/') else 'DEFAULT_BUILD_TAGS'
    tags = (repo / 'release' / preset).read_text().strip()
    if key.startswith('linux/'):
        tags += ',with_purego'
    flags = ((repo / 'release/LDFLAGS').read_text().strip()
             + ' -s -w -X github.com/sagernet/sing-box/constant.Version=' + config['version']
             + ' -buildid=' + build_id)
    command = receipt.get('buildCommand')
    require(isinstance(command, list) and len(command) == 14 and isinstance(command[12], str),
            'actual build command shape differs')
    expected = ['go', 'build', '-buildvcs=true', '-mod=readonly', '-p', '1', '-trimpath',
                '-tags', tags, '-ldflags', flags, '-o', command[12], './cmd/sing-box']
    suffix = '/' + basename(config, key) + '/' + target(config, key)['executable']
    require(command == expected and command[12].replace('\\', '/').endswith(suffix)
            and receipt.get('tags') == tags and receipt.get('ldflags') == flags,
            'actual build command/ldflags differ from frozen source inputs')


def build_settings(text, expected, key, expected_cgo=None):
    require(text.splitlines()[0].endswith('go1.25.5'), 'actual binary Go version differs')
    settings = {}
    for line in text.splitlines():
        parts = line.split('\t')
        if len(parts) >= 3 and parts[1] == 'build':
            name, value = parts[2].split('=', 1)
            settings[name] = value
    os_name, arch = key.split('/')
    require(settings.get('vcs.revision') == expected and settings.get('vcs.modified') == 'false', 'actual binary VCS identity differs')
    require(settings.get('GOOS') == os_name and settings.get('GOARCH') == arch, 'actual binary target differs')
    require(settings.get('CGO_ENABLED') == (expected_cgo if expected_cgo is not None else ('1' if os_name == 'darwin' else '0')), 'actual CGO differs')
    # Go 1.25.5 deliberately omits -ldflags under -trimpath (go.dev/issue/52372).
    # Native and assembly independently read the actual binary using go tool buildid.
    require(settings.get('-trimpath') == 'true' and '-ldflags' not in settings,
            'actual binary trimpath BuildInfo differs')
    return settings


def build_info(text, expected, key, expected_cgo=None):
    settings = build_settings(text, expected, key, expected_cgo)
    deps, replacements = [], []
    for line in text.splitlines():
        parts = line.split('\t')
        if len(parts) >= 4 and parts[1] == 'dep':
            deps.append({'module': parts[2], 'version': parts[3], 'h1': parts[4] if len(parts) >= 5 else ''})
        elif len(parts) >= 4 and parts[1] == '=>':
            require(deps and deps[-1]['module'] == MODULE and deps[-1]['version'] == VERSION
                    and parts[2:4] == [REPLACEMENT, '(devel)'], 'unexpected binary module replacement')
            replacements.append(deps.pop())
    require(len(replacements) == 1 and deps and all(re.fullmatch(r'h1:[A-Za-z0-9+/]+=', d['h1']) for d in deps),
            'actual complete module/replacement graph required')
    acquisition = [d for d in deps if d['module'].startswith('github.com/sagernet/cronet-go/lib/')]
    return {'settings': settings, 'normalModules': [d for d in deps if d not in acquisition],
            'prebuiltAcquisitionModules': acquisition, 'localReplacement': replacements[0]}


def validate_smoke(actual, expected, library=None):
    require({k: v for k, v in actual.items() if k != 'library'}
            == {k: v for k, v in expected.items() if k != 'library'}, 'final packaged native smoke differs')
    if library is None:
        require(not actual.get('library'), 'static smoke contains a sidecar')
    else:
        require(Path(actual.get('library', '')).resolve() == library.resolve(), 'actual load path differs')


def native_header(data, key):
    os_name, arch = key.split('/')
    if os_name == 'linux':
        require(len(data) >= 20 and data[:6] == b'\x7fELF\x02\x01'
                and struct.unpack_from('<H', data, 18)[0] == {'amd64': 62, 'arm64': 183}[arch], 'wrong ELF target')
    elif os_name == 'darwin':
        require(len(data) >= 32 and data[:4] == b'\xcf\xfa\xed\xfe'
                and struct.unpack_from('<I', data, 4)[0] == {'amd64': 0x1000007, 'arm64': 0x100000c}[arch], 'wrong Mach-O target')
    else:
        require(len(data) >= 64 and data[:2] == b'MZ', 'wrong PE target')
        offset = struct.unpack_from('<I', data, 60)[0]
        require(offset + 6 <= len(data) and data[offset:offset + 4] == b'PE\0\0'
                and struct.unpack_from('<H', data, offset + 4)[0] == {'amd64': 0x8664, 'arm64': 0xaa64}[arch], 'wrong PE target')


def material(repo, config):
    index_raw = (repo / 'release/desktop-source-candidate/DESKTOP-SOURCE-NOTICE-INDEX-controlled.json').read_bytes()
    require(sha(index_raw) == config['noticeIndexSha256'], 'notice index drift')
    index = json.loads(index_raw)
    notice = (repo / 'release/desktop-source-candidate/DESKTOP-SOURCE-NOTICE-SUPERSET.txt').read_bytes()
    require(sha(notice) == config['noticeSha256'], 'notice drift')
    for row in index['noticeRecords']:
        check_bytes(notice[row['byteOffset']:row['byteOffset'] + row['bytes']], row, 'notice slice')
    return index, notice


def repackage(repo, config, key, receipt, fingerprint, graph, version_output, output):
    row = target(config, key)
    root = basename(config, key)
    archive = Path(receipt['archivePath'])
    original = read_archive(archive, receipt['archive'])
    require({name.split('/')[0] for name in original} == {root}, 'archive root/version differs; renaming is forbidden')
    require(version_output.splitlines()[0] == 'sing-box version ' + config['version'], 'actual kernel version differs')
    require(receipt['sourceCommit'] == fingerprint['sourceCommit']
            and receipt['sourceTree'] == fingerprint['sourceTree'], 'build source differs')
    core = root + '/' + row['executable']
    require(core in original and receipt['payloadHashes'][row['executable']] == sha(original[core][0]), 'core bytes differ')
    if row['sidecar']:
        require(root + '/' + row['sidecar'] in original, 'required Cronet sidecar absent')
        require(sha(original[root + '/' + row['sidecar']][0]) == receipt['cronet']['sha256'], 'Cronet bytes differ')
    else:
        require(not any(name.endswith(('.so', '.dll', '.dylib')) for name in original), 'static target has dynamic sidecar')
    require('with_gvisor' in receipt['tags'].split(',') and 'with_naive_outbound' in receipt['tags'].split(','), 'required capabilities absent')
    preset = (repo / 'release' / ('DEFAULT_BUILD_TAGS_WINDOWS' if key.startswith('windows/') else 'DEFAULT_BUILD_TAGS')).read_text().strip()
    expected_tags = set(preset.split(',')) | ({'with_purego'} if key.startswith('linux/') else set())
    require(set(receipt['tags'].split(',')) == expected_tags
            and set(graph['settings'].get('-tags', '').strip('"').split(',')) == expected_tags, 'actual full feature preset differs')
    smoke = receipt['extractedNativeCronetSmoke']
    require((smoke['os'], smoke['arch'], smoke['version'], smoke['gvisorCompiled'])
            == (*key.split('/'), config_version_cronet(config, repo), True), 'actual unpacked capability differs')
    require(smoke['linkage'] == receipt['nativeCronetSmoke']['linkage'], 'unpacked linkage differs')
    index, notice = material(repo, config)
    covered = {(d['module'], d['version'], d['h1']) for d in index['modules']}
    require(all((d['module'], d['version'], d['h1']) in covered
                for d in [*graph['normalModules'], *graph['prebuiltAcquisitionModules']]), 'new module needs source/notice review')
    pins = json.loads((repo / config['inputPinsPath']).read_bytes())
    allowed_libraries = {(d['module'], d['moduleVersion'], d['moduleSum']) for d in pins['libraries']}
    require(all((d['module'], d['version'], d['h1']) in allowed_libraries
                for d in graph['prebuiltAcquisitionModules']), 'unapproved acquisition module')
    members = dict(original)
    members[root + '/LICENSE'] = ((repo / 'LICENSE').read_bytes(), 0o644)
    current_notice = production_notice(repo, config, fingerprint, key)
    members[root + '/NOTICE'] = (current_notice, 0o644)
    members[root + '/licenses/NOTICE'] = (current_notice, 0o644)
    members[root + '/licenses/DESKTOP-SOURCE-NOTICE-SUPERSET.txt'] = (notice, 0o644)
    source_record = {'schema': 'polaris-production-source-reference-v1', 'version': config['version'],
                     'sourceCommit': fingerprint['sourceCommit'], 'sourceTree': fingerprint['sourceTree'],
                     'sourceFingerprint': fingerprint, 'normalModules': graph['normalModules'],
                     'prebuiltAcquisitionModules': graph['prebuiltAcquisitionModules'],
                     'sourceDelivery': 'fixed public references in polaris-box-assets.json plus automatic GitHub Source code archives',
                     'closureReview': 'pending-independent-applicability-and-compiler-runtime-review'}
    members[root + '/source/SOURCE-INDEX.json'] = (encode(source_record), 0o644)
    portable = portable_source_identity(fingerprint)
    platform = platform_identity(fingerprint, key, config['version'], receipt['tags'], config['tag'])
    provider = provider_identity(repo, fingerprint)
    provenance = {**receipt, 'schema': 'polaris-production-native-receipt-v1', 'version': config['version'],
                  'tag': config['tag'], 'target': key, 'sourceFingerprint': fingerprint,
                  'buildID': build_identity(fingerprint, key, config['version'], receipt['tags'], config['tag']),
                  'portableSourceIdentity': portable, 'portablePlatformIdentity': platform,
                  'sourceIdentityFingerprint': portable['fingerprint'], 'platformInputFingerprint': platform['fingerprint'],
                  'providerContract': provider['facts']['providerContract'], 'providerFingerprint': provider['fingerprint'],
                  'providerIdentity': provider,
                  'noticeIdentity': {'sourceCommit': fingerprint['sourceCommit'], 'sourceTree': fingerprint['sourceTree'],
                                    'version': config['version'], 'tag': config['tag'], 'target': key, 'sha256': sha(current_notice)},
                  'buildGraph': graph, 'actualVersionOutput': version_output, 'candidateOnly': True,
                  'publicationEligible': False, 'publicUploadPerformed': False,
                  'signatureObservation': {'core': {k: v for k, v in receipt['coreNative'].items()
                      if any(word in k.lower() for word in ('format', 'signature', 'certificate', 'authenticode'))},
                      'cronet': {k: v for k, v in receipt['cronetNative'].items()
                      if any(word in k.lower() for word in ('format', 'signature', 'certificate', 'authenticode'))},
                      'trustValidated': False},
                  'signaturePolicy': 'preserve measured original bytes; ad-hoc/not-signed observations do not assert trust',
                  'consumerAcceptance': 'pending'}
    provenance.pop('archivePath', None)
    members[root + '/provenance.json'] = (encode(provenance), 0o644)
    members.pop(root + '/SHA256SUMS', None)
    members[root + '/SHA256SUMS'] = (''.join(f'{sha(data)}  {name[len(root)+1:]}\n'
        for name, (data, mode) in sorted(members.items())).encode(), 0o644)
    final = output / (root + row['suffix'])
    write_archive(final, members)
    record = {**file_info(final), 'members': {name: sha(data) for name, (data, mode) in members.items()}}
    require(read_archive(final, record) == members, 'final archive roundtrip differs')
    require(members[core] == original[core], 'packaging changed binary bytes or mode')
    return {**provenance, 'archive': record, 'core': {'member': row['executable'], 'bytes': len(members[core][0]),
            'sha256': sha(members[core][0])}, 'sidecar': None if not row['sidecar'] else
            {'member': row['sidecar'], 'bytes': len(members[root + '/' + row['sidecar']][0]),
             'sha256': sha(members[root + '/' + row['sidecar']][0])}}


def config_version_cronet(config, repo):
    return json.loads((repo / config['inputPinsPath']).read_bytes())['cronetVersion']


def native(repo, source, expected, key, output):
    config, tree = frozen_source(source, expected)
    verify_source(repo, expected)
    require((source / '.git').is_dir(), 'Go1.25.5 requires a standalone checkout for VCS stamping')
    require(not output.exists() and not output.resolve().is_relative_to(source.resolve()), 'fresh external output required')
    output.mkdir(parents=True)
    os_name, arch = key.split('/')
    target(config, key)
    # Process-local isolation only; no global go env/config updates.
    os.environ.update(isolated_go_environment())
    os.environ.update(GOMAXPROCS='2', GOEXPERIMENT='', GOAMD64='v1', GOARM64='v8.0',
                      GOOS=os_name, GOARCH=arch, CGO_ENABLED='1' if os_name == 'darwin' else '0')
    for name in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'CGO_CFLAGS', 'CGO_CPPFLAGS', 'CGO_CXXFLAGS', 'CGO_FFLAGS', 'CGO_LDFLAGS'):
        os.environ.pop(name, None)
    go = Path(shutil.which('go')).resolve()
    fp = collect(source, expected, go, output / 'module-list.json')
    build_tags = (source / 'release' / ('DEFAULT_BUILD_TAGS_WINDOWS' if os_name == 'windows' else 'DEFAULT_BUILD_TAGS')).read_text().strip()
    if os_name == 'linux':
        build_tags += ',with_purego'
    build_id = build_identity(fp, key, config['version'], build_tags, config['tag'])
    if os_name == 'windows':
        # Compile/vet the entire replacement and run its seven platform tests
        # before the expensive core build. Keep Go test's default vet enabled.
        log = output / 'windows-replacement-regressions.log'
        try:
            log.write_text(run([go, 'test', '-mod=readonly', '-p', '1', '-parallel', '2',
                '-count=1', '-v', '-tags', build_tags, '-ldflags',
                (source / 'release/LDFLAGS').read_text().strip(),
                '-run', '^TestWindows(DNS|Lifecycle)', './...'],
                source / 'third_party/sing-tun', dict(os.environ)))
        except RuntimeError as error:
            log.write_text(str(error) + '\n')
            raise
    manifest = copy.deepcopy(json.loads((repo / config['inputPinsPath']).read_bytes()))
    manifest.update(sourceCommit=expected, sourceTree=tree, candidateVersion=config['version'],
                    upstreamBaselineCommit=config['upstreamCommit'], upstreamBaselineTag=config['upstreamTag'],
                    sourceRole='production-desktop', buildVCS=True, buildID=build_id)
    technical = output / 'technical'
    receipt = build_native(SimpleNamespace(source=source, output=technical, os=os_name, arch=arch), repo, manifest)
    binary = technical / basename(config, key) / target(config, key)['executable']
    actual_version = run([binary, 'version'], source)
    require(run([go, 'tool', 'buildid', binary], source).strip() == build_id, 'actual BuildID differs')
    validate_build_command(source, config, receipt, key, build_id)
    graph = build_info(receipt['buildInfo'], expected, key)
    tags = receipt['tags']
    regression_env = dict(os.environ)
    if os_name == 'darwin':
        compiler = receipt['compiler']
        regression_env.update(CC=run(['xcrun', '--sdk', 'macosx', '--find', 'clang']).strip(),
                              SDKROOT=compiler['SDKROOT'], CGO_CFLAGS=compiler['cgoCflags'],
                              CGO_LDFLAGS=compiler['cgoLdflags'])
    regression = run([go, 'test', '-mod=readonly', '-p', '1', '-parallel', '2', '-count=1', '-v',
                      '-tags', tags, '-ldflags', (source / 'release/LDFLAGS').read_text().strip(),
                      './common/dialer', './dns', './option', './dns/transport/local/systemconfig'], source, regression_env)
    (output / 'dns-regressions.log').write_text(regression)
    receipt['archivePath'] = str(technical / receipt['archive']['name'])
    final_output = output / 'final'
    final_output.mkdir()
    final = repackage(repo, config, key, receipt, fp, graph, actual_version, final_output)
    final['buildID'] = build_id
    # Reload the final packaged bytes, rather than borrowing the technical archive's proof.
    members = read_archive(final_output / final['archive']['name'], final['archive'])
    import tempfile
    with tempfile.TemporaryDirectory(prefix='polaris-production-reload-') as directory:
        root = Path(directory)
        for name, (data, mode) in members.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(mode)
        row = target(config, key)
        core = root / basename(config, key) / row['executable']
        diagnostics = dict(os.environ)
        for name in ('LD_LIBRARY_PATH', 'LD_PRELOAD', 'DYLD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES'):
            diagnostics.pop(name, None)
        if os_name == 'windows':
            diagnostics['PATH'] = str(Path(os.environ['SystemRoot']) / 'System32')
        require(run([core, 'version'], source, diagnostics) == actual_version, 'final unpacked core version differs')
        args = [core, 'tools', 'cronet', '--expected-version', manifest['cronetVersion']]
        if row['sidecar']:
            args += ['--library', root / basename(config, key) / row['sidecar'], '--sha256', final['sidecar']['sha256']]
        final['finalPackageCronetSmoke'] = json.loads(run(args, source, diagnostics))
        validate_smoke(final['finalPackageCronetSmoke'], receipt['nativeCronetSmoke'],
                       root / basename(config, key) / row['sidecar'] if row['sidecar'] else None)
    final['buildID'] = build_id
    verify_source(source, expected)
    (final_output / 'production-receipt.json').write_bytes(encode(final))
    return {'target': key, 'archive': final['archive']['name'], 'publicationEligible': False}


def assemble(repo, expected, inputs, openwrt_inputs, guest_inputs, output):
    config, tree = frozen_source(repo, expected)
    require(not output.exists(), 'fresh assembly output required')
    receipt_paths = sorted(inputs.glob('*/final/production-receipt.json'))
    require(all(path.is_file() and not path.is_symlink() for path in receipt_paths), 'regular final receipts required')
    receipts = [json.loads(path.read_bytes()) for path in receipt_paths]
    keys = {x['target'] for x in receipts}
    require(len(receipts) == 6 and keys == {x['target'] for x in config['desktop']}, 'same-run six-target receipts required')
    run_id, attempt = os.environ.get('GITHUB_RUN_ID'), os.environ.get('GITHUB_RUN_ATTEMPT')
    require(run_id and attempt, 'assembly must bind actual workflow run/attempt')
    output.mkdir(parents=True)
    index = {'schema': 'polaris-production-assets-v1', 'repository': config['repository'],
             'version': config['version'], 'tag': config['tag'], 'tagObject': None,
             'sourceCommit': expected, 'sourceTree': tree, 'workflowRun': run_id, 'workflowAttempt': attempt,
             'publicationEligible': False, 'publicUploadPerformed': False,
             'gates': {'independentSourceReview': 'pending', 'licenseSourceReview': 'pending',
                       'AppOwnerSignoff': 'pending', 'actualPublicDownloadConsumerAcceptance': 'pending'}, 'platforms': []}
    normal, acquisition = set(), set()
    for receipt_path, row in sorted(zip(receipt_paths, receipts), key=lambda x: x[1]['target']):
        require(row['schema'] == 'polaris-production-native-receipt-v1' and row['version'] == config['version']
                and row['sourceCommit'] == expected and row['sourceTree'] == tree
                and row['workflowCommit'] == expected and str(row['workflowRun']) == run_id
                and str(row['workflowAttempt']) == attempt, 'mixed source/run/attempt/version receipt')
        verify_fingerprint(repo, row['sourceFingerprint'], expected, tree)
        spec = target(config, row['target'])
        root = basename(config, row['target'])
        require(row['archive']['name'] == root + spec['suffix'], 'actual archive name differs')
        archive = receipt_path.parent / (root + spec['suffix'])
        require(archive.is_file() and not archive.is_symlink(), 'regular controlled final archive required')
        require({path.name for path in receipt_path.parent.iterdir()} == {archive.name, receipt_path.name},
                'final directory must contain exactly the archive and receipt')
        members = read_archive(archive, row['archive'])
        provenance = json.loads(members[root + '/provenance.json'][0])
        for name in ('sourceCommit', 'sourceTree', 'version', 'tag', 'target', 'workflowCommit',
                     'workflowRun', 'workflowAttempt', 'sourceFingerprint', 'buildGraph', 'buildID', 'signatureObservation',
                     'tags', 'ldflags', 'buildCommand',
                     'portableSourceIdentity', 'portablePlatformIdentity', 'noticeIdentity',
                     'sourceIdentityFingerprint', 'platformInputFingerprint', 'providerContract', 'providerFingerprint', 'providerIdentity'):
            require(provenance[name] == row[name], 'inner provenance and aggregate receipt differ: ' + name)
        require(row['buildID'] == build_identity(row['sourceFingerprint'], row['target'], config['version'], row['tags'], config['tag']),
                'source-derived BuildID differs')
        validate_build_command(repo, config, row, row['target'], row['buildID'])
        require(row['archive']['name'] == root + spec['suffix'], 'actual archive name differs')
        core = members[root + '/' + spec['executable']][0]
        require(sha(core) == row['core']['sha256'] and len(core) == row['core']['bytes'], 'actual core pin differs')
        native_header(core, row['target'])
        import tempfile
        with tempfile.TemporaryDirectory(prefix='polaris-production-static-identity-') as directory:
            path = Path(directory) / spec['executable']
            path.write_bytes(core)
            graph = build_info(run(['go', 'version', '-m', path]), expected, row['target'])
            preset = (repo / 'release' / ('DEFAULT_BUILD_TAGS_WINDOWS' if row['target'].startswith('windows/') else 'DEFAULT_BUILD_TAGS')).read_text().strip()
            tags = set(preset.split(',')) | ({'with_purego'} if row['target'].startswith('linux/') else set())
            require(set(row['tags'].split(',')) == tags
                    and set(graph['settings'].get('-tags', '').strip('"').split(',')) == tags, 'actual packaged full preset differs')
            require(graph == row['buildGraph'] and run(['go', 'tool', 'buildid', path]).strip() == row['buildID'],
                    'actual packaged Go graph/BuildID differs')
        if spec['sidecar']:
            sidecar = members[root + '/' + spec['sidecar']][0]
            require(row['sidecar']['member'] == spec['sidecar'] and sha(sidecar) == row['sidecar']['sha256']
                    and len(sidecar) == row['sidecar']['bytes'] and sha(sidecar) == row['cronet']['sha256'], 'actual sidecar pin differs')
            native_header(sidecar, row['target'])
        require(members[root + '/LICENSE'][0] == (repo / 'LICENSE').read_bytes(), 'root LICENSE differs')
        notice = production_notice(repo, config, row['sourceFingerprint'], row['target'])
        require(members[root + '/NOTICE'][0] == notice and members[root + '/licenses/NOTICE'][0] == notice
                and row['noticeIdentity']['sha256'] == sha(notice), 'actual product NOTICE differs')
        require(row['portableSourceIdentity'] == portable_source_identity(row['sourceFingerprint'])
                and row['portablePlatformIdentity'] == platform_identity(row['sourceFingerprint'], row['target'],
                    config['version'], row['tags'], config['tag']), 'portable source/platform facts differ')
        provider = provider_identity(repo, row['sourceFingerprint'])
        require(row['providerIdentity'] == provider and row['providerFingerprint'] == provider['fingerprint']
                and row['providerContract'] == provider['facts']['providerContract']
                and row['sourceIdentityFingerprint'] == row['portableSourceIdentity']['fingerprint']
                and row['platformInputFingerprint'] == row['portablePlatformIdentity']['fingerprint'], 'provider/normalized identity differs')
        shutil.copyfile(archive, output / archive.name)
        target(config, row['target'])
        actual_smoke = row.get('finalPackageCronetSmoke', {})
        validate_smoke(actual_smoke, row['nativeCronetSmoke'],
                       Path(actual_smoke['library']) if target(config, row['target'])['sidecar'] else None)
        normal.update((d['module'], d['version'], d['h1']) for d in row['buildGraph']['normalModules'])
        acquisition.update((d['module'], d['version'], d['h1']) for d in row['buildGraph']['prebuiltAcquisitionModules'])
        index['platforms'].append(row)
    from polaris_openwrt import validate_assembled_openwrt
    from polaris_public_sources import delivery, verify_public
    openwrt_rows = validate_assembled_openwrt(repo, expected, tree, openwrt_inputs, guest_inputs, output, run_id, attempt)
    index['openwrtPlatforms'] = openwrt_rows
    graphs = [r['buildGraph'] for r in index['platforms'] + openwrt_rows]
    index['sourceDelivery'] = delivery(repo, config, expected, tree, graphs)
    # Availability checks belong to this same whole-batch run; original bytes,
    # complete Git source trees and toolchain source references are verified.
    source_work = output.parent / 'public-source-check'
    index['sourceDelivery']['sourceAvailability'] = verify_public(index['sourceDelivery'], source_work)
    # No stale preparation note and no self-hashing recursion: each emitted metadata file is
    # covered by the outer checksums; expected archive/member pins come from this frozen index.
    (output / 'polaris-box-assets.json').write_bytes(encode(index))
    files = [file_info(f) for f in sorted(output.iterdir())]
    (output / 'SHA256SUMS').write_text(''.join(f"{f['sha256']}  {f['name']}\n" for f in files))
    verify_source(repo, expected)
    return {'version': config['version'], 'sourceCommit': expected, 'assetCount': len(files) + 1,
            'publicationEligible': False, 'indexSha256': digest(output / 'polaris-box-assets.json')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['plan', 'verify-source', 'native', 'assemble'])
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--source', type=Path)
    parser.add_argument('--expected-head')
    parser.add_argument('--target')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--inputs', type=Path)
    parser.add_argument('--openwrt-inputs', type=Path)
    parser.add_argument('--guest-inputs', type=Path)
    args = parser.parse_args()
    config = plan(args.repo)
    if args.mode == 'plan':
        result = {'version': config['version'], 'tag': config['tag'], 'matrix':
            [dict(row, kind='desktop') for row in TARGETS] +
            [dict(os='openwrt',arch=arch,runner='ubuntu-24.04',tool_arch='amd64',kind='openwrt')
             for arch in ['x86_64','aarch64_generic']],
                  'consumerContract': config['consumerContract'], 'publicationEligible': False}
    elif args.mode == 'verify-source':
        require(args.expected_head, 'full source SHA required')
        _, tree = frozen_source(args.repo, args.expected_head)
        result = {'sourceCommit': args.expected_head, 'sourceTree': tree, 'cleanSourceVerified': True}
    elif args.mode == 'native':
        require(all([args.source, args.expected_head, args.target, args.output]), 'native arguments missing')
        result = native(args.repo, args.source, args.expected_head, args.target, args.output)
    else:
        require(all([args.expected_head, args.inputs, args.openwrt_inputs, args.guest_inputs, args.output]), 'assembly arguments missing')
        result = assemble(args.repo, args.expected_head, args.inputs, args.openwrt_inputs, args.guest_inputs, args.output)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
