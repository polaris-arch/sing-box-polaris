"""Offline DNS source/consumer preparation. Never build, sign, tag or publish."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import zipfile

import polaris_dns_identity as dns

CONTRACT = 'release/polaris-dns-publication-contract.json'
INDEX = 'release/dns-source/SOURCE-INDEX.json'
FILES = 'release/dns-source/SING-TUN-SOURCE-FILES.json'
A01_PACKAGE_SHA = '70ff6e51660cc8ea140a30513c42c7b842b4fdb62ba41d863b08405db63ea5ed'
A01_INDEX_SHA = 'b9127a5c25821cca2bce26b24a63b7c114902d36421e131b3e1d9568270f8e97'
TECHNICAL_PRODUCER = 'a451c7101466201e0afa1b08065aa1705bf96bef'
TECHNICAL_RUN = '38086801501'
PLANNED_TAG = 'polaris-v1.15.0-alpha.11-2'
PLANNED_VERSION = '1.15.0-alpha.11.polaris.2'
PENDING_FIELDS = ('sourceTag', 'sourceTagObject', 'sourceManifestSha256', 'sourceReceiptFingerprint',
                  'finalPlatformBuildIDs', 'finalFourCoreHashes', 'finalFourReceipts',
                  'finalMacSignatures', 'finalCarrierHashes', 'finalSourcePackageHash', 'finalPublicationTag')
TARGETS = {'linux': ('linux', 'amd64'), 'win': ('windows', 'amd64'),
           'mac-x64': ('darwin', 'amd64'), 'mac-arm64': ('darwin', 'arm64')}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def file_sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def safe_name(name):
    path = PurePosixPath(name)
    require(name and not path.is_absolute() and '..' not in path.parts
            and '\\' not in name and ':' not in name and str(path) == name,
            'unsafe source member: ' + repr(name))
    return path


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args])


def source_blobs(repo, prefix=None):
    require(git(repo, 'rev-parse', dns.SOURCE + '^{tree}').decode().strip() == dns.TREE,
            'fixed product source tree differs')
    args = ['ls-tree', '-r', '-z', dns.SOURCE]
    if prefix:
        args += ['--', prefix]
    rows = []
    for line in git(repo, *args).split(b'\0'):
        if not line:
            continue
        identity, raw_name = line.split(b'\t', 1)
        mode, kind, blob = identity.decode().split()
        name = raw_name.decode()
        safe_name(name)
        if not prefix and kind == 'commit' and mode == '160000':
            require(name in ('clients/android', 'clients/apple', 'clients/desktop'),
                    'unexpected source gitlink')
            continue  # CLI source archive binds these refs, not mobile/client trees.
        require(kind == 'blob' and mode in ('100644', '100755'),
                'only regular tracked source blobs accepted')
        rows.append({'path': name, 'mode': mode, 'gitBlob': blob})
    raw = subprocess.check_output(['git', '-C', str(repo), 'cat-file', '--batch'],
                                  input=('\n'.join(r['gitBlob'] for r in rows) + '\n').encode())
    stream = io.BytesIO(raw)
    blobs = {}
    for row in rows:
        oid, kind, size = stream.readline().decode().split()
        data = stream.read(int(size))
        require(oid == row['gitBlob'] and kind == 'blob' and stream.read(1) == b'\n',
                'Git blob batch identity differs')
        require(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == oid,
                'Git blob bytes differ')
        blobs[row['path']] = data
        row.update(bytes=len(data), sha256=dns.sha(data))
    require(not stream.read(), 'unexpected Git batch trailing data')
    return rows, blobs


def source_archive(repo):
    data = git(repo, '-c', 'tar.umask=0022', 'archive', '--format=tar', dns.SOURCE)
    rows, blobs = source_blobs(repo)
    modes = {row['path']: row['mode'] for row in rows}
    actual = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        for member in archive:
            name = member.name.rstrip('/')
            safe_name(name)
            if member.isdir():
                continue
            require(member.isfile() and name not in actual, 'source archive links/duplicates forbidden')
            raw = archive.extractfile(member).read()
            actual[name] = raw
            require(name in modes, 'source archive has untracked member')
            expected_mode = 0o755 if modes[name] == '100755' else 0o644
            require(member.mode & 0o777 == expected_mode, 'source archive executable mode differs')
    require(actual == blobs, 'source archive omits or alters tracked source files')
    return data, len(rows)


def client_gitlinks(repo):
    rows = []
    for line in git(repo, 'ls-tree', '-r', dns.SOURCE).decode().splitlines():
        identity, name = line.split('\t', 1)
        mode, kind, oid = identity.split()
        if mode == '160000':
            rows.append({'path': name, 'mode': mode, 'commit': oid})
    require({r['path'] for r in rows} == {'clients/android', 'clients/apple', 'clients/desktop'}
            and len(rows) == 3, 'exact existing client submodule refs required')
    return rows


def baseline_files(raw, binding):
    require(dns.sha(raw) == binding['baselineZipSha256'], 'sing-tun baseline ZIP differs')
    prefix = binding['module'] + '@' + binding['version'] + '/'
    files = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for entry in archive.infolist():
            if entry.is_dir():
                continue
            require(entry.filename.startswith(prefix), 'baseline ZIP module/version path differs')
            name = entry.filename[len(prefix):]
            safe_name(name)
            require(name not in files and entry.external_attr >> 16 & 0o170000 in (0, 0o100000),
                    'baseline ZIP duplicate/link forbidden')
            files[name] = archive.read(entry)
    require(len(files) == binding['baselineFiles'] == 253, 'complete 253-file baseline required')
    return files


def replacement_index(repo, baseline, binding):
    rows, blobs = source_blobs(repo, 'third_party/sing-tun')
    require(len(rows) == binding['replacementFileCount'] == 256
            and git(repo, 'rev-parse', dns.SOURCE + ':third_party/sing-tun').decode().strip()
            == binding['replacementTree'], 'complete exact replacement tree required')
    patched = {name.removeprefix('third_party/sing-tun/'): data for name, data in blobs.items()}
    changed = sorted(name for name in baseline if name in patched and baseline[name] != patched[name])
    added = sorted(set(patched) - set(baseline))
    require(set(baseline) <= set(patched) and changed == binding['changedBaselineFiles']
            and added == sorted(binding['addedFiles']), 'replacement changed/added inventory differs')
    return {'schema': 'polaris-dns-sing-tun-source-files-v1', 'sourceCommit': dns.SOURCE,
            'sourceTree': dns.TREE, 'replacementTree': binding['replacementTree'],
            'binding': binding,
            'baselineFiles': [{'path': name, 'bytes': len(raw), 'sha256': dns.sha(raw)}
                              for name, raw in sorted(baseline.items())],
            'modifiedFiles': rows, 'changedBaselineFiles': changed, 'addedFiles': added,
            'other252BaselineFilesByteExact': True}


def parse_dependencies(build_info):
    normal = {}; replacements = []; main = []; pending = None; seen = set()
    for line in build_info.splitlines()[1:]:
        fields = line.strip().split('\t')
        if fields[0] in ('dep', 'mod'):
            require(len(fields) in (3, 4), 'malformed BuildInfo module')
            require(fields[1] not in seen, 'duplicate BuildInfo module')
            seen.add(fields[1])
            pending = tuple(fields[1:3])
            if fields[0] == 'mod':
                main.append(pending)
                pending = None
            elif len(fields) == 4:
                normal[fields[1]] = (fields[2], fields[3])
        elif fields[0] == '=>':
            require(pending is not None and len(fields) == 3, 'unbound/malformed replacement')
            replacements.append((pending, fields[1], fields[2]))
            pending = None
        elif fields[0] == 'build' or not line.strip():
            pending = None
    require(len(main) == 1 and main[0][0] == 'github.com/sagernet/sing-box'
            and main[0][1] in dns.ROOT_MODULE_VERSIONS, 'unique fixed root module required')
    return normal, replacements


def final_platform_identity(contract, source_receipt_fingerprint, key):
    require(re.fullmatch('[a-f0-9]{64}', source_receipt_fingerprint or '') is not None,
            'actual shared-provider source receipt fingerprint required')
    require(key in TARGETS, 'unknown desktop platform')
    row = contract['platformPolicy'][key]
    facts = {'sourceReceiptFingerprint': source_receipt_fingerprint,
             'buildTree': dns.TREE, 'overlays': [], 'version': contract['plannedFinalVersion'],
             'goVersion': '1.25.5', 'platform': key, 'transportPins': contract['transportPins'],
             'patchedModules': {'requiredLinked': [], 'allowedAbsent': []},
             'transportModules': row['transportModules'], 'goos': row['goos'],
             'goarch': row['goarch'], 'cgo': row['cgo'], 'tags': row['tags'],
             'portableSourceFingerprint': contract['portableSourceFingerprint'],
             'sourceOwnedReplacements': [contract['sourceOwnedReplacement']]}
    fingerprint = dns.sha(dns.canonical(facts).encode())
    return {'facts': facts, 'sourceFingerprint': source_receipt_fingerprint,
            'platformInputFingerprint': fingerprint, 'buildID': 'polaris-desktop-source-v1-' + fingerprint}


def bind_final_receipt_context(facts, candidate, env):
    """Hash fresh final producer facts with their real context, never convert a technical receipt."""
    require(facts.get('schema') == 'polaris-desktop-core-v1'
            and facts.get('version') == PLANNED_VERSION
            and facts.get('sourceReceipt', {}).get('sourceCommit') == dns.SOURCE
            and facts.get('buildTree') == dns.TREE
            and str(facts.get('buildID', '')).startswith('polaris-desktop-source-v1-'),
            'fresh final DNS producer facts required; technical/old receipts forbidden')
    require(not any(name in facts for name in ('fingerprint', 'repository', 'runId', 'runAttempt')),
            'receipt context/fingerprint must be bound once before hashing')
    require(isinstance(candidate, str) and re.fullmatch('[a-f0-9]{40}', candidate) is not None
            and facts.get('candidate') == candidate and env.get('GITHUB_SHA') == candidate
            and env.get('GITHUB_ACTIONS') == 'true'
            and env.get('GITHUB_REPOSITORY') == 'polaris-arch/Polaris'
            and isinstance(env.get('GITHUB_RUN_ID'), str)
            and isinstance(env.get('GITHUB_RUN_ATTEMPT'), str)
            and re.fullmatch('[1-9][0-9]*', env['GITHUB_RUN_ID']) is not None
            and re.fullmatch('[1-9][0-9]*', env['GITHUB_RUN_ATTEMPT']) is not None,
            'actual App producer repository/candidate/run/attempt context required')
    receipt = dict(facts, repository=env['GITHUB_REPOSITORY'], runId=env['GITHUB_RUN_ID'],
                   runAttempt=env['GITHUB_RUN_ATTEMPT'])
    receipt['fingerprint'] = dns.sha(dns.canonical(receipt).encode())
    return receipt


def validate_final_receipt_context(receipt, candidate, env):
    """Consumer compares the hashed producer context to its actual current run."""
    facts = {key: value for key, value in receipt.items()
             if key not in ('fingerprint', 'repository', 'runId', 'runAttempt')}
    expected = bind_final_receipt_context(facts, candidate, env)
    require(receipt == expected, 'producer receipt context/fingerprint differs from current App run')
    return receipt


def validate_contract(contract):
    require(contract['schema'] == 'polaris-dns-desktop-publication-contract-v1'
            and contract['sourceCommit'] == dns.SOURCE and contract['sourceTree'] == dns.TREE
            and contract['sourceOverlay'] == 0 and contract['goVersion'] == '1.25.5',
            'publication contract source/toolchain differs')
    require(contract['plannedRoleTag'] == PLANNED_TAG and contract['plannedFinalVersion'] == PLANNED_VERSION,
            'reviewed planned role tag/version differs')
    require(contract['AppAdmissible'] is False and contract['publicationEligible'] is False
            and set(contract['notYetProduced']) == set(PENDING_FIELDS)
            and all(value is None for value in contract['notYetProduced'].values()),
            'preparation cannot claim produced/admissible inputs')
    require(contract['roleTagAnnotationRequiredLines'] == ['Role: desktop',
            'Upstream-Tag: v1.15.0-alpha.11',
            'Upstream-Commit: 6afeff4c0f7123b5782f888812e96b8c82c7b699'],
            'role tag annotation contract differs')
    require(contract['formalReceipts']['schema'] == 'polaris-desktop-core-v1'
            and contract['formalReceipts']['freshFourTargets'] == list(TARGETS)
            and contract['formalReceipts']['singleCandidateRunAttempt'] is True
            and contract['formalReceipts']['technicalReceiptAdmissible'] is False
            and contract['formalReceipts']['oldDOrA01OriginsAdmissibleForDNS'] is False,
            'formal all-current four-core contract differs')
    require(contract['formalReceipts']['contextFieldsBoundBeforeFingerprint'] == ['repository', 'runId', 'runAttempt']
            and contract['formalReceipts']['repository'] == 'polaris-arch/Polaris'
            and contract['formalReceipts']['producerOutputsRequired'] is False
            and contract['formalReceipts']['envelopeBindsFourMeasuredOutputs'] is True,
            'fresh producer context/output envelope contract differs')
    require(contract['sourceCollection']['isolatedGoSettings'] == {
            'GOENV': 'off', 'GOWORK': 'off', 'GOFLAGS': '', 'GOTOOLCHAIN': 'local'}
            and contract['sourceCollection']['buildVCS'] is True
            and contract['sourceCollection']['requiredVCS'] == {'vcs': 'git', 'vcs.revision': dns.SOURCE,
            'vcs.time': dns.SOURCE_TIME, 'vcs.modified': 'false'}, 'source/VCS isolation contract differs')
    require(set(contract['platformPolicy']) == set(TARGETS)
            and len(contract['consumerWriteSet']) == 15
            and len({row['path'] for row in contract['consumerWriteSet']}) == 15,
            'exact four targets and 15 consumer paths required')
    require(contract['buildIDContract']['prefix'] == 'polaris-desktop-source-v1-'
            and contract['buildIDContract']['algorithm'] == 'sha256(canonical(platformFacts))',
            'App BuildID algorithm differs')
    for key, (goos, goarch) in TARGETS.items():
        row = contract['platformPolicy'][key]
        require((row['goos'], row['goarch'], row['cgo']) == (goos, goarch, '1' if goos == 'darwin' else '0'),
                'native platform/CGO differs')
        require(row['tags'] == sorted(set(row['tags'])) and 'with_gvisor' in row['tags']
                and ('with_purego' in row['tags']) == (goos != 'darwin'), 'platform tags differ')
        require(row['sourceOwnedModules'] == {'requiredLinked': ['github.com/sagernet/sing-tun'],
                                              'allowedAbsent': []}, 'source-owned all-four link policy differs')
        require(sorted(row['transportModules']['requiredLinked'] + row['transportModules']['confirmedAbsent'])
                == sorted(contract['transportPins']), 'transport module partition differs')
    expected_signatures = {'linux': {'state': 'not-applicable'}, 'win': {'state': 'not-applicable'},
                          'mac-x64': {'allowedStates': ['signed', 'unsigned'], 'unsignedRequires': 'thin x86_64 Mach-O and exact codesign unsigned error'},
                          'mac-arm64': {'allowedStates': ['signed']}}
    require(contract['signatures'] == expected_signatures, 'existing App Mac signature policy differs')


def validate_technical_receipts(root, contract, manifest, index):
    union = {}; observed = {}
    require(set(index['technicalReceiptPins']) == set(TARGETS), 'exact four receipt pins required')
    for key, pin in index['technicalReceiptPins'].items():
        safe_name(pin['path'])
        path = root / pin['path']
        require(path.is_file() and path.stat().st_size == pin['bytes'] and file_sha(path) == pin['sha256'],
                'fixed original technical receipt bytes differ: ' + key)
        receipt = json.loads(path.read_text())
        require(receipt['schema'] == 'polaris-dns-technical-native-v1'
                and receipt['producerHead'] == TECHNICAL_PRODUCER
                and receipt['workflowCommit'] == TECHNICAL_PRODUCER
                and str(receipt['workflowRun']) == TECHNICAL_RUN and str(receipt['workflowAttempt']) == '1'
                and receipt['sourceCommit'] == dns.SOURCE and receipt['sourceTree'] == dns.TREE
                and receipt['AppAdmissible'] is False and receipt['publicationEligible'] is False,
                'technical source/run/schema/admission differs')
        identity = dns.source_identity(receipt['actualSourceFingerprint'], manifest)
        require(identity['fingerprint'] == contract['portableSourceFingerprint']
                and identity == receipt['commonSourceIdentity'], 'portable source identity differs')
        goos, goarch = TARGETS[key]
        platform = dns.platform_identity(identity, manifest, goos, goarch, receipt['tags'])
        require(platform == receipt['platformInputIdentity'], 'technical platform identity differs')
        dns.validate_build_info(receipt['buildInfo'], manifest, platform,
                                receipt['actualBuildID'], receipt['actualCoreVersion'])
        require(sorted(receipt['tags'].split(',')) == contract['platformPolicy'][key]['tags'],
                'technical vs final target tag policy differs')
        library = next(row for row in manifest['libraries'] if row['target'] == goos + '_' + goarch)
        require(receipt['cronet'] == library, 'fixed Cronet library input differs')
        normal, replacements = parse_dependencies(receipt['buildInfo'])
        binding = manifest['replacementBinding']
        require(replacements == [((binding['module'], binding['version']), binding['replacementPath'], '(devel)')],
                'exact one sing-tun replacement required')
        for module, pair in normal.items():
            require(module not in union or union[module] == pair, 'four-platform module version/sum differs')
            union[module] = pair
        row = contract['platformPolicy'][key]['transportModules']
        require(all(normal.get(m, (None,))[0] == contract['transportPins'][m] for m in row['requiredLinked'])
                and not any(m in normal for m in row['confirmedAbsent']), 'actual transport partition differs')
        observed[key] = {'technicalCoreSha256': receipt['payloadHashes']['sing-box.exe' if key == 'win' else 'sing-box'],
                         'technicalArchiveSha256': receipt['archive']['sha256']}
    expected = {r['module']: (r['version'], r['h1']) for r in index['normalModules']}
    require(len(expected) == len(index['normalModules']) == 151 and union == expected,
            'exact actual four-platform 151-module union required')
    return observed


def validate_reuse_package(path, index):
    require(path.stat().st_size == 271716261 and file_sha(path) == A01_PACKAGE_SHA,
            'original immutable a01 source package differs')
    wanted = {r['sourceBundleMember']: (r['zipBytes'], r['zipSha256'])
              for r in index['normalModules'] if r['sourceBundleMember']}
    baseline = index['baselineModuleZip']
    wanted[baseline['sourceBundleMember']] = (baseline['zipBytes'], baseline['zipSha256'])
    for row in index['reusedSourceArchiveInputs']:
        wanted['sources/' + row['filename']] = (row['bytes'], row['sha256'])
    for row in [index['reusedStandardLibraryArchiveInput'], index['reusedPublishedSourceIndex'],
                *index['reusedComponentEvidenceInputs']]:
        wanted[row['path']] = (row['bytes'], row['sha256'])
    notice = index['reusedNotice']
    wanted[notice['member']] = (notice['bytes'], notice['sha256'])
    require(len(wanted) == 156, 'module/baseline/Cronet/Go/notice and historical coverage inputs required')
    seen = set(); verified = set(); baseline_raw = None
    with tarfile.open(path, 'r|gz') as archive:
        for member in archive:
            safe_name(member.name)
            require(member.isfile() and member.name not in seen and member.size >= 0,
                    'original source package duplicate/link forbidden')
            seen.add(member.name)
            if member.name not in wanted:
                continue
            size, expected_hash = wanted[member.name]
            require(member.size == size, 'reused source input size differs')
            stream = archive.extractfile(member)
            if member.name in (baseline['sourceBundleMember'], notice['member']):
                raw = stream.read()
                actual_hash = dns.sha(raw)
                if member.name == baseline['sourceBundleMember']:
                    baseline_raw = raw
                else:
                    for row in notice['records']:
                        data = raw[row['byteOffset']:row['byteOffset'] + row['bytes']]
                        require(len(data) == row['bytes'] and dns.sha(data) == row['sha256'],
                                'original raw notice slice differs')
            else:
                actual_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
            require(actual_hash == expected_hash, 'reused source input hash differs: ' + member.name)
            verified.add(member.name)
    require(verified == set(wanted), 'reused source package omits required inputs')
    return baseline_raw


def validate_inputs(repo, package, technical_root):
    contract = json.loads((repo / CONTRACT).read_text())
    validate_contract(contract)
    require(file_sha(repo / INDEX) == contract['sourceIndexSha256']
            and file_sha(repo / FILES) == contract['replacementFileIndexSha256'], 'controlled DNS indexes differ')
    index = json.loads((repo / INDEX).read_text())
    require(index['sourceCommit'] == dns.SOURCE and index['sourceTree'] == dns.TREE
            and index['AppAdmissible'] is False and index['publicationEligible'] is False
            and index['reusedA01IndexSha256'] == A01_INDEX_SHA,
            'DNS source index identity/scope differs')
    require(index['unexpandedClientGitlinks'] == client_gitlinks(repo), 'client gitlink binding differs')
    manifest_path = repo / 'release/polaris-dns-candidate-inputs.json'
    require(file_sha(manifest_path) == contract['technicalInputManifestSha256'], 'technical input bytes differ')
    manifest = json.loads(manifest_path.read_text())
    require(contract['sourceOwnedReplacement'] == dict(manifest['replacementBinding'],
            bindingSha256=manifest['sourceFileSha256']['release/dependency-sources/sing-tun-replacement.json']),
            'source-owned replacement declaration differs')
    observed = validate_technical_receipts(technical_root, contract, manifest, index)
    raw = validate_reuse_package(package, index)
    baseline = baseline_files(raw, manifest['replacementBinding'])
    require(replacement_index(repo, baseline, manifest['replacementBinding']) == json.loads((repo / FILES).read_text()),
            'actual baseline/modified source inventory differs')
    for name, expected in manifest['sourceFileSha256'].items():
        require(dns.sha(git(repo, 'show', dns.SOURCE + ':' + name)) == expected,
                'frozen source binding bytes differ: ' + name)
    archive, count = source_archive(repo)
    source_record = index['newKernelSourceArchiveInput']
    require(len(archive) == source_record['bytes'] and dns.sha(archive) == source_record['sha256']
            and count == source_record['trackedFileCount'], 'new full tracked DNS source archive differs')
    summary = {'schema': 'polaris-dns-publication-preparation-validation-v1',
               'sourceCommit': dns.SOURCE, 'sourceTree': dns.TREE,
               'normalModulesVerified': 151, 'moduleSourceZipsVerified': 147,
               'noticeSlicesVerified': len(index['reusedNotice']['records']),
               'reusedStandardLibrarySourceSha256': index['reusedStandardLibraryArchiveInput']['sha256'],
               'baselineFilesVerified': 253, 'modifiedFilesVerified': 256,
               'newKernelSourceArchiveInput': source_record, 'originalTechnicalInputs': observed,
               'plannedRoleTag': contract['plannedRoleTag'], 'plannedFinalVersion': contract['plannedFinalVersion'],
               'AppAdmissible': False, 'publicationEligible': False,
               'builtOrSignedOrPublished': False}
    return summary, archive, raw


def write_source_inputs(output, repo, summary, archive, baseline):
    output = output.resolve()
    require(not output.is_relative_to(repo.resolve()), 'output must be outside producer checkout')
    require(not output.exists(), 'fresh source preparation output required')
    output.mkdir(parents=True)
    (output / summary['newKernelSourceArchiveInput']['filename']).write_bytes(archive)
    (output / 'sing-tun-original-module.zip').write_bytes(baseline)
    # The full kernel archive already contains all 256 patched source files,
    # binding, baseline declaration, patch and main manifests; do not duplicate it.
    for name in (CONTRACT, INDEX, FILES):
        (output / Path(name).name).write_bytes((repo / name).read_bytes())
    (output / 'validation.json').write_text(json.dumps(summary, indent=2) + '\n')
    records = [{'file': p.name, 'bytes': p.stat().st_size, 'sha256': file_sha(p)}
               for p in sorted(output.iterdir())]
    (output / 'SOURCE-INPUT-SHA256.json').write_text(json.dumps(records, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--a01-source-package', type=Path, required=True)
    parser.add_argument('--technical-artifacts', type=Path, required=True)
    parser.add_argument('--write-source-inputs', type=Path,
                        help='Optional small immutable source inputs only; no final distribution pack')
    args = parser.parse_args()
    summary, archive, baseline = validate_inputs(args.repo, args.a01_source_package, args.technical_artifacts)
    if args.write_source_inputs:
        write_source_inputs(args.write_source_inputs, args.repo, summary, archive, baseline)
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
