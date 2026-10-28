"""Offline source/notice assembly bound to frozen native platform receipts."""
import argparse
import gzip
import hashlib
import io
import json
import pathlib
import shutil
import tarfile
import zipfile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def file_hash(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def safe_member(name):
    pure = pathlib.PurePosixPath(name)
    require(bool(name) and not pure.is_absolute() and '..' not in pure.parts
            and '\\' not in name and ':' not in name and str(pure) == name,
            'unsafe source package member: ' + repr(name))


def input_path(root, name):
    safe_member(name)
    path = (root / name).resolve()
    require(path.is_relative_to(root.resolve()), 'input escapes declared root: ' + name)
    return path


def check_file(path, record):
    require(path.is_file(), 'missing source input: ' + str(path))
    require(path.stat().st_size == record['bytes'], 'input size mismatch: ' + str(path))
    require(file_hash(path) == record['sha256'], 'input SHA256 mismatch: ' + str(path))


def add_bytes(archive, name, data, mode=0o644):
    safe_member(name)
    member = tarfile.TarInfo(name)
    member.size, member.mode, member.mtime = len(data), mode, 0
    member.uid = member.gid = 0
    archive.addfile(member, io.BytesIO(data))


SOURCE_COMMIT = 'a01da7a942b3a0dbbfdfda2bba5bd63d5bd9d932'
SOURCE_TREE = '0bd19d8461347887c884f10250a402aa85decfe6'
ORIGINAL_PRODUCER = '720ead161c71415e23f38a82c29d314a4754ab9c'
REPAIR_PRODUCER = '226e88cab62b8818620668a28b496d833c01c953'
NATIVE_BINDINGS = {
    'linux/amd64': (38072592310, ORIGINAL_PRODUCER),
    'linux/arm64': (38072592310, ORIGINAL_PRODUCER),
    'windows/amd64': (38072592310, ORIGINAL_PRODUCER),
    'windows/arm64': (38074825396, REPAIR_PRODUCER),
    'darwin/amd64': (38074825396, REPAIR_PRODUCER),
    'darwin/arm64': (38074825396, REPAIR_PRODUCER),
}


def validate_native_bindings(index, stage):
    scope = index.get('scopeKey', 'original-three')
    require(scope in ('original-three', 'desktop-six'), 'unknown native source scope')
    wanted = set(NATIVE_BINDINGS) if scope == 'desktop-six' else {
        'linux/amd64', 'linux/arm64', 'windows/amd64'}
    platforms = index['platforms']
    actual = [row['platform'] for row in platforms]
    require(len(actual) == len(set(actual)) and set(actual) == wanted,
            'native platform set mismatch: require exact unique ' + scope + ' targets')
    require(index['sourceCommit'] == SOURCE_COMMIT and index['sourceTree'] == SOURCE_TREE
            and index['sourceOverlay'] == 0, 'native source identity mismatch')
    modules = {(m['module'], m['version'], m['h1']): m for m in index['modules']}
    require(len(modules) == len(index['modules']), 'duplicate source-union module')
    require(len({m['module'] for m in index['modules']}) == len(modules),
            'multiple versions for one source-union module')
    assembly = {r['path']: r for r in index['sourceAssemblyInputs']}
    require(len(assembly) == len(index['sourceAssemblyInputs']), 'duplicate assembly input')
    union = set()
    for row in platforms:
        platform = row['platform']
        run, producer = NATIVE_BINDINGS[platform]
        require(row['nativeAccepted'] is True and row['acceptedRun'] == run and
                row['acceptedProducerCommit'] == producer and row['originalRun'] == run and
                row['originalProducerCommit'] == producer, 'native producer/run binding mismatch')
        require(row['productSourceCommit'] == SOURCE_COMMIT and row['productSourceTree'] == SOURCE_TREE,
                'platform product source binding mismatch')
        name = 'receipts/' + platform.replace('/', '-') + '-producer' + producer[:6] + '-run' + str(run) + '.json'
        require(row.get('nativeReceiptPath', name) == name and name in assembly,
                'missing exact native receipt input: ' + platform)
        raw = input_path(stage, name).read_bytes()
        expected = assembly[name]
        require(len(raw) == expected['bytes'] and hashlib.sha256(raw).hexdigest() == expected['sha256'],
                'native receipt bytes differ from frozen input: ' + platform)
        receipt = json.loads(raw)
        require(receipt['sourceCommit'] == SOURCE_COMMIT and receipt['sourceTree'] == SOURCE_TREE and
                receipt['sourceOverlay'] == 0 and receipt['workflowCommit'] == producer and
                str(receipt['workflowRun']) == str(run) and str(receipt['workflowAttempt']) == '1',
                'native receipt source/producer/run identity mismatch: ' + platform)
        require(receipt['archive']['sha256'] == row['archiveSha256'], 'native archive binding mismatch')
        core_name = 'sing-box.exe' if platform.startswith('windows/') else 'sing-box'
        require(receipt['payloadHashes'][core_name] == row['coreSha256'], 'native core binding mismatch')
        current = set()
        for line in receipt['buildInfo'].splitlines():
            fields = line.split()
            require(not fields or fields[0] != '=>', 'unexpected replaced module in frozen a01 receipt')
            if fields and fields[0] == 'dep':
                require(len(fields) == 4 and fields[3].startswith('h1:'), 'invalid native BuildInfo module')
                key = tuple(fields[1:4])
                require(key not in current and key in modules, 'native module missing or mismatched in source union')
                current.add(key)
        keys = {name + '@' + version for name, version, _ in current}
        require(len(current) == row['moduleCount'] and len(row['moduleKeys']) == len(keys) and
                set(row['moduleKeys']) == keys, 'native per-platform module membership mismatch')
        notices = {i for key in current for i in modules[key]['noticeRecordIndexes']}
        require(len(row['goNoticeRecordIndexes']) == len(notices) and
                set(row['goNoticeRecordIndexes']) == notices, 'native module notice binding mismatch')
        target = platform.replace('/', '_')
        acquisition = row['prebuiltCronetInput']
        actual_library = receipt['cronet']
        require(acquisition['target'] == actual_library['target'] == target and
                acquisition['module'] == 'github.com/sagernet/cronet-go/lib/' + target,
                'native Cronet target/module binding mismatch')
        for field in ('module', 'moduleVersion', 'moduleSum', 'sha256', 'gitBlob'):
            require(acquisition[field] == actual_library[field], 'native Cronet input binding mismatch: ' + field)
        require((acquisition['module'], acquisition['moduleVersion'], acquisition['moduleSum']) in current,
                'native Cronet acquisition absent from BuildInfo')
        union.update(current)
    require(union == set(modules), 'source module union differs from actual native receipts')
    require(index['verifiedSourceUnionModuleCount'] == len(union), 'source module union count mismatch')
    for key, module in modules.items():
        require(bool(module['noticeRecordIndexes']), 'module has no indexed notice candidate')
        for number in module['noticeRecordIndexes']:
            require(isinstance(number, int) and 0 <= number < len(index['noticeRecords']) and
                    index['noticeRecords'][number]['source'] == key[0] + '@' + key[1],
                    'module notice source/record binding mismatch')
    return scope


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-root', type=pathlib.Path, required=True)
    parser.add_argument('--stage-dir', type=pathlib.Path, required=True)
    parser.add_argument('--module-cache', type=pathlib.Path, required=True)
    parser.add_argument('--go-toolchain-zip', type=pathlib.Path, required=True)
    parser.add_argument('--output-dir', type=pathlib.Path)
    parser.add_argument('--validate-only', action='store_true')
    options = parser.parse_args()
    stage = options.stage_dir.resolve()
    closure = options.evidence_root.resolve() / 'cronet-license-closure'
    module_cache = options.module_cache.resolve()
    index = json.loads((stage / 'DESKTOP-SOURCE-NOTICE-INDEX-controlled.json').read_text())
    require(index['publicationEligible'] is False and
            index['packageNoticeInputsAdoptedByProducer'] is False,
            'this helper only accepts unpublished, unadopted review inputs')
    scope = validate_native_bindings(index, stage)
    notice = input_path(stage, 'DESKTOP-SOURCE-NOTICE-SUPERSET.txt')
    raw = notice.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == index['noticeBundle']['sha256'],
            'notice bundle SHA256 mismatch')
    for record in index['noticeRecords']:
        offset, length = record['byteOffset'], record['bytes']
        require(isinstance(offset, int) and isinstance(length, int) and offset >= 0 and length >= 0,
                'invalid notice slice')
        data = raw[offset:offset + length]
        require(len(data) == length and hashlib.sha256(data).hexdigest() == record['sha256'],
                'notice slice SHA256 mismatch')
    sources = []
    for record in index['sourceArchiveInputs']:
        path = input_path(closure, record['filename'])
        check_file(path, record)
        sources.append(('sources/' + record['filename'], path, dict(record)))
    sources.append(('notices/DESKTOP-SOURCE-NOTICE-SUPERSET.txt', notice, dict(index['noticeBundle'])))
    for record in index['buildRecipeInputs'] + index['sourceAssemblyInputs']:
        path = input_path(stage, record['path'])
        check_file(path, record)
        sources.append((record['path'], path, dict(record)))
    for module in index['modules']:
        name = module['sourceBundleMember']
        if name is None:
            continue
        safe_member(name)
        require(name.startswith('modules/'), 'invalid module source member')
        path = input_path(module_cache, name.removeprefix('modules/'))
        expected = {'bytes': module['zipBytes'], 'sha256': module['zipSha256']}
        check_file(path, expected)
        sources.append((name, path, expected))
    toolchain = options.go_toolchain_zip.resolve()
    require(file_hash(toolchain) == index['localGoToolchainInput']['zipSha256'],
            'Go toolchain source ZIP SHA256 mismatch')
    names = [name for name, _, _ in sources]
    require(len(names) == len(set(names)), 'duplicate source input member')
    if options.validate_only:
        print(json.dumps({'inputValidation': 'passed', 'modules': len(index['modules']),
                          'rawNoticeSlices': len(index['noticeRecords']),
                          'archiveInputs': len(index['sourceArchiveInputs']),
                          'recipeInputs': len(index['buildRecipeInputs']),
                          'assemblyInputs': len(index['sourceAssemblyInputs']),
                          'publicationEligible': False}))
        return
    require(options.output_dir is not None, '--output-dir required for assembly')
    output_dir = options.output_dir.resolve()
    require(not output_dir.exists(), 'use a fresh output directory; preserve previous candidate bytes')
    output_dir.mkdir(parents=True, mode=0o700)
    toolchain_snapshot = output_dir / 'verified-go-toolchain-input.zip'
    with toolchain.open('rb') as original, toolchain_snapshot.open('xb') as snapshot:
        shutil.copyfileobj(original, snapshot)
    require(file_hash(toolchain_snapshot) == index['localGoToolchainInput']['zipSha256'],
            'verified Go toolchain snapshot SHA256 mismatch')
    stdlib = output_dir / 'go1.25.5-standard-library-source-v2.tar.gz'
    count = 0
    with stdlib.open('xb') as stream, gzip.GzipFile(fileobj=stream, mode='wb', mtime=0, compresslevel=1) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as archive, zipfile.ZipFile(toolchain_snapshot) as source:
            prefix = next(name.split('/src/')[0] + '/' for name in source.namelist() if '/src/' in name)
            for name in sorted(source.namelist()):
                relative = name.removeprefix(prefix)
                if (relative.startswith('src/') or relative in ('LICENSE', 'PATENTS', 'VERSION')) and not name.endswith('/'):
                    mode = (source.getinfo(name).external_attr >> 16) & 0o777
                    add_bytes(archive, 'go1.25.5/' + relative, source.read(name), mode or 0o644)
                    count += 1
    toolchain_snapshot.unlink()
    stdlib_expected = {'bytes': stdlib.stat().st_size, 'sha256': file_hash(stdlib)}
    sources.append(('sources/' + stdlib.name, stdlib, stdlib_expected))
    portable = dict(index)
    portable.update(completeCorrespondingSource=False, completeThirdPartyNotices=False,
                    standardLibrarySource={'version': 'go1.25.5', 'fileCount': count,
                                          'derivedFromToolchainZipSha256': index['localGoToolchainInput']['zipSha256'],
                                          'sourceArchiveSha256': stdlib_expected['sha256']},
                    sourcePackageMembers=[{'path': name, 'bytes': expected['bytes'], 'sha256': expected['sha256']} for name, _, expected in sources])
    index_bytes = (json.dumps(portable, indent=2) + '\n').encode()
    readme = ("Polaris a01 desktop source/notice review candidate: " + scope + ".\n\n"
              "Actual platform receipts retain their original source/run/producer identities.\n"
              "The source union has " + str(len(index['modules'])) + " modules and " +
              str(sum(bool(m['sourceBundleMember']) for m in index['modules'])) + " source ZIPs.\n"
              "The notice superset has " + str(len(index['noticeRecords'])) + " raw slices.\n"
              "Original and explicitly Git-byte-restored Naiveproxy source remain separate.\n"
              "The actual curated compiler-rt patch and generated/inline/nested source texts\n"
              "remain in the conservative full source archives. This is not an original link\n"
              "map, a claim of complete applicable notices, or a legal compliance guarantee.\n"
              "Compiler/SDK/PGO binary reproducibility and applicable shipped-code/runtime\n"
              "source and notice obligations are tracked separately.\n\n"
              "Download pinned Cronet .so/.dll/.a; only the Go kernel is compiled. macOS\n"
              "links the supplied .a. Use exact receipt flags and the saved producer recipes.\n"
              "Binary-acquisition module ZIPs are indexed, not labelled Chromium source.\n\n"
              "Existing six native binary archives still contain only six primary licenses.\n"
              "Reviewed notice adoption, final archive/member checks and stable public source\n"
              "delivery remain pending. Mobile carriers are a separate acceptance batch and\n"
              "do not block the six desktop CLI technical acceptance. publicationEligible=false.\n").encode()

    checksums = [(expected['sha256'], name) for name, _, expected in sources]
    checksums += [(hashlib.sha256(index_bytes).hexdigest(), 'SOURCE-INDEX.json'),
                  (hashlib.sha256(readme).hexdigest(), 'README.txt')]
    sum_bytes = ''.join(digest + '  ' + name + '\n' for digest, name in sorted(checksums, key=lambda row: row[1])).encode()
    version = 'v4' if scope == 'desktop-six' else 'v3'
    label = 'six-platforms' if scope == 'desktop-six' else 'three-platforms'
    bundle = output_dir / ('polaris-box-a01-desktop-source-candidate-' + label + '-' + version + '.tar.gz')
    pending = bundle.with_name(bundle.name + '.pending')
    with pending.open('xb') as stream, gzip.GzipFile(filename=bundle.name, fileobj=stream, mode='wb', mtime=0, compresslevel=1) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as archive:
            for name, path, expected in sorted(sources):
                safe_member(name)
                member = tarfile.TarInfo(name)
                member.size, member.mode, member.mtime = expected['bytes'], 0o644, 0
                with path.open('rb') as file_stream:
                    archive.addfile(member, file_stream)
            add_bytes(archive, 'SOURCE-INDEX.json', index_bytes)
            add_bytes(archive, 'README.txt', readme)
            add_bytes(archive, 'SHA256SUMS', sum_bytes)
    require(pending.stat().st_size < 300_000_000, 'source candidate exceeds bounded size')
    with tarfile.open(pending) as archive:
        members = archive.getmembers()
        require(len(members) == len({m.name for m in members}) == len(sources) + 3,
                'archive member count or uniqueness mismatch')
        for member in members:
            safe_member(member.name)
            require(member.isfile(), 'unexpected non-file source package member')
        require(archive.extractfile('SHA256SUMS').read() == sum_bytes,
                'packaged checksum manifest differs from frozen expected hashes')
        expected_members = {name: {'bytes': expected['bytes'], 'sha256': expected['sha256']}
                            for name, _, expected in sources}
        for name, data in [('SOURCE-INDEX.json', index_bytes), ('README.txt', readme), ('SHA256SUMS', sum_bytes)]:
            expected_members[name] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        require(set(archive.getnames()) == set(expected_members), 'archive expected member set mismatch')
        for name, expected in expected_members.items():
            require(archive.getmember(name).size == expected['bytes'], 'packaged member size mismatch: ' + name)
            with archive.extractfile(name) as member_stream:
                require(hashlib.file_digest(member_stream, 'sha256').hexdigest() == expected['sha256'],
                        'packaged member differs from frozen expected SHA256: ' + name)
    pending.rename(bundle)
    record = {'filename': bundle.name, 'bytes': bundle.stat().st_size, 'sha256': file_hash(bundle),
              'verifiedMemberCount': len(sources) + 3,
              'sourceModuleZipCount': sum(bool(m['sourceBundleMember']) for m in index['modules']),
              'productSourceCommit': index['sourceCommit'], 'actualAcceptedPlatformCount': len(index['platforms']),
              'actualNativeSourceUnionComplete': True, 'sourceScope': scope,
              'completeSixTargetSource': False, 'noticeInputsAdoptedByNativeProducer': False,
              'publicSourceDeliveryPerformed': False, 'publicationEligible': False}
    (output_dir / ('bounded-source-package-receipt-' + version + '.json')).write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
