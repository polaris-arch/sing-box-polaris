#!/usr/bin/env python3
"""Build native, unsigned review candidates only. No tag/release/API writes."""
import argparse
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import shlex
import struct
import subprocess
import tarfile
import tempfile
import zipfile


def windows_native_machine(kernel=None):
    # GetNativeSystemInfo can report x64 to an emulated x64 process on ARM64.
    # IsWow64Process2 returns the physical host architecture separately.
    if kernel is None:
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.IsWow64Process2.argtypes = [ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ushort), ctypes.POINTER(ctypes.c_ushort)]
    kernel.IsWow64Process2.restype = ctypes.c_int
    process_machine, native_machine = ctypes.c_ushort(), ctypes.c_ushort()
    if not kernel.IsWow64Process2(kernel.GetCurrentProcess(),
                                 ctypes.byref(process_machine), ctypes.byref(native_machine)):
        raise OSError('IsWow64Process2 failed; native host architecture unavailable')
    arch = {0x8664: 'amd64', 0xaa64: 'arm64'}.get(native_machine.value)
    if arch is None:
        raise ValueError(f'unsupported native Windows machine: {native_machine.value:#x}')
    return {'nativeArch': arch, 'nativeMachine': native_machine.value,
            'processMachine': process_machine.value, 'api': 'IsWow64Process2'}


def darwin_cgo_flags(sdk_path):
    # Direct clang invocation needs the SDK that xcrun resolved, including at link.
    return '-isysroot ' + shlex.quote(sdk_path) + ' -mmacosx-version-min=13.0'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(args, cwd=None, env=None):
    result = subprocess.run([str(x) for x in args], cwd=cwd, env=env,
                            capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(f'{args!r}: exit {result.returncode}\n{result.stdout}\n{result.stderr}')
    return result.stdout


def required_cronet_symbols(wrapper_dir, os_name, arch):
    files = ['loader_windows.go'] if os_name == 'windows' else ['loader_unix.go']
    if os_name == 'windows' and arch in ('amd64', 'arm64'):
        files.append('loader_windows_float.go')
    required = set()
    for filename in files:
        source = (wrapper_dir / 'internal/cronet' / filename).read_text()
        symbols = re.findall(r'registerFunc\([^,\n]+,\s*"([^"]+)"', source)
        if not symbols:
            raise ValueError('no required symbols extracted from ' + filename)
        required.update(symbols)
    return required


def verify_required_exports(required, exported):
    missing = required - set(exported)
    if missing:
        raise ValueError('Cronet required C exports missing: ' + ', '.join(sorted(missing)))



CRONET_REJECTION_PATTERNS = {
    'missing-library-argument': ('required-library', r'^Error: --library is required;'),
    'missing-path': ('missing-library-path', r'^Error: (?:lstat|stat|readlink|CreateFile|GetFileAttributes(?:Ex)?) .*absent-library:'),
    'wrong-digest': ('library-digest-mismatch', r'^Error: Cronet library SHA-256 mismatch:'),
    'same-size-changed-bytes': ('library-digest-mismatch', r'^Error: Cronet library SHA-256 mismatch:'),
    'wrong-version': ('engine-version-mismatch', r'^Error: Cronet version mismatch:'),
    'wrong-machine-with-matching-byte-hash': ('native-library-load-failure', r'^Error: cronet: failed to load library '),
    'missing-cronet-ABI-with-matching-byte-hash': ('required-ABI-symbol-missing', r'^Error: cronet: symbol Cronet_[A-Za-z0-9_]+ not found:'),
    'static-rejects-sidecar': ('static-sidecar-rejected', r'^Error: this build links Cronet statically;'),
}


def validate_cronet_rejection(name, trial):
    category, pattern = CRONET_REJECTION_PATTERNS[name]
    # mainCommand.Execute returns an ordinary error through log.Fatal (exit 1).
    # Signals, Windows crash status, Go panic, and unrelated errors cannot pass.
    if (trial.returncode != 1 or trial.stdout or
            re.search(r'(?im)^(?:panic:|fatal error:|SIG[A-Z]+:)', trial.stderr) or
            not re.search(pattern, trial.stderr)):
        raise ValueError(f'negative Cronet case did not produce {category}: {name}; '
                         f'exit {trial.returncode}; stdout={trial.stdout!r}; stderr={trial.stderr!r}')
    return {'case': name, 'expectedErrorCategory': category, 'errorCategoryMatched': True,
            'exitCode': trial.returncode, 'stdout': trial.stdout, 'stderr': trial.stderr}


def pe_metadata(data):
    if data[:2] != b'MZ':
        raise ValueError('not PE')
    offset = struct.unpack_from('<I', data, 60)[0]
    if data[offset:offset + 4] != b'PE\0\0':
        raise ValueError('bad PE signature')
    machine, count = struct.unpack_from('<HH', data, offset + 4)
    opt = offset + 24
    size = struct.unpack_from('<H', data, offset + 20)[0]
    magic = struct.unpack_from('<H', data, opt)[0]
    if magic not in (0x10b, 0x20b):
        raise ValueError('bad PE optional header')
    directory = opt + (112 if magic == 0x20b else 96)
    sections = []
    for i in range(count):
        sections.append(struct.unpack_from('<IIII', data, opt + size + i * 40 + 8))
    def locate(rva):
        for virtual_size, address, raw_size, raw in sections:
            if address <= rva < address + max(virtual_size, raw_size):
                return raw + rva - address
        raise ValueError('unmapped RVA')
    def string(rva):
        start = locate(rva)
        return data[start:data.index(b'\0', start)].decode('ascii')
    export_rva, _ = struct.unpack_from('<II', data, directory)
    exports = []
    if export_rva:
        start = locate(export_rva)
        names_count = struct.unpack_from('<I', data, start + 24)[0]
        names = locate(struct.unpack_from('<I', data, start + 32)[0])
        exports = [string(struct.unpack_from('<I', data, names + i * 4)[0])
                   for i in range(names_count)]
    imports = []
    import_rva, _ = struct.unpack_from('<II', data, directory + 8)
    if import_rva:
        start = locate(import_rva)
        while any(data[start:start + 20]):
            imports.append(string(struct.unpack_from('<I', data, start + 12)[0]))
            start += 20
    delay = []
    delay_rva, _ = struct.unpack_from('<II', data, directory + 13 * 8)
    if delay_rva:
        start = locate(delay_rva)
        while any(data[start:start + 32]):
            flags, name = struct.unpack_from('<II', data, start)
            if flags & 1 != 1:
                raise ValueError('legacy VA delay imports need separate validation')
            delay.append(string(name))
            start += 32
    certificate, certificate_size = struct.unpack_from('<II', data, directory + 4 * 8)
    return {'format': 'PE', 'machine': machine, 'imports': imports,
            'delayImports': delay, 'exports': sorted(exports),
            'certificateTablePresent': bool(certificate and certificate_size),
            'signatureTrustValidated': False}


def inspect_binary(path, os_name, arch):
    if os_name == 'windows':
        result = pe_metadata(path.read_bytes())
        if result['machine'] != {'amd64': 0x8664, 'arm64': 0xaa64}[arch]:
            raise ValueError('wrong PE machine')
        return result
    if os_name == 'linux':
        header = path.read_bytes()[:20]
        if header[:4] != b'\x7fELF' or header[4:6] != b'\x02\x01':
            raise ValueError('expected little-endian ELF64')
        machine = struct.unpack_from('<H', header, 18)[0]
        if machine != {'amd64': 62, 'arm64': 183}[arch]:
            raise ValueError('wrong ELF machine')
        return {'format': 'ELF', 'machine': machine,
                'dynamic': run(['readelf', '-d', path]),
                'symbolVersions': run(['readelf', '--version-info', '--wide', path])}
    data = path.read_bytes()[:32]
    if data[:4] != b'\xcf\xfa\xed\xfe':
        raise ValueError('expected thin Mach-O64')
    cpu = struct.unpack_from('<I', data, 4)[0]
    if cpu != {'amd64': 0x1000007, 'arm64': 0x100000c}[arch]:
        raise ValueError('wrong Mach-O CPU')
    return {'format': 'Mach-O', 'cpuType': cpu, 'loadCommands': run(['otool', '-l', path]),
            'dependencies': run(['otool', '-L', path]),
            'codeSignatureInspection': subprocess.run(['codesign', '-d', '--verbose=4', str(path)], capture_output=True, text=True, check=False).stderr,
            'signatureTrustValidated': False}


def archive_members(archive):
    """Read, never blindly extract: allow only ordinary files under one root."""
    members = {}
    if archive.suffix == '.zip':
        with zipfile.ZipFile(archive) as reader:
            for entry in reader.infolist():
                mode = entry.external_attr >> 16
                if entry.is_dir() or (mode & 0o170000) not in (0, 0o100000):
                    raise ValueError('nonregular zip member')
                name = entry.filename
                if name in members:
                    raise ValueError('duplicate archive member')
                members[name] = reader.read(entry)
    else:
        with tarfile.open(archive, 'r:gz') as reader:
            for entry in reader.getmembers():
                if not entry.isfile() or entry.name in members:
                    raise ValueError('nonregular/duplicate tar member')
                members[entry.name] = reader.extractfile(entry).read()
    for name in members:
        if '\\' in name or name.startswith('/') or ':' in name or '..' in name.split('/'):
            raise ValueError('unsafe member path')
    roots = {name.split('/')[0] for name in members}
    if len(roots) != 1 or any('/' not in name for name in members):
        raise ValueError('expected one archive root')
    return members


def package(root, destination, os_name):
    files = sorted(p for p in root.rglob('*') if p.is_file())
    if any(p.is_symlink() for p in root.rglob('*')):
        raise ValueError('package contains symlink')
    if os_name == 'windows':
        with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED) as writer:
            for file in files:
                writer.write(file, file.relative_to(root.parent).as_posix())
    else:
        with tarfile.open(destination, 'w:gz') as writer:
            for file in files:
                writer.add(file, arcname=file.relative_to(root.parent).as_posix(), recursive=False)
    actual = archive_members(destination)
    expected = {file.relative_to(root.parent).as_posix(): file.read_bytes() for file in files}
    if actual != expected:
        raise ValueError('archive bytes/membership differ from staged payload')
    return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--os', choices=['linux', 'windows', 'darwin'], required=True)
    parser.add_argument('--arch', choices=['amd64', 'arm64'], required=True)
    options = parser.parse_args()
    producer = Path(__file__).resolve().parents[1]
    manifest = json.loads((producer / 'release/polaris-candidate-inputs.json').read_text())
    source = options.source.resolve()
    output = options.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if output.is_relative_to(source):
        raise ValueError('build outputs must be outside frozen source checkout')
    host_os = {'Linux': 'linux', 'Windows': 'windows', 'Darwin': 'darwin'}[platform.system()]
    host_machine = platform.machine()
    windows_machine = windows_native_machine() if host_os == 'windows' else None
    host_arch = windows_machine['nativeArch'] if windows_machine else {
        'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}[host_machine]
    if (host_os, host_arch) != (options.os, options.arch):
        raise ValueError('native host required; no cross build acceptance')
    if host_os == 'darwin' and subprocess.run(['sysctl', '-in', 'sysctl.proc_translated'], capture_output=True, text=True, check=False).stdout.strip() == '1':
        raise ValueError('Rosetta execution is not native architecture acceptance')
    if run(['git', 'rev-parse', 'HEAD'], source).strip() != manifest['sourceCommit']:
        raise ValueError('source SHA differs from manifest')
    if run(['git', 'rev-parse', 'HEAD^{tree}'], source).strip() != manifest['sourceTree']:
        raise ValueError('source tree differs from manifest')
    if run(['git', 'status', '--porcelain=v1', '--untracked-files=all'], source):
        raise ValueError('source checkout is dirty')
    env = dict(os.environ, GOTOOLCHAIN='local', GOMAXPROCS='2', CGO_ENABLED='1' if host_os == 'darwin' else '0',
               GOOS=host_os, GOARCH=host_arch)
    go_info = json.loads(run(['go', 'env', '-json', 'GOVERSION', 'GOHOSTOS', 'GOHOSTARCH', 'CC'], source, env))
    if go_info['GOVERSION'] != 'go' + manifest['Go'] or (go_info['GOHOSTOS'], go_info['GOHOSTARCH']) != (host_os, host_arch):
        raise ValueError('wrong Go toolchain/native host')
    compiler = None
    if host_os == 'darwin':
        sdk_path = run(['xcrun', '--sdk', 'macosx', '--show-sdk-path']).strip()
        cgo_flags = darwin_cgo_flags(sdk_path)
        env.update(CC=run(['xcrun', '--sdk', 'macosx', '--find', 'clang']).strip(),
                   SDKROOT=sdk_path, CGO_CFLAGS=cgo_flags, CGO_LDFLAGS=cgo_flags)
        run([env['CC'], '-isysroot', sdk_path, '-mmacosx-version-min=13.0',
             '-x', 'c', '-fsyntax-only', '-include', 'stdlib.h', os.devnull], env=env)
        compiler = {'version': run([env['CC'], '--version']), 'SDK': run(['xcrun', '--sdk', 'macosx', '--show-sdk-version']).strip(),
                    'SDKPath': sdk_path, 'SDKROOT': env['SDKROOT'], 'stdlibHeaderCheck': 'passed',
                    'cgoCflags': env['CGO_CFLAGS'], 'cgoLdflags': env['CGO_LDFLAGS']}
    def module(path, version):
        info = json.loads(run(['go', 'mod', 'download', '-json', path + '@' + version], source, env))
        if info.get('Error'):
            raise ValueError(info['Error'])
        expected_line = path + ' ' + version + ' ' + info['Sum']
        if expected_line not in (source / 'go.sum').read_text().splitlines():
            raise ValueError('module sum not present in frozen source')
        return info
    library = next(row for row in manifest['libraries'] if row['target'] == host_os + '_' + host_arch)
    info = module(library['module'], library['moduleVersion'])
    if info['Sum'] != library['moduleSum'] or info['Origin']['Hash'] != library['moduleOrigin']:
        raise ValueError('library module provenance differs')
    raw = Path(info['Dir']) / library['file']
    if raw.stat().st_size != library['bytes'] or digest(raw) != library['sha256']:
        raise ValueError('raw Cronet library byte mismatch')
    raw_data = raw.read_bytes()
    if hashlib.sha1(b'blob ' + str(len(raw_data)).encode() + b'\0' + raw_data).hexdigest() != library['gitBlob']:
        raise ValueError('raw Cronet library Git blob mismatch')
    wrapper = module('github.com/sagernet/cronet-go', manifest['wrapperVersion'])
    if wrapper['Origin']['Hash'] != manifest['wrapperCommit']:
        raise ValueError('wrapper source differs')
    wrapper_dir = Path(wrapper['Dir'])
    required = required_cronet_symbols(wrapper_dir, host_os, host_arch)
    if host_os == 'windows':
        metadata = inspect_binary(raw, host_os, host_arch)
        verify_required_exports(required, metadata['exports'])
    elif host_os == 'linux':
        symbols = run(['readelf', '--dyn-syms', '--wide', raw])
        exported = {line.split()[-1].split('@')[0] for line in symbols.splitlines() if ' UND ' not in line and len(line.split()) > 7}
        verify_required_exports(required, exported)
        metadata = inspect_binary(raw, host_os, host_arch)
    else:
        symbols = run(['xcrun', 'nm', '-gU', '-j', raw])
        exported = {line.strip().removeprefix('_') for line in symbols.splitlines()}
        verify_required_exports(required, exported)
        metadata = {'format': 'static archive', 'requiredSymbolsVerified': sorted(required),
                    'nativeNmOutputSHA256': hashlib.sha256(symbols.encode()).hexdigest(),
                    'byteMatchedPriorObjectInventory': library['observedNative']}
    metadata['requiredSymbolsVerified'] = sorted(required)
    name = f"polaris-box-{manifest['candidateVersion']}-{host_os}-{host_arch}"
    root = output / name
    root.mkdir(exist_ok=False)
    binary = root / ('sing-box.exe' if host_os == 'windows' else 'sing-box')
    tags = (source / 'release' / ('DEFAULT_BUILD_TAGS_WINDOWS' if host_os == 'windows' else 'DEFAULT_BUILD_TAGS')).read_text().strip()
    if host_os == 'linux':
        tags += ',with_purego'
    if 'with_gvisor' not in tags.split(','):
        raise ValueError('gVisor capability absent from actual preset')
    flags = (source / 'release/LDFLAGS').read_text().strip() + ' -s -w -X github.com/sagernet/sing-box/constant.Version=' + manifest['candidateVersion']
    command = ['go', 'build', '-mod=readonly', '-p', '1', '-trimpath', '-tags', tags, '-ldflags', flags, '-o', str(binary), './cmd/sing-box']
    run(command, source, env)
    diagnostics_env = dict(env)
    for key in ('LD_LIBRARY_PATH', 'LD_PRELOAD', 'DYLD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES'):
        diagnostics_env.pop(key, None)
    if host_os == 'windows':
        diagnostics_env['PATH'] = str(Path(os.environ['SystemRoot']) / 'System32')
    args = [str(binary), 'tools', 'cronet', '--expected-version', manifest['cronetVersion']]
    if host_os != 'darwin':
        sidecar = root / library['file']
        shutil.copyfile(raw, sidecar)
        args += ['--library', str(sidecar), '--sha256', library['sha256']]
    smoke = json.loads(run(args, source, diagnostics_env))
    if (smoke['os'], smoke['arch'], smoke['version'], smoke['gvisorCompiled']) != (host_os, host_arch, manifest['cronetVersion'], True):
        raise ValueError('native Cronet/gVisor capability receipt mismatch')
    negatives = []
    def reject_case(name, arguments):
        trial = subprocess.run([str(binary), 'tools', 'cronet'] + arguments, cwd=source,
                               env=diagnostics_env, capture_output=True, text=True, timeout=20)
        negatives.append(validate_cronet_rejection(name, trial))
    if host_os == 'darwin':
        reject_case('wrong-version', ['--expected-version', '0'])
        reject_case('static-rejects-sidecar', ['--expected-version', manifest['cronetVersion'], '--library', str(raw)])
    else:
        version_args = ['--expected-version', manifest['cronetVersion']]
        reject_case('missing-library-argument', version_args)
        reject_case('missing-path', version_args + ['--library', str(output / 'absent-library'), '--sha256', library['sha256']])
        reject_case('wrong-digest', version_args + ['--library', str(sidecar), '--sha256', '0' * 64])
        reject_case('wrong-version', ['--expected-version', '0', '--library', str(sidecar), '--sha256', library['sha256']])
        changed = output / ('changed-' + library['file'])
        changed_data = bytearray(raw_data)
        changed_data[len(changed_data) // 2] ^= 1
        changed.write_bytes(changed_data)
        reject_case('same-size-changed-bytes', version_args + ['--library', str(changed), '--sha256', library['sha256']])
        other_arch = 'arm64' if host_arch == 'amd64' else 'amd64'
        other = next(row for row in manifest['libraries'] if row['target'] == host_os + '_' + other_arch)
        foreign_info = module(other['module'], other['moduleVersion'])
        if foreign_info['Sum'] != other['moduleSum'] or foreign_info['Origin']['Hash'] != other['moduleOrigin']:
            raise ValueError('foreign-machine fixture module differs')
        foreign = Path(foreign_info['Dir']) / other['file']
        if digest(foreign) != other['sha256']:
            raise ValueError('foreign-machine fixture byte mismatch')
        reject_case('wrong-machine-with-matching-byte-hash', version_args + ['--library', str(foreign), '--sha256', other['sha256']])
        if host_os == 'windows':
            missing_abi = Path(os.environ['SystemRoot']) / 'System32/version.dll'
        else:
            missing_abi = output / 'missing-cronet-abi.so'
            fixture = output / 'missing-cronet-abi.c'
            fixture.write_text('void *Cronet_Buffer_Create(void) { return 0; }\n')
            run(['cc', '-shared', '-fPIC', '-o', missing_abi, fixture])
        reject_case('missing-cronet-ABI-with-matching-byte-hash', version_args + ['--library', str(missing_abi), '--sha256', digest(missing_abi)])
    (output / 'cronet-native-negative-cases.json').write_text(json.dumps(negatives, indent=2) + '\n')
    regression_tags = tags if 'with_purego' in tags.split(',') else tags + ',with_purego'
    tests = run(['go', 'test', '-mod=readonly', '-p', '1', '-parallel', '2', '-count=1', '-v', '-run',
                 '^(TestStackCapabilitiesWithoutSystemTun|TestPolarisGVisorBuildEntrypoints|TestCronetDiagnosticRequiresExactLibraryBytes|TestCronetDiagnosticRejectsFIFOWithoutBlocking)$',
                 '-tags', regression_tags, '-ldflags', (source / 'release/LDFLAGS').read_text().strip(),
                 './protocol/tun', './cmd/internal/build_libbox', './cmd/sing-box'], source, env)
    (output / 'regressions.log').write_text(tests)
    licenses = root / 'licenses'
    licenses.mkdir()
    for file, expected in manifest['licenseFiles'].items():
        original = producer / 'release/licenses' / file
        if digest(original) != expected:
            raise ValueError('license input mismatch')
        shutil.copyfile(original, licenses / file)
    receipt = {'sourceCommit': manifest['sourceCommit'], 'sourceTree': manifest['sourceTree'],
               'upstreamBaseline': manifest['upstreamBaselineCommit'], 'sourceRole': manifest['sourceRole'], 'sourceOverlay': 0,
               'workflowCommit': os.environ.get('GITHUB_SHA'), 'workflowRun': os.environ.get('GITHUB_RUN_ID'),
               'workflowAttempt': os.environ.get('GITHUB_RUN_ATTEMPT'), 'job': os.environ.get('GITHUB_JOB'),
               'runnerOS': platform.platform(), 'pythonMachine': host_machine, 'windowsHostMachine': windows_machine, 'Go': go_info, 'compiler': compiler, 'CGO_ENABLED': env['CGO_ENABLED'],
               'tags': tags, 'ldflags': flags, 'buildCommand': command, 'buildInfo': run(['go', 'version', '-m', binary], source, env),
               'coreNative': inspect_binary(binary, host_os, host_arch), 'cronet': library, 'cronetNative': metadata,
               'nativeCronetSmoke': smoke, 'nativeCronetNegativeCases': negatives, 'sourceReviewed': False, 'licenseClosure': manifest['licenseClosure'],
               'candidateOnly': True, 'publicationEligible': False, 'distributionSigningPerformed': False,
               'deviceTunAcceptance': False, 'mobileFinalLinkAcceptance': False,
               'payloadHashes': {file.relative_to(root).as_posix(): digest(file) for file in root.rglob('*') if file.is_file()}}
    (root / 'provenance.json').write_text(json.dumps(receipt, indent=2) + '\n')
    checksums = [(digest(file), file.relative_to(root).as_posix()) for file in sorted(root.rglob('*')) if file.is_file()]
    (root / 'SHA256SUMS').write_text(''.join(f'{sha}  {file}\n' for sha, file in checksums))
    archive = output / (name + ('.zip' if host_os == 'windows' else '.tar.gz'))
    members = package(root, archive, host_os)
    with tempfile.TemporaryDirectory(prefix='polaris-extracted-') as directory:
        extracted = Path(directory)
        for member, data in members.items():
            file = extracted / member
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(data)
        core = extracted / name / binary.name
        core.chmod(0o755)
        probe = [str(core), 'tools', 'cronet', '--expected-version', manifest['cronetVersion']]
        if host_os != 'darwin':
            probe += ['--library', str(extracted / name / library['file']), '--sha256', library['sha256']]
        extracted_smoke = json.loads(run(probe, source, diagnostics_env))
        if any(extracted_smoke[key] != smoke[key] for key in ('os', 'arch', 'version', 'linkage', 'gvisorCompiled')):
            raise ValueError('extracted native capability receipt differs')
        receipt['extractedNativeCronetSmoke'] = extracted_smoke
    if run(['git', 'rev-parse', 'HEAD'], source).strip() != manifest['sourceCommit'] or run(['git', 'rev-parse', 'HEAD^{tree}'], source).strip() != manifest['sourceTree']:
        raise ValueError('source SHA/tree changed during producer')
    if run(['git', 'status', '--porcelain=v1', '--untracked-files=all'], source):
        raise ValueError('frozen source changed during producer')
    receipt['archive'] = {'name': archive.name, 'bytes': archive.stat().st_size, 'sha256': digest(archive),
                          'members': {name: hashlib.sha256(data).hexdigest() for name, data in members.items()}}
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'archive': receipt['archive']['name'], 'sha256': receipt['archive']['sha256'],
                      'nativeSmokePassed': True, 'publicationEligible': False}))


if __name__ == '__main__':
    main()
