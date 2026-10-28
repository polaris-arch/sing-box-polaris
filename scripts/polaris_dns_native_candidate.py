#!/usr/bin/env python3
"""Build fixed-source DNS technical candidates only. No publication or App admission."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

from polaris_go_environment import isolated_go_environment, validate_go_arguments, verify_source
import polaris_dns_identity as dns
from polaris_native_candidate import (
    darwin_cgo_flags, digest, inspect_binary, package, required_cronet_symbols,
    run, validate_cronet_rejection, verify_required_exports, windows_native_machine,
)

DNS_INPUT_SHA256 = '49ad7a307716c784ed7d04921635b257c766cd18f568502199ee7578713f79fb'


def checked_license_input(producer, name, expected):
    # Both manifests still hash the packaged filename NOTICE. Select the DNS
    # source payload without changing either fixed manifest or the a01 lane.
    original = producer / 'release/licenses' / ('DNS-NOTICE' if name == 'NOTICE' else name)
    if digest(original) != expected:
        raise ValueError('license input mismatch')
    return original


def require_vcs_checkout(source):
    # Pinned Go 1.25.5 discovers Git via a .git directory, not a worktree gitfile.
    # Fail before downloads/builds; actual binary VCS metadata remains mandatory.
    if not (source / '.git').is_dir():
        raise ValueError('Go 1.25.5 VCS stamping requires a standalone .git directory checkout')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--os', choices=['linux', 'windows', 'darwin'], required=True)
    parser.add_argument('--arch', choices=['amd64', 'arm64'], required=True)
    parser.add_argument('--expected-producer-head', required=True)
    options = parser.parse_args()
    producer = Path(__file__).resolve().parents[1]
    verify_source(producer, options.expected_producer_head)
    input_bytes = (producer / 'release/polaris-dns-candidate-inputs.json').read_bytes()
    if dns.sha(input_bytes) != DNS_INPUT_SHA256:raise ValueError('fixed DNS manifest bytes differ')
    manifest = json.loads(input_bytes)
    if (options.os, options.arch) not in dns.TARGETS:raise ValueError('only four desktop consumers allowed')
    source = options.source.resolve()
    require_vcs_checkout(source)
    output = options.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
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
    dns.check_source(source, manifest)
    env = isolated_go_environment(dict(os.environ, GOMAXPROCS='2', CGO_ENABLED='1' if host_os == 'darwin' else '0', GOOS=host_os, GOARCH=host_arch, GOEXPERIMENT='', GOAMD64='v1', GOARM64='v8.0'))
    for key in ('GIT_DIR','GIT_WORK_TREE','GIT_INDEX_FILE','CGO_CFLAGS','CGO_CPPFLAGS','CGO_CXXFLAGS','CGO_FFLAGS','CGO_LDFLAGS'):
        env.pop(key,None)
    go = Path(shutil.which('go')).resolve()
    go_commands = []
    def go_run(arguments, cwd=None, env=env):
        dns.check_source(source, manifest)
        actual_env = isolated_go_environment(env)
        args = [str(go)] + [str(x) for x in arguments[1:]]
        if args[1:4] == ['mod','download','-json']:
            allowed = {x['module']+'@'+x['moduleVersion'] for x in manifest['libraries']}
            allowed.add('github.com/sagernet/cronet-go@'+manifest['wrapperVersion'])
            if len(args)!=5 or args[4] not in allowed:raise ValueError('unapproved module download')
        elif args[1:3] == ['tool','buildid']:
            if len(args)!=4 or Path(args[3]).resolve().parent.parent != output:raise ValueError('unapproved BuildID read')
        else:validate_go_arguments(args[1:])
        result = subprocess.run(args,cwd=cwd,env=actual_env,capture_output=True,text=True)
        go_commands.append({'command':args,'cwd':str(cwd), 'exitCode':result.returncode,
            'isolatedSettings':{k:actual_env[k] for k in ('GOENV','GOWORK','GOFLAGS','GOTOOLCHAIN')},
            'stdoutSha256':dns.sha(result.stdout.encode()),'stderrSha256':dns.sha(result.stderr.encode())})
        (output/'go-invocations.json').write_text(json.dumps(go_commands,indent=2)+'\n')
        dns.check_source(source, manifest)
        if result.returncode:raise RuntimeError(f'{args!r}: exit {result.returncode}\n{result.stdout}\n{result.stderr}')
        return result.stdout
    source_fp = json.loads(run([sys.executable, source/'scripts/polaris_source_fingerprint.py',
        '--repo',source,'--expected-head',manifest['sourceCommit'],'--go',go,
        '--module-list-output',output/'actual-module-list.json'],source,env))
    (output/'actual-source-fingerprint.json').write_text(json.dumps(source_fp,indent=2)+'\n')
    common_identity = dns.source_identity(source_fp,manifest)
    go_info = json.loads(go_run(['go', 'env', '-json', 'GOVERSION', 'GOHOSTOS', 'GOHOSTARCH', 'CC'], source, env))
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
        info = json.loads(go_run(['go', 'mod', 'download', '-json', path + '@' + version], source, env))
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
    platform_identity = dns.platform_identity(common_identity,manifest,host_os,host_arch,tags)
    flags = (source / 'release/LDFLAGS').read_text().strip() + ' -s -w -X github.com/sagernet/sing-box/constant.Version=' + manifest['candidateVersion']
    flags += ' -buildid=' + platform_identity['buildID']
    command = ['go', 'build', '-buildvcs=true', '-mod=readonly', '-p', '1', '-trimpath', '-tags', tags, '-ldflags', flags, '-o', str(binary), './cmd/sing-box']
    go_run(command, source, env)
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
    tests = go_run(['go', 'test', '-trimpath', '-mod=readonly', '-p', '1', '-parallel', '2', '-count=1', '-v', '-run',
                 '^(TestStackCapabilitiesWithoutSystemTun|TestPolarisGVisorBuildEntrypoints|TestCronetDiagnosticRequiresExactLibraryBytes|TestCronetDiagnosticRejectsFIFOWithoutBlocking)$',
                 '-tags', regression_tags, '-ldflags', (source / 'release/LDFLAGS').read_text().strip(),
                 './protocol/tun', './cmd/internal/build_libbox', './cmd/sing-box'], source, env)
    (output / 'regressions.log').write_text(tests)
    dns_tests = go_run(['go','test','-trimpath','-mod=readonly','-p','1','-parallel','2','-count=1','-v','-run','^TestWindows(DNS|Lifecycle)', 'github.com/sagernet/sing-tun'],source,env)
    (output/'windows-dns-mocks-native.log').write_text(dns_tests)
    build_info = go_run(['go','version','-m',binary],source,env)
    build_id = go_run(['go','tool','buildid',binary],source,env).strip()
    version_output = run([binary,'version'],source,diagnostics_env)
    (output/'actual-buildinfo.txt').write_text(build_info)
    (output/'actual-buildid.txt').write_text(build_id+'\n')
    (output/'actual-core-version.txt').write_text(version_output)
    binary_identity = dns.validate_build_info(build_info,manifest,platform_identity,build_id,version_output)
    licenses = root / 'licenses'
    licenses.mkdir()
    for file, expected in manifest['licenseFiles'].items():
        original = checked_license_input(producer, file, expected)
        shutil.copyfile(original, licenses / file)
    receipt = {'sourceCommit': manifest['sourceCommit'], 'sourceTree': manifest['sourceTree'],
               'upstreamBaseline': manifest['upstreamBaselineCommit'], 'sourceRole': manifest['sourceRole'], 'sourceOverlay': 0,
               'workflowCommit': os.environ.get('GITHUB_SHA'), 'workflowRun': os.environ.get('GITHUB_RUN_ID'),
               'workflowAttempt': os.environ.get('GITHUB_RUN_ATTEMPT'), 'job': os.environ.get('GITHUB_JOB'),
               'runnerOS': platform.platform(), 'pythonMachine': host_machine, 'windowsHostMachine': windows_machine, 'Go': go_info, 'compiler': compiler, 'CGO_ENABLED': env['CGO_ENABLED'],
               'tags': tags, 'ldflags': flags, 'buildCommand': command, 'buildInfo': build_info,
               'coreNative': inspect_binary(binary, host_os, host_arch), 'cronet': library, 'cronetNative': metadata,
               'nativeCronetSmoke': smoke, 'nativeCronetNegativeCases': negatives, 'sourceReviewed': False, 'licenseClosure': manifest['licenseClosure'],
               'candidateOnly': True, 'publicationEligible': False, 'distributionSigningPerformed': False,
               'deviceTunAcceptance': False, 'mobileFinalLinkAcceptance': False,
               'payloadHashes': {file.relative_to(root).as_posix(): digest(file) for file in root.rglob('*') if file.is_file()}}
    receipt.update(schema='polaris-dns-technical-native-v1', actualSourceFingerprint=source_fp,
        commonSourceIdentity=common_identity, platformInputIdentity=platform_identity,
        actualBinaryIdentity=binary_identity, actualBuildID=build_id, actualCoreVersion=version_output,
        replacementPatchSha256=manifest['replacementBinding']['patchSha256'],
        producerHead=options.expected_producer_head, inputManifestSha256=DNS_INPUT_SHA256,
        isolatedGoInvocations=go_commands, AppAdmissible=False, realWindowsDNSAcceptance=False)
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
    dns.check_source(source,manifest)
    verify_source(producer,options.expected_producer_head)
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'archive': receipt['archive']['name'], 'sha256': receipt['archive']['sha256'],
                      'nativeSmokePassed': True, 'publicationEligible': False}))


if __name__ == '__main__':
    main()
