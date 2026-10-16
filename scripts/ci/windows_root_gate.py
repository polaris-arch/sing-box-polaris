"""Run preserved official Root deletion + forced legacy fallback on Windows CI.

Only the source-owned regression test is overlaid. Production compatibility
patches no longer change these official handle-relative files. This is not a
claim that an actual Win7 VM or the rebuilt legacy compiler has been tested.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PureWindowsPath
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def regression_source(patch):
    part = patch.split('+++ b/src/os/root_removeall_polaris_windows_test.go\n')
    if len(part) != 2:
        raise ValueError('missing/duplicate source-owned Windows Root regression')
    lines = part[1].splitlines()
    match = re.fullmatch(r'@@ -0,0 \+1,(\d+) @@', lines[0])
    if not match or int(match[1]) != len(lines) - 1 or not all(line.startswith('+') for line in lines[1:]):
        raise ValueError('unexpected Windows Root regression patch layout')
    return ''.join(line[1:] + '\n' for line in lines[1:])


def combined_test_source(host, regression):
    if host.count('package os_test') != 1 or host.count('import (') != 1:
        raise ValueError('unexpected official Windows Root test host')
    # All other regression imports already exist in the pinned official file.
    for required in ['"internal/syscall/windows"', '"os"', '"path/filepath"', '"testing"']:
        if required not in host:
            raise ValueError('Windows Root test host import missing: ' + required)
    if '"os/exec"' in host or 'TestPolarisRootRemoveAllConfinement' in host:
        raise ValueError('Windows Root test host unexpectedly contains overlay inputs')
    marker = 'func TestPolarisRootRemoveAllConfinement(t *testing.T) {'
    if regression.count(marker) != 1:
        raise ValueError('Windows Root regression entry mismatch')
    return host.replace('import (', 'import (\n\t"os/exec"', 1) + '\n' + regression[regression.index(marker):]


def overlay_replacements(os_directory, test_file):
    # Go's loader keys overlays by the lexical go-list Dir. Resolve/realpath can
    # cross setup-go's C: junction into D: and silently stop applying the overlay.
    directory = PureWindowsPath(os_directory)
    if not directory.is_absolute():
        raise ValueError('Go os package directory is not an absolute Windows path')
    return {'Replace': {str(directory / 'root_windows_test.go'): str(test_file)}}


def main():
    parser = argparse.ArgumentParser();parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'win32' or os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('GITHUB_REPOSITORY') != 'polaris-arch/sing-box-polaris':
        raise RuntimeError('Windows Root runtime gate is owned remote CI only')
    spec = importlib.util.spec_from_file_location('legacy_go', ROOT / '.github/setup_legacy_go.py')
    legacy = importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
    manifest, entry, patch, _, manifest_hash = legacy.toolchain_input('windows7', 'linux-amd64')
    actual_go = subprocess.check_output(['go', 'env', 'GOVERSION'], text=True).strip()
    if actual_go != 'go' + manifest['version']:
        raise RuntimeError('Windows Root gate Go version mismatch')
    raw_goroot = subprocess.check_output(['go', 'env', 'GOROOT'], text=True).strip()
    goroot = Path(raw_goroot)  # Preserve the selected Go toolchain's junction spelling.
    raw_os_directory = subprocess.check_output(['go', 'list', '-f', '{{.Dir}}', 'os'],
                                              env=dict(os.environ, GOTOOLCHAIN='local', GOENV='off'), text=True).strip()
    measured = {name: legacy.file_hash(goroot / name) for name in entry['preservedRootSources']}
    if measured != entry['preservedRootSources']:
        raise RuntimeError('official preserved Root source bytes differ')
    raw_patch = patch.read_text()
    # Fail if a later compatibility edit quietly reintroduces an os.Root fallback.
    for name in measured:
        if 'diff --git a/' + name + ' ' in raw_patch:
            raise RuntimeError('legacy patch modifies preserved Root confinement source')
    test = regression_source(raw_patch)
    if hashlib.sha256(test.encode()).hexdigest() != entry['rootRemoveAllRegressionSHA256']:
        raise RuntimeError('Windows Root regression source hash mismatch')
    output = args.output.resolve();output.mkdir(parents=True, exist_ok=True)
    # Overlay an existing, discovered os_test file. Adding a synthetic new
    # filename to the standard library overlay did not make go test discover it.
    host = Path(raw_os_directory) / 'root_windows_test.go'
    host_raw = host.read_bytes()
    host_sha = hashlib.sha256(host_raw).hexdigest()
    if host_sha != entry['rootRemoveAllTestHostSHA256']:
        raise RuntimeError('official Windows Root test host bytes differ')
    combined = combined_test_source(host_raw.decode(), test)
    test_file = output / 'root_windows_test.go';test_file.write_text(combined, encoding='utf-8', newline='\n')
    overlay = output / 'overlay.json'
    replacements = overlay_replacements(raw_os_directory, test_file)
    overlay.write_text(json.dumps(replacements) + '\n')
    command = ['go', 'test', '-json', '-p=2', '-parallel=1', '-count=1', '-timeout=3m',
               '-overlay=' + str(overlay), '-run=^TestPolarisRootRemoveAllConfinement$', 'os']
    receipt = {'sourceCommit': os.environ['GITHUB_SHA'], 'goVersion': actual_go, 'manifestSHA256': manifest_hash,
               'patchSHA256': entry['patchSHA256'], 'preservedRootSources': measured,
               'regressionSHA256': entry['rootRemoveAllRegressionSHA256'],
               'rawGOROOT': raw_goroot, 'rawOSPackageDirectory': raw_os_directory,
               'overlayHostKey': next(iter(replacements['Replace'])),
               'hostSHA256': host_sha, 'combinedTestSHA256': hashlib.sha256(combined.encode()).hexdigest(), 'command': command,
               'scope': 'official Root on hosted Windows; normal + junction/symlink confinement; native and forced legacy Deleteat fallback',
               'notVerified': ['actual Win7 runtime', 'rebuilt legacy compiler runtime']}
    # First demand actual Go test discovery. Merely presenting overlay source
    # and obtaining exit0 ('no tests to run') cannot satisfy this gate.
    discover = ['go', 'test', '-p=2', '-overlay=' + str(overlay),
                '-list=^TestPolarisRootRemoveAllConfinement$', 'os']
    receipt['discoveryCommand'] = discover
    receipt['exitCode'] = None
    try:
        discovery = subprocess.run(discover, cwd=ROOT, env=dict(os.environ, GOTOOLCHAIN='local', GOENV='off'),
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        (output / 'test-discovery.log').write_text(discovery.stdout)
        receipt['discoveryExitCode'] = discovery.returncode
        if discovery.returncode or discovery.stdout.splitlines().count('TestPolarisRootRemoveAllConfinement') != 1:
            raise RuntimeError('actual Go test discovery omitted the required Root regression')
        # Parent owns this process tree, deadline and scratch/cache slots.
        result = subprocess.run(command, cwd=ROOT, env=dict(os.environ, GOTOOLCHAIN='local', GOENV='off'))
        receipt['exitCode'] = result.returncode
        if result.returncode:
            raise RuntimeError('Windows Root confinement regression failed')
    finally:
        after = {name: legacy.file_hash(goroot / name) for name in entry['preservedRootSources']}
        receipt['preservedRootSourcesAfter'] = after
        receipt['testHostAfterSHA256'] = legacy.file_hash(host)
        (output / 'root-gate.json').write_text(json.dumps(receipt, indent=2) + '\n')
        if after != measured or receipt['testHostAfterSHA256'] != host_sha:
            raise RuntimeError('official Windows Root sources changed during test overlay')


if __name__ == '__main__':
    main()
