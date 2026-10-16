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
from pathlib import Path
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
    goroot = Path(subprocess.check_output(['go', 'env', 'GOROOT'], text=True).strip()).resolve()
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
    test_file = output / 'root_removeall_polaris_windows_test.go';test_file.write_text(test, encoding='utf-8', newline='\n')
    overlay = output / 'overlay.json'
    overlay.write_text(json.dumps({'Replace': {str(goroot / 'src/os/root_removeall_polaris_windows_test.go'): str(test_file)}}) + '\n')
    command = ['go', 'test', '-json', '-p=2', '-parallel=1', '-count=1', '-timeout=3m',
               '-overlay=' + str(overlay), '-run=^TestPolarisRootRemoveAllConfinement$', 'os']
    receipt = {'sourceCommit': os.environ['GITHUB_SHA'], 'goVersion': actual_go, 'manifestSHA256': manifest_hash,
               'patchSHA256': entry['patchSHA256'], 'preservedRootSources': measured,
               'regressionSHA256': entry['rootRemoveAllRegressionSHA256'], 'command': command,
               'scope': 'official Root on hosted Windows; normal + junction/symlink confinement; native and forced legacy Deleteat fallback',
               'notVerified': ['actual Win7 runtime', 'rebuilt legacy compiler runtime']}
    # Parent owns this process tree, deadline, scratch/cache slots and original log.
    result = subprocess.run(command, cwd=ROOT, env=dict(os.environ, GOTOOLCHAIN='local', GOENV='off'))
    receipt['exitCode'] = result.returncode
    (output / 'root-gate.json').write_text(json.dumps(receipt, indent=2) + '\n')
    if result.returncode:
        raise RuntimeError('Windows Root confinement regression failed')


if __name__ == '__main__':
    main()
