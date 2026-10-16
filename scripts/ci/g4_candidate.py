"""Candidate-only retirement gates. No tags, release, upload or device access."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

SDK = 'github.com/sagernet/tailscale'
OWNED_SDK = 'github.com/polaris-arch/tailscale'
GO_VERSION = (Path(__file__).resolve().parents[2] / 'release/GO_VERSION').read_text().strip()
# This is the product's existing linker contract (including its reviewed
# runtime linkname use), not a new test-only relaxation.
PRODUCTION_LDFLAGS = (Path(__file__).resolve().parents[2] / 'release/LDFLAGS').read_text().strip()
SDK_PACKAGES = (
    'util/dirscope', 'util/execqueue', 'control/controlclient', 'ipn/store',
    'ipn/ipnlocal', 'ipn/ipnlocal/netmapcache', 'feature/acme', 'tka', 'tsnet',
)
FORK_PACKAGES = (
    './adapter', './daemon', './experimental/libbox', './protocol/tailscale',
    './common/badversion', './cmd/internal/read_tag',
    './cmd/internal/update_android_version', './cmd/internal/update_desktop_version',
    './cmd/internal/update_apple_version',
)


def require_owned_sdk(module):
    replacement = module.get('Replace', {})
    if (module.get('Path') != SDK or replacement.get('Path') != OWNED_SDK or
            not replacement.get('Version') or not replacement.get('Sum', '').startswith('h1:')):
        raise RuntimeError('G4 requires the immutable owned SDK version and verified h1; no upstream/local substitute')
    return replacement


def commands():
    # Tests in a dependency are not discovered by `go test ./...` in this module.
    return [
        ['go', 'test', '-race', '-count=1', '-timeout=10m',
         *[SDK + '/' + package for package in SDK_PACKAGES]],
        ['go', 'test', '-race', '-count=1', '-timeout=10m', '-ldflags=' + PRODUCTION_LDFLAGS, '-tags=with_tailscale', *FORK_PACKAGES],
    ]


def main():
    if sys.platform not in ('linux', 'darwin'):
        raise RuntimeError('candidate runtime gates require Linux or macOS')
    env = dict(os.environ, GOTOOLCHAIN='local', GOFLAGS='-mod=readonly')
    root = Path(__file__).resolve().parents[2]

    def run(command, **kwargs):
        print('+', ' '.join(command), flush=True)
        return subprocess.run(command, cwd=root, env=env, check=True, text=True, **kwargs)

    if run(['go', 'env', 'GOVERSION'], capture_output=True).stdout.strip() != 'go' + GO_VERSION:
        raise RuntimeError('candidate gates require pinned Go' + GO_VERSION)
    run(['go', 'mod', 'download', SDK])
    module = json.loads(run(['go', 'list', '-m', '-json', SDK], capture_output=True).stdout)
    require_owned_sdk(module)
    print(json.dumps({'candidateSDK': module}, sort_keys=True), flush=True)
    run(['go', 'mod', 'verify'])
    for command in commands():
        run(command)
    if sys.platform == 'linux':
        # Compile only; do not describe a cross target binary as an executed test.
        # This specifically includes directory_taildrop_other.go, absent on Unix.
        with tempfile.TemporaryDirectory(prefix='g4-cross-') as temporary:
            cross_env = dict(env, GOOS='windows', GOARCH='amd64', CGO_ENABLED='0')
            command = ['go', 'test', '-c', '-ldflags=' + PRODUCTION_LDFLAGS, '-tags=with_tailscale',
                       '-o', str(Path(temporary) / 'tailscale.test.exe'), './protocol/tailscale']
            print('+ cross compile only:', ' '.join(command), flush=True)
            subprocess.run(command, cwd=root, env=cross_env, check=True)
    # Dependency resolution or test tooling must not quietly update source pins.
    run(['git', 'diff', '--exit-code', '--', 'go.mod', 'go.sum'])


if __name__ == '__main__':
    main()
