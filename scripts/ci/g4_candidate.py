"""Candidate-only retirement gates. No tags, release, upload or device access."""
import json
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile

SDK = 'github.com/sagernet/tailscale'
OWNED_SDK = 'github.com/polaris-arch/tailscale'
LOCAL_SDK = './third_party/tailscale'
LOCAL_MANIFEST = 'release/dependency-sources/tailscale-runtime-manifest.json'
LOCAL_MANIFEST_SHA256 = '25394ab3321f36dcf117cf1027bf89adaa529f5f27a7921eab3a9e7e31fc0ec6'
GO_VERSION = (Path(__file__).resolve().parents[2] / 'release/GO_VERSION').read_text().strip()
# This is the product's existing linker contract (including its reviewed
# runtime linkname use), not a new test-only relaxation.
PRODUCTION_LDFLAGS = (Path(__file__).resolve().parents[2] / 'release/LDFLAGS').read_text().strip()
SDK_PACKAGES = (
    'util/dirscope', 'util/execqueue', 'control/controlclient', 'ipn/store',
    'ipn/ipnlocal', 'ipn/ipnlocal/netmapcache', 'feature/acme', 'tka', 'tsnet',
    'net/netmon', 'wgengine/magicsock', 'wgengine',
)
FORK_PACKAGES = (
    './option', './adapter', './daemon', './experimental/libbox', './experimental/libbox/internal/oomprofile', './protocol/tailscale',
    './common/badversion', './cmd/internal/read_tag',
    './cmd/internal/update_android_version', './cmd/internal/update_desktop_version',
    './cmd/internal/update_apple_version',
)


def verify_local_sdk(root):
    """Verify the complete selected carrier, not just the modified files."""
    root = Path(root).resolve(strict=True)
    manifest_path = root / LOCAL_MANIFEST
    if manifest_path.is_symlink():
        raise RuntimeError('local SDK manifest must be a regular file')
    encoded = manifest_path.read_bytes()
    if hashlib.sha256(encoded).hexdigest() != LOCAL_MANIFEST_SHA256:
        raise RuntimeError('local SDK manifest identity changed')
    manifest = json.loads(encoded)
    if (manifest.get('schema') != 'polaris-tailscale-runtime-source-v1'
            or manifest.get('module') != SDK
            or manifest.get('directory') != 'third_party/tailscale'
            or manifest.get('repository') != 'polaris-arch/tailscale'
            or manifest.get('commit') != '2f88101070463571831f8fdca7e0d58cbe26cb4b'
            or manifest.get('original_git_tree') != '06fbc9361160494eb4625387ea57f35c6b2c1fc5'):
        raise RuntimeError('local SDK original source identity changed')
    directory = root / 'third_party/tailscale'
    if (root / 'third_party').is_symlink() or directory.is_symlink():
        raise RuntimeError('local SDK directory must not redirect')
    expected = {}
    for row in manifest['files']:
        path = PurePosixPath(row['path'])
        if (path.is_absolute() or '..' in path.parts or str(path) != row['path']
                or row['path'] in expected or row['mode'] not in ('100644', '100755', '120000')):
            raise RuntimeError('invalid local SDK manifest path or mode')
        expected[row['path']] = row
    actual = {p.relative_to(directory).as_posix(): p for p in directory.rglob('*')
              if p.is_file() or p.is_symlink()}
    if set(actual) != set(expected):
        raise RuntimeError('local SDK file set changed')
    for name, path in actual.items():
        row = expected[name]
        if any(parent.is_symlink() for parent in path.parents if parent != root):
            raise RuntimeError('local SDK parent path redirects')
        if row['mode'] == '120000':
            if not path.is_symlink():
                raise RuntimeError('local SDK symlink type changed')
            target = os.readlink(path)
            relative = PurePosixPath(target)
            if (relative.is_absolute() or '..' in relative.parts
                    or target != row['symlink_target']
                    or (path.parent / target).resolve() not in
                    {p.resolve() for p in actual.values() if not p.is_symlink()}):
                raise RuntimeError('local SDK symlink target changed')
            data = target.encode()
        else:
            if path.is_symlink() or not path.is_file():
                raise RuntimeError('local SDK file type changed')
            mode = '100755' if path.stat().st_mode & 0o111 else '100644'
            if mode != row['mode']:
                raise RuntimeError('local SDK executable mode changed')
            data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != row['sha256']:
            raise RuntimeError('local SDK content changed: ' + name)
    declarations = re.findall(r'^module[ \t]+([^\s]+)[ \t]*$',
                              (directory / 'go.mod').read_text(), re.M)
    if declarations != [SDK]:
        raise RuntimeError('local SDK module declaration changed')
    return manifest


def require_owned_sdk(module, root=None):
    replacement = module.get('Replace', {})
    if module.get('Path') == SDK and replacement.get('Path') == LOCAL_SDK:
        if root is None or replacement.get('Version'):
            raise RuntimeError('local SDK requires exact repository evidence')
        verify_local_sdk(root)
        if Path(replacement.get('Dir', '')).resolve() != (Path(root) / 'third_party/tailscale').resolve():
            raise RuntimeError('resolved local SDK directory differs')
        return replacement
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
    module = json.loads(run(['go', 'list', '-m', '-json', SDK], capture_output=True).stdout)
    if module.get('Replace', {}).get('Path') == LOCAL_SDK:
        require_owned_sdk(module, root)
    else:
        # Download only the original remote branch to obtain its verified h1.
        if module.get('Replace', {}).get('Path') != OWNED_SDK:
            raise RuntimeError('G4 SDK replacement is not an owned source')
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
