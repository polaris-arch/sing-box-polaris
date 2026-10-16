"""Build/cache verified source-owned Go compatibility toolchains on CI only."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def toolchain_input(mode, host):
    raw = (ROOT / '.github/go-toolchains.json').read_bytes()
    manifest = json.loads(raw)
    if manifest['version'] != (ROOT / 'release/GO_VERSION').read_text().strip():
        raise RuntimeError('Go manifest/version mismatch')
    entry = manifest['legacy'][mode]
    patch = ROOT / entry['patch']
    if not patch.resolve().is_relative_to(ROOT / '.github/patches'):
        raise RuntimeError('patch escaped source-owned directory')
    if file_hash(patch) != entry['patchSHA256']:
        raise RuntimeError('source-owned patch hash mismatch')
    archive = manifest['archives'][host]
    return manifest, entry, patch, archive, hashlib.sha256(raw).hexdigest()


def main(mode):
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('GITHUB_REPOSITORY') != 'polaris-arch/sing-box-polaris':
        raise RuntimeError('legacy toolchain installation is restricted to the owned CI runner')
    host = {'Linux': 'linux', 'Darwin': 'darwin'}[platform.system()] + '-' + {'x86_64': 'amd64', 'arm64': 'arm64', 'aarch64': 'arm64'}[platform.machine()]
    manifest, entry, patch, archive, manifest_hash = toolchain_input(mode, host)
    target = Path.home() / 'go' / entry['target']
    marker = target / 'polaris-toolchain.json'
    identity = {'goVersion': 'go' + manifest['version'], 'manifestSHA256': manifest_hash,
                'archiveSHA256': archive['sha256'], 'patchSHA256': entry['patchSHA256'],
                'officialCommit': manifest['officialCommit'], 'patchSourceCommits': entry['sourceCommits']}
    if target.is_symlink():
        raise RuntimeError("toolchain target must not be a symlink")
    if target.exists():
        measured = json.loads(marker.read_text())
        if any(measured.get(k) != v for k, v in identity.items()):
            raise RuntimeError('restored compatibility toolchain input mismatch; do not reuse this cache')
        expected_executables = {'bin/go', 'pkg/tool/' + host.replace('-', '_') + '/link'}
        if set(measured.get('executables', {})) != expected_executables:
            raise RuntimeError('restored toolchain executable inventory mismatch')
        for path, digest in measured['executables'].items():
            if file_hash(target / path) != digest:
                raise RuntimeError('restored toolchain executable mismatch')
        print(json.dumps({'cacheValidated': True, **measured}, sort_keys=True))
        return
    runner_temp = Path(os.environ['RUNNER_TEMP']).resolve()
    if shutil.disk_usage(runner_temp).free < 11 * 1024 ** 3:
        raise RuntimeError("legacy toolchain requires 3GiB growth plus 8GiB headroom")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='polaris-go-compat-', dir=runner_temp) as scratch_name:
        scratch = Path(scratch_name)
        downloaded = scratch / archive['filename']
        count = 0
        with urllib.request.urlopen('https://go.dev/dl/' + archive['filename'], timeout=60) as response, downloaded.open('wb') as output:
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                if count > archive['bytes']:
                    raise RuntimeError('official Go archive exceeded pinned size')
                output.write(chunk)
        if count != archive['bytes'] or file_hash(downloaded) != archive['sha256']:
            raise RuntimeError('official Go archive size/hash mismatch')
        bootstrap = scratch / 'bootstrap'
        bootstrap.mkdir()
        with tarfile.open(downloaded) as tar:
            members = tar.getmembers()
            if len(members) > 25000 or sum(m.size for m in members) > 1024 ** 3:
                raise RuntimeError('official Go archive exceeds extraction budget')
            if any(not (m.name == 'go' or m.name.startswith('go/')) or m.issym() or m.islnk() for m in members):
                raise RuntimeError('unexpected official Go archive layout')
            tar.extractall(bootstrap, members=members, filter='data')
        shutil.copytree(bootstrap / 'go', target)
        env = dict(os.environ, GOTOOLCHAIN='local', GOROOT_BOOTSTRAP=str(bootstrap / 'go'),
                   GOROOT_FINAL=str(target), GOMAXPROCS='2')
        env.pop('GOROOT', None)
        # Source-only changes to cmd/link do not modify the shipped linker binary.
        # Rebuild all tools from the patched sources rather than reporting an
        # unpatched linker as legacy-compatible.
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)], cwd=target, check=True, env=env)
        subprocess.run(['bash', 'make.bash'], cwd=target / 'src', check=True, env=env)
        version = subprocess.check_output([str(target / 'bin/go'), 'env', 'GOVERSION'], env=env, text=True).strip()
        if version != identity['goVersion']:
            raise RuntimeError('rebuilt compatibility Go version mismatch')
        identity['executables'] = {str(f.relative_to(target)): file_hash(f) for f in [target / 'bin/go', target / 'pkg/tool' / (host.replace('-', '_')) / 'link']}
        marker.write_text(json.dumps(identity, sort_keys=True, indent=2) + '\n')
        print(json.dumps({'cacheValidated': False, **identity}, sort_keys=True))


if __name__ == '__main__':
    main(sys.argv[1])
