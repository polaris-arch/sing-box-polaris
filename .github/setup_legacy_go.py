"""Build/cache verified source-owned Go compatibility toolchains on CI only."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import stat
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


def toolchain_files(target):
    """Measure the complete fixed toolchain, not only the driver and linker."""
    if target.is_symlink() or not target.is_dir():
        raise RuntimeError('toolchain target must be an ordinary directory')
    files = {}
    total = 0
    for directory, dirs, names in os.walk(target, followlinks=False):
        for name in sorted(dirs + names):
            path = Path(directory) / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise RuntimeError('toolchain contains a symlink')
            if stat.S_ISDIR(metadata.st_mode):
                continue
            relative = path.relative_to(target).as_posix()
            if relative == 'polaris-toolchain.json':
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError('toolchain contains a non-regular file')
            total += metadata.st_size
            if len(files) >= 50000 or total > 3 * 1024 ** 3:
                raise RuntimeError('rebuilt toolchain exceeds fixed inventory budget')
            files[relative] = {'sha256': file_hash(path), 'bytes': metadata.st_size,
                               'mode': stat.S_IMODE(metadata.st_mode)}
    return files


def verify_cached_toolchain(target, host, identity):
    marker = target / 'polaris-toolchain.json'
    if target.is_symlink() or not target.is_dir():
        raise RuntimeError('toolchain target must be an ordinary directory')
    metadata = marker.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 16 * 1024 ** 2:
        raise RuntimeError('invalid toolchain identity file')
    # This detects restored-file drift against the post-build inventory; the
    # mutable cache and its marker are not independent provenance/signatures.
    measured = json.loads(marker.read_text())
    if any(measured.get(k) != v for k, v in identity.items()):
        raise RuntimeError('restored compatibility toolchain input mismatch; do not reuse this cache')
    files = toolchain_files(target)
    required = {'bin/go', 'bin/gofmt', 'VERSION', 'go.env', 'src/runtime/runtime2.go',
                'src/os/root.go', 'src/cmd/compile/main.go', 'src/cmd/asm/main.go'}
    required.update('pkg/tool/' + host.replace('-', '_') + '/' + tool for tool in ('compile', 'asm', 'link'))
    if not required <= files.keys() or measured.get('files') != files:
        raise RuntimeError('restored complete toolchain file inventory/content/mode mismatch')
    return measured


def cache_summary(measured):
    files = measured['files']
    return {**{k: v for k, v in measured.items() if k != 'files'},
            'fileCount': len(files), 'fileBytes': sum(row['bytes'] for row in files.values()),
            'filesSHA256': hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'verificationScope': 'post-build input-bound cache consistency, not independent provenance against replacement of both marker and tree'}


def require_archive_members(members):
    if len(members) > 25000 or sum(m.size for m in members) > 1024 ** 3:
        raise RuntimeError('official Go archive exceeds extraction budget')
    for member in members:
        path = PurePosixPath(member.name)
        if (not path.parts or path.parts[0] != 'go' or path.is_absolute() or '..' in path.parts
                or member.size < 0 or not (member.isfile() or member.isdir())):
            raise RuntimeError('unexpected official Go archive layout')


def main(mode):
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('GITHUB_REPOSITORY') != 'polaris-arch/sing-box-polaris':
        raise RuntimeError('legacy toolchain installation is restricted to the owned CI runner')
    host = {'Linux': 'linux', 'Darwin': 'darwin'}[platform.system()] + '-' + {'x86_64': 'amd64', 'arm64': 'arm64', 'aarch64': 'arm64'}[platform.machine()]
    manifest, entry, patch, archive, manifest_hash = toolchain_input(mode, host)
    target = Path.home() / 'go' / entry['target']
    marker = target / 'polaris-toolchain.json'
    identity = {'goVersion': 'go' + manifest['version'], 'manifestSHA256': manifest_hash,
                'archiveSHA256': archive['sha256'], 'patchSHA256': entry['patchSHA256'],
                'officialCommit': manifest['officialCommit'], 'patchSourceCommits': entry['sourceCommits'],
                'host': host, 'cacheFormat': 'complete-toolchain-files-v1',
                'installerSHA256': file_hash(Path(__file__)),
                'buildEnvironment': {'GOEXPERIMENT': '', 'GOAMD64': 'v1', 'GOENV': 'off', 'GOFLAGS': ''}}
    if target.is_symlink():
        raise RuntimeError("toolchain target must not be a symlink")
    if target.exists():
        measured = verify_cached_toolchain(target, host, identity)
        print(json.dumps({'cacheValidated': True, **cache_summary(measured)}, sort_keys=True))
        return
    runner_temp = Path(os.environ['RUNNER_TEMP']).resolve()
    if shutil.disk_usage(runner_temp).free < 11 * 1024 ** 3:
        raise RuntimeError("legacy toolchain requires 3GiB growth plus 8GiB headroom")
    target.parent.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(target.parent).free < 11 * 1024 ** 3:
        raise RuntimeError('toolchain target filesystem lacks 3GiB growth plus 8GiB headroom')
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
            require_archive_members(members)
            tar.extractall(bootstrap, members=members, filter='data')
        shutil.copytree(bootstrap / 'go', target)
        env = dict(os.environ, GOTOOLCHAIN='local', GOROOT_BOOTSTRAP=str(bootstrap / 'go'),
                   GOROOT_FINAL=str(target), GOMAXPROCS='2')
        env.pop('GOROOT', None)
        env.update(identity['buildEnvironment'])
        env['GOOS'], env['GOARCH'] = host.split('-')
        env['GOHOSTOS'], env['GOHOSTARCH'] = host.split('-')
        # Source-only changes to cmd/link do not modify the shipped linker binary.
        # Rebuild all tools from the patched sources rather than reporting an
        # unpatched linker as legacy-compatible.
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)], cwd=target, check=True, env=env)
        subprocess.run(['bash', 'make.bash'], cwd=target / 'src', check=True, env=env)
        version = subprocess.check_output([str(target / 'bin/go'), 'env', 'GOVERSION'], env=env, text=True).strip()
        if version != identity['goVersion']:
            raise RuntimeError('rebuilt compatibility Go version mismatch')
        identity['files'] = toolchain_files(target)
        marker.write_text(json.dumps(identity, sort_keys=True, indent=2) + '\n')
        verify_cached_toolchain(target, host, {k: v for k, v in identity.items() if k != 'files'})
        print(json.dumps({'cacheValidated': False, **cache_summary(identity)}, sort_keys=True))


if __name__ == '__main__':
    main(sys.argv[1])
