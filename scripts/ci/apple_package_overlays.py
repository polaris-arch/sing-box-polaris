#!/usr/bin/env python3
"""Exact unsigned Apple lint-only dependency overlays; never approve a plugin.

Original recipes and Package.resolved remain immutable. Receipts describe actual
post-build source; merely generating an expected record is not a producer check.
"""
import argparse
import base64
from contextlib import ExitStack
import difflib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = 'release/ci/apple-swift-package-overlays.json'
IDS = {'codeeditsourceeditor', 'codeedittextview'}
LINE = b'                .plugin(name: "SwiftLint", package: "SwiftLintPlugin")\n'
MAX_FILES = 4096
MAX_BYTES = 256 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def object_id(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def blob(raw):
    return object_id('blob', raw)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def safe_path(root, relative):
    name = PurePosixPath(relative)
    require(not name.is_absolute() and '..' not in name.parts and '\\' not in relative
            and name.parts and '.git' not in name.parts, 'unsafe Apple package path')
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), 'unsafe Apple package root')
    path = root
    for part in name.parts[:-1]:
        path = path / part
        require(path.is_dir() and not path.is_symlink(), 'Apple source path traverses symlink')
    return path / name.parts[-1]


def regular(root, relative):
    path = safe_path(root, relative)
    require(path.is_file() and not path.is_symlink(), 'non-regular Apple source file')
    require(path.stat().st_size <= MAX_BYTES, 'Apple source file exceeds budget')
    return path.read_bytes()


def git(directory, *arguments):
    # Cache/environment metadata must not redirect the worktree/index/object
    # store or replace a pinned tree while preserving its advertised OID.
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_NO_REPLACE_OBJECTS='1')
    return subprocess.check_output([
        'git', '--no-optional-locks', '-c', 'core.fsmonitor=false',
        '-c', 'core.hooksPath=/dev/null', '-C', str(directory), *arguments], env=env)


def definition(root=ROOT):
    root = Path(root)
    raw = regular(root, CONTRACT)
    spec = json.loads(raw)
    require(type(spec.get('schema')) is int and spec['schema'] == 1 and spec.get('purpose') ==
            'unsigned-apple-disable-unused-lint-invocations', 'invalid Apple package contract')
    require(spec.get('removedLine', '').encode() == LINE, 'unexpected Apple plugin transform')
    packages = spec.get('packages', [])
    require(len(packages) == 2 and {p.get('identity') for p in packages} == IDS,
            'Apple package overlay inventory differs')
    client = spec['client']
    original_client = json.loads(regular(root, 'release/ci/client-overlays.json'))['platforms']['apple']
    require(all(client[k] == original_client[k] for k in ('repository', 'commit', 'tree')),
            'Apple package contract client mismatch')
    require(client['lockRecipe'] == 'release/dependency-sources/clients/runtime/recipes/sing-box-for-apple/' + client['lockfile'],
            'Apple package lock recipe path mismatch')
    lock = regular(root, client['lockRecipe'])
    require(sha(lock) == client['lockSHA256'], 'Apple original lock identity mismatch')
    pins = json.loads(lock)['pins']
    require(len({p['identity'] for p in pins}) == len(pins), 'duplicate Apple package pin')
    pins = {p['identity']: p for p in pins}
    plugin = spec['plugin']
    require(plugin['identity'] == 'swiftlintplugin' and plugin['product'] == 'SwiftLint'
            and plugin['role'] == 'build-only-lint-no-code-generation', 'unexpected Apple plugin role')
    for package in packages + [plugin]:
        require(re.fullmatch('[0-9a-f]{40}', package['revision']), 'invalid Apple package revision')
        pin = pins.get(package['identity'], {})
        require(pin.get('location', '').removesuffix('.git') == package['repository'].removesuffix('.git')
                and pin.get('state', {}).get('revision') == package['revision'], 'Apple package lock pin mismatch')
    require(pins['swiftlintplugin']['state'].get('version') == plugin['version'], 'Apple lint version mismatch')
    recipes = json.loads(regular(root, 'release/dependency-sources/clients/runtime/recipe-index.json'))
    recipes = {row['path']: row for row in recipes}
    for package in packages:
        path = package['originalRecipe']
        require(path == 'release/dependency-sources/clients/runtime/recipes/swift-packages/' + package['identity'] + '/Package.swift',
                'Apple original recipe path mismatch')
        baseline = regular(root, path)
        source = recipes.get(path, {})
        require((source.get('revision'), source.get('sha256'), source.get('bytes')) ==
                (package['revision'], package['beforeSHA256'], package['beforeBytes']), 'Apple recipe index mismatch')
        require(source.get('sourceURL') == package['repository'].replace('https://github.com/', 'https://raw.githubusercontent.com/') +
                '/' + package['revision'] + '/Package.swift', 'Apple recipe source mismatch')
        transformed(baseline, package)
    return spec


def transformed(baseline, package):
    require((sha(baseline), blob(baseline), len(baseline)) ==
            (package['beforeSHA256'], package['beforeGitBlob'], package['beforeBytes']), 'Apple manifest baseline mismatch')
    require(type(package['removedInvocationLines']) is int and package['removedInvocationLines'] == 2
            and baseline.count(LINE) == 2, 'Apple plugin invocation count mismatch')
    result = baseline.replace(LINE, b'')
    require(b'.plugin(' not in result, 'unexpected remaining Apple package plugin')
    require((sha(result), len(result)) == (package['afterSHA256'], package['afterBytes']),
            'Apple transformed manifest identity mismatch')
    return result


def expected_record(source, root=ROOT):
    require(isinstance(source, str) and re.fullmatch('[0-9a-f]{40}', source), 'full Apple core source required')
    root = Path(root)
    spec = definition(root)
    rows = []
    for package in sorted(spec['packages'], key=lambda row: row['identity']):
        baseline = regular(root, package['originalRecipe'])
        result = transformed(baseline, package)
        diff = ''.join(difflib.unified_diff(baseline.decode().splitlines(True), result.decode().splitlines(True),
                                          fromfile='a/Package.swift', tofile='b/Package.swift'))
        rows.append({**package, 'path': 'Package.swift', 'afterGitBlob': blob(result),
                     'baseline': base64.b64encode(baseline).decode(), 'diff': diff, 'diffSHA256': sha(diff.encode())})
    return {'schema': 'polaris-apple-package-overlays-v1', 'coreSourceCommit': source,
            'manifestSHA256': sha(regular(root, CONTRACT)), 'clientCommit': spec['client']['commit'],
            'lockSHA256': spec['client']['lockSHA256'], 'packages': rows}


def validate(record, source, root=ROOT):
    require(isinstance(record, dict) and canonical(record) == canonical(expected_record(source, root)),
            'Apple package source receipt mismatch')


def actual_client(spec, root):
    directory = Path(root) / 'clients/apple'
    require(directory.is_dir() and not directory.is_symlink()
            and Path(git(directory, 'rev-parse', '--show-toplevel').decode().strip()).resolve() == directory.resolve(),
            'actual Apple client worktree escapes root')
    require(git(directory, 'rev-parse', 'HEAD').decode().strip() == spec['client']['commit'],
            'actual Apple client commit mismatch')
    require(git(directory, 'rev-parse', 'HEAD^{tree}').decode().strip() == spec['client']['tree'],
            'actual Apple client tree mismatch')
    require(sha(regular(directory, spec['client']['lockfile'])) == spec['client']['lockSHA256'],
            'actual Apple Package.resolved changed')


def package_directory(packages_root, identity):
    directory = safe_path(packages_root, 'checkouts')
    require(directory.is_dir() and not directory.is_symlink(), 'missing/unsafe Swift package checkouts')
    children = list(directory.iterdir())
    require(len(children) <= 256, 'Swift package checkout inventory exceeds budget')
    matches = [p for p in children if p.name.casefold() == identity]
    require(len(matches) == 1 and matches[0].is_dir() and not matches[0].is_symlink(),
            'missing/duplicate/unsafe Apple package checkout: ' + identity)
    return matches[0]


def inspect_package(directory, package, baseline, result, output):
    require(Path(git(directory, 'rev-parse', '--show-toplevel').decode().strip()).resolve() == directory.resolve(),
            'Apple checkout worktree escapes package root')
    require(git(directory, 'rev-parse', 'HEAD').decode().strip() == package['revision'], 'actual Apple package revision mismatch')
    require(object_id('commit', git(directory, 'cat-file', 'commit', package['revision'])) == package['revision'],
            'Apple cached commit object hash mismatch')
    require(git(directory, 'rev-parse', 'HEAD^{tree}').decode().strip() == package['tree'], 'actual Apple package tree mismatch')
    require(object_id('tree', git(directory, 'cat-file', 'tree', package['tree'])) == package['tree'],
            'Apple cached root tree object hash mismatch')
    require(git(directory, 'show', 'HEAD:Package.swift') == baseline, 'actual Apple committed manifest mismatch')
    # Check all actual bytes against the immutable tree, not Git's mutable index,
    # stat cache, assume-unchanged bits, or just the two changed manifest hashes.
    entries = git(directory, 'ls-tree', '-rz', '-t', '--full-tree', 'HEAD').split(b'\0')
    entries = [entry for entry in entries if entry]
    require(0 < len(entries) <= MAX_FILES, 'Apple package tree budget exceeded')
    total = 0
    seen = set()
    for entry in entries:
        metadata, name = entry.split(b'\t', 1)
        mode, kind, expected_blob = metadata.decode().split()
        name = name.decode()
        if kind == 'tree':
            path = safe_path(directory, name)
            require(mode == '040000' and path.is_dir() and not path.is_symlink()
                    and object_id('tree', git(directory, 'cat-file', 'tree', expected_blob)) == expected_blob,
                    'Apple cached subtree object/path mismatch')
            continue
        require(name not in seen and kind == 'blob' and mode in ('100644', '100755', '120000'),
                'unexpected Apple package tree entry')
        seen.add(name)
        path = safe_path(directory, name)
        if mode == '120000':
            require(path.is_symlink(), 'Apple package symlink mode changed')
            link = os.readlink(path)
            resolved = path.resolve()
            require(not Path(link).is_absolute() and resolved.is_relative_to(directory.resolve())
                    and '.git' not in resolved.relative_to(directory.resolve()).parts,
                    'Apple package symlink escapes pinned source')
            raw = link.encode()
        else:
            raw = regular(directory, name)
            actual_mode = '100755' if path.stat().st_mode & 0o111 else '100644'
            require(actual_mode == mode, 'Apple package source mode changed')
        total += len(raw)
        require(total <= MAX_BYTES, 'Apple package source bytes exceed budget')
        if name == 'Package.swift':
            require(mode == '100644' and raw in ([result] if output else [baseline, result]),
                    'actual Apple manifest is not exact allowed overlay')
        else:
            require(blob(raw) == expected_blob, 'unexpected Apple package source change: ' + name)
    require('Package.swift' in seen, 'Apple package manifest absent from source tree')
    cached = git(directory, 'ls-files', '--cached', '-z').decode().split('\0')[:-1]
    require(len(cached) == len(seen) and set(cached) == seen, 'Apple package index inventory differs from pinned tree')
    require(not git(directory, 'ls-files', '--others', '-z'), 'untracked Apple package source')


def verify_actual(packages_root, output, root=ROOT):
    root = Path(root)
    spec = definition(root)
    actual_client(spec, root)
    writes = []
    for package in spec['packages']:
        directory = package_directory(packages_root, package['identity'])
        baseline = regular(root, package['originalRecipe'])
        result = transformed(baseline, package)
        inspect_package(directory, package, baseline, result, output)
        writes.append((directory / 'Package.swift', result, baseline))
    return writes


def file_flags(info):
    return getattr(info, 'st_flags', 0)


def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_nlink, file_flags(info))


def diagnose(writes, stage, error=None):
    # Fixed two-file scope, metadata only: no env, credentials, attributes or source contents.
    record = {'stage': stage, 'euid': os.geteuid(), 'egid': os.getegid(), 'files': []}
    if error is not None:
        record.update(error=type(error).__name__[:80], errno=getattr(error, 'errno', None))
    for path, *_ in writes:
        for target, label in ((path, path.parent.name + '/Package.swift'),
                              (path.parent, path.parent.name + '/')):
            item = {'path': label}
            try:
                info = target.lstat()
                item.update(mode=oct(stat.S_IMODE(info.st_mode)), uid=info.st_uid, gid=info.st_gid,
                            dev=info.st_dev, inode=info.st_ino, links=info.st_nlink,
                            size=info.st_size, flags=file_flags(info))
            except OSError as failure:
                item.update(error=type(failure).__name__, errno=failure.errno)
            record['files'].append(item)
    # A diagnosis must never mask the primary failure, and is not a release receipt.
    try:
        print('apple-package-overlay: ' + canonical(record)[:8192], file=sys.stderr)
    except OSError:
        pass


def read_descriptor(fd, limit):
    os.lseek(fd, 0, os.SEEK_SET)
    result = bytearray()
    while len(result) <= limit:
        chunk = os.read(fd, min(65536, limit + 1 - len(result)))
        if not chunk:
            break
        result.extend(chunk)
    require(len(result) <= limit, 'Apple manifest exceeds exact source size')
    return bytes(result)


def write_descriptor(fd, raw):
    os.lseek(fd, 0, os.SEEK_SET)
    remaining = memoryview(raw)
    while remaining:
        count = os.write(fd, remaining)
        require(0 < count <= len(remaining), 'short Apple manifest write')
        remaining = remaining[count:]
    os.ftruncate(fd, len(raw))
    os.fsync(fd)


def check_entry(entry, modes):
    path, fd = entry['path'], entry['read_fd']
    info = os.fstat(fd)
    require(file_identity(info) == file_identity(entry['info'])
            and stat.S_IMODE(info.st_mode) in modes, 'Apple manifest filesystem identity changed')
    current = os.stat('Package.swift', dir_fd=entry['directory_fd'], follow_symlinks=False)
    require(stat.S_ISREG(current.st_mode) and file_identity(current) == file_identity(info)
            and current.st_mode == info.st_mode, 'Apple manifest path changed')
    directory = path.parent.lstat()
    require(stat.S_ISDIR(directory.st_mode)
            and file_identity(directory) == file_identity(entry['directory_info'])
            and directory.st_mode == entry['directory_info'].st_mode, 'Apple checkout directory changed')


def restore_modes(entries):
    failures = []
    for entry in entries:
        if not entry['promoted']:
            continue
        try:
            info = os.fstat(entry['read_fd'])
            require(file_identity(info) == file_identity(entry['info']), 'Apple mode restoration identity changed')
            mode = stat.S_IMODE(info.st_mode)
            require(mode in (entry['mode'], entry['mode'] | stat.S_IWUSR), 'unexpected Apple mode during restoration')
            if mode != entry['mode']:
                os.fchmod(entry['read_fd'], entry['mode'])
            require(stat.S_IMODE(os.fstat(entry['read_fd']).st_mode) == entry['mode'],
                    'Apple manifest mode restoration failed')
        except (OSError, ValueError) as error:
            failures.append(type(error).__name__)
    require(not failures, 'Apple manifest mode restoration failed: ' + ','.join(failures))


def apply(packages_root, root=ROOT):
    writes = verify_actual(packages_root, False, root)
    diagnose(writes, 'before')
    entries = []
    with ExitStack() as handles:
        try:
            # Both full trees AND both filesystem identities validate before any permission/write change.
            for path, result, baseline in writes:
                directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                handles.callback(os.close, directory_fd)
                fd = os.open('Package.swift', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
                handles.callback(os.close, fd)
                info = os.fstat(fd)
                mode = stat.S_IMODE(info.st_mode)
                protected = sum(getattr(stat, flag, 0) for flag in
                                ('UF_IMMUTABLE', 'SF_IMMUTABLE', 'UF_APPEND', 'SF_APPEND'))
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                        and info.st_nlink == 1, 'Apple manifest must be owned, regular and single-link')
                require(not mode & 0o7111 and not file_flags(info) & protected,
                        'unsafe Apple manifest mode or flags')
                before = read_descriptor(fd, len(result) + 2 * len(LINE))
                require(before in (baseline, result),
                        'Apple manifest changed after source verification')
                entry = dict(path=path, result=result, before=before, info=info, mode=mode,
                             read_fd=fd, directory_fd=directory_fd,
                             directory_info=os.fstat(directory_fd), promoted=False, touched=False)
                entries.append(entry)
                check_entry(entry, (mode,))
            # Prepare every changed file before writing either. An already-overlaid readonly cache is a no-op.
            for entry in entries:
                if entry['before'] == entry['result']:
                    continue
                check_entry(entry, (entry['mode'],))
                if not entry['mode'] & stat.S_IWUSR:
                    entry['promoted'] = True
                    os.fchmod(entry['read_fd'], entry['mode'] | stat.S_IWUSR)
                check_entry(entry, (entry['mode'] | stat.S_IWUSR,))
                fd = os.open('Package.swift', os.O_RDWR | os.O_NOFOLLOW, dir_fd=entry['directory_fd'])
                handles.callback(os.close, fd)
                require(file_identity(os.fstat(fd)) == file_identity(entry['info']), 'Apple write descriptor changed')
                entry['write_fd'] = fd
            for entry in entries:
                check_entry(entry, (entry['mode'] | stat.S_IWUSR,) if entry['promoted'] else (entry['mode'],))
                require(read_descriptor(entry['read_fd'], len(entry['before'])) == entry['before'],
                        'Apple manifest changed before write')
            for entry in entries:
                if 'write_fd' in entry:
                    entry['touched'] = True
                    write_descriptor(entry['write_fd'], entry['result'])
            restore_modes(entries)
            verify_actual(packages_root, True, root)
            for entry in entries:
                check_entry(entry, (entry['mode'],))
        except BaseException as error:
            failures = []
            for entry in reversed(entries):
                if not entry['touched']:
                    continue
                try:
                    check_entry(entry, (entry['mode'], entry['mode'] | stat.S_IWUSR))
                    # The already-open descriptor remains writable after restoring readonly mode.
                    write_descriptor(entry['write_fd'], entry['before'])
                    require(read_descriptor(entry['read_fd'], len(entry['before'])) == entry['before'],
                            'Apple manifest rollback bytes differ')
                except (OSError, ValueError) as failure:
                    failures.append(type(failure).__name__)
            try:
                restore_modes(entries)
            except (OSError, ValueError) as failure:
                failures.append(type(failure).__name__)
            diagnose(writes, 'rollback-incomplete' if failures else 'failed-restored', error)
            if failures:
                raise RuntimeError('Apple manifest rollback incomplete: ' + ','.join(failures)) from error
            raise
    diagnose(writes, 'verified-modes-restored')


def collect(source, packages_root=None, root=ROOT):
    if packages_root is None:
        packages_root = Path(os.environ['RUNNER_TEMP']) / 'SourcePackages'
    verify_actual(packages_root, True, root)
    record = expected_record(source, root)
    validate(record, source, root)
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['check-lock', 'apply'])
    parser.add_argument('--source-packages', type=Path)
    arguments = parser.parse_args()
    if arguments.action == 'check-lock':
        actual_client(definition(), ROOT)
    else:
        if arguments.source_packages is None:
            parser.error('--source-packages is required for apply')
        apply(arguments.source_packages)
