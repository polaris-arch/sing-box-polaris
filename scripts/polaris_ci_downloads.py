#!/usr/bin/env python3
"""Content-pinned acquisition cache only; extracted tools/results are never cached."""
import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
import re
import shutil
import time
import urllib.parse
import urllib.request

SDK_LIMIT = 512 * 1024 * 1024
NDK_LIMIT = 2 * 1024 * 1024 * 1024
SHA = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[a-zA-Z0-9._-]{1,255}\Z')


def require(value, message):
    if not value:
        raise ValueError(message)


def safe_ancestry(path):
    """lstat root-to-leaf: do not traverse a link/reparse point to inspect it."""
    path = Path(os.path.abspath(path))
    for component in reversed([path, *path.parents]):
        try:
            metadata = component.lstat()
        except FileNotFoundError:
            break
        require(not stat.S_ISLNK(metadata.st_mode)
                and not (getattr(metadata, 'st_file_attributes', 0) & 0x400),
                'unsafe archive ancestry or reparse point')
        if component != path:
            require(stat.S_ISDIR(metadata.st_mode), 'non-directory archive ancestor')
    return path


def regular(path):
    path = safe_ancestry(path)
    require(stat.S_ISREG(path.lstat().st_mode), 'regular cached archive required')


def archive_pin(path, expected, limit):
    regular(path)
    require(path.stat().st_size <= limit, 'archive exceeds acquisition budget')
    with path.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    require(actual == expected, 'cached archive SHA-256 differs')
    return {'bytes': path.stat().st_size, 'sha256': actual}


def openwrt_inputs(repo, root, architecture):
    require('\n' not in str(root) and '\r' not in str(root), 'single-line cache path required')
    require(architecture in ('x86_64', 'aarch64_generic'), 'fixed OpenWrt architecture required')
    value = json.loads((repo / 'release/polaris-openwrt-inputs.json').read_bytes())
    require(value['schema'] == 'polaris-openwrt-release-plan-v1', 'wrong input plan')
    keys = ['ipk-x64' if architecture == 'x86_64' else 'ipk-arm64', 'apk-host']
    result = {}
    for role, key in zip(('sdk', 'apk'), keys):
        records = [r for r in value['sdkInputs'] if r['key'] == key]
        require(len(records) == 1, 'unique SDK pin required')
        row = records[0]
        require(NAME.fullmatch(row['file']) and row['file'].endswith('.tar.zst') and SHA.fullmatch(row['sha256']), 'invalid SDK archive identity')
        require(row['url'].startswith('https://downloads.openwrt.org/releases/')
                and row['url'].rsplit('/', 1)[-1] == row['file'], 'SDK public source differs')
        result[role] = {'path': str(root / row['file']), 'sha256': row['sha256'], 'limitBytes': SDK_LIMIT}
    clang = value['clangInput']
    name = clang['url'].rsplit('/', 1)[-1]
    require(NAME.fullmatch(name) and name.endswith('.tar.xz') and SHA.fullmatch(clang['sha256'])
            and 0 < clang['bytes'] <= SDK_LIMIT
            and clang['url'].startswith('https://commondatastorage.googleapis.com/chromium-browser-clang/Linux_x64/'),
            'fixed Clang archive identity required')
    result['clang'] = {'path': str(root / name), 'sha256': clang['sha256'],
                       'bytes': clang['bytes'], 'limitBytes': clang['bytes']}
    return result


def inspect_inputs(rows, output, github_output=None):
    result = {'schema': 'polaris-ci-acquisition-check-v1', 'cacheAuthority': 'archive SHA only', 'inputs': {}}
    invalid = False
    for role, row in rows.items():
        path = Path(row['path'])
        state = {'expectedSha256': row['sha256'], 'limitBytes': row['limitBytes'], 'present': None}
        try:
            safe_ancestry(path)
            state['present'] = path.exists()
        except (OSError, ValueError):
            state.update(valid=False, error='unsafe-archive-path; no target read')
            invalid = True
        if state['present']:
            try:
                state.update(archive_pin(path, row['sha256'], row['limitBytes']), valid=True)
            except (OSError, ValueError) as error:
                state.update(valid=False, error=str(error))
                invalid = True
        result['inputs'][role] = state
    result['valid'] = not invalid
    print(json.dumps(result, sort_keys=True), flush=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    if github_output:
        with github_output.open('a') as out:
            for role, row in rows.items():
                out.write(f"{role}_path={row['path']}\n{role}_digest={row['sha256']}\n")
                out.write(f"{role}_valid={'true' if result['inputs'][role].get('valid') else 'false'}\n")
    require(not invalid, 'preserve invalid cache input and fail before using it')
    return result


def acquire_ndk(url, expected, destination, deadline_seconds=1200):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == 'https' and parsed.netloc == 'dl.google.com'
            and parsed.path.startswith('/android/repository/') and not parsed.query and not parsed.fragment
            and isinstance(expected, str) and SHA.fullmatch(expected), 'fixed public NDK input required')
    safe_ancestry(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    safe_ancestry(destination)
    if destination.exists() or destination.is_symlink():
        return archive_pin(destination, expected, NDK_LIMIT)
    partial = destination.with_name(destination.name + '.partial')
    require(not partial.exists() and not partial.is_symlink(), 'preserve interrupted download')
    deadline = time.monotonic() + deadline_seconds
    count = 0
    digest = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=90) as response, partial.open('xb') as stream:
        require(response.geturl().startswith('https://dl.google.com/android/repository/'), 'NDK redirect differs')
        while block := response.read(1024 * 1024):
            count += len(block)
            require(count <= NDK_LIMIT and time.monotonic() <= deadline, 'NDK download budget exceeded')
            digest.update(block)
            stream.write(block)
    require(digest.hexdigest() == expected, 'downloaded NDK SHA-256 differs; preserve partial')
    partial.rename(destination)
    return archive_pin(destination, expected, NDK_LIMIT)


def preserve_bad_inputs(rows, output):
    """Only failed/missing partial input bytes; never copy valid tool caches."""
    safe_ancestry(output)
    output.mkdir(parents=True, exist_ok=True)
    retained = []
    for role, row in rows.items():
        original = Path(row['path'])
        for path in (original, original.with_name(original.name + '.partial')):
            # Independent of archive_pin failure: a rejected path is never
            # treated as merely a hash mismatch and copied through its parent.
            try:
                safe_ancestry(path)
                metadata = path.lstat()
                require(stat.S_ISREG(metadata.st_mode), 'nonregular input')
            except FileNotFoundError:
                continue
            except (OSError, ValueError):
                retained.append({'role': role, 'name': path.name, 'retained': False,
                                 'reason': 'unsafe-ancestry-or-nonregular; target not read'})
                continue
            if metadata.st_size > row['limitBytes']:
                retained.append({'role': role, 'name': path.name, 'bytes': metadata.st_size,
                                 'retained': False, 'reason': 'oversized; bounded copy refused'})
                continue
            try:
                archive_pin(path, row['sha256'], row['limitBytes'])
                continue
            except (OSError, ValueError):
                # Repeat ancestry and regular-file checks immediately before
                # opening. NOFOLLOW/fstat bind copying to the checked inode.
                target = None
                created = False
                try:
                    safe_ancestry(path)
                    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
                    with os.fdopen(fd, 'rb') as source:
                        opened = os.fstat(source.fileno())
                        require(stat.S_ISREG(opened.st_mode)
                                and (opened.st_dev, opened.st_ino) == (metadata.st_dev, metadata.st_ino),
                                'archive inode changed before preservation')
                        target = output / path.name
                        safe_ancestry(target)
                        with target.open('xb') as destination:
                            created = True
                            copied = 0
                            while block := source.read(1024 * 1024):
                                copied += len(block)
                                require(copied <= row['limitBytes'], 'input grew past preservation budget')
                                destination.write(block)
                    with target.open('rb') as stream:
                        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                    retained.append({'role': role, 'name': path.name, 'bytes': target.stat().st_size,
                                     'sha256': digest, 'retained': True})
                except (OSError, ValueError):
                    if created:
                        safe_ancestry(target)
                        target.unlink()  # Only this new incomplete evidence copy.
                    retained.append({'role': role, 'name': path.name, 'retained': False,
                                     'reason': 'unsafe or incomplete copy; no archive retained'})
    (output / 'bad-input-retention.json').write_text(json.dumps(retained, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('openwrt-plan', 'openwrt-check', 'ndk', 'preserve-openwrt', 'preserve-ndk'))
    parser.add_argument('--repo', type=Path)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--architecture')
    parser.add_argument('--url')
    parser.add_argument('--sha256')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--github-output', type=Path)
    args = parser.parse_args()
    if args.mode.startswith('openwrt') or args.mode == 'preserve-openwrt':
        rows = openwrt_inputs(args.repo, args.root.absolute(), args.architecture)
        if args.mode == 'openwrt-plan':
            print(json.dumps(rows, sort_keys=True), flush=True)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(rows, indent=2) + '\n')
            with args.github_output.open('a') as out:
                for role, row in rows.items():
                    out.write(f"{role}_path={row['path']}\n{role}_digest={row['sha256']}\n")
        elif args.mode == 'openwrt-check':
            inspect_inputs(rows, args.output, args.github_output)
        else:
            preserve_bad_inputs(rows, args.output)
    else:
        rows = {'ndk': {'path': str(args.root.absolute() / 'ndk.zip'), 'sha256': args.sha256, 'limitBytes': NDK_LIMIT}}
        if args.mode == 'preserve-ndk':
            preserve_bad_inputs(rows, args.output)
        else:
            try:
                actual = acquire_ndk(args.url, args.sha256, Path(rows['ndk']['path']))
                inspect_inputs(rows, args.output)
                print(json.dumps({'ndkArchive': actual, 'consumerStillUnpacksFresh': True}), flush=True)
            except (OSError, ValueError, KeyboardInterrupt):
                preserve_bad_inputs(rows, args.output.parent / 'invalid-inputs')
                raise


if __name__ == '__main__':
    main()
