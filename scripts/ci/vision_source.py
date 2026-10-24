"""Verify the exact source-owned Vision module before the existing TLS gate."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import stat
import sys

WINDOWS = sys.platform == 'win32'
PREFIX = 'third_party/sing-vmess/'

MODULE = 'github.com/sagernet/sing-vmess'
VERSION = 'v0.2.9-0.20260929152519-9b95ab8c9478'
REFRACTION = 'v1.8.3-0.20261006222701-ff1b50fbbe9a'
BINDING = 'release/dependency-sources/sing-vmess-replacement.json'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def git_object(kind, raw):
    return hashlib.sha1(kind + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def windows_git_inventory(root, diagnostics):
    """NTFS has no Git executable bit: bind HEAD, index and actual worktree bytes.

    Never infer an executable bit from a manifest alone, from an extension, or
    from Python's Windows stat. POSIX continues to check its actual mode below.
    """
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args], timeout=30, stderr=subprocess.PIPE)
    try:
        top = Path(git('rev-parse', '--show-toplevel').decode().strip()).resolve()
        if top != root.resolve():
            raise ValueError('Vision Windows source root is not Git top level')
        inventories = {}
        diagnostics['git'] = inventories
        diagnostics['indexStages'] = {}
        for kind, command in (
                ('head', ('ls-tree', '-r', '-z', 'HEAD', '--', PREFIX)),
                ('index', ('ls-files', '--stage', '-z', '--', PREFIX))):
            rows = {}
            inventories[kind] = rows
            for raw in git(*command).split(b'\0'):
                if not raw:
                    continue
                header, path_raw = raw.split(b'\t', 1)
                path = path_raw.decode('utf-8')
                if not path.startswith(PREFIX):
                    raise ValueError('Vision Git inventory escaped module')
                name = path[len(PREFIX):]
                fields = header.decode('ascii').split(' ')
                if kind == 'head':
                    mode, object_type, blob = fields
                    valid = object_type == 'blob'
                else:
                    mode, blob, stage = fields
                    diagnostics['indexStages'][name] = stage
                    valid = stage == '0'
                if (not valid or mode not in ('100644', '100755') or
                        not re.fullmatch('[0-9a-f]{40}', blob) or name in rows):
                    diagnostics['invalidGitEntry'] = {'kind': kind, 'path': name, 'header': header.decode('ascii')}
                    raise ValueError('Vision Git inventory is not unique regular stage zero source')
                rows[name] = {'mode': mode, 'gitBlob': blob}
            inventories[kind] = rows
        diagnostics['git'] = inventories
        if not inventories['head'] or inventories['head'] != inventories['index']:
            raise ValueError('Vision HEAD/index source identity differs')
        return inventories['index']
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError('Vision Windows Git source metadata unavailable') from error


def redirected(path):
    info = path.lstat()
    return (stat.S_ISLNK(info.st_mode) or
            bool(getattr(info, 'st_file_attributes', 0) & 0x400))


def validate(root, diagnostics=None):
    root = Path(root)
    diagnostics = {} if diagnostics is None else diagnostics
    diagnostics['modeSource'] = 'git-head-and-index' if WINDOWS else 'posix-filesystem'
    manifest = json.loads((root / BINDING).read_bytes())
    if (manifest['schema'], manifest['module'], manifest['upstreamVersion'],
            manifest['upstreamCommit'], manifest['upstreamTree'], manifest['replacementPath']) != (
            'polaris-repository-module-replacement-v1', MODULE, VERSION,
            '9b95ab8c9478f8e8ebe5758d325ec8cda8197c5c',
            'a06b7a8c92405026f307860c7172765924209470', './third_party/sing-vmess'):
        raise ValueError('Vision source baseline differs')
    module = (root / 'go.mod').read_text()
    if not re.search(r'^\s*' + re.escape(MODULE + ' ' + VERSION) + r'\s*$', module, re.M):
        raise ValueError('Vision root version differs')
    if not re.search(r'^replace ' + re.escape(MODULE) + r' => ./third_party/sing-vmess$', module, re.M):
        raise ValueError('Vision root replacement differs')
    nested = root / 'third_party/sing-vmess'
    if redirected(nested.parent) or redirected(nested) or not nested.is_dir():
        raise ValueError('Vision replacement root redirected')
    observed = {}
    diagnostics['observed'] = observed
    diagnostics['expected'] = manifest['files']
    metadata_error = None
    metadata = None
    if WINDOWS:
        try:
            metadata = windows_git_inventory(root, diagnostics)
        except ValueError as error:
            metadata_error = error
            diagnostics['metadataError'] = str(error)
            metadata = {}
    filesystem_modes = {}
    diagnostics['filesystemModes'] = filesystem_modes
    diagnostics['filesystemStatModes'] = {}
    def tree(directory):
        rows = []
        for path in directory.iterdir():
            if redirected(path):
                raise ValueError('Vision replacement link')
            if path.is_dir():
                mode, blob, key = '40000', tree(path), path.name.encode() + b'/'
            elif path.is_file():
                raw = path.read_bytes()
                st_mode = path.stat().st_mode
                filesystem_mode = '100755' if st_mode & 0o111 else '100644'
                name = path.relative_to(nested).as_posix()
                filesystem_modes[name] = filesystem_mode
                diagnostics['filesystemStatModes'][name] = oct(st_mode)
                mode = metadata.get(name, {}).get('mode', 'untracked') if WINDOWS else filesystem_mode
                blob, key = git_object(b'blob', raw), path.name.encode()
                observed[path.relative_to(nested).as_posix()] = {
                    'afterSHA256': digest(raw), 'gitBlob': blob, 'mode': mode, 'bytes': len(raw)}
            else:
                raise ValueError('Vision non-regular source')
            rows.append((key, mode.encode() + b' ' + path.name.encode() + b'\0' + bytes.fromhex(blob)))
        return git_object(b'tree', b''.join(row for _, row in sorted(rows)))
    actual_tree = tree(nested)
    diagnostics['missing'] = sorted(set(manifest['files']) - set(observed))
    diagnostics['extra'] = sorted(set(observed) - set(manifest['files']))
    modes_known = all(row['mode'] in ('100644', '100755') for row in observed.values())
    diagnostics['actualTree'] = actual_tree if modes_known else None
    if not modes_known:
        diagnostics['treeUnavailableReason'] = 'one or more actual files lack trusted executable metadata'
    diagnostics['expectedTree'] = manifest['replacementTree']
    if metadata_error is not None:
        raise metadata_error
    if WINDOWS and (set(metadata) != set(observed) or any(
            metadata[name] != {key: observed[name][key] for key in ('mode', 'gitBlob')}
            for name in metadata)):
        raise ValueError('Vision actual worktree bytes differ from HEAD/index')
    declared = {name: {key: row[key] for key in ('afterSHA256', 'gitBlob', 'mode', 'bytes')}
                for name, row in manifest['files'].items()}
    if (observed != declared or actual_tree != manifest['replacementTree'] or
            len(observed) != manifest['replacementFileCount'] or manifest['upstreamFileCount'] != 33):
        raise ValueError('Vision complete source bytes/modes/tree differ')
    for text in (module, (nested / 'go.mod').read_text()):
        if not re.search(r'^\s*github.com/refraction-networking/utls ' + re.escape(REFRACTION) + r'\s*$', text, re.M):
            raise ValueError('Vision provider pin differs')
    if manifest['patch'] != 'release/dependency-sources/sing-vmess-vision.patch' or digest((root / manifest['patch']).read_bytes()) != manifest['patchSHA256']:
        raise ValueError('Vision patch identity differs')
    notice = manifest['notice']
    raw = (nested / 'LICENSE').read_bytes()
    bundle = (root / notice['existingBundle']).read_bytes()
    if (notice['path'] != 'third_party/sing-vmess/LICENSE' or not notice['unchangedUpstream'] or
            digest(raw) != notice['sha256'] or len(raw) != notice['bytes'] or
            bundle[notice['existingByteOffset']:notice['existingByteOffset'] + len(raw)] != raw):
        raise ValueError('Vision upstream notice differs from existing bundle')
    return {'module': MODULE, 'version': VERSION, 'replacementTree': actual_tree,
            'replacementFileCount': len(observed), 'bindingSHA256': digest((root / BINDING).read_bytes()),
            'modeSource': diagnostics['modeSource']}
