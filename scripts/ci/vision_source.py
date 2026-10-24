"""Verify the exact source-owned Vision module before the existing TLS gate."""
import hashlib
import json
from pathlib import Path
import re

MODULE = 'github.com/sagernet/sing-vmess'
VERSION = 'v0.2.9-0.20260929152519-9b95ab8c9478'
REFRACTION = 'v1.8.3-0.20261006222701-ff1b50fbbe9a'
BINDING = 'release/dependency-sources/sing-vmess-replacement.json'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def git_object(kind, raw):
    return hashlib.sha1(kind + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def validate(root):
    root = Path(root)
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
    if nested.is_symlink() or not nested.is_dir():
        raise ValueError('Vision replacement root redirected')
    observed = {}
    def tree(directory):
        rows = []
        for path in directory.iterdir():
            if path.is_symlink():
                raise ValueError('Vision replacement link')
            if path.is_dir():
                mode, blob, key = '40000', tree(path), path.name.encode() + b'/'
            elif path.is_file():
                raw = path.read_bytes()
                mode = '100755' if path.stat().st_mode & 0o111 else '100644'
                blob, key = git_object(b'blob', raw), path.name.encode()
                observed[path.relative_to(nested).as_posix()] = {
                    'afterSHA256': digest(raw), 'gitBlob': blob, 'mode': mode, 'bytes': len(raw)}
            else:
                raise ValueError('Vision non-regular source')
            rows.append((key, mode.encode() + b' ' + path.name.encode() + b'\0' + bytes.fromhex(blob)))
        return git_object(b'tree', b''.join(row for _, row in sorted(rows)))
    actual_tree = tree(nested)
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
            'replacementFileCount': len(observed), 'bindingSHA256': digest((root / BINDING).read_bytes())}
