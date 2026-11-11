"""Offline, bounded validation of the current P2 Cronet source overlay.

validate_overlay(source_root) returns SHA256 identities for every data file read.
It needs only the exact source directory, including in a cold source archive.
No Git checkout, tool, subprocess, network or native execution is used.
"""
import base64
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath

MANIFEST = 'release/dependency-sources/cronet-go-windows-native-observation.json'
PATCH = 'release/dependency-sources/cronet-go-windows-native-observation.patch'
VENDOR = 'third_party/cronet-go'
BASE_COMMIT = 'c7960c2020904d90aebb74ad6320bb3701f6041e'
BASE_TREE = '42f8717ff0a1ae0329d5825f14e4b75e3f66a713'
BASE_VENDOR_TREE = '444994a3a06f5a6c184060448b9ea00e4d59ec27'
HISTORICAL = {
    'release/dependency-sources/cronet-go-replacement.json': {
        'bytes': 54745, 'sha256': 'd0835f0590a179b43c560bc4c348a627f6d7af4bcffeb1bd33b8febfe23757d1'},
    'release/dependency-sources/cronet-go-client-admission.patch': {
        'bytes': 19010, 'sha256': '8595a6da43ef8241cedec593bccf07ab81a0afa8281de21567fc8920445699d4'}}
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 256


def _fail(message):
    raise ValueError('Cronet Windows overlay: ' + message)


def _shape(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        _fail('closed shape differs')


def _path(value):
    if (type(value) is not str or not value or len(value) > 240
            or not all(re.fullmatch(r'[A-Za-z0-9_.+-]+', p) and p not in ('.', '..') for p in value.split('/'))):
        _fail('unsafe path')
    return value


def _hex(value, length):
    if type(value) is not str or not re.fullmatch('[0-9a-f]{' + str(length) + '}', value):
        _fail('object identity differs')


def _hash(kind, raw):
    return hashlib.sha1(kind + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def _record(record):
    _shape(record, ('path', 'mode', 'bytes', 'sha256', 'gitBlob'))
    _path(record['path'])
    if record['mode'] not in ('100644', '100755') or type(record['bytes']) is not int or not 0 <= record['bytes'] <= MAX_FILE_BYTES:
        _fail('file mode/size differs')
    _hex(record['sha256'], 64)
    _hex(record['gitBlob'], 40)


def _check(raw, record):
    if (len(raw) != record['bytes'] or hashlib.sha256(raw).hexdigest() != record['sha256']
            or _hash(b'blob', raw) != record['gitBlob']):
        _fail('file bytes/blob differ: ' + record['path'])


def _tree(records):
    root = {}
    for record in records:
        parts = record['path'].split('/')
        node = root
        for part in parts[:-1]:
            value = node.setdefault(part, {})
            if type(value) is not dict:
                _fail('file/directory collision')
            node = value
        if parts[-1] in node:
            _fail('duplicate file/directory')
        node[parts[-1]] = (record['mode'], record['gitBlob'])
    def digest(node):
        entries = []
        for name, value in node.items():
            mode, oid = ('40000', digest(value)) if type(value) is dict else value
            entries.append((name.encode() + (b'/' if mode == '40000' else b''),
                            mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(oid)))
        return _hash(b'tree', b''.join(raw for _, raw in sorted(entries)))
    return digest(root)


def _tree_entries(raw):
    entries = {}; offset = 0; order = []
    while offset < len(raw):
        end = raw.find(b'\0', offset)
        if end < 0 or end + 21 > len(raw):
            _fail('truncated tree proof')
        header = raw[offset:end].split(b' ')
        if len(header) != 2:
            _fail('tree entry shape differs')
        mode, name = header
        try:
            name = name.decode('ascii'); mode = mode.decode('ascii')
        except UnicodeError:
            _fail('nonportable tree proof')
        _path(name)
        if '/' in name or name in entries or mode not in ('40000', '100644', '100755', '120000', '160000'):
            _fail('duplicate/invalid tree entry')
        entries[name] = (mode, raw[end + 1:end + 21].hex())
        order.append(name.encode() + (b'/' if mode == '40000' else b''))
        offset = end + 21
    if order != sorted(order):
        _fail('noncanonical tree order')
    return entries


def _patch_sections(raw, changes):
    lines = raw.splitlines(keepends=True); offset = 0; sections = {}
    while offset < len(lines):
        old = lines[offset]; offset += 1
        if offset >= len(lines):
            _fail('truncated patch header')
        new = lines[offset]; offset += 1
        if not old.startswith(b'--- ') or not new.startswith(b'+++ ') or not old.endswith(b'\n') or not new.endswith(b'\n'):
            _fail('patch header differs')
        try:
            old = old[4:-1].decode('ascii'); new = new[4:-1].decode('ascii')
        except UnicodeError:
            _fail('patch path encoding differs')
        name = new[2:] if new.startswith('b/') else old[2:] if old.startswith('a/') else ''
        _path(name)
        if name not in changes or name in sections:
            _fail('extra/duplicate patch path')
        item = changes[name]
        if old != ('a/' + name if item['before'] is not None else '/dev/null') or new != ('b/' + name if item['after'] is not None else '/dev/null'):
            _fail('patch path/operation mismatch')
        hunks = []
        while offset < len(lines) and not lines[offset].startswith(b'--- '):
            match = re.fullmatch(rb'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\n', lines[offset])
            if not match:
                _fail('patch hunk header differs')
            a, ac, b, bc = (int(value) if value is not None else 1 for value in match.groups()); offset += 1
            removed = []; added = []
            while len(removed) < ac or len(added) < bc:
                if offset >= len(lines) or lines[offset][:1] not in (b'-', b'+'):
                    _fail('truncated/nonzero-context hunk')
                line = lines[offset]; offset += 1
                target = removed if line[:1] == b'-' else added
                target.append(line[1:])
                if offset < len(lines) and lines[offset] == b'\\ No newline at end of file\n':
                    if not target[-1].endswith(b'\n'):
                        _fail('invalid no-newline marker')
                    target[-1] = target[-1][:-1]; offset += 1
            if len(removed) != ac or len(added) != bc or (not ac and not bc):
                _fail('zero-context patch quantity differs')
            hunks.append((a, ac, b, bc, removed, added))
        if not hunks:
            _fail('empty patch section')
        sections[name] = hunks
    if set(sections) != set(changes):
        _fail('missing patch path')
    return sections


def _apply(raw, hunks, reverse=False):
    source = raw.splitlines(keepends=True); result = []; cursor = 0
    for a, ac, b, bc, removed, added in hunks:
        if reverse:
            a, ac, b, bc, removed, added = b, bc, a, ac, added, removed
        start = a - 1 if ac else a
        output_start = b - 1 if bc else b
        if start < cursor or start > len(source) or source[start:start + ac] != removed:
            _fail('cold patch exact source mismatch')
        result.extend(source[cursor:start])
        if len(result) != output_start:
            _fail('cold patch exact coordinates differ')
        result.extend(added); cursor = start + ac
    result.extend(source[cursor:])
    return b''.join(result)


def validate_overlay(source_root):
    """Validate exact source data, return all 141 data-file path/SHA256 inputs."""
    root = Path(source_root)
    if root.is_symlink() or not root.is_dir():
        _fail('source root is not a real directory')
    inputs = {}; total = 0
    def read(name):
        nonlocal total
        _path(name); path = root
        for part in PurePosixPath(name).parts:
            path = path / part
            if path.is_symlink():
                _fail('symlink in source data path')
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            _fail('missing/nonregular/oversized data file: ' + name)
        with path.open('rb') as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        total += len(raw)
        if len(raw) > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
            _fail('data byte budget exceeded')
        inputs[name] = hashlib.sha256(raw).hexdigest()
        return raw
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _fail('duplicate JSON key')
            result[key] = value
        return result
    try:
        manifest = json.loads(read(MANIFEST), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('Cronet Windows overlay: invalid JSON') from error
    _shape(manifest, ('schema', 'module', 'replacementPath', 'baseCommit', 'baseTree', 'baseVendorTree',
                      'baseTreeProof', 'baseFiles', 'unchangedGitlinks', 'changes', 'patch', 'patchSHA256',
                      'historicalMaterials', 'nativeBinaryValidated', 'scope', 'patchContextLines'))
    fixed = {'schema': 'polaris-source-bound-module-overlay-v1', 'module': 'github.com/sagernet/cronet-go',
             'replacementPath': VENDOR, 'baseCommit': BASE_COMMIT, 'baseTree': BASE_TREE,
             'baseVendorTree': BASE_VENDOR_TREE, 'unchangedGitlinks': [], 'patch': PATCH,
             'historicalMaterials': HISTORICAL, 'nativeBinaryValidated': False, 'patchContextLines': 0}
    if any(type(manifest[k]) is not type(v) or manifest[k] != v for k, v in fixed.items()):
        _fail('fixed version/base/history/scope differs')
    if type(manifest['scope']) is not str or not 1 <= len(manifest['scope']) <= 512:
        _fail('scope differs')
    _hex(manifest['patchSHA256'], 64)
    proofs = manifest['baseTreeProof']
    if type(proofs) is not list or len(proofs) != 2:
        _fail('tree proof count differs')
    parent = BASE_TREE
    for proof, path, child in zip(proofs, ('', 'third_party'), ('third_party', 'cronet-go')):
        _shape(proof, ('path', 'gitTree', 'rawBase64'))
        if proof['path'] != path or proof['gitTree'] != parent or type(proof['rawBase64']) is not str or len(proof['rawBase64']) > 65536:
            _fail('tree proof binding differs')
        try:
            raw = base64.b64decode(proof['rawBase64'], validate=True)
        except ValueError as error:
            raise ValueError('Cronet Windows overlay: invalid tree encoding') from error
        if _hash(b'tree', raw) != parent:
            _fail('tree Merkle identity differs')
        entries = _tree_entries(raw)
        if child not in entries or entries[child][0] != '40000':
            _fail('missing vendor ancestor')
        parent = entries[child][1]
    if parent != BASE_VENDOR_TREE:
        _fail('vendor Merkle binding differs')
    base = manifest['baseFiles']; delta = manifest['changes']
    if type(base) is not list or len(base) != 135 or type(delta) is not list or len(delta) != 6:
        _fail('base/delta count differs')
    expected = {}
    for record in base:
        _record(record)
        if record['path'] in expected:
            _fail('duplicate base path')
        expected[record['path']] = record
    if _tree(base) != BASE_VENDOR_TREE:
        _fail('complete base Merkle identity differs')
    changes = {}
    for item in delta:
        _shape(item, ('path', 'operation', 'before', 'after')); name = _path(item['path'])
        if name in changes or item['before'] != expected.get(name) or item['before'] == item['after']:
            _fail('duplicate/mismatched delta')
        for record in (item['before'], item['after']):
            if record is not None:
                _record(record)
                if record['path'] != name:
                    _fail('delta record path differs')
        operation = 'add' if item['before'] is None else 'delete' if item['after'] is None else 'modify'
        if item['operation'] != operation or (item['before'] is None and item['after'] is None):
            _fail('delta operation differs')
        changes[name] = item
        if item['after'] is None:
            expected.pop(name)
        else:
            expected[name] = item['after']
    if len(expected) != 137:
        _fail('current file count differs')
    vendor = root / VENDOR
    # Check ancestors even before traversal; os.walk never follows symlink dirs.
    for path in (root / 'third_party', vendor):
        if path.is_symlink() or not path.is_dir():
            _fail('vendor directory differs')
    actual = set(); actual_dirs = set(); entries_seen = 0
    def walk_error(error):
        raise ValueError('Cronet Windows overlay: unreadable vendor directory') from error
    for directory, directories, files in os.walk(vendor, followlinks=False, onerror=walk_error):
        entries_seen += len(directories) + len(files)
        if entries_seen > MAX_ENTRIES:
            _fail('vendor entry budget exceeded')
        for name in directories:
            actual_dirs.add((Path(directory) / name).relative_to(vendor).as_posix())
        for name in directories + files:
            path = Path(directory) / name
            if path.is_symlink():
                _fail('vendor symlink')
            if name in files:
                actual.add(path.relative_to(vendor).as_posix())
    expected_dirs = {parent.as_posix() for name in expected for parent in PurePosixPath(name).parents if parent.as_posix() != '.'}
    if actual != set(expected) or actual_dirs != expected_dirs:
        _fail('missing/extra current files')
    current = {}
    for name in sorted(actual):
        raw = read(VENDOR + '/' + name); record = expected[name]
        mode = '100755' if (vendor / name).stat().st_mode & stat.S_IXUSR else '100644'
        if mode != record['mode']:
            _fail('current file mode differs')
        _check(raw, record); current[name] = raw
    for name, pin in HISTORICAL.items():
        raw = read(name)
        if len(raw) != pin['bytes'] or inputs[name] != pin['sha256']:
            _fail('historical material differs')
    patch = read(PATCH)
    if inputs[PATCH] != manifest['patchSHA256']:
        _fail('patch SHA256 differs')
    sections = _patch_sections(patch, changes)
    for name, item in changes.items():
        after = current.get(name, b'')
        before = _apply(after, sections[name], reverse=True)
        if item['before'] is None:
            if before:
                _fail('added path has nonempty base')
        else:
            _check(before, item['before'])
        if _apply(before, sections[name]) != after:
            _fail('cold forward reconstruction differs')
    return dict(sorted(inputs.items()))
