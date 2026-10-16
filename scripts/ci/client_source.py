"""Exact client gitlinks + explicit source-owned build overlays, separate from core.

No tag, gitlink, signing credential or upstream repository is changed. The
candidate receipt carries the actual client diff, including generated version
metadata, so the client is never represented as an unmodified core source tree.
"""
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / 'release/ci/client-overlays.json'
JOBS = {'build_android': 'android', 'build_windows_client': 'windows',
        'build_linux_client': 'linux', 'build_apple': 'apple', 'build_apple_app_store': 'apple'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def git(directory, *args):
    return subprocess.check_output(['git', '-C', str(directory), *args])


def definition(platform):
    return json.loads(MANIFEST.read_text())['platforms'][platform]


def edits(raw, entry):
    blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    if blob != entry['beforeGitBlob'] or sha(raw) != entry['beforeSHA256']:
        raise ValueError('client overlay baseline mismatch: ' + entry['path'])
    text = raw.decode()
    for edit in entry['edits']:
        if text.count(edit['old']) != edit['count']:
            raise ValueError('client overlay anchor mismatch: ' + entry['path'])
        text = text.replace(edit['old'], edit['new'])
    after = text.encode()
    if sha(after) != entry['afterSHA256']:
        raise ValueError('client overlay result differs from source-owned identity')
    return after


def checkout(platform):
    spec = definition(platform)
    directory = ROOT / spec['path']
    head = git(directory, 'rev-parse', 'HEAD').decode().strip()
    tree_entry = git(ROOT, 'ls-tree', 'HEAD', spec['path']).decode().split()
    if head != spec['commit'] or git(directory, 'rev-parse', 'HEAD^{tree}').decode().strip() != spec['tree'] or tree_entry[:3] != ['160000', 'commit', head]:
        raise ValueError('client checkout differs from exact source-owned gitlink')
    return spec, directory


def apply(platform, unsigned=False):
    spec, directory = checkout(platform)
    writes = []
    for entry in spec['files']:
        if entry['kind'] == 'unsigned' and not unsigned:
            continue
        p = directory / entry['path']
        if p.is_symlink():
            raise ValueError('client source symlink forbidden')
        writes.append((p, edits(p.read_bytes(), entry)))
    # Validate the complete edit set before changing a single source file.
    for p, raw in writes:
        p.write_bytes(raw)


def collect(platform, unsigned):
    spec, directory = checkout(platform)
    selected = {e['path']: e for e in spec['files'] if e['kind'] != 'unsigned' or unsigned}
    changed = set(git(directory, 'diff', '--name-only', '-z', 'HEAD').decode().strip('\0').split('\0')) - {''}
    if not changed <= set(selected) | set(spec['versionMetadata']):
        raise ValueError('unlisted client source changes: ' + repr(sorted(changed)))
    rows = []
    for path in sorted(changed | set(selected)):
        p = directory / path
        if p.is_symlink() or not p.is_file():
            raise ValueError('client source must remain a regular file: ' + path)
        raw = p.read_bytes()
        baseline = git(directory, 'show', spec['commit'] + ':' + path)
        if path in selected:
            expected = edits(baseline, selected[path])
            if raw != expected:
                raise ValueError('client build changed a reviewed overlay: ' + path)
        rows.append({'path': path, 'kind': selected[path]['kind'] if path in selected else 'generated-version-metadata',
                     'beforeSHA256': sha(baseline), 'afterSHA256': sha(raw), 'bytes': len(raw)})
    diff = git(directory, 'diff', '--no-ext-diff', '--binary', '--full-index', 'HEAD').decode()
    record = {'schema': 'polaris-client-source-v1', 'platform': platform, 'repository': spec['repository'],
              'baseCommit': spec['commit'], 'baseTree': git(directory, 'rev-parse', 'HEAD^{tree}').decode().strip(),
              'coreSourceCommit': git(ROOT, 'rev-parse', 'HEAD').decode().strip(),
              'overlayManifestSHA256': sha(MANIFEST.read_bytes()), 'unsigned': unsigned,
              'sourceOverlayCount': len(selected), 'files': rows, 'diff': diff, 'diffSHA256': sha(diff.encode())}
    validate(record, platform, record['coreSourceCommit'], unsigned)
    return record


def validate(record, platform, source, unsigned):
    spec = definition(platform)
    selected = {e['path']: e for e in spec['files'] if e['kind'] != 'unsigned' or unsigned}
    if (record.get('schema'), record.get('platform'), record.get('repository'), record.get('baseCommit'), record.get('baseTree'),
        record.get('coreSourceCommit'), record.get('overlayManifestSHA256'), record.get('unsigned'), record.get('sourceOverlayCount')) != (
        'polaris-client-source-v1', platform, spec['repository'], spec['commit'], spec['tree'], source,
        sha(MANIFEST.read_bytes()), unsigned, len(selected)):
        raise ValueError('client source receipt identity mismatch')
    if type(record.get('unsigned')) is not bool or type(record.get('sourceOverlayCount')) is not int:
        raise ValueError('client overlay count/mode must have exact types')
    if not isinstance(record.get('diff'), str) or len(record['diff'].encode()) > 1024*1024:
        raise ValueError('client source diff exceeds bounded source evidence budget')
    if record.get('diffSHA256') != sha(record['diff'].encode()):
        raise ValueError('client source diff digest mismatch')
    rows = record['files']; paths = [e['path'] for e in rows]
    if len(paths) != len(set(paths)) or not set(selected) <= set(paths) <= set(selected) | set(spec['versionMetadata']):
        raise ValueError('client source change inventory mismatch')
    for row in rows:
        if row['path'] in selected:
            expected = selected[row['path']]
            if (row['kind'], row['beforeSHA256'], row['afterSHA256']) != (expected['kind'], expected['beforeSHA256'], expected['afterSHA256']):
                raise ValueError('client source overlay hashes mismatch')
        elif row['kind'] != 'generated-version-metadata':
            raise ValueError('unknown client source change')
        for key in ('beforeSHA256', 'afterSHA256'):
            if not isinstance(row.get(key), str) or not re.fullmatch(r'[0-9a-f]{64}', row[key]):
                raise ValueError('invalid actual client source digest')
        if type(row['bytes']) is not int or row['bytes'] <= 0:
            raise ValueError('invalid client source size')


def record_signed(platform, directory):
    # Same source evidence for signed builds; signing remains strict and separate.
    record = {'schema': 'polaris-client-source-evidence-v1', 'sourceCommit': git(ROOT, 'rev-parse', 'HEAD').decode().strip(),
              'workflowRunId': os.environ['GITHUB_RUN_ID'], 'workflowAttempt': os.environ['GITHUB_RUN_ATTEMPT'],
              'clientSource': collect(platform, False)}
    root = Path(directory);root.mkdir(exist_ok=True)
    (root / ('polaris-candidate-manifest-client-source-' + os.environ['GITHUB_JOB'] + '.json')).write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    if sys.argv[1] == 'apply':
        apply(sys.argv[2], unsigned='--unsigned' in sys.argv[3:])
    elif sys.argv[1] == 'record-signed':
        record_signed(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit('expected apply or record-signed')
