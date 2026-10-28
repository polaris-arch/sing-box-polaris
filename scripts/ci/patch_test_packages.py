"""Partition the patch queue by actual go.mod boundaries; never invoke Go."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

from g4_candidate import SDK, SDK_PACKAGES


MODULES = {
    '.': 'github.com/sagernet/sing-box',
    'third_party/sing-tun': 'github.com/sagernet/sing-tun',
    'third_party/metacubex-utls': 'github.com/metacubex/utls',
    'third_party/cronet-go': 'github.com/sagernet/cronet-go',
    'third_party/fswatch': 'github.com/sagernet/fswatch',
    'third_party/sing': 'github.com/sagernet/sing',
    'third_party/sing-quic': 'github.com/sagernet/sing-quic',
    'third_party/tailscale': SDK,
    'third_party/wireguard-go': 'github.com/sagernet/wireguard-go',
    'third_party/tfo-go': 'github.com/database64128/tfo-go/v2',
}
MARKERS = {'third_party/sing-tun': 'sing-tun-selected',
           'third_party/metacubex-utls': 'metacubex-utls-selected',
           'third_party/cronet-go': 'cronet-go-selected',
           'third_party/fswatch': 'fswatch-selected',
           'third_party/sing': 'sing-selected',
           'third_party/sing-quic': 'sing-quic-selected',
           'third_party/tailscale': 'tailscale-selected',
           'third_party/wireguard-go': 'wireguard-go-selected',
           'third_party/tfo-go': 'tfo-go-selected'}

# The SDK gate is deliberately bounded and shared with G4. Run these import
# paths from the root module so its verified replacements remain effective.
BOUNDED_MODULE_PACKAGES = {
    'third_party/tailscale': tuple(SDK + '/' + package for package in SDK_PACKAGES),
}
SCHEMA_INPUT_PACKAGES = {'daemon/runtime_config.proto': './daemon'}


EVIDENCE_ROOT = 'release/dependency-sources/sing-usbip/sing-box-source-evidence'
EVIDENCE_MODULE = 'github.com/polaris-arch/sing-box-polaris/source-evidence/sing-usbip'
EVIDENCE_MANIFEST = 'release/dependency-sources/sing-usbip/source-tar-materials-manifest.json'
EVIDENCE_SOURCE_ROOT = 'release/dependency-sources/sing-usbip/source'
EVIDENCE_MODULES = {EVIDENCE_ROOT: EVIDENCE_MODULE,
                    EVIDENCE_SOURCE_ROOT: 'github.com/sagernet/sing-usbip'}


def verify_read_only_evidence(root, owner=EVIDENCE_ROOT):
    """Validate the narrow archived snapshot; it is never a runnable module.

    A Go module boundary removes these four partial historical files from root
    ./... discovery. Hashes and the exact file set still fail closed here, while
    service/usbip and cmd/internal/build_boxdd remain ordinary live packages.
    """
    if owner not in EVIDENCE_MODULES:
        raise ValueError('unregistered read-only evidence root')
    directory = root / owner
    marker = directory / 'go.mod'
    if directory.is_symlink() or marker.is_symlink() or not marker.is_file():
        raise ValueError('missing or unsafe read-only evidence module boundary')
    # Only the module declaration and language version are permitted. No
    # require/replace/workspace directives can turn this into executable scope.
    if owner == EVIDENCE_ROOT:
        declarations = [line.strip() for line in marker.read_text().splitlines()
                        if line.strip() and not line.lstrip().startswith('//')]
        if declarations != ['module ' + EVIDENCE_MODULE, 'go 1.27.0']:
            raise ValueError('read-only evidence module identity or directives changed')
    manifest = json.loads((root / EVIDENCE_MANIFEST).read_text())
    if (manifest.get('schema') != 'polaris-sing-usbip-source-tar-materials-v1'
            or manifest.get('baseDirectory') != 'release/dependency-sources'):
        raise ValueError('invalid read-only evidence manifest')
    prefix = str(PurePosixPath(owner).relative_to('release/dependency-sources')) + '/'
    expected = {}
    for row in manifest['files']:
        if not row['path'].startswith(prefix):
            continue
        relative = PurePosixPath(row['path'][len(prefix):])
        if (relative.is_absolute() or '..' in relative.parts
                or str(relative) != row['path'][len(prefix):] or str(relative) in expected):
            raise ValueError('invalid read-only evidence path')
        expected[str(relative)] = row
    if not expected:
        raise ValueError('empty read-only evidence manifest')
    actual = set()
    for path in directory.rglob('*'):
        if path.is_symlink():
            raise ValueError('symlink in read-only evidence')
        if path.is_file() and (path != marker or owner != EVIDENCE_ROOT):
            actual.add(path.relative_to(directory).as_posix())
    if actual != set(expected):
        raise ValueError('read-only evidence file set changed')
    for relative, row in expected.items():
        data = (directory / relative).read_bytes()
        if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('read-only evidence hash mismatch: ' + relative)
    return {'module': EVIDENCE_MODULES[owner], 'manifest': EVIDENCE_MANIFEST,
            'verifiedFiles': len(expected), 'changedPaths': [],
            'boundary': {'path': owner + '/go.mod',
                         'identity': 'current-added' if owner == EVIDENCE_ROOT else 'historical-inventoried',
                         'sha256': hashlib.sha256(marker.read_bytes()).hexdigest()}}


def selection(root, changed_paths):
    """Account for each changed Go/input path or reject an unowned module.

    Nested modules run ./... from their own root except the bounded G4 SDK
    selection. Schema inputs select their generated-code package. Removed root
    packages and root-input-only changes fall back to full root validation.
    This keeps deleted directories out of arguments without losing tests.
    """
    root = Path(root).resolve(strict=True)
    selected = {}
    evidence = {}
    for name in sorted(set(changed_paths)):
        path = PurePosixPath(name)
        schema_package = SCHEMA_INPUT_PACKAGES.get(str(path))
        if (path.suffix != '.go' and path.name not in {'go.mod', 'go.sum'}
                and schema_package is None):
            continue
        if (path.is_absolute() or '..' in path.parts or str(path) != name
                or any(c in name for c in '\r\n\0\\')):
            raise ValueError('invalid changed Go/input path: ' + repr(name))
        if any((root / str(parent)).is_symlink()
               for parent in (path.parent, *path.parent.parents)):
            raise ValueError('symlink in module boundary: ' + name)
        evidence_owner = next((owner for owner in EVIDENCE_MODULES
                               if path.is_relative_to(owner)), None)
        if evidence_owner is not None:
            if evidence_owner not in evidence:
                evidence[evidence_owner] = verify_read_only_evidence(root, evidence_owner)
            evidence[evidence_owner]['changedPaths'].append(name)
            continue
        owner = None
        for parent in (path.parent, *path.parent.parents):
            directory = root / str(parent)
            if directory.is_symlink() or (directory / 'go.mod').is_symlink():
                raise ValueError('symlink in module boundary: ' + str(parent))
            if (directory / 'go.mod').is_file():
                owner = str(parent)
                break
        if owner not in MODULES:
            raise ValueError('changed module has no approved test runner: ' + str(owner))
        for nested in MARKERS:
            if path.is_relative_to(nested) and owner != nested:
                raise ValueError('missing or changed nested module boundary: ' + nested)
        if path.name in {'go.mod', 'go.sum'} and str(path.parent) != owner:
            raise ValueError('unaccounted module input boundary: ' + name)
        identities = re.findall(r'^module[ \t]+([^\s]+)[ \t]*$',
                                (root / owner / 'go.mod').read_text(), re.M)
        if identities != [MODULES[owner]]:
            raise ValueError('module identity mismatch: ' + owner)
        entry = selected.setdefault(owner, {'module': MODULES[owner],
                                            'changedPaths': [], 'packages': set(),
                                            'fullValidation': owner != '.'})
        entry['changedPaths'].append(name)
        if owner == '.' and (path.suffix == '.go' or schema_package is not None):
            if (schema_package is None and not (root / name).is_file()
                    or schema_package is not None and not (root / path.parent).is_dir()):
                entry['fullValidation'] = True
            else:
                entry['packages'].add(schema_package or
                                      ('.' if path.parent == PurePosixPath('.')
                                       else './' + str(path.parent)))
    for owner, entry in selected.items():
        if owner in BOUNDED_MODULE_PACKAGES:
            entry['packages'] = list(BOUNDED_MODULE_PACKAGES[owner])
            entry['fullValidation'] = False
        elif entry['fullValidation'] or not entry['packages']:
            entry['packages'] = ['./...']
            entry['fullValidation'] = True
        else:
            entry['packages'] = sorted(entry['packages'])
    plan = {'schema': 'polaris-patch-module-selection-v1',
            'modules': dict(sorted(selected.items()))}
    if evidence:
        plan['readOnlyEvidence'] = evidence
    return plan


def write_plan(directory, plan):
    # A fresh runner-owned directory prevents stale selected markers surviving
    # a later invocation. Validate the entire plan before creating any files.
    directory = Path(directory)
    directory.parent.mkdir(parents=True, exist_ok=True)
    directory.mkdir()
    (directory / 'selection.json').write_text(json.dumps(plan, indent=2) + '\n')
    packages = plan['modules'].get('.', {}).get('packages', [])
    (directory / 'root-packages.txt').write_text(''.join(p + '\n' for p in packages))
    packages = plan['modules'].get('third_party/tailscale', {}).get('packages', [])
    (directory / 'tailscale-packages.txt').write_text(''.join(p + '\n' for p in packages))
    for owner, name in MARKERS.items():
        if owner in plan['modules']:
            (directory / name).write_text(MODULES[owner] + '\n')


def changed_paths(root, base, head):
    """Require the official baseline ancestor, then compare the exact snapshots."""
    subprocess.run(['git', 'merge-base', '--is-ancestor', base, head], cwd=root, check=True)
    raw = subprocess.check_output(['git', 'diff', '--name-only', '--no-renames', '-z',
                                   base + '..' + head], cwd=root)
    paths = [p.decode('utf-8', errors='strict') for p in raw.split(b'\0') if p]
    return paths, base


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True)
    parser.add_argument('--output-directory', required=True)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.base):
        parser.error('base must be a full lowercase commit SHA')
    root = Path(__file__).resolve().parents[2]
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    # Preserve the verified release baseline's ancestry during history cleanup.
    paths, merge_base = changed_paths(root, args.base, head)
    plan = selection(root, paths)
    plan.update({'baseCommit': args.base, 'sourceCommit': head, 'mergeBaseCommit': merge_base,
                 'baseIsAncestor': merge_base == args.base})
    write_plan(args.output_directory, plan)
    print(json.dumps(plan, sort_keys=True))


if __name__ == '__main__':
    main()

