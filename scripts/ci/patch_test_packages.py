"""Partition the patch queue by actual go.mod boundaries; never invoke Go."""
import argparse
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
    'third_party/go-nat': 'github.com/libp2p/go-nat',
    'third_party/tailscale': SDK,
    'third_party/wireguard-go': 'github.com/sagernet/wireguard-go',
    'third_party/tfo-go': 'github.com/database64128/tfo-go/v2',
    'third_party/sing-vmess': 'github.com/sagernet/sing-vmess',
}
MARKERS = {'third_party/sing-tun': 'sing-tun-selected',
           'third_party/metacubex-utls': 'metacubex-utls-selected',
           'third_party/cronet-go': 'cronet-go-selected',
           'third_party/fswatch': 'fswatch-selected',
           'third_party/sing': 'sing-selected',
           'third_party/sing-quic': 'sing-quic-selected',
           'third_party/go-nat': 'go-nat-selected',
           'third_party/tailscale': 'tailscale-selected',
           'third_party/wireguard-go': 'wireguard-go-selected',
           'third_party/tfo-go': 'tfo-go-selected',
           'third_party/sing-vmess': 'sing-vmess-selected'}

# The SDK gate is deliberately bounded and shared with G4. Run these import
# paths from the root module so its verified replacements remain effective.
BOUNDED_MODULE_PACKAGES = {
    'third_party/tailscale': tuple(SDK + '/' + package for package in SDK_PACKAGES),
}
SCHEMA_INPUT_PACKAGES = {'daemon/runtime_config.proto': './daemon'}


def selection(root, changed_paths):
    """Account for each changed Go/input path or reject an unowned module.

    Nested modules run ./... from their own root except the bounded G4 SDK
    selection. Schema inputs select their generated-code package. Removed root
    packages and root-input-only changes fall back to full root validation.
    This keeps deleted directories out of arguments without losing tests.
    """
    root = Path(root).resolve(strict=True)
    selected = {}
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
        owner = None
        for parent in (path.parent, *path.parent.parents):
            directory = root / str(parent)
            if directory.is_symlink() or (directory / 'go.mod').is_symlink():
                raise ValueError('symlink in module boundary: ' + str(parent))
            if (directory / 'go.mod').is_file():
                owner = str(parent)
                break
        if owner == 'release':
            # release/go.mod only keeps archived license evidence out of root ./...
            if ((root / 'release/go.mod').read_text()
                    != 'module github.com/polaris-arch/sing-box-polaris/release\n\ngo 1.27.0\n'
                    or name != 'release/go.mod' and not path.is_relative_to('release/licenses')):
                raise ValueError('unaccounted release module path: ' + name)
            continue
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

