"""Partition the patch queue by actual go.mod boundaries; never invoke Go."""
import argparse
import json
from pathlib import Path, PurePosixPath
import re
import subprocess


MODULES = {
    '.': 'github.com/sagernet/sing-box',
    'third_party/sing-tun': 'github.com/sagernet/sing-tun',
    'third_party/metacubex-utls': 'github.com/metacubex/utls',
}
MARKERS = {'third_party/sing-tun': 'sing-tun-selected',
           'third_party/metacubex-utls': 'metacubex-utls-selected'}


def selection(root, changed_paths):
    """Account for each changed Go/input path or reject an unowned module.

    Nested modules always run ./... from their own root. Removed root packages
    and root-input-only changes fall back to full root validation. This keeps
    deleted directories out of package arguments without silently losing tests.
    """
    root = Path(root).resolve(strict=True)
    selected = {}
    for name in sorted(set(changed_paths)):
        path = PurePosixPath(name)
        if path.suffix != '.go' and path.name not in {'go.mod', 'go.sum'}:
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
        if owner == '.' and path.suffix == '.go':
            if not (root / name).is_file():
                entry['fullValidation'] = True
            else:
                entry['packages'].add('.' if path.parent == PurePosixPath('.')
                                      else './' + str(path.parent))
    for owner, entry in selected.items():
        if entry['fullValidation'] or not entry['packages']:
            entry['packages'] = ['./...']
            entry['fullValidation'] = True
        else:
            entry['packages'] = sorted(entry['packages'])
    return {'schema': 'polaris-patch-module-selection-v1',
            'modules': dict(sorted(selected.items()))}


def write_plan(directory, plan):
    # A fresh runner-owned directory prevents stale selected markers surviving
    # a later invocation. Validate the entire plan before creating any files.
    directory = Path(directory)
    directory.parent.mkdir(parents=True, exist_ok=True)
    directory.mkdir()
    (directory / 'selection.json').write_text(json.dumps(plan, indent=2) + '\n')
    packages = plan['modules'].get('.', {}).get('packages', [])
    (directory / 'root-packages.txt').write_text(''.join(p + '\n' for p in packages))
    for owner, name in MARKERS.items():
        if owner in plan['modules']:
            (directory / name).write_text(MODULES[owner] + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True)
    parser.add_argument('--output-directory', required=True)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.base):
        parser.error('base must be a full lowercase commit SHA')
    root = Path(__file__).resolve().parents[2]
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    subprocess.run(['git', 'merge-base', '--is-ancestor', args.base, head], cwd=root, check=True)
    raw = subprocess.check_output(['git', 'diff', '--name-only', '--no-renames', '-z',
                                   args.base + '..' + head], cwd=root)
    paths = [p.decode('utf-8', errors='strict') for p in raw.split(b'\0') if p]
    plan = selection(root, paths)
    plan.update({'baseCommit': args.base, 'sourceCommit': head})
    write_plan(args.output_directory, plan)
    print(json.dumps(plan, sort_keys=True))


if __name__ == '__main__':
    main()
