#!/usr/bin/env python3
"""Check the pinned formatter's fixed point without rewriting the checkout."""
import difflib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile

# Includes the final, byte-identical verification pass. Never accept a cycle or
# a partially formatted result when this finite bound is reached.
MAX_FORMAT_PASSES = 6


def emit_diff(path, before, after):
    """Emit a byte-preserving ordinary unified diff, including missing EOF LF."""
    def source_lines(data):
        # Unified diff line numbers count LF only, even inside raw literals.
        parts = data.split(b'\n')
        return [part + b'\n' for part in parts[:-1]] + ([parts[-1]] if parts[-1] else [])

    lines = difflib.diff_bytes(
        difflib.unified_diff, source_lines(before), source_lines(after),
        fromfile=os.fsencode('a/' + path), tofile=os.fsencode('b/' + path),
    )
    for line in lines:
        sys.stdout.buffer.write(line)
        if not line.endswith(b'\n'):
            sys.stdout.buffer.write(b'\n\\ No newline at end of file\n')
    sys.stdout.buffer.flush()



# Match the root module's existing lint exclusions, not arbitrary workspace or
# local replace targets. Nested modules are independent even when tracked here.
EXCLUDED_PREFIXES = ('vendor/', 'third_party/', 'release/dependency-sources/',
                     'builtin/', 'examples/', 'transport/simple-obfs/')


def checked_path(path, source):
    if (not isinstance(path, str) or not path or PurePosixPath(path).is_absolute()
            or '..' in PurePosixPath(path).parts or '\\' in path
            or any(c in path for c in '\x00\r\n')):
        raise SystemExit('Invalid ' + source + ' path')
    return PurePosixPath(path).as_posix()


def excluded(path):
    return path.startswith(EXCLUDED_PREFIXES) or 'testdata' in PurePosixPath(path).parts


def regular_source(path):
    source = Path(path)
    if (any(p.is_symlink() for p in (source, *source.parents))
            or not source.exists() or not stat.S_ISREG(source.stat().st_mode)):
        raise SystemExit('Missing or unsafe owned Go source: ' + path)
    return source


def generated_source(data):
    # Go's generated-code convention is a standalone line comment before the
    # first non-comment package clause. Strings, block comments and later text
    # cannot exempt an owned file from formatting.
    data = data.removeprefix(b'\xef\xbb\xbf')
    marked = False
    while data:
        data = data.lstrip(b' \t\r\n')
        if data.startswith(b'//'):
            line, _, data = data.partition(b'\n')
            marked |= re.fullmatch(rb'// Code generated .* DO NOT EDIT\.\r?', line) is not None
        elif data.startswith(b'/*'):
            end = data.find(b'*/', 2)
            if end < 0:
                return False
            data = data[end + 2:]
        else:
            return marked and re.match(rb'package\s', data) is not None
    return False


def tracked_files():
    top = subprocess.run(['git', 'rev-parse', '--show-toplevel'],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if (top.returncode or top.stderr
            or Path(os.fsdecode(top.stdout).rstrip('\n')).resolve() != Path.cwd().resolve()):
        raise SystemExit('Cannot establish tracked owned formatting scope')
    result = subprocess.run(['git', 'ls-files', '--stage', '-z'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode or result.stderr or not result.stdout.endswith(b'\0'):
        raise SystemExit('Cannot establish tracked owned formatting scope')
    entries = {}
    for record in result.stdout.split(b'\0'):
        if not record:
            continue
        try:
            header, raw_path = record.split(b'\t', 1)
            mode, oid, stage = header.decode('ascii').split(' ')
            path = raw_path.decode('utf-8')
        except (ValueError, UnicodeError):
            raise SystemExit('Invalid tracked index record')
        if (checked_path(path, 'tracked') != path or stage != '0'
                or mode not in ('100644', '100755', '120000', '160000')
                or re.fullmatch('[0-9a-f]{40}', oid) is None or path in entries):
            raise SystemExit('Conflicting or invalid tracked index record')
        entries[path] = (mode, oid)
    if 'go.mod' not in entries:
        raise SystemExit('Missing tracked root module')
    return entries


def module_boundaries(entries):
    modules = []
    for path, (mode, oid) in sorted(entries.items()):
        if (path != 'go.mod' and not path.endswith('/go.mod')) or excluded(path):
            continue
        source = regular_source(path)
        data = source.read_bytes()
        actual = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if mode not in ('100644', '100755') or actual != oid:
            raise SystemExit('Tracked module boundary changed: ' + path)
        # Parse only; no edits, dependency resolution, toolchain download or
        # module build. Invalid boundaries must not silently hide owned files.
        result = subprocess.run(['go', 'mod', 'edit', '-json', '-modfile=' + str(source.resolve())], cwd=source.parent,
                                env=dict(os.environ, GOFLAGS='', GOENV='off', GOWORK='off', GOTOOLCHAIN='local',
                                         GOPROXY='off', GOSUMDB='off'),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        try:
            module = json.loads(result.stdout).get('Module')
        except (ValueError, AttributeError):
            module = None
        if (result.returncode or result.stderr or not isinstance(module, dict)
                or not isinstance(module.get('Path'), str) or not module['Path']):
            raise SystemExit('Invalid tracked module boundary: ' + path)
        if source.read_bytes() != data:
            raise SystemExit('Module boundary changed while parsing: ' + path)
        if path != 'go.mod':
            modules.append(str(PurePosixPath(path).parent) + '/')
    return tuple(modules)


def owned_scope(inventory):
    historical = set()
    paths = [row['path'] for row in inventory['files']]
    paths.extend(inventory.get('dailyHotFormattingScope', {}).get('paths', []))
    # Preserve explicit historical fail-closed checks without claiming the new
    # tracked union was covered by that old audit or acceptedTree.
    for value in paths:
        path = checked_path(value, 'inventory')
        if not path.endswith('.go') or path.endswith('.pb.go') or excluded(path):
            continue
        regular_source(path)
        historical.add(path)
    entries = tracked_files()
    nested = module_boundaries(entries)
    if any(path.startswith(nested) for path in historical):
        raise SystemExit('Historical owned source moved into a nested module')
    selected = set()
    for path in sorted(set(entries) | historical):
        if (not path.endswith('.go') or path.endswith('.pb.go') or excluded(path)
                or path.startswith(nested)):
            continue
        if path not in entries or entries[path][0] not in ('100644', '100755'):
            raise SystemExit('Untracked or unsafe owned Go source: ' + path)
        source = regular_source(path)
        if not generated_source(source.read_bytes()):
            selected.add(path)
    print('Owned formatting scope: ' + json.dumps({
        'historicalSelected': len(selected & historical),
        'trackedSelected': len(selected),
        'trackedAdditional': len(selected - historical),
        'nestedModules': len(nested),
    }, sort_keys=True), file=sys.stderr)
    return sorted(selected)


def main():
    root = Path.cwd()
    inventory = json.loads(Path('release/audit-remediation-source-inventory.json').read_text())
    if inventory.get('schema') != 'audit-remediation-source-inventory-v1':
        raise SystemExit('Invalid current remediation inventory; historical source is unsupported')
    files = owned_scope(inventory)
    if not files:
        raise SystemExit('Empty owned Go formatting scope')
    original = {path: Path(path).read_bytes() for path in files}
    tool = os.environ['GOLANGCI_LINT']
    # Keep the same executable after switching the formatter's working directory.
    resolved_tool = shutil.which(tool)
    if resolved_tool or os.sep in tool:
        tool = str(Path(resolved_tool or tool).resolve())
    version = subprocess.run([tool, 'version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    sys.stderr.buffer.write(version.stdout + version.stderr)
    sys.stderr.buffer.flush()
    if version.returncode:
        raise SystemExit(version.returncode if version.returncode > 0 else 1)

    with tempfile.TemporaryDirectory(prefix='owned-go-format-') as directory:
        copy = Path(directory) / 'source'
        if copy.is_relative_to(root):
            raise SystemExit('Formatter temporary copy must be outside the checkout')
        # Preserve config, module/workspace files, nested modules and local
        # replacements. Only explicit owned files are passed to the formatter.
        # Preserve unrelated symlinks without following them; owned paths above
        # must have no symlink components. No checkout file is a write target.
        shutil.copytree(root, copy, symlinks=True, ignore=shutil.ignore_patterns('.git'))
        previous = original
        for pass_number in range(1, MAX_FORMAT_PASSES + 1):
            result = subprocess.run(
                [tool, 'fmt', '--config', '.golangci.yml', '--', *files], cwd=copy,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            # Write mode normally emits nothing. The pinned MetaFormatter logs
            # individual formatter errors as warnings but can still exit zero;
            # reject diagnostics as well as process failures instead of passing.
            sys.stderr.buffer.write(result.stdout + result.stderr)
            sys.stderr.buffer.flush()
            print('Owned formatter pass ' + str(pass_number) + ' exit code: ' + str(result.returncode), file=sys.stderr, flush=True)
            if result.returncode:
                raise SystemExit(result.returncode if result.returncode > 0 else 1)
            if result.stdout or result.stderr:
                raise SystemExit('Owned formatter emitted unexpected diagnostics; refusing an unverified result')
            current = {path: (copy / path).read_bytes() for path in files}
            if current == previous:
                break
            previous = current
        else:
            raise SystemExit('Owned formatter did not reach a byte-stable fixed point after ' + str(MAX_FORMAT_PASSES) + ' passes')

    # Judge the original checkout, never the already-formatted private copy.
    dirty = False
    for path in files:
        if Path(path).read_bytes() != original[path]:
            raise SystemExit('Owned source changed during formatting check: ' + path)
        if original[path] != current[path]:
            dirty = True
            emit_diff(path, original[path], current[path])
    if dirty:
        raise SystemExit('Owned source formatting differs; format and commit before final validation')
    print('Owned Go formatting clean: ' + str(len(files)) + ' files; vendor/generated excluded')


if __name__ == '__main__':
    main()
