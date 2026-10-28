#!/usr/bin/env python3
"""Check the pinned formatter's fixed point without rewriting the checkout."""
import difflib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
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


def main():
    root = Path.cwd()
    inventory = json.loads(Path('release/audit-remediation-source-inventory.json').read_text())
    if inventory.get('schema') != 'audit-remediation-source-inventory-v1':
        raise SystemExit('Invalid current remediation inventory; historical source is unsupported')
    files = []
    paths = [row['path'] for row in inventory['files']]
    paths.extend(inventory.get('dailyHotFormattingScope', {}).get('paths', []))
    for path in paths:
        if (not isinstance(path, str) or PurePosixPath(path).is_absolute()
                or '..' in PurePosixPath(path).parts or any(c in path for c in '\x00\r\n')):
            raise SystemExit('Invalid inventory path')
        path = PurePosixPath(path).as_posix()
        if not path.endswith('.go') or path.endswith('.pb.go') or path.startswith(('vendor/', 'third_party/', 'release/dependency-sources/')):
            continue
        source = Path(path)
        if not source.is_file() or any(p.is_symlink() for p in (source, *source.parents)):
            raise SystemExit('Missing or unsafe owned Go source: ' + path)
        if 'Code generated ' in source.read_text()[:2048]:
            continue
        files.append(path)
    files = sorted(set(files))
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
