#!/usr/bin/env python3
"""Check owned remediation Go sources only; missing current inventory fails closed."""
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys

inventory = json.loads(Path('release/audit-remediation-source-inventory.json').read_text())
if inventory.get('schema') != 'audit-remediation-source-inventory-v1':
    raise SystemExit('Invalid current remediation inventory; historical source is unsupported')
files = []
paths = [row['path'] for row in inventory['files']]
paths.extend(inventory.get('dailyHotFormattingScope', {}).get('paths', []))
for path in paths:
    if not isinstance(path, str) or PurePosixPath(path).is_absolute() or '..' in PurePosixPath(path).parts:
        raise SystemExit('Invalid inventory path')
    if not path.endswith('.go') or path.endswith('.pb.go') or path.startswith(('vendor/', 'third_party/', 'release/dependency-sources/')):
        continue
    if not Path(path).is_file() or Path(path).is_symlink():
        raise SystemExit('Missing or unsafe owned Go source: ' + path)
    if 'Code generated ' in Path(path).read_text()[:2048]:
        continue
    files.append(path)
files = sorted(set(files))
if not files:
    raise SystemExit('Empty owned Go formatting scope')
tool = os.environ['GOLANGCI_LINT']
subprocess.run([tool, 'version'], check=True)
result = subprocess.run(
    [tool, 'fmt', '--config', '.golangci.yml', '--diff', *files],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
)
# Emit both complete streams before checking status: --diff returns 1 for changes.
sys.stdout.buffer.write(result.stdout)
sys.stdout.buffer.flush()
sys.stderr.buffer.write(result.stderr)
sys.stderr.buffer.flush()
print('Owned formatter exit code: ' + str(result.returncode), file=sys.stderr, flush=True)
if result.returncode != 0:
    raise SystemExit(result.returncode if result.returncode > 0 else 1)
if result.stdout:
    raise SystemExit('Owned source formatting differs; format and commit before final validation')
print('Owned Go formatting clean: ' + str(len(files)) + ' files; vendor/generated excluded')
