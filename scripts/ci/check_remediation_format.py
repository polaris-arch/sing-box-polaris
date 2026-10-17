#!/usr/bin/env python3
"""Check owned remediation Go sources only; missing current inventory fails closed."""
import json
import os
from pathlib import Path, PurePosixPath
import subprocess

inventory = json.loads(Path('release/audit-remediation-source-inventory.json').read_text())
if inventory.get('schema') != 'audit-remediation-source-inventory-v1':
    raise SystemExit('Invalid current remediation inventory; historical source is unsupported')
files = []
for row in inventory['files']:
    path = row['path']
    if not isinstance(path, str) or PurePosixPath(path).is_absolute() or '..' in PurePosixPath(path).parts:
        raise SystemExit('Invalid inventory path')
    if not path.endswith('.go') or path.endswith('.pb.go') or path.startswith(('vendor/', 'third_party/')):
        continue
    if not Path(path).is_file() or Path(path).is_symlink():
        raise SystemExit('Missing or unsafe owned Go source: ' + path)
    files.append(path)
files = sorted(set(files))
if not files:
    raise SystemExit('Empty owned Go formatting scope')
tool = os.environ['GOLANGCI_LINT']
subprocess.run([tool, 'version'], check=True)
result = subprocess.run([tool, 'fmt', '--config', '.golangci.yml', '--diff', *files], stdout=subprocess.PIPE, check=True)
if result.stdout:
    print(result.stdout.decode(), end='')
    raise SystemExit('Owned source formatting differs; format and commit before final validation')
print('Owned Go formatting clean: ' + str(len(files)) + ' files; vendor/generated excluded')
