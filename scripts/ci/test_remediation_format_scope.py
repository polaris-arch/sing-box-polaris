"""Exercise the existing formatter selection without executing native tools."""
import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('check_remediation_format.py')

class FormatScopeTests(unittest.TestCase):
    def check_scope(self, extra):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'release').mkdir()
            for name in ('old.go', 'new.go'):
                (root / name).write_text('package fixture\n')
            (root / 'release/audit-remediation-source-inventory.json').write_text(json.dumps({
                'schema': 'audit-remediation-source-inventory-v1',
                'files': [{'path': 'old.go'}],
                'dailyHotFormattingScope': {'paths': extra},
            }))
            calls = []
            def execute(command, **kwargs):
                calls.append(command)
                return type('Result', (), {'stdout': b'', 'stderr': b'', 'returncode': 0})()
            output = io.TextIOWrapper(io.BytesIO())
            previous = Path.cwd()
            try:
                os.chdir(root)
                with patch.dict(os.environ, GOLANGCI_LINT='fixed-formatter'), patch('subprocess.run', execute), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                    runpy.run_path(str(SCRIPT))
            finally:
                os.chdir(previous)
            return calls

    def test_union_deduplicates_and_excludes_dependencies_and_generated_bindings(self):
        calls = self.check_scope(['new.go', 'old.go', 'third_party/native/a.go', 'vendor/a.go', 'daemon/api.pb.go'])
        self.assertEqual(calls[-1], ['fixed-formatter', 'fmt', '--config', '.golangci.yml', '--diff', 'new.go', 'old.go'])

    def test_missing_owned_path_fails_closed(self):
        with self.assertRaisesRegex(SystemExit, 'Missing or unsafe'):
            self.check_scope(['missing.go'])

    def test_unsafe_path_fails_closed(self):
        with self.assertRaisesRegex(SystemExit, 'Invalid inventory path'):
            self.check_scope(['../outside.go'])
