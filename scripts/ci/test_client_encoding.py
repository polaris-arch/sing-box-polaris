"""Client entrypoints and material JSON must not depend on the Windows locale."""
import ast
import json
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest import mock

import client_source as client
import record_candidate

ROOT = Path(__file__).resolve().parents[2]
READ_TEXT = Path.read_text


def cp1252_read(path, encoding=None, errors=None):
    return READ_TEXT(path, encoding=encoding or 'cp1252', errors=errors)


class ClientEncodingTests(unittest.TestCase):
    def test_actual_manifest_under_cp1252(self):
        raw = client.MANIFEST.read_bytes()
        with self.assertRaises(UnicodeDecodeError):
            raw.decode('cp1252')
        with mock.patch.object(Path, 'read_text', cp1252_read):
            for platform in ('windows', 'linux', 'apple', 'android'):
                self.assertEqual(client.definition(platform), json.loads(raw)['platforms'][platform])

    def test_windows_unsigned_entry_preserves_unicode_and_line_bytes(self):
        # The entrypoint, manifest read, baseline/hash checks and overlay write are real.
        # Only Git plumbing is replaced with a fixed committed fixture.
        before = '標題\r\nold\n'.encode('utf-8')
        after = '標題\r\nsing-box-polaris\n'.encode('utf-8')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); directory = root / 'clients/desktop'; directory.mkdir(parents=True)
            (directory / 'source.txt').write_bytes(before)
            entry = {'path':'source.txt', 'kind':'branding', 'beforeMode':'100644',
                     'beforeGitBlob':client.blob(before), 'beforeSHA256':client.sha(before),
                     'afterSHA256':client.sha(after), 'edits':[{'old':'old', 'new':'sing-box-polaris', 'count':1}]}
            spec = {'path':'clients/desktop', 'commit':'a'*40, 'tree':'b'*40, 'baselineFiles':{}, 'files':[entry]}
            manifest = root / 'manifest.json'
            manifest.write_bytes(json.dumps({'platforms':{'windows':spec}, 'unicode':'標題'}, ensure_ascii=False).encode('utf-8'))
            def git(directory, *args):
                if args == ('rev-parse','HEAD'): return b'a'*40
                if args == ('rev-parse','HEAD^{tree}'): return b'b'*40
                if args == ('ls-tree','HEAD','clients/desktop'): return b'160000 commit '+b'a'*40+b'\tclients/desktop\n'
                if args == ('show','a'*40+':source.txt'): return before
                raise AssertionError(args)
            with mock.patch.multiple(client, ROOT=root, MANIFEST=manifest), mock.patch.object(client, 'git', git), mock.patch.object(Path, 'read_text', cp1252_read), mock.patch.object(sys, 'argv', ['unsigned_clients.py','windows']):
                runpy.run_path(str(ROOT / 'scripts/ci/unsigned_clients.py'), run_name='__main__')
            self.assertEqual((directory / 'source.txt').read_bytes(), after)
            self.assertEqual(client.sha((directory / 'source.txt').read_bytes()), entry['afterSHA256'])

    def test_candidate_receipt_is_utf8_lf(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / '包.exe').write_bytes(b'fixture')
            env = {'GITHUB_REPOSITORY':'polaris-arch/sing-box-polaris', 'GITHUB_REPOSITORY_ID':'1421657509',
                   'GITHUB_JOB':'build_windows_client', 'GITHUB_RUN_ID':'1', 'GITHUB_RUN_ATTEMPT':'1'}
            with mock.patch.dict(record_candidate.os.environ, env), mock.patch.object(record_candidate,'git',return_value='a'*40), mock.patch.object(client,'collect',return_value={'fixture':'標題'}):
                record_candidate.main(root)
            raw = (root / 'polaris-candidate-manifest-build_windows_client-default.json').read_bytes()
            self.assertNotIn(b'\r', raw)
            self.assertTrue(raw.endswith(b'\n'))
            self.assertEqual(json.loads(raw.decode('utf-8'))['files'][0]['path'], '包.exe')

    def test_material_text_boundaries_are_explicit(self):
        for name in ('client_source','record_candidate','android_runtime_materials','native_release_index','github_release','owned_distribution','publisher_run_receipt'):
            tree = ast.parse((ROOT / f'scripts/ci/{name}.py').read_bytes())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ('read_text','write_text'):
                    keywords = {k.arg:ast.literal_eval(k.value) for k in node.keywords}
                    self.assertEqual(keywords.get('encoding'), 'utf-8', (name,node.lineno))
                    if node.func.attr == 'write_text': self.assertEqual(keywords.get('newline'), '\n', (name,node.lineno))


if __name__ == '__main__':
    unittest.main()
