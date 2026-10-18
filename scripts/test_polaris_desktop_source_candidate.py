import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

SCRIPT = pathlib.Path(__file__).with_name('polaris_desktop_source_candidate.py')


class SourceAssemblyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.stage = self.root / 'stage'
        self.stage.mkdir()
        closure = self.root / 'evidence/cronet-license-closure'
        closure.mkdir(parents=True)
        self.cache = self.root / 'cache'
        self.cache.mkdir()
        self.go = self.root / 'go.zip'
        with zipfile.ZipFile(self.go, 'w') as z:
            z.writestr('toolchain/src/a.go', b'package a\n')
            z.writestr('toolchain/LICENSE', b'Go license\n')
        notice = self.stage / 'DESKTOP-SOURCE-NOTICE-SUPERSET.txt'
        notice.write_bytes(b'NOTICE\r\n')
        source = closure / 'source.tar'
        source.write_bytes(b'fixed source')
        recipe = self.stage / 'build-recipes/script.py'
        recipe.parent.mkdir()
        recipe.write_bytes(b'print("recipe")\n')
        module = self.cache / 'example/@v/v1.zip'
        module.parent.mkdir(parents=True)
        module.write_bytes(b'fixed module')
        self.notice_bytes = b'NOTICE\r\n'
        self.index = {
            'publicationEligible': False, 'packageNoticeInputsAdoptedByProducer': False,
            'platforms': [], 'scopeKey': 'original-three',
            'sourceCommit': 'a01da7a942b3a0dbbfdfda2bba5bd63d5bd9d932',
            'sourceTree': '0bd19d8461347887c884f10250a402aa85decfe6', 'sourceOverlay': 0,
            'sourceArchiveInputs': [dict(filename=source.name, **self.record(source))],
            'noticeBundle': self.record(notice),
            'noticeRecords': [dict(source='example@v1', byteOffset=0, **self.record(notice))],
            'buildRecipeInputs': [dict(path='build-recipes/script.py', **self.record(recipe))],
            'sourceAssemblyInputs': [],
            'modules': [{'module': 'example', 'version': 'v1', 'h1': 'h1:fixture-code',
                         'noticeRecordIndexes': [0], 'sourceBundleMember': 'modules/example/@v/v1.zip',
                         'zipBytes': module.stat().st_size, 'zipSha256': self.sha(module)}],
            'localGoToolchainInput': {'zipSha256': self.sha(self.go)}
        }
        for platform in ('linux/amd64', 'linux/arm64', 'windows/amd64'):
            self.add_native_platform(platform)
        self.write_index()
        self.command = [sys.executable, str(SCRIPT), '--evidence-root', str(self.root / 'evidence'),
                        '--stage-dir', str(self.stage), '--module-cache', str(self.cache),
                        '--go-toolchain-zip', str(self.go)]

    def add_native_platform(self, platform):
        original = platform in ('linux/amd64', 'linux/arm64', 'windows/amd64')
        run = 38072592310 if original else 38074825396
        producer = ('720ead161c71415e23f38a82c29d314a4754ab9c' if original else
                    '226e88cab62b8818620668a28b496d833c01c953')
        target = platform.replace('/', '_')
        module = 'github.com/sagernet/cronet-go/lib/' + target
        version = 'v0.0.0-20260929213014-a1cafd93eb1f'
        h1 = 'h1:fixture-' + target
        offset = len(self.notice_bytes)
        self.notice_bytes += b'NOTICE\r\n'
        notice = self.stage / 'DESKTOP-SOURCE-NOTICE-SUPERSET.txt'
        notice.write_bytes(self.notice_bytes)
        self.index['noticeBundle'] = self.record(notice)
        number = len(self.index['noticeRecords'])
        self.index['noticeRecords'].append({'source': module + '@' + version,
                                          'byteOffset': offset, 'bytes': 8,
                                          'sha256': hashlib.sha256(b'NOTICE\r\n').hexdigest()})
        self.index['modules'].append({'module': module, 'version': version, 'h1': h1,
                                      'noticeRecordIndexes': [number], 'sourceBundleMember': None})
        self.index['verifiedSourceUnionModuleCount'] = len(self.index['modules'])
        cronet = {'target': target, 'module': module, 'moduleVersion': version, 'moduleSum': h1,
                  'sha256': 'c' * 64, 'gitBlob': 'd' * 40}
        row = {'platform': platform, 'nativeAccepted': True, 'acceptedRun': run,
               'originalRun': run, 'acceptedProducerCommit': producer,
               'originalProducerCommit': producer, 'productSourceCommit': self.index['sourceCommit'],
               'productSourceTree': self.index['sourceTree'], 'archiveSha256': 'a' * 64,
               'coreSha256': 'b' * 64, 'moduleCount': 2,
               'moduleKeys': ['example@v1', module + '@' + version],
               'goNoticeRecordIndexes': [0, number], 'prebuiltCronetInput': cronet}
        self.index['platforms'].append(row)
        receipt = {'sourceCommit': self.index['sourceCommit'], 'sourceTree': self.index['sourceTree'],
                   'sourceOverlay': 0, 'workflowCommit': producer, 'workflowRun': str(run),
                   'workflowAttempt': '1', 'archive': {'sha256': 'a' * 64},
                   'payloadHashes': {'sing-box.exe' if platform.startswith('windows/') else 'sing-box': 'b' * 64},
                   'buildInfo': 'dep example v1 h1:fixture-code\ndep ' + module + ' ' + version + ' ' + h1 + '\n',
                   'cronet': cronet}
        path = 'receipts/' + platform.replace('/', '-') + '-producer' + producer[:6] + '-run' + str(run) + '.json'
        file = self.stage / path
        file.parent.mkdir(exist_ok=True)
        file.write_text(json.dumps(receipt))
        self.index['sourceAssemblyInputs'].append(dict(path=path, **self.record(file)))
        return row, receipt, file

    def make_six_scope(self):
        self.index['scopeKey'] = 'desktop-six'
        for platform in ('windows/arm64', 'darwin/amd64', 'darwin/arm64'):
            self.add_native_platform(platform)
        self.write_index()

    @staticmethod
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def record(self, path):
        return {'bytes': path.stat().st_size, 'sha256': self.sha(path)}

    def write_index(self):
        (self.stage / 'DESKTOP-SOURCE-NOTICE-INDEX-controlled.json').write_text(json.dumps(self.index))

    def run_helper(self, *args, optimized=False):
        command = list(self.command)
        if optimized:
            command.insert(1, '-O')
        return subprocess.run(command + list(args), capture_output=True, text=True)

    def reject(self, message, optimized=False):
        result = self.run_helper('--validate-only', optimized=optimized)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)

    def test_valid_inputs_and_actual_archive(self):
        self.assertEqual(self.run_helper('--validate-only').returncode, 0)
        output = self.root / 'output'
        result = self.run_helper('--output-dir', str(output))
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        bundle = output / receipt['filename']
        self.assertEqual(self.sha(bundle), receipt['sha256'])
        with tarfile.open(bundle) as archive:
            self.assertEqual(archive.extractfile('notices/DESKTOP-SOURCE-NOTICE-SUPERSET.txt').read(), self.notice_bytes)
            self.assertEqual(archive.extractfile('modules/example/@v/v1.zip').read(), b'fixed module')
        self.assertEqual((self.stage / 'DESKTOP-SOURCE-NOTICE-SUPERSET.txt').read_bytes(), self.notice_bytes)
        self.assertNotEqual(self.run_helper('--output-dir', str(output)).returncode, 0)
        self.assertEqual(self.sha(bundle), receipt['sha256'])

    def run_with_post_preflight_rewrite(self, target, replacement, expected_error):
        spec = importlib.util.spec_from_file_location('packager_under_test', SCRIPT)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        original_hash = helper.file_hash
        original_bytes = target.read_bytes()
        self.assertEqual(len(original_bytes), len(replacement))
        rewritten = False

        def injected_hash(path):
            nonlocal rewritten
            result = original_hash(path)
            if pathlib.Path(path) == self.go and not rewritten:
                # Go input is checked after source inputs, immediately before assembly.
                target.write_bytes(replacement)
                rewritten = True
            return result

        output = self.root / 'post-preflight-output'
        with mock.patch.object(helper, 'file_hash', injected_hash), mock.patch.object(
                sys, 'argv', self.command[1:] + ['--output-dir', str(output)]):
            with self.assertRaisesRegex(ValueError, expected_error):
                helper.main()
        self.assertTrue(rewritten)
        self.assertFalse((output / 'bounded-source-package-receipt-v3.json').exists())
        self.assertFalse((output / 'polaris-box-a01-desktop-source-candidate-three-platforms-v3.tar.gz').exists())
        target.write_bytes(original_bytes)

    def test_same_length_rewrite_after_preflight_rejects_unapproved_member(self):
        self.run_with_post_preflight_rewrite(
            self.cache / 'example/@v/v1.zip', b'wrong module',
            'packaged member differs from frozen expected SHA256')

    def test_toolchain_rewrite_after_preflight_cannot_change_derived_source(self):
        self.run_with_post_preflight_rewrite(
            self.go, b'x' * self.go.stat().st_size,
            'verified Go toolchain snapshot SHA256 mismatch')

    def test_notice_corruption_rejected_even_with_python_optimization(self):
        (self.stage / 'DESKTOP-SOURCE-NOTICE-SUPERSET.txt').write_bytes(b'NOTICE!\n')
        self.reject('notice bundle SHA256 mismatch', optimized=True)

    def test_slice_mismatch(self):
        self.index['noticeRecords'][0]['byteOffset'] = 1
        self.write_index()
        self.reject('notice slice SHA256 mismatch')

    def test_module_digest_mismatch(self):
        (self.cache / 'example/@v/v1.zip').write_bytes(b'badxx module')
        self.reject('input SHA256 mismatch')

    def test_archive_digest_mismatch(self):
        (self.root / 'evidence/cronet-license-closure/source.tar').write_bytes(b'wrong source')
        self.reject('input SHA256 mismatch')

    def test_recipe_digest_mismatch(self):
        self.index['buildRecipeInputs'][0]['sha256'] = '0' * 64
        self.write_index()
        self.reject('input SHA256 mismatch')

    def test_traversal_and_absolute_members(self):
        for name in ['../escape', '/absolute', 'C:/escape', 'bad\\name', '', 'x/../escape']:
            with self.subTest(name=name):
                self.index['buildRecipeInputs'][0]['path'] = name
                self.write_index()
                self.reject('unsafe source package member')

    def test_symlink_escape(self):
        outside = self.root / 'outside.py'
        outside.write_bytes(b'print("recipe")\n')
        recipe = self.stage / 'build-recipes/script.py'
        recipe.unlink()
        recipe.symlink_to(outside)
        self.reject('input escapes declared root')

    def test_duplicate_archive_member(self):
        self.index['sourceAssemblyInputs'] += self.index['buildRecipeInputs'][:]
        self.write_index()
        self.reject('duplicate source input member')

    def test_toolchain_digest_mismatch(self):
        self.index['localGoToolchainInput']['zipSha256'] = '0' * 64
        self.write_index()
        self.reject('Go toolchain source ZIP SHA256 mismatch')

    def test_relabelled_six_platform_scope_rejected(self):
        self.index['platforms'] *= 2
        self.write_index()
        self.reject('native platform set mismatch')

    def test_exact_six_receipts_assemble_with_original_producers(self):
        self.make_six_scope()
        result = self.run_helper('--output-dir', str(self.root / 'six-output'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['actualAcceptedPlatformCount'], 6)
        self.assertIn('six-platforms-v4', json.loads(result.stdout)['filename'])

    def test_duplicate_or_missing_platform_cannot_count_as_six(self):
        self.make_six_scope()
        self.index['platforms'][-1]['platform'] = 'windows/arm64'
        self.write_index()
        self.reject('native platform set mismatch')

    def test_old_receipt_cannot_be_relabelled_as_repair_producer(self):
        self.index['platforms'][0]['acceptedProducerCommit'] = '226e88cab62b8818620668a28b496d833c01c953'
        self.write_index()
        self.reject('native producer/run binding mismatch')

    def test_receipt_identity_checked_even_when_its_bytes_are_indexed(self):
        self.make_six_scope()
        record = self.index['sourceAssemblyInputs'][-1]
        path = self.stage / record['path']
        receipt = json.loads(path.read_text())
        receipt['workflowRun'] = '38072592310'
        path.write_text(json.dumps(receipt))
        record.update(self.record(path))
        self.write_index()
        self.reject('native receipt source/producer/run identity mismatch')

    def test_extra_module_cannot_be_added_without_native_buildinfo(self):
        self.index['modules'].append({'module': 'extra', 'version': 'v1', 'h1': 'h1:extra',
                                      'sourceBundleMember': None, 'noticeRecordIndexes': [0]})
        self.write_index()
        self.reject('source module union differs')

    def test_module_h1_mismatch_cannot_be_hidden_by_name_and_version(self):
        self.index['modules'][0]['h1'] = 'h1:changed'
        self.write_index()
        self.reject('native module missing or mismatched')

    def test_platform_module_membership_cannot_omit_dependencies(self):
        self.index['platforms'][0]['moduleKeys'].pop()
        self.write_index()
        self.reject('native per-platform module membership mismatch')

    def test_platform_notice_binding_cannot_omit_module_license(self):
        self.index['platforms'][0]['goNoticeRecordIndexes'].pop()
        self.write_index()
        self.reject('native module notice binding mismatch')

    def test_cronet_library_bytes_bound_to_actual_receipt(self):
        # deepcopy is needed because the fixture originally reuses this dict.
        self.index['platforms'][0]['prebuiltCronetInput'] = dict(self.index['platforms'][0]['prebuiltCronetInput'])
        self.index['platforms'][0]['prebuiltCronetInput']['sha256'] = '0' * 64
        self.write_index()
        self.reject('native Cronet input binding mismatch')


if __name__ == '__main__':
    unittest.main()
