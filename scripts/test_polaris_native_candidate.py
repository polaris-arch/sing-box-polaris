import io
import shlex
from pathlib import Path
import tarfile
import tempfile
import subprocess
import unittest
from unittest.mock import Mock
import zipfile
from polaris_native_candidate import archive_members, package, required_cronet_symbols, verify_required_exports, validate_cronet_rejection, windows_native_machine, darwin_cgo_flags

from polaris_native_matrix import select_targets


class CandidateArchiveTests(unittest.TestCase):
    def test_exact_payload_roundtrip_in_both_archive_formats(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / 'polaris-box-candidate-linux-amd64'
            (root / 'licenses').mkdir(parents=True)
            (root / 'sing-box').write_bytes(b'kernel\x00bytes')
            (root / 'libcronet.so').write_bytes(b'library\x00bytes')
            (root / 'licenses/NOTICE').write_text('exact notice')
            for os_name, suffix in [('linux', '.tar.gz'), ('windows', '.zip')]:
                with self.subTest(os=os_name):
                    members = package(root, base / ('candidate' + suffix), os_name)
                    self.assertEqual(members[root.name + '/sing-box'], b'kernel\x00bytes')
                    self.assertEqual(len(members), 3)

    def test_tar_rejects_traversal_links_duplicate_and_multiple_roots(self):
        for names, link in [(['root/../escape'], None), (['root/link'], tarfile.SYMTYPE),
                            (['root/link'], tarfile.LNKTYPE), (['root/x', 'root/x'], None),
                            (['one/x', 'two/x'], None)]:
            with self.subTest(names=names, link=link), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'candidate.tar.gz'
                with tarfile.open(path, 'w:gz') as writer:
                    for name in names:
                        entry = tarfile.TarInfo(name)
                        if link:
                            entry.type = link
                            entry.linkname = '/outside'
                            writer.addfile(entry)
                        else:
                            entry.size = 1
                            writer.addfile(entry, io.BytesIO(b'x'))
                with self.assertRaises(ValueError):
                    archive_members(path)

    def test_zip_rejects_windows_paths_and_symlinks(self):
        for name, mode in [('root/../escape', 0), ('C:/escape', 0),
                           ('root\\escape', 0), ('root/link', 0o120777)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'candidate.zip'
                with zipfile.ZipFile(path, 'w') as writer:
                    entry = zipfile.ZipInfo(name)
                    entry.external_attr = mode << 16
                    writer.writestr(entry, b'/outside')
                with self.assertRaises(ValueError):
                    archive_members(path)


class CronetRequiredExportsTests(unittest.TestCase):
    def test_windows_64_bit_float_exports_are_required(self):
        core = 'Cronet_Engine_Create'
        floats = ['Cronet_EngineParams_network_thread_priority_set',
                  'Cronet_EngineParams_network_thread_priority_get']
        with tempfile.TemporaryDirectory() as directory:
            wrapper = Path(directory)
            source = wrapper / 'internal/cronet'
            source.mkdir(parents=True)
            (source / 'loader_windows.go').write_text(f'registerFunc(&engineCreate, "{core}")')
            (source / 'loader_windows_float.go').write_text('\n'.join(
                f'registerFunc(&function, "{symbol}")' for symbol in floats))
            for arch in ('amd64', 'arm64'):
                with self.subTest(arch=arch):
                    required = required_cronet_symbols(wrapper, 'windows', arch)
                    self.assertEqual(required, {core, *floats})
                    verify_required_exports(required, required)
                    for missing in floats:
                        with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, missing):
                            verify_required_exports(required, required - {missing})



class CronetNegativeCategoryTests(unittest.TestCase):
    def test_expected_ordinary_errors_are_classified(self):
        cases = {
            'missing-library-argument': '--library is required; no fallback',
            'missing-path': 'lstat /tmp/absent-library: no such file or directory',
            'wrong-digest': 'Cronet library SHA-256 mismatch: got one, want two',
            'same-size-changed-bytes': 'Cronet library SHA-256 mismatch: got one, want two',
            'wrong-version': 'Cronet version mismatch: got one, want two',
            'wrong-machine-with-matching-byte-hash': 'cronet: failed to load library /tmp/foreign: bad machine',
            'missing-cronet-ABI-with-matching-byte-hash': 'cronet: symbol Cronet_Buffer_Create not found: absent',
            'static-rejects-sidecar': 'this build links Cronet statically; --library/--sha256 do not apply',
        }
        for name, message in cases.items():
            with self.subTest(name=name):
                trial = subprocess.CompletedProcess([], 1, '', 'Error: ' + message + '\nUsage:\n')
                receipt = validate_cronet_rejection(name, trial)
                self.assertTrue(receipt['errorCategoryMatched'])
        windows_path = subprocess.CompletedProcess([], 1, '', 'Error: CreateFile C:\\tmp\\absent-library: The system cannot find the file specified.\n')
        self.assertTrue(validate_cronet_rejection('missing-path', windows_path)['errorCategoryMatched'])

    def test_crashes_and_unrelated_nonzero_errors_never_pass(self):
        expected = 'Error: Cronet version mismatch: got one, want two\n'
        for code, stdout, stderr in [(0, '', expected), (-11, '', expected), (2, '', expected),
                (3221225477, '', expected), (1, '', expected + 'panic: failure\n'),
                (1, '', expected + 'fatal error: runtime crash\n'),
                (1, '', 'Error: unrelated failure\n'), (1, '', ''),
                (1, '{"version":"unexpected"}', expected)]:
            with self.subTest(code=code, stderr=stderr), self.assertRaisesRegex(ValueError, 'engine-version-mismatch'):
                validate_cronet_rejection('wrong-version', subprocess.CompletedProcess([], code, stdout, stderr))


class NativeWindowsHostTests(unittest.TestCase):
    def kernel(self, process, native, success=True):
        kernel = Mock()
        kernel.GetCurrentProcess.return_value = 123
        def machine(handle, process_out, native_out):
            self.assertEqual(handle, 123)
            process_out._obj.value, native_out._obj.value = process, native
            return int(success)
        kernel.IsWow64Process2.side_effect = machine
        return kernel

    def test_emulated_x64_python_uses_native_arm64_host(self):
        result = windows_native_machine(self.kernel(0x8664, 0xaa64))
        self.assertEqual(result['nativeArch'], 'arm64')
        self.assertEqual(result['processMachine'], 0x8664)

    def test_native_amd64_and_arm64_hosts(self):
        for code, arch in [(0x8664, 'amd64'), (0xaa64, 'arm64')]:
            with self.subTest(arch=arch):
                self.assertEqual(windows_native_machine(self.kernel(0, code))['nativeArch'], arch)

    def test_unknown_host_and_failed_api_never_fall_back_to_python(self):
        with self.assertRaises(ValueError):
            windows_native_machine(self.kernel(0x8664, 0x14c))
        with self.assertRaises(OSError):
            windows_native_machine(self.kernel(0x8664, 0xaa64, False))


class NativeMatrixTests(unittest.TestCase):
    def test_each_platform_selects_exactly_one_original_runner(self):
        all_targets = select_targets('all')
        self.assertEqual(len(all_targets), 6)
        for target in all_targets:
            self.assertEqual(select_targets(target['os'] + '/' + target['arch']), [target])
        self.assertEqual(select_targets('windows/arm64')[0]['runner'], 'windows-11-arm')

    def test_only_three_failed_original_platforms_are_selected(self):
        targets = select_targets('windows/arm64,darwin/amd64,darwin/arm64')
        self.assertEqual([(target['os'], target['arch']) for target in targets],
                         [('windows', 'arm64'), ('darwin', 'amd64'), ('darwin', 'arm64')])

    def test_missing_unknown_or_injected_selection_is_rejected(self):
        for selection in ['', 'windows', 'windows/386', '${{ runner.os }}', 'all;echo bad', 'windows/arm64,windows/arm64', 'all,darwin/amd64']:
            with self.subTest(selection=selection), self.assertRaises(ValueError):
                select_targets(selection)


class DarwinSdkTests(unittest.TestCase):
    def test_sdk_path_is_an_exact_sysroot_argument_even_with_spaces(self):
        sdk = '/Applications/Xcode Test.app/SDKs/MacOSX.sdk'
        self.assertEqual(shlex.split(darwin_cgo_flags(sdk)),
                         ['-isysroot', sdk, '-mmacosx-version-min=13.0'])


if __name__ == '__main__':
    unittest.main()
