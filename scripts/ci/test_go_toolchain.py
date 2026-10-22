"""Toolchain input/cache negative controls; no downloading or compilation."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('legacy_go',ROOT/'.github/setup_legacy_go.py')
legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)


class ToolchainControls(unittest.TestCase):
    def test_windows_console_hunk_fixture_is_exact_official_source(self):
        # These complete source/license files were copied from the hash-pinned
        # official archive; no reconstructed snippet or patched-source fixture.
        fixture=ROOT/'scripts/ci/testdata/go1.27.2'
        self.assertIn('/scripts/ci/testdata/go1.27.2/** -text',(ROOT/'.gitattributes').read_text())
        manifest=json.loads((ROOT/'.github/go-toolchains.json').read_text())
        self.assertEqual(manifest['officialCommit'],'022c8636110ebac86a9b88724cda168ed713c21f')
        self.assertEqual(manifest['archives']['linux-amd64']['sha256'],
                         'ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5')
        for name,digest in [('exec_windows.go','031afbedd3b2e8ee58d890b8ff3df3df67f5556ff174768ec17e9fe31d44ae40'),
                            ('LICENSE','911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad')]:
            self.assertEqual(legacy.file_hash(fixture/name),digest)

    @unittest.skipUnless(shutil.which('patch'),'real patch executable required for cold source applicability')
    def test_windows_console_hunk_applies_cold_with_zero_fuzz_and_rejects_drift(self):
        _,_,patch,_,_=legacy.toolchain_input('windows7','linux-amd64')
        raw=patch.read_text()
        header='diff --git a/src/syscall/exec_windows.go b/src/syscall/exec_windows.go\n'
        self.assertGreater(raw.count(header),0)
        # The patch queue may visit this file more than once; replay every
        # section in its original order, not only the previously failing hunk.
        section='\n'.join(header+part.split('\ndiff --git ',1)[0] for part in raw.split(header)[1:])+'\n'
        context=' \tprocAttrList, err := newProcThreadAttributeList(2)\n'
        self.assertEqual(section.count(context),1)
        self.assertIn('@@ -374,11 +388,19 @@',section)
        # Recreate precisely the former asymmetric trailing-context defect.
        old=section.replace('@@ -374,11 +388,19 @@','@@ -374,10 +388,18 @@').replace(context,'')
        official=(ROOT/'scripts/ci/testdata/go1.27.2/exec_windows.go').read_bytes()
        drift=official.replace(b'procAttrList, err := newProcThreadAttributeList(2)',
                               b'procAttrList, err := newProcThreadAttributeList(3)')
        self.assertNotEqual(drift,official)
        for name,selected,source,accepted in [('fixed',section,official,True),
                                              ('former-missing-context',old,official,False),
                                              ('unreviewed-source',section,drift,False)]:
            with self.subTest(case=name),tempfile.TemporaryDirectory() as td:
                root=Path(td);file=root/'src/syscall/exec_windows.go';file.parent.mkdir(parents=True)
                file.write_bytes(source);selected_patch=root/'selected.patch';selected_patch.write_text(selected)
                result=subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',str(selected_patch)],
                                      cwd=root,text=True,capture_output=True)
                output=result.stdout+result.stderr
                if accepted:
                    self.assertEqual(result.returncode,0,output)
                    self.assertFalse(list(root.rglob('*.rej')))
                    actual=file.read_text()
                    self.assertIn('defer DuplicateHandle(destinationProcessHandle, fd[i]',actual)
                    self.assertIn(context[1:],actual)
                else:
                    self.assertNotEqual(result.returncode,0,output)
                    self.assertTrue(list(root.rglob('*.rej')),output)

    def test_windows_console_duplicate_cleanup_uses_actual_destination(self):
        patch=(ROOT/'.github/patches/go1.27.2/windows7.patch').read_text()
        added='\n'.join(line[1:] for line in patch.splitlines() if line.startswith('+') and not line.startswith('+++'))
        self.assertIn('destinationProcessHandle := parentProcess',added)
        self.assertIn('if parentProcess != p && isLegacyWin7ConsoleHandle(Handle(attr.Files[i])) {',added)
        self.assertIn('destinationProcessHandle = p',added)
        duplicate='DuplicateHandle(p, Handle(attr.Files[i]), destinationProcessHandle, &fd[i], 0, true, DUPLICATE_SAME_ACCESS)'
        cleanup='defer DuplicateHandle(destinationProcessHandle, fd[i], 0, nil, 0, false, DUPLICATE_CLOSE_SOURCE)'
        self.assertIn(duplicate,added)
        self.assertIn(cleanup,added)
        self.assertLess(added.index(duplicate),added.index(cleanup))
        self.assertNotIn('defer DuplicateHandle(parentProcess, fd[i]',added)
        # Inert ownership table: actual Windows handle behavior still requires
        # native acceptance. Successful duplication installs one defer; later
        # setup/CreateProcess failure and success must close that same table.
        for alternate_parent in (False,True):
            for legacy_console in (False,True):
                for phase in ('duplicate-failed','later-setup-failed','create-failed','success'):
                    current=1;parent=2 if alternate_parent else current
                    destination=current if alternate_parent and legacy_console else parent
                    deferred=[] if phase=='duplicate-failed' else [(destination,17)]
                    with self.subTest(alternate=alternate_parent,console=legacy_console,phase=phase):
                        self.assertEqual(len(deferred),0 if phase=='duplicate-failed' else 1)
                        if deferred:self.assertEqual(deferred[0][0],destination)

    def test_exact_official_version_and_source_owned_patch_hashes(self):
        for mode,host in [('windows7','linux-amd64'),('macos1013','darwin-arm64')]:
            manifest,entry,patch,archive,_=legacy.toolchain_input(mode,host)
            self.assertEqual(manifest['version'],'1.27.2');self.assertEqual(legacy.file_hash(patch),entry['patchSHA256'])
            self.assertEqual(archive['filename'],'go1.27.2.'+host+'.tar.gz')
        m=json.loads((ROOT/'.github/go-toolchains.json').read_text())
        self.assertEqual(legacy.file_hash(ROOT/m['iosCPU']['patch']),m['iosCPU']['patchSHA256'])
        self.assertEqual(m['iosCPU']['features'],['AES','PMULL','SHA1','SHA2'])
        self.assertNotIn('ATOMICS',m['iosCPU']['features']);self.assertNotIn('SHA512',m['iosCPU']['features'])

    def test_crlf_patch_is_rejected_without_normalizing_raw_identity(self):
        raw=b"source-owned patch\nsecond line\n"
        expected=hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'.github/patches').mkdir(parents=True);(root/'release').mkdir()
            patch=root/'.github/patches/fixture.patch';patch.write_bytes(raw)
            (root/'release/GO_VERSION').write_bytes(b'1.27.2\n')
            fixture={'version':'1.27.2','legacy':{'windows7':{'patch':'.github/patches/fixture.patch','patchSHA256':expected}},'archives':{'linux-amd64':{}}}
            (root/'.github/go-toolchains.json').write_text(json.dumps(fixture))
            with mock.patch.object(legacy,'ROOT',root):
                self.assertEqual(legacy.toolchain_input('windows7','linux-amd64')[1]['patchSHA256'],expected)
                crlf=raw.replace(b'\n',b'\r\n');patch.write_bytes(crlf)
                actual=hashlib.sha256(crlf).hexdigest()
                with self.assertRaises(RuntimeError) as rejected:
                    legacy.toolchain_input('windows7','linux-amd64')
                self.assertIn('expected='+expected,str(rejected.exception))
                self.assertIn('actual='+actual,str(rejected.exception))
                self.assertEqual(patch.read_bytes(),crlf)
                self.assertNotEqual(actual,expected)
        attrs=(ROOT/'.gitattributes').read_text()
        self.assertIn('/.github/patches/** -text',attrs)
        self.assertIn('/.github/go_ios_cpu_features.patch -text',attrs)

    def test_reused_toolchain_requires_complete_actual_file_identity(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            paths=['bin/go','bin/gofmt','pkg/tool/linux_amd64/link','pkg/tool/linux_amd64/compile',
                   'pkg/tool/linux_amd64/asm','src/runtime/runtime2.go','src/os/root.go',
                   'src/cmd/compile/main.go','src/cmd/asm/main.go','go.env','VERSION']
            for path in paths:
                p=root/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(path.encode())
            identity={'goVersion':'go1.27.2','patchSHA256':'fixture','archiveSHA256':'pinned fixture archive',
                      'cacheFormat':'complete-toolchain-files-v1'}
            marker=dict(identity,files=legacy.toolchain_files(root))
            marker_path=root/'polaris-toolchain.json'
            marker_path.write_text(json.dumps(marker))
            self.assertEqual(legacy.verify_cached_toolchain(root,'linux-amd64',identity),marker)
            for path in paths:
                with self.subTest(path=path):
                    p=root/path;original=p.read_bytes();p.write_bytes(b'tampered')
                    self.assertRaises(RuntimeError,legacy.verify_cached_toolchain,root,'linux-amd64',identity)
                    p.write_bytes(original)
            for bad in [dict(marker,goVersion='go1.27.1'),dict(marker,files={}),
                        dict(marker,archiveSHA256='different'),dict(marker,patchSHA256='different')]:
                marker_path.write_text(json.dumps(bad))
                self.assertRaises(RuntimeError,legacy.verify_cached_toolchain,root,'linux-amd64',identity)
            marker_path.write_text(json.dumps(marker))
            extra=root/'src/unexpected.go';extra.write_bytes(b'added source')
            self.assertRaises(RuntimeError,legacy.verify_cached_toolchain,root,'linux-amd64',identity)
            extra.unlink()
            missing=root/'pkg/tool/linux_amd64/asm';data=missing.read_bytes();missing.unlink()
            self.assertRaises(RuntimeError,legacy.verify_cached_toolchain,root,'linux-amd64',identity)
            missing.write_bytes(data)
            config=root/'go.env';mode=config.stat().st_mode;config.chmod(0o700)
            self.assertRaises(RuntimeError,legacy.verify_cached_toolchain,root,'linux-amd64',identity)
            config.chmod(mode)
            self.assertEqual(legacy.verify_cached_toolchain(root,'linux-amd64',identity),marker)
            alias=root/'tool-link'
            try:alias.symlink_to(root/'bin/go')
            except OSError:pass  # Host permission; all regular-file controls above remain mandatory.
            else:self.assertRaises(RuntimeError,legacy.verify_cached_toolchain,root,'linux-amd64',identity)

    def test_windows_patch_retains_official_root_confinement_and_real_gate(self):
        manifest=json.loads((ROOT/'.github/go-toolchains.json').read_text())
        entry=manifest['legacy']['windows7'];patch=(ROOT/entry['patch']).read_text()
        for name,digest in entry['preservedRootSources'].items():
            self.assertEqual(len(digest),64)
            self.assertNotIn('diff --git a/'+name+' ',patch)
        spec=importlib.util.spec_from_file_location('root_gate',ROOT/'scripts/ci/windows_root_gate.py')
        gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
        source=gate.regression_source(patch)
        host='package os_test\nimport (\n\t"internal/syscall/windows"\n\t"os"\n\t"path/filepath"\n\t"testing"\n)\n'
        combined=gate.combined_test_source(host,source)
        self.assertIn('func TestPolarisRootRemoveAllConfinement',combined)
        self.assertIn('"os/exec"',combined)
        self.assertRaises(ValueError,gate.combined_test_source,host.replace('package os_test','package os'),source)
        self.assertRaises(ValueError,gate.combined_test_source,host,source.replace('func TestPolarisRootRemoveAllConfinement','func Removed'))
        self.assertEqual(hashlib.sha256(source.encode()).hexdigest(),entry['rootRemoveAllRegressionSHA256'])
        for required in ['TestDeleteatFallback','"ordinary"','"junction"','"symlink"','root.RemoveAll(target)','root.RemoveAll("sub")']:
            self.assertIn(required,source)
        for broken in [patch.replace('@@ -0,0 +1,','@@ -0,1 +1,'),patch+'+extra\n']:
            self.assertRaises(ValueError,gate.regression_source,broken)
        text=(ROOT/'scripts/ci/utls_gate.py').read_text()
        self.assertIn("sys.platform == 'win32'",text)
        self.assertIn("'scripts/ci/windows_root_gate.py'",text)
        self.assertIn("('native', 'legacy-fallback')",text)
        self.assertIn("('ordinary', 'junction', 'symlink')",text)

    def test_windows_overlay_keeps_go_loader_junction_spelling(self):
        spec=importlib.util.spec_from_file_location('root_gate',ROOT/'scripts/ci/windows_root_gate.py')
        gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
        selected=r'C:\hostedtoolcache\windows\go\1.27.2\x64\src\os'
        actual_target=r'D:\a\_temp\root_windows_test.go'
        # Metadata regression runs on Linux/macOS too; no junction or compiler
        # is needed, and no filesystem resolution may replace the Go loader key.
        with mock.patch.object(Path,'resolve',side_effect=AssertionError('unexpected junction resolution')):
            mapping=gate.overlay_replacements(selected,actual_target)
        key=selected+r'\root_windows_test.go'
        self.assertEqual(mapping,{'Replace':{key:actual_target}})
        self.assertNotIn(actual_target,mapping['Replace'])
        self.assertRaises(ValueError,gate.overlay_replacements,r'go\src\os',actual_target)

    def test_final_consumer_contract_requires_the_same_exact_go_toolchain(self):
        import jsonschema
        schema=json.loads((ROOT/'release/ci/native-release-contract.schema.json').read_text())
        expected='go'+(ROOT/'release/GO_VERSION').read_text().strip()
        rows=schema['properties']['platforms']['properties']
        self.assertEqual(set(rows),{'linux','win','mac-x64','mac-arm64'})
        for target,row in rows.items():
            field=row['properties']['goVersion']
            with self.subTest(target=target):
                jsonschema.Draft202012Validator(field).validate(expected)
                for invalid in ['go1.26.8','go1.27.1','go1.27.20','unknown','']:
                    with self.assertRaises(jsonschema.ValidationError):jsonschema.Draft202012Validator(field).validate(invalid)

    def test_archive_layout_and_resource_negative_controls(self):
        valid=tarfile.TarInfo('go/bin/go');valid.size=10;legacy.require_archive_members([valid])
        for name,kind in [('../escape',tarfile.REGTYPE),('/go/bin/go',tarfile.REGTYPE),('go/../escape',tarfile.REGTYPE),
                          ('go/bin/link',tarfile.SYMTYPE),('go/device',tarfile.CHRTYPE)]:
            member=tarfile.TarInfo(name);member.type=kind
            with self.subTest(name=name):self.assertRaises(RuntimeError,legacy.require_archive_members,[member])
        huge=tarfile.TarInfo('go/huge');huge.size=1024**3+1
        self.assertRaises(RuntimeError,legacy.require_archive_members,[huge])
