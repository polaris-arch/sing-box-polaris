"""Toolchain input/cache negative controls; no downloading or compilation."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('legacy_go',ROOT/'.github/setup_legacy_go.py')
legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)


class ToolchainControls(unittest.TestCase):
    def test_exact_official_version_and_source_owned_patch_hashes(self):
        for mode,host in [('windows7','linux-amd64'),('macos1013','darwin-arm64')]:
            manifest,entry,patch,archive,_=legacy.toolchain_input(mode,host)
            self.assertEqual(manifest['version'],'1.27.2');self.assertEqual(legacy.file_hash(patch),entry['patchSHA256'])
            self.assertEqual(archive['filename'],'go1.27.2.'+host+'.tar.gz')
        m=json.loads((ROOT/'.github/go-toolchains.json').read_text())
        self.assertEqual(legacy.file_hash(ROOT/m['iosCPU']['patch']),m['iosCPU']['patchSHA256'])
        self.assertEqual(m['iosCPU']['features'],['AES','PMULL','SHA1','SHA2'])
        self.assertNotIn('ATOMICS',m['iosCPU']['features']);self.assertNotIn('SHA512',m['iosCPU']['features'])

    def test_reused_toolchain_requires_input_and_all_actual_executable_hashes(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);files={'bin/go':b'go','pkg/tool/linux_amd64/link':b'link'}
            for path,data in files.items():
                p=root/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
            identity={'goVersion':'go1.27.2','patchSHA256':'fixture'}
            marker=dict(identity,executables={p:hashlib.sha256(data).hexdigest() for p,data in files.items()})
            (root/'polaris-toolchain.json').write_text(json.dumps(marker))
            self.assertEqual(legacy.verify_cached_toolchain(root,'linux-amd64',identity),marker)
            for bad in [dict(marker,goVersion='go1.27.1'),dict(marker,executables={}),dict(marker,executables={'../elsewhere':'wrong'})]:
                (root/'polaris-toolchain.json').write_text(json.dumps(bad))
                self.assertRaises(RuntimeError,legacy.verify_cached_toolchain,root,'linux-amd64',identity)
            (root/'polaris-toolchain.json').write_text(json.dumps(marker));(root/'bin/go').write_bytes(b'tampered')
            self.assertRaises(RuntimeError,legacy.verify_cached_toolchain,root,'linux-amd64',identity)

    def test_archive_layout_and_resource_negative_controls(self):
        valid=tarfile.TarInfo('go/bin/go');valid.size=10;legacy.require_archive_members([valid])
        for name,kind in [('../escape',tarfile.REGTYPE),('/go/bin/go',tarfile.REGTYPE),('go/../escape',tarfile.REGTYPE),
                          ('go/bin/link',tarfile.SYMTYPE),('go/device',tarfile.CHRTYPE)]:
            member=tarfile.TarInfo(name);member.type=kind
            with self.subTest(name=name):self.assertRaises(RuntimeError,legacy.require_archive_members,[member])
        huge=tarfile.TarInfo('go/huge');huge.size=1024**3+1
        self.assertRaises(RuntimeError,legacy.require_archive_members,[huge])
