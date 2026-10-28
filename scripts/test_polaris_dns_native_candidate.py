import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from polaris_dns_native_candidate import checked_license_input, require_vcs_checkout


class VcsCheckoutTests(unittest.TestCase):
    def test_worktree_gitfile_and_missing_repository_fail_before_build(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            with self.assertRaisesRegex(ValueError, 'standalone .git directory'):
                require_vcs_checkout(source)
            (source / '.git').write_text('gitdir: /external/worktree/metadata')
            with self.assertRaisesRegex(ValueError, 'standalone .git directory'):
                require_vcs_checkout(source)
            (source / '.git').unlink()
            (source / '.git').mkdir()
            require_vcs_checkout(source)


class DNSNoticeBindingTests(unittest.TestCase):
    def test_each_original_manifest_retains_its_distinct_notice_bytes(self):
        producer = Path(__file__).resolve().parents[1]
        native = json.loads((producer / 'release/polaris-candidate-inputs.json').read_bytes())
        dns = json.loads((producer / 'release/polaris-dns-candidate-inputs.json').read_bytes())
        self.assertNotEqual(native['licenseFiles']['NOTICE'], dns['licenseFiles']['NOTICE'])
        self.assertEqual(hashlib.sha256((producer / 'release/licenses/NOTICE').read_bytes()).hexdigest(),
                         native['licenseFiles']['NOTICE'])
        for name, expected in dns['licenseFiles'].items():
            path = checked_license_input(producer, name, expected)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected)

    def test_a01_notice_cannot_be_packaged_as_dns_notice(self):
        producer = Path(__file__).resolve().parents[1]
        manifest = json.loads((producer / 'release/polaris-dns-candidate-inputs.json').read_bytes())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'release/licenses').mkdir(parents=True)
            (root / 'release/licenses/DNS-NOTICE').write_bytes((producer / 'release/licenses/NOTICE').read_bytes())
            with self.assertRaisesRegex(ValueError, 'license input mismatch'):
                checked_license_input(root, 'NOTICE', manifest['licenseFiles']['NOTICE'])


if __name__ == '__main__':
    unittest.main()
