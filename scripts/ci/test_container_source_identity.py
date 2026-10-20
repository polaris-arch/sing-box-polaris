"""Container source identity differs legitimately from the workflow dispatch ref."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


class ContainerSourceIdentityTests(unittest.TestCase):
    def workflow(self):
        return yaml.safe_load((ROOT / '.github/workflows/publish-container.yml').read_text())

    def test_dispatch_revision_is_not_selected_tag_revision(self):
        workflow = self.workflow()
        selected = 'a' * 40
        dispatch = 'b' * 40
        for name in ('build_binary', 'build_docker', 'merge'):
            with self.subTest(job=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                # The fixture isolates source binding; the existing verifier has
                # its own tests. Both git queries represent a verified tag HEAD.
                (root / 'git').write_text('#!/bin/sh\nprintf "%s\\n" "$FIXTURE_SOURCE"\n')
                (root / 'python3').write_text('#!/bin/sh\nexit 0\n')
                (root / 'git').chmod(0o755)
                (root / 'python3').chmod(0o755)
                step = next(s for s in workflow['jobs'][name]['steps']
                            if s.get('name') == 'Verify reviewed owned distribution and exact source tag')
                environment = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                                   FIXTURE_SOURCE=selected, GITHUB_SHA=dispatch,
                                   VERSION='v1.15.0-polaris-alpha.12', GITHUB_ENV=str(root / 'env'))
                result = subprocess.run(['bash', '-c', step['run']], env=environment,
                                        text=True, capture_output=True, check=True)
                self.assertEqual((root / 'env').read_text(), 'SOURCE_REVISION=' + selected + '\n')
                self.assertIn(selected, result.stdout)
                self.assertNotIn(dispatch, result.stdout)

    def test_binary_receipt_and_oci_label_use_one_source_identity(self):
        workflow = self.workflow()
        binary = workflow['jobs']['build_binary']['steps']
        flags = next(s['run'] for s in binary if s.get('name') == 'Set shared ldflags')
        self.assertIn('constant.SourceRevision=$SOURCE_REVISION', flags)
        self.assertNotIn('GITHUB_SHA', flags)
        prepare = next(s['run'] for s in binary if s.get('name') == 'Prepare artifact')
        self.assertIn('"$SOURCE_REVISION" > source-revision.txt', prepare)
        upload = next(s for s in binary if s.get('name') == 'Upload binary')
        self.assertIn('source-revision.txt', upload['with']['path'].splitlines())
        docker = workflow['jobs']['build_docker']['steps']
        check = next(s['run'] for s in docker if s.get('name') == 'Prepare binary')
        self.assertIn('test "$(cat source-revision.txt)" = "$SOURCE_REVISION"', check)
        self.assertIn('set -euo pipefail', check)
        metadata = next(s for s in docker if s.get('id') == 'meta')
        self.assertIn('org.opencontainers.image.revision=${{ env.SOURCE_REVISION }}', metadata['with']['labels'])
        contract = yaml.safe_load((ROOT / '.github/workflows/ci-contract.yml').read_text())
        self.assertTrue(any('test_container_source_identity.py' in s.get('run', '')
                            for s in contract['jobs']['contract']['steps']))

    def test_mismatched_binary_receipt_stops_before_image_build(self):
        workflow = self.workflow()
        check = next(s['run'] for s in workflow['jobs']['build_docker']['steps']
                     if s.get('name') == 'Prepare binary')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'source-revision.txt').write_text('a' * 40 + '\n')
            result = subprocess.run(['bash', '-c', check], cwd=root,
                                    env=dict(os.environ, SOURCE_REVISION='b' * 40),
                                    text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('chmod:', result.stderr)


if __name__ == '__main__':
    unittest.main()
