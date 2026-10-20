"""Inert publication-boundary regressions; every remote operation is mocked."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import owned_distribution as owned
from release_identity import validate_publication_index


class OwnedPublicationGateTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.previous = Path.cwd()
        os.chdir(self.temp.name)
        self.addCleanup(os.chdir, self.previous)
        self.dist = Path('dist')
        self.dist.mkdir()
        self.source, self.tree, self.tag_object = 'a' * 40, 'b' * 40, 'c' * 40
        self.tag = 'v1.15.0-polaris-alpha.12'
        self.archive_bytes = b'fixture source archive'
        archive = {'name': 'sing-box-polaris-source-' + self.source + '.tar.gz',
                   'bytes': len(self.archive_bytes),
                   'sha256': hashlib.sha256(self.archive_bytes).hexdigest()}
        self.index = {'schema': 'polaris-upstream-native-assets-v1',
                      'repository': owned.REPO, 'repositoryId': int(owned.REPO_ID),
                      'version': self.tag[1:], 'tag': self.tag,
                      'tagObject': self.tag_object, 'sourceCommit': self.source,
                      'sourceTree': self.tree, 'sourceArchive': archive,
                      'distributionMaterials': {'publicationEligible': True,
                                               'sourceCommit': self.source,
                                               'sourceTree': self.tree,
                                               'sourceArchive': copy.deepcopy(archive)}}
        self.index_path = self.dist / 'polaris-upstream-native-assets.json'
        self.archive_path = self.dist / archive['name']
        self.archive_path.write_bytes(self.archive_bytes)
        self.write_index(self.index)

    def write_index(self, index):
        self.index_path.write_text(json.dumps(index), encoding='utf-8')

    def git(self, *args):
        return {'HEAD': self.source, 'HEAD^{tree}': self.tree,
                'refs/tags/' + self.tag: self.tag_object}[args[-1]]

    def test_rejected_candidate_never_reaches_remote_operations(self):
        cases = ['missing', 'malformed', 'staging', 'source', 'tree', 'tag', 'tag-object',
                 'repository', 'version', 'false', 'integer-true', 'missing-eligibility',
                 'missing-materials', 'materials-source', 'materials-tree',
                 'materials-archive', 'archive-name', 'archive-bytes']
        for case in cases:
            with self.subTest(case=case):
                index = copy.deepcopy(self.index)
                self.archive_path.write_bytes(self.archive_bytes)
                if case == 'staging': index['schema'] = 'polaris-upstream-native-staging-v1'
                elif case in ('source', 'tree', 'tag', 'tag-object', 'repository', 'version'):
                    key = {'source': 'sourceCommit', 'tree': 'sourceTree',
                           'tag-object': 'tagObject'}.get(case, case)
                    index[key] = 'wrong'
                elif case == 'false': index['distributionMaterials']['publicationEligible'] = False
                elif case == 'integer-true': index['distributionMaterials']['publicationEligible'] = 1
                elif case == 'missing-eligibility': index['distributionMaterials'].pop('publicationEligible')
                elif case == 'missing-materials': index.pop('distributionMaterials')
                elif case.startswith('materials-'):
                    key = {'materials-source': 'sourceCommit', 'materials-tree': 'sourceTree',
                           'materials-archive': 'sourceArchive'}[case]
                    index['distributionMaterials'][key] = 'wrong'
                elif case == 'archive-name': index['sourceArchive']['name'] = '../outside'
                elif case == 'archive-bytes': self.archive_path.write_bytes(b'changed')
                self.write_index(index)
                if case == 'missing': self.index_path.unlink()
                elif case == 'malformed': self.index_path.write_text('{', encoding='utf-8')
                with patch.object(owned, 'verify_tag', return_value=self.tag), \
                     patch.object(owned, 'run', side_effect=self.git), \
                     patch.object(owned.subprocess, 'run') as remote_run, \
                     patch.object(owned.subprocess, 'check_output') as remote_read:
                    with self.assertRaises((ValueError, OSError)):
                        owned.publish()
                    remote_run.assert_not_called()
                    remote_read.assert_not_called()

    def test_eligible_bound_index_preserves_draft_then_verify_then_publish(self):
        events = []

        def remote_run(args, **kwargs):
            events.append(args)
            if args[:2] == ['gh', 'api']:
                return subprocess.CompletedProcess(args, 1, '', 'HTTP 404')
            return subprocess.CompletedProcess(args, 0, '', '')

        def remote_read(args, **kwargs):
            self.assertEqual(events[-1][:3], ['gh', 'release', 'create'])
            return json.dumps({'assets': [
                {'name': p.name, 'size': p.stat().st_size,
                 'digest': 'sha256:' + hashlib.sha256(p.read_bytes()).hexdigest()}
                for p in self.dist.iterdir()]})

        with patch.object(owned, 'verify_tag', return_value=self.tag), \
             patch.object(owned, 'run', side_effect=self.git), \
             patch.object(owned.subprocess, 'run', side_effect=remote_run), \
             patch.object(owned.subprocess, 'check_output', side_effect=remote_read):
            owned.publish()
        self.assertEqual(len(events), 3)
        self.assertIn('--draft', events[1])
        self.assertEqual(events[2], ['gh', 'release', 'edit', self.tag, '--draft=false'])

    def test_shared_gate_rejects_non_object_and_strict_false_values(self):
        for invalid in (None, [], 'index'):
            with self.assertRaises(ValueError):
                validate_publication_index(invalid, self.source, self.tag, self.tag_object)
        for invalid in (False, 1, 'true', None):
            index = copy.deepcopy(self.index)
            index['distributionMaterials']['publicationEligible'] = invalid
            with self.assertRaises(ValueError):
                validate_publication_index(index, self.source, self.tag, self.tag_object)
