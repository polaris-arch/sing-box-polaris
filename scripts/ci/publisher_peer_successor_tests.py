"""Synthetic ordinary data controls; no genuine producer/native success claimed."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import publisher_peer_successor as s
import publisher_peer_registry as registry
import publisher_peer_evidence_12_9 as old
from publisher_peer_evidence_12_9_tests import Alpha129PeerEvidenceTests


class SuccessorPeerPreparationTests(unittest.TestCase):
    def setUp(self):
        # Reuse complete 14-case/42-process synthetic evidence, never a real run.
        fixture = Alpha129PeerEvidenceTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.source, self.tree, self.tag_object = 'a' * 40, 'b' * 40, 'c' * 40
        def translate(value):
            raw = json.dumps(value).replace(old.SOURCE, self.source).replace(old.VERSION, s.VERSION)
            return json.loads(raw)
        self.index, self.receipt = translate(fixture.index), translate(fixture.r)
        self.index.update(sourceTree=self.tree, tagObject=self.tag_object)
        for row in self.index['platforms']:
            row['sourceTree'] = self.tree
        row = next(r for r in self.index['platforms'] if r['id'] == 'sing-box-' + s.VERSION + '-linux-amd64')
        self.row = copy.deepcopy(row)
        self.row['archive'].pop('releaseName')
        self.receipt['context']['sourceTree'] = self.tree
        self.receipt['identity']['nativeRowSHA256'] = hashlib.sha256(json.dumps(self.row, sort_keys=True).encode()).hexdigest()
        self.receipt['producerRowSHA256'] = hashlib.sha256(self.raw(self.row)).hexdigest()
        self.artifacts = translate(fixture.artifacts[str(old.RUN_ID)])
        self.run = translate(fixture.runs[str(old.RUN_ID)])
        self.run.update(id=old.RUN_ID, head_branch='v' + s.VERSION,
                        repository={'id':1421657509,'full_name':'polaris-arch/sing-box-polaris'},
                        head_repository={'id':1421657509,'full_name':'polaris-arch/sing-box-polaris'})
        self.args = dict(source=self.source, tree=self.tree, tag_object=self.tag_object,
                         expected_run_id=self.run['id'], expected_attempt=self.run['run_attempt'])

    @staticmethod
    def raw(value):
        return (json.dumps(value, indent=2) + '\n').encode()

    def derive(self):
        return s.derive(self.run, self.artifacts, self.raw(self.index), self.raw(self.row),
                        self.raw(self.receipt), **self.args)

    def test_exact_producer_tuple_is_read_from_receipt_and_actual_api_not_predicted(self):
        raw = self.derive()
        selected, hashed = s.selection(raw)
        self.assertEqual(selected['runId'], self.run['id'])
        self.assertEqual(selected['runAttempt'], self.run['run_attempt'])
        self.assertEqual(selected['sourceCommit'], self.source)
        self.assertFalse(selected['publicationEligible'])
        self.assertEqual(selected['member']['sha256'], hashlib.sha256(self.raw(self.receipt)).hexdigest())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / s.PATH
            path.parent.mkdir(parents=True)
            path.write_bytes(raw)
            policy = registry.select(root, self.source, s.VERSION, 'v' + s.VERSION, self.tree, self.tag_object)
            self.assertEqual(policy, {'selection': selected, 'sha256': hashed})
            scope = {'all': {'workflow': self.run['path'], 'requiredArtifacts': [], 'payloadRules': {}}}
            self.assertIn(selected['artifact']['name'], registry.scoped(scope, policy, {'all':str(self.run['id'])})['all']['requiredArtifacts'])
            for source, version, tag in [(old.SOURCE,s.VERSION,'v'+s.VERSION), (self.source,old.VERSION,'v'+s.VERSION)]:
                with self.assertRaises(ValueError):
                    registry.select(root, source, version, tag)
            with self.assertRaises(ValueError):
                registry.select(root, self.source, s.VERSION, 'v' + s.VERSION, 'd'*40, self.tag_object)

    def test_absent_selector_and_partial_current_identity_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                registry.select(Path(directory), self.source, s.VERSION, 'v' + s.VERSION)
            with self.assertRaises(ValueError):
                registry.select(Path(directory), self.source, s.VERSION, 'vold')
        self.assertIsNone(registry.select(Path('unused'), 'unregistered', 'old', 'vold'))

    def test_run_attempt_expiry_source_tag_bytes_and_cleanup_controls_stay_strict(self):
        pristine = copy.deepcopy((self.run, self.artifacts, self.index, self.row, self.receipt))
        mutations = [lambda:self.run.update(run_attempt=True), lambda:self.run.update(run_attempt=2),
            lambda:self.run.update(id=987654321),
            lambda:self.run['repository'].update(full_name='SagerNet/sing-box'),
            lambda:self.run['head_repository'].update(id=True),
            lambda:self.run.update(head_sha='d'*40), lambda:self.run.update(head_branch='v'+old.VERSION),
            lambda:self.run.update(conclusion='failure'), lambda:self.index.update(schema='polaris-upstream-native-staging-v1'),
            lambda:self.index.update(tagObject='d'*40), lambda:self.index['platforms'].pop(),
            lambda:self.receipt.update(publicationEligible=True), lambda:self.receipt.update(privateWorkspaceDeleted=False),
            lambda:self.receipt['cases'][0]['cleanup'][0].update(exitCode=1),
            lambda:self.receipt['context'].update(runAttempt=2),
            lambda:self.artifacts[-1].update(expired=True),
            lambda:self.artifacts[-1]['workflow_run'].update(head_sha='d'*40),
            lambda:self.artifacts[-1].update(created_at='2020-01-01T00:00:00Z'),
            lambda:self.artifacts.append(copy.deepcopy(self.artifacts[-1])),
            lambda:self.row['archive'].update(sha256='d'*64)]
        for mutation in mutations:
            self.run,self.artifacts,self.index,self.row,self.receipt = copy.deepcopy(pristine)
            mutation()
            with self.subTest(mutation=mutation), self.assertRaises((ValueError,KeyError)):
                self.derive()

    def test_same_existing_inventory_assemble_stream_and_native_job_negatives_consume_successor(self):
        import publisher_peer_evidence_tests as shared
        import github_release as publisher
        template, _ = old.load(publisher.ROOT)
        fake_source, fake_run = 'e' * 40, 123
        template = json.loads(json.dumps(template).replace(old.SOURCE, fake_source).replace(old.VERSION, s.VERSION))
        template['runId'] = fake_run
        real_load = s.load
        def fixture_load(root):
            if Path(root) == publisher.ROOT:
                return copy.deepcopy(template), '0' * 64  # Only synthetic setup; no production selector supplied.
            return real_load(root)
        with mock.patch.object(s,'SOURCE',fake_source,create=True), mock.patch.object(s,'RUN_ID',fake_run,create=True), \
             mock.patch.object(s,'load',side_effect=fixture_load), mock.patch.object(shared,'e',s):
            harness = shared.PeerEvidenceTests()
            try:
                harness.setUp()
                harness.test_real_shared_inventory_consumes_bounded_exact_selection_jobs_metadata()
                harness.test_real_shared_inventory_rejects_foreign_missing_skipped_and_mismatched_job_metadata()
                harness.test_full_inventory_assemble_stream_excludes_peer()
            finally:
                harness.doCleanups()

    def test_cli_caller_inputs_never_replace_fixed_source_tree_tag_run_or_review_authority(self):
        raw = self.derive()
        self.assertFalse(json.loads(raw)['publicationEligible'])
        for key, wrong in [('source','d'*40),('tree','d'*40),('tag_object','d'*40),
                           ('expected_run_id',999999),('expected_attempt',2),
                           ('expected_run_id',True),('expected_attempt',1.0)]:
            saved = self.args.copy()
            self.args[key] = wrong
            try:
                with self.subTest(key=key,wrong=wrong), self.assertRaises(ValueError):
                    self.derive()
            finally:
                self.args = saved
        self.assertIsNone(s.mapping(Path('unused'),'all','some-artifact','payload',None))
