"""Exercise the existing complete peer gate for the exact alpha.12.9 selection."""
import copy
import hashlib
import json
from pathlib import Path
from unittest import mock

import github_release as p
import publisher_peer_evidence_12_9 as current
import publisher_peer_evidence_tests as historical_tests
import publisher_peer_registry as registry


class Alpha129PeerEvidenceTests(historical_tests.PeerEvidenceTests):
    def setUp(self):
        patcher = mock.patch.object(historical_tests, 'e', current)
        patcher.start()
        self.addCleanup(patcher.stop)
        super().setUp()

    def test_historical_fixture_version_restores_current_modules_on_error(self):
        for previous in (module for module in registry.MODULES if module is not current):
            raw = (p.ROOT / previous.PATH).read_bytes()
            self.assertNotEqual(previous.SOURCE, current.SOURCE)
            self.assertEqual(registry.select(p.ROOT, previous.SOURCE, previous.VERSION,
                                             'v' + previous.VERSION)['selection']['sourceCommit'], previous.SOURCE)
            self.assertEqual((p.ROOT / previous.PATH).read_bytes(), raw)
        self.assertEqual(registry.select(self.root, current.SOURCE, current.VERSION, 'v' + current.VERSION), self.policy)

    def test_registry_mixed_tuple_and_inventory_publisher_rejected(self):
        for module in registry.MODULES:
            good = [module.SOURCE, module.VERSION, 'v' + module.VERSION]
            for position in range(3):
                bad = good.copy(); bad[position] = 'unknown'
                with self.subTest(identity=bad), self.assertRaises(ValueError):
                    registry.select(p.ROOT, *bad)
        self.assertIsNone(registry.select(p.ROOT, 'unregistered', 'old', 'vold'))
        with self.assertRaises(ValueError):
            registry.check_inventory(p.ROOT, dict(sourceCommit='unknown', version='old', tag='vold',
                                                 controlledPeerEvidence={}), self.publisher)
        actual = self.inventory()
        real_load = current.load
        for field in ('path', 'sha256', 'publisherCommit'):
            changed = copy.deepcopy(actual)
            changed['controlledPeerEvidence'][field] = 'wrong'
            with mock.patch.object(current, 'load', side_effect=lambda _: real_load(self.root)), self.assertRaises(ValueError):
                registry.check_inventory(p.ROOT, changed, self.publisher)

    def test_selection_source_tampering_cannot_rebind_receipt_or_api(self):
        policy = copy.deepcopy(self.policy)
        policy['selection']['sourceCommit'] = 'a' * 40
        receipt = copy.deepcopy(self.r)
        receipt['context'].update(sourceCommit='a' * 40, workflowCommit='a' * 40)
        with self.assertRaises(ValueError):
            current.validate_receipt(policy, self.measured(), receipt)
        api = copy.deepcopy(self.artifacts[str(self.s['runId'])][-1])
        api['workflow_run']['head_sha'] = 'a' * 40
        with self.assertRaises(ValueError):
            current.check_api(policy, 'all', self.runs[str(self.s['runId'])], api)

    def test_oci_ordinary_strict_gate_unchanged(self):
        import oci_material_registry
        self.assertTrue(oci_material_registry.supports_source(current.SOURCE))
        with mock.patch.object(p, 'validate_oci_material_reuse', side_effect=ValueError('actual OCI material drift')) as gate:
            with self.assertRaisesRegex(ValueError, 'actual OCI material drift'):
                p.measure_oci_materials(Path('not-executed'), 'oci-linux-loong64', current.SOURCE, '41379223932', 1)
            gate.assert_called_once_with(Path('not-executed'), 'oci-linux-loong64', current.SOURCE, '41379223932', 1)

    def test_current_attempt_expiry_and_public_eligibility_never_accept_historical_evidence(self):
        original = self.artifacts[str(self.s['runId'])][-1]
        run = self.runs[str(self.s['runId'])]
        for change in (dict(run_attempt=2), dict(path='.github/workflows/linux.yml')):
            with self.subTest(change=change), self.assertRaises(ValueError):
                current.check_api(self.policy, 'all', dict(run, **change), original)
        expired = copy.deepcopy(original); expired['expired'] = True
        with self.assertRaises(ValueError):
            current.check_api(self.policy, 'all', run, expired)
        for field, value in (('created_at', '2026-10-25T04:59:59Z'), ('expired', True)):
            rows = self.artifacts[str(self.s['runId'])]
            changed = copy.deepcopy(original); changed[field] = value
            rows[-1] = changed
            try:
                with self.subTest(field=field), self.assertRaises(ValueError):
                    self.inventory()
            finally:
                rows[-1] = original
        for change in (dict(publicationEligible=True), dict(context=dict(self.r['context'], runAttempt=2)),
                       dict(context=dict(self.r['context'], runId=40956987023))):
            with self.subTest(change=change), self.assertRaises(ValueError):
                current.validate_receipt(self.policy, self.measured(), dict(self.r, **change))

    def test_committed_selection_pins_the_measured_final_evidence_without_making_it_public(self):
        raw = (p.ROOT / current.PATH).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), 'c0a5d2051dd97f7ec6d1613ac6c1ec2c169346a28e076614a4649a00297fe249')
        selected = json.loads(raw)
        self.assertEqual((selected['sourceCommit'], selected['sourceTree'], selected['tagObject'], selected['runId'], selected['runAttempt']),
                         ('dfb1fc278c22ff73b833f12b986c0e499238e535', '8ea894e795393cb4cddef57578733f1256200da1',
                          'bac0f17b4bf9ba073996b4ac98f3707fca89a3da', 41379197191, 1))
        self.assertEqual(selected['member'], {'path': 'receipt.json', 'bytes': 428818,
                         'sha256': '92292c1fd55fd628586ff6d73d0c2de27f61ce46e9761e34758eafbed8338fe6'})
        self.assertEqual(selected['nativeIndexSHA256'], '781bc0d903d9ee25631c032e2859cfabd78b47dbfb7cbddce2e6e66317baece2')
        self.assertFalse(selected['publicationEligible'])
        scope = p.release_scope(current.VERSION)
        original = copy.deepcopy(scope)
        scoped = registry.scoped(scope, current.select(p.ROOT, current.SOURCE, current.VERSION, 'v' + current.VERSION),
                                 {'all': str(current.RUN_ID), 'linux': '41379210301', 'docker': '41379223932'})
        self.assertEqual(scope, original)
        name = selected['artifact']['name']
        self.assertEqual(set(scoped['all']['requiredArtifacts']) - set(original['all']['requiredArtifacts']), {name})
        self.assertEqual(len(original['all']['requiredArtifacts']), 72)
        self.assertEqual(len(scoped['all']['requiredArtifacts']), 73)
        self.assertEqual(scoped['all']['payloadRules'][name], [{'pattern': r'receipt\.json', 'count': 1}])
        self.assertEqual(p.publication('all', name, 'receipt.json', current.SOURCE), (None, current.DISPOSITION))
        self.assertNotIn(name, scoped['linux']['requiredArtifacts'])
        self.assertNotIn(name, scoped['docker']['requiredArtifacts'])
