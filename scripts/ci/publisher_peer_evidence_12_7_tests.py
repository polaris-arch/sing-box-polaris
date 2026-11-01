"""Exercise the existing complete peer gate for the exact alpha.12.7 selection."""
import copy
from unittest import mock

import github_release as p
import publisher_peer_evidence_12_7 as current
import publisher_peer_evidence_tests as historical_tests
import publisher_peer_registry as registry


class Alpha127PeerEvidenceTests(historical_tests.PeerEvidenceTests):
    def setUp(self):
        patcher = mock.patch.object(historical_tests, 'e', current)
        patcher.start()
        self.addCleanup(patcher.stop)
        super().setUp()

    def test_historical_fixture_version_restores_current_modules_on_error(self):
        for previous in registry.MODULES[:-1]:
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
