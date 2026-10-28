"""Run the established synthetic end-to-end gate against the second exact policy."""
import copy
from pathlib import Path
from unittest import mock

import github_release as p
import publisher_peer_evidence as previous
import publisher_peer_evidence_12_5 as current
import publisher_peer_evidence_tests as historical_tests
import publisher_peer_registry as registry


class CurrentPeerEvidenceTests(historical_tests.PeerEvidenceTests):
    def setUp(self):
        # Reuse fixture mechanics, not historical producer/selection bytes.
        # unittest runs these methods serially; restore even if setup raises.
        patcher = mock.patch.object(historical_tests, 'e', current)
        patcher.start()
        self.addCleanup(patcher.stop)
        super().setUp()

    def test_historical_fixture_version_restores_current_modules_on_error(self):
        old_raw = (p.ROOT / previous.PATH).read_bytes()
        self.assertNotEqual(previous.SOURCE, current.SOURCE)
        self.assertNotEqual(previous.PATH, current.PATH)
        self.assertEqual(registry.select(p.ROOT, previous.SOURCE, previous.VERSION, 'v' + previous.VERSION)['selection']['sourceCommit'], previous.SOURCE)
        self.assertEqual(registry.select(self.root, current.SOURCE, current.VERSION, 'v' + current.VERSION), self.policy)
        self.assertEqual((p.ROOT / previous.PATH).read_bytes(), old_raw)

    def test_oci_ordinary_strict_gate_unchanged(self):
        import oci_material_registry
        self.assertTrue(oci_material_registry.supports_source(current.SOURCE))
        with mock.patch.object(p, 'validate_oci_material_reuse', side_effect=ValueError('actual OCI material drift')) as gate:
            with self.assertRaisesRegex(ValueError, 'actual OCI material drift'):
                p.measure_oci_materials(Path('not-executed'), 'oci-linux-loong64', current.SOURCE, '40320104873', 1)
            gate.assert_called_once_with(Path('not-executed'), 'oci-linux-loong64', current.SOURCE, '40320104873', 1)

    def test_registry_mixed_or_partial_tuple_never_falls_back(self):
        for m in (previous, current):
            good = [m.SOURCE, m.VERSION, 'v' + m.VERSION]
            for position in range(3):
                for other in ('unknown', [current.SOURCE, current.VERSION, 'v' + current.VERSION][position]
                              if m is previous else [previous.SOURCE, previous.VERSION, 'v' + previous.VERSION][position]):
                    bad = good.copy(); bad[position] = other
                    with self.subTest(identity=bad), self.assertRaises(ValueError):
                        registry.select(p.ROOT, *bad)
                    with self.assertRaises(ValueError):
                        registry.check_inventory(p.ROOT, dict(zip(('sourceCommit', 'version', 'tag'), bad)), self.publisher)
        self.assertIsNone(registry.select(p.ROOT, 'unregistered', 'old', 'vold'))
        with self.assertRaises(ValueError):
            registry.check_inventory(p.ROOT, dict(sourceCommit='unknown', version='old', tag='vold', controlledPeerEvidence={}), self.publisher)

    def test_registry_record_policy_hash_publisher_and_source_cannot_cross(self):
        actual = self.inventory()
        real_load = current.load
        for mutation in (
                lambda a: a['controlledPeerEvidence'].update(path=previous.PATH),
                lambda a: a['controlledPeerEvidence'].update(sha256='0' * 64),
                lambda a: a['controlledPeerEvidence'].update(publisherCommit='a' * 40),
                lambda a: a['controlledPeerEvidence']['evidence'].update(sourceCommit=previous.SOURCE)):
            changed = copy.deepcopy(actual); mutation(changed)
            with mock.patch.object(current, 'load', side_effect=lambda _: real_load(self.root)), self.assertRaises(ValueError):
                registry.check_inventory(p.ROOT, changed, self.publisher)

