import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

import polaris_dns_publication as publication

ROOT = Path(__file__).resolve().parents[1]


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads((ROOT / publication.CONTRACT).read_text())

    def test_preparation_is_four_current_targets_with_unknown_real_outputs(self):
        publication.validate_contract(self.contract)
        self.assertEqual(len(self.contract['consumerWriteSet']), 15)
        self.assertTrue(all(v is None for v in self.contract['notYetProduced'].values()))

    def test_missing_or_fake_final_input_cannot_activate_preparation(self):
        mutations = [('AppAdmissible', True), ('publicationEligible', True)]
        for field, value in mutations:
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'preparation'):
                trial = copy.deepcopy(self.contract); trial[field] = value
                publication.validate_contract(trial)
        for value in ({}, {'sourceTagObject': 'a' * 40}):
            with self.subTest(pending=value), self.assertRaisesRegex(ValueError, 'preparation'):
                trial = copy.deepcopy(self.contract); trial['notYetProduced'] = value
                publication.validate_contract(trial)

    def test_exact_planned_role_version_and_annotation(self):
        for field, value in [('plannedRoleTag', 'polaris-box-v1.15.0-alpha.11-2'),
                             ('plannedFinalVersion', '1.15.0-alpha.11.polaris.candidate-aafc521b'),
                             ('roleTagAnnotationRequiredLines', ['Role: mobile'])]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                trial = copy.deepcopy(self.contract); trial[field] = value
                publication.validate_contract(trial)

    def test_four_gate_and_historical_origin_may_not_be_weakened(self):
        for field, value in [('freshFourTargets', ['win']), ('singleCandidateRunAttempt', False),
                             ('technicalReceiptAdmissible', True), ('oldDOrA01OriginsAdmissibleForDNS', True)]:
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'four-core'):
                trial = copy.deepcopy(self.contract); trial['formalReceipts'][field] = value
                publication.validate_contract(trial)

    def test_host_settings_and_replacement_link_policy_cannot_drift(self):
        for field, value in [('GOENV', 'on'), ('GOWORK', '/tmp/go.work'),
                             ('GOFLAGS', '-overlay=/tmp/x'), ('GOTOOLCHAIN', 'auto')]:
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'isolation'):
                trial = copy.deepcopy(self.contract); trial['sourceCollection']['isolatedGoSettings'][field] = value
                publication.validate_contract(trial)
        for key in publication.TARGETS:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'source-owned'):
                trial = copy.deepcopy(self.contract); trial['platformPolicy'][key]['sourceOwnedModules']['allowedAbsent'] = ['github.com/sagernet/sing-tun']
                publication.validate_contract(trial)

    def test_mac_arm64_cannot_use_intel_unsigned_exception(self):
        trial = copy.deepcopy(self.contract)
        trial['signatures']['mac-arm64']['allowedStates'].append('unsigned')
        with self.assertRaisesRegex(ValueError, 'signature'):
            publication.validate_contract(trial)

    def test_final_ids_require_real_provider_receipt_and_change_with_input(self):
        for value in (None, '', 'technical', '0' * 63):
            with self.subTest(value=value), self.assertRaises(ValueError):
                publication.final_platform_identity(self.contract, value, 'linux')
        ids = {key: publication.final_platform_identity(self.contract, '0' * 64, key)['buildID']
               for key in publication.TARGETS}
        self.assertEqual(len(set(ids.values())), 4)
        self.assertTrue(all(v.startswith('polaris-desktop-source-v1-') for v in ids.values()))
        self.assertNotEqual(ids['linux'], publication.final_platform_identity(self.contract, '1' * 64, 'linux')['buildID'])
        trial = copy.deepcopy(self.contract); trial['sourceOwnedReplacement']['replacementTree'] = '0' * 40
        self.assertNotEqual(ids['linux'], publication.final_platform_identity(trial, '0' * 64, 'linux')['buildID'])
        # Post-link output/signature values are not recursive pre-link inputs.
        trial = copy.deepcopy(self.contract); trial['notYetProduced']['finalMacSignatures'] = {'fake': 'fixture'}
        self.assertEqual(ids['linux'], publication.final_platform_identity(trial, '0' * 64, 'linux')['buildID'])


class SourceBoundaryTests(unittest.TestCase):
    def test_source_member_escape_and_windows_paths_are_rejected(self):
        for value in ('../outside', '/absolute', 'a/../x', 'a//x', 'C:/x', 'a\\x', ''):
            with self.subTest(value=value), self.assertRaises(ValueError):
                publication.safe_name(value)

    def test_baseline_zip_rejects_escape_duplicate_and_foreign_module(self):
        prefix = 'github.com/sagernet/sing-tun@v1/'
        for names in ([prefix + '../x'], ['other@v1/x'], [prefix + 'x', prefix + 'x']):
            with self.subTest(names=names):
                out = io.BytesIO()
                with zipfile.ZipFile(out, 'w') as archive:
                    for name in names:
                        archive.writestr(name, b'fixture')
                raw = out.getvalue()
                binding = {'baselineZipSha256': publication.dns.sha(raw), 'module': 'github.com/sagernet/sing-tun',
                           'version': 'v1', 'baselineFiles': 253}
                with self.assertRaises(ValueError):
                    publication.baseline_files(raw, binding)

    def test_baseline_zip_corruption_and_incomplete_snapshot_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'ZIP differs'):
            publication.baseline_files(b'broken', {'baselineZipSha256': '0' * 64})
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as archive:
            archive.writestr('github.com/sagernet/sing-tun@v1/go.mod', b'fixture')
        raw = out.getvalue()
        with self.assertRaisesRegex(ValueError, '253-file'):
            publication.baseline_files(raw, {'baselineZipSha256': publication.dns.sha(raw),
                'module': 'github.com/sagernet/sing-tun', 'version': 'v1', 'baselineFiles': 253})

    def test_duplicate_root_or_replacement_modules_reject_even_without_h1(self):
        header = 'core: go1.25.5\n\tmod\tgithub.com/sagernet/sing-box\t' + publication.dns.ROOT_MODULE_VERSIONS[0] + '\n'
        line = '\tdep\tgithub.com/sagernet/sing-tun\tv1\n\t=>\t./third_party/sing-tun\t(devel)\n'
        for raw in (header + header.split('\n', 1)[1], header + line + line, header + '\t=>\t./x\t(devel)\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                publication.parse_dependencies(raw)

    def test_technical_receipt_wrong_schema_source_or_run_is_rejected(self):
        for field, value in [('schema', 'polaris-desktop-core-v1'), ('sourceCommit', '0' * 40),
                             ('workflowRun', '1'), ('AppAdmissible', True)]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                raw = {'schema': 'polaris-dns-technical-native-v1', 'producerHead': publication.TECHNICAL_PRODUCER,
                       'workflowCommit': publication.TECHNICAL_PRODUCER, 'workflowRun': publication.TECHNICAL_RUN,
                       'workflowAttempt': '1', 'sourceCommit': publication.dns.SOURCE, 'sourceTree': publication.dns.TREE,
                       'AppAdmissible': False, 'publicationEligible': False}
                raw[field] = value
                path = root / 'receipt.json'; path.write_text(json.dumps(raw))
                pin = {'path': path.name, 'bytes': path.stat().st_size, 'sha256': publication.file_sha(path)}
                index = {'technicalReceiptPins': {key:pin for key in publication.TARGETS}}
                with self.assertRaisesRegex(ValueError, 'technical source/run/schema'):
                    publication.validate_technical_receipts(root, {}, {}, index)

    def test_source_output_must_be_fresh_and_outside_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / 'repo'; repo.mkdir()
            for output in (repo / 'out', Path(tmp)):
                with self.subTest(output=output), self.assertRaises(ValueError):
                    publication.write_source_inputs(output, repo, {}, b'', b'')


class FinalReceiptContextTests(unittest.TestCase):
    def setUp(self):
        # Synthetic metadata only; no fixture is an actual native verdict.
        self.candidate = 'c' * 40
        self.facts = {'schema': 'polaris-desktop-core-v1', 'candidate': self.candidate,
                      'version': publication.PLANNED_VERSION, 'buildTree': publication.dns.TREE,
                      'sourceReceipt': {'sourceCommit': publication.dns.SOURCE},
                      'buildID': 'polaris-desktop-source-v1-' + '0' * 64}
        self.env = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'polaris-arch/Polaris',
                    'GITHUB_SHA': self.candidate, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '2'}

    def test_context_is_bound_before_fingerprint_without_changing_original_facts(self):
        original = copy.deepcopy(self.facts)
        receipt = publication.bind_final_receipt_context(self.facts, self.candidate, self.env)
        self.assertEqual(self.facts, original)
        self.assertEqual([receipt[k] for k in ('repository', 'runId', 'runAttempt')],
                         ['polaris-arch/Polaris', '123', '2'])
        fingerprint = receipt.pop('fingerprint')
        self.assertEqual(fingerprint, publication.dns.sha(publication.dns.canonical(receipt).encode()))
        receipt['fingerprint'] = fingerprint
        self.assertEqual(receipt, publication.validate_final_receipt_context(receipt, self.candidate, self.env))

    def test_context_change_or_fingerprint_tamper_rejects_old_run(self):
        receipt = publication.bind_final_receipt_context(self.facts, self.candidate, self.env)
        for field, value in [('GITHUB_RUN_ID', '124'), ('GITHUB_RUN_ATTEMPT', '3'),
                             ('GITHUB_REPOSITORY', 'polaris-arch/polaris-box'), ('GITHUB_SHA', 'd' * 40)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                env = dict(self.env); env[field] = value
                publication.validate_final_receipt_context(receipt, self.candidate, env)
        for field, value in [('runId', '124'), ('runAttempt', 2), ('fingerprint', '0' * 64)]:
            with self.subTest(tamper=field), self.assertRaises(ValueError):
                trial = dict(receipt); trial[field] = value
                publication.validate_final_receipt_context(trial, self.candidate, self.env)

    def test_technical_or_legacy_receipt_cannot_be_rebound(self):
        for field, value in [('schema', 'polaris-dns-technical-native-v1'), ('sourceReceipt', {'sourceCommit': 'a01'}),
                             ('version', '1.15.0-alpha.11.polaris.candidate-aafc521b'),
                             ('buildID', 'polaris-dns-technical-v1-' + '0' * 64)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                trial = copy.deepcopy(self.facts); trial[field] = value
                publication.bind_final_receipt_context(trial, self.candidate, self.env)
        bound = publication.bind_final_receipt_context(self.facts, self.candidate, self.env)
        with self.assertRaisesRegex(ValueError, 'bound once'):
            publication.bind_final_receipt_context(bound, self.candidate, self.env)

    def test_unknown_candidate_repository_run_attempt_cannot_stamp_receipt(self):
        for field, value in [('GITHUB_ACTIONS', 'false'), ('GITHUB_RUN_ID', ''), ('GITHUB_RUN_ID', '0'),
                             ('GITHUB_RUN_ATTEMPT', '0'), ('GITHUB_RUN_ATTEMPT', 1)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                env = dict(self.env); env[field] = value
                publication.bind_final_receipt_context(self.facts, self.candidate, env)

    def test_preparation_requires_outputs_false_then_measured_envelope(self):
        plan = json.loads((ROOT / publication.CONTRACT).read_text())
        for field, value in [('producerOutputsRequired', True), ('envelopeBindsFourMeasuredOutputs', False),
                             ('contextFieldsBoundBeforeFingerprint', [])]:
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'envelope'):
                trial = copy.deepcopy(plan); trial['formalReceipts'][field] = value
                publication.validate_contract(trial)


if __name__ == '__main__':
    unittest.main()
