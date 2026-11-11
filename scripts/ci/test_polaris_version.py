"""One version contract across producers, identities, package metadata and scope."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from contextlib import chdir
from unittest.mock import patch

import polaris_version as v
import release_identity as identity
import native_release_index as native
import github_release as publisher

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads((ROOT / 'scripts/ci/testdata/polaris-versions.json').read_text())
PLAN = json.loads((ROOT / 'release/ci/github-release.json').read_text())


class IdentityComparisonTests(unittest.TestCase):
    def test_nested_json_identity_preserves_scalar_types_order_and_paths(self):
        self.assertTrue(identity.same_identity({'id': 1, 'flags': [False], 'path': Path('/identity')},
                                               {'path': Path('/identity'), 'flags': [False], 'id': 1}))
        for a, b in ((1, 1.0), (1, True), (0, False), (0, 0.0), (False, 0.0)):
            with self.subTest(a=a, b=b):
                self.assertFalse(identity.same_identity({'nested': [a]}, {'nested': [b]}))
        self.assertFalse(identity.same_identity([1, 2], [2, 1]))
        self.assertFalse(identity.same_identity(Path('/identity'), '/identity'))
        for value in (float('nan'), float('inf'), float('-inf')):
            self.assertFalse(identity.same_identity({'value': value}, {'value': value}))


class PolarisVersionTests(unittest.TestCase):
    def test_shared_parser_roundtrip_and_rejections(self):
        for value in CONTRACT['valid']:
            for parser in [v.validate, identity.validate_version, native.validate_version, publisher.validate_version]:
                with self.subTest(value=value, parser=parser):
                    self.assertIs(parser, v.validate)
                    self.assertEqual(parser(value), value)
        for value in CONTRACT['invalid'] + [None, 12]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                v.validate(value)

    def test_self_contained_schemas_share_the_parser_contract(self):
        import jsonschema
        for name, count in [('native-release-index.schema.json', 4), ('native-release-contract.schema.json', 10)]:
            schema = json.loads((ROOT / 'release/ci' / name).read_text())
            jsonschema.Draft202012Validator.check_schema(schema)
            refs = []
            def collect(value, path=''):
                if isinstance(value, dict):
                    if value.get('$ref', '').startswith('#/$defs/polaris'):
                        refs.append((path + '/$ref', value['$ref']))
                    for key, child in value.items():
                        collect(child, path + '/' + key.replace('~', '~0').replace('/', '~1'))
                elif isinstance(value, list):
                    for index, child in enumerate(value):
                        collect(child, path + '/' + str(index))
            collect(schema)
            self.assertEqual(len(refs), count)
            if name == 'native-release-index.schema.json':
                self.assertCountEqual(refs, [
                    ('/properties/version/$ref', '#/$defs/polarisVersion'),
                    ('/properties/tag/$ref', '#/$defs/polarisTag'),
                    ('/properties/platforms/items/properties/version/$ref', '#/$defs/polarisVersion'),
                    ('/properties/platforms/items/properties/tag/$ref', '#/$defs/polarisTag'),
                ])
            for tag in [False, True]:
                key = 'polarisTag' if tag else 'polarisVersion'
                field = schema['$defs'][key]
                self.assertEqual(field, {'type': 'string', 'pattern': v.schema_pattern(tag)})
                validator = jsonschema.Draft202012Validator(field)
                for value in CONTRACT['valid']:
                    validator.validate(('v' if tag else '') + value)
                for value in CONTRACT['invalid']:
                    with self.subTest(schema=name, value=value, tag=tag), self.assertRaises(jsonschema.ValidationError):
                        validator.validate(('v' if tag else '') + value)

    def test_cli_keeps_raw_patch_and_windows_resource_bounds(self):
        script = ROOT / 'scripts/ci/polaris_version.py'
        for value in ['1.15.0-polaris-alpha.12.1', '1.15.0-polaris-alpha.12.2', '1.15.0-polaris-alpha.12.3', '1.15.0-polaris-alpha.12.4', '1.15.0-polaris-alpha.12.5', '1.15.0-polaris-alpha.12.6', '1.15.0-polaris-alpha.12.7', PLAN['version']]:
            for args in [[value], [value, '65535']]:
                output = subprocess.check_output([sys.executable, str(script), *args], text=True)
                self.assertEqual(output, value + '\n')
        for args in [[PLAN['version'], '65536'], [PLAN['version'], '0'], [PLAN['version'], '01'],
                     [PLAN['version'], '١'], ['65536.15.0-polaris-alpha.12.1', '1']]:
            result = subprocess.run([sys.executable, str(script), *args], capture_output=True)
            self.assertNotEqual(result.returncode, 0, args)

    def test_apk_metadata_and_both_real_consumers(self):
        cases = {'1.15.0': '1.15.0-r0', '1.15.0-alpha.12': '1.15.0_alpha12-r0',
                 '1.15.0-beta.8': '1.15.0_beta8-r0', '1.15.0-rc.3': '1.15.0_rc3-r0',
                 '1.15.0-polaris-alpha.12': '1.15.0_alpha12-r0',
                 '1.15.0-polaris-alpha.12.0': '1.15.0_alpha12_p0-r0',
                 '1.15.0-polaris-alpha.12.1': '1.15.0_alpha12_p1-r0',
                 '1.15.0-polaris-alpha.12.2': '1.15.0_alpha12_p2-r0',
                 '1.15.0-polaris-alpha.12.3': '1.15.0_alpha12_p3-r0',
                 '1.15.0-polaris-alpha.12.4': '1.15.0_alpha12_p4-r0',
                 '1.15.0-polaris-alpha.12.5': '1.15.0_alpha12_p5-r0',
                 '1.15.0-polaris-alpha.12.6': '1.15.0_alpha12_p6-r0',
                 '1.15.0-polaris-alpha.12.7': '1.15.0_alpha12_p7-r0',
                 '1.15.0-polaris-alpha.12.10': '1.15.0_alpha12_p10-r0',
                 '1.15.0-polaris-alpha.13': '1.15.0_alpha13-r0',
                 '1.15.0-polaris-beta.1.2': '1.15.0_beta1_p2-r0',
                 '1.15.0-polaris-rc.1.2': '1.15.0_rc1_p2-r0'}
        for raw, expected in cases.items():
            self.assertEqual(v.apk_version(raw), expected)
            for name in ['build_alpine_apk.sh', 'build_openwrt_apk.sh']:
                # Execute the actual assignment, without installing files or invoking apk.
                text = (ROOT / '.github' / name).read_text()
                assignment = next(line for line in text.splitlines() if line.startswith('APK_VERSION='))
                env = dict(os.environ, PROJECT=str(ROOT), VERSION=raw)
                actual = subprocess.check_output(['bash', '-e', '-c', assignment + '\nprintf "%s" "$APK_VERSION"'], env=env, text=True)
                self.assertEqual(actual, expected)
        for raw in CONTRACT['invalid']:
            if raw not in ('1.15.0',):
                with self.subTest(raw=raw), self.assertRaises(ValueError):
                    v.apk_version(raw)

    def test_native_names_and_exact_plan_scope(self):
        for version in ['1.15.0-polaris-alpha.12.1', '1.15.0-polaris-alpha.12.2', '1.15.0-polaris-alpha.12.3', '1.15.0-polaris-alpha.12.4', '1.15.0-polaris-alpha.12.5', '1.15.0-polaris-alpha.12.6', '1.15.0-polaris-alpha.12.7', PLAN['version'], '1.15.0-polaris-alpha.13']:
            names = native.expected_native(version)
            self.assertTrue(all(name.startswith('sing-box-' + version + '-') for name in names))
            # Simulate a separately reviewed next plan; syntax never selects a release.
            with patch.object(publisher, 'VERSION', version):
                scope = publisher.release_scope(version)
                rules = scope['all']['payloadRules']['binary-linux_amd64-glibc']
                files = {f'sing-box-{version}-linux-amd64-glibc.tar.gz': {}}
                publisher.verify_payloads(files, rules, 'binary-linux_amd64-glibc')
                for wrong in ['1.15.0-polaris-alpha.12', version + '0', version + '.1']:
                    with self.assertRaises(ValueError):
                        publisher.verify_payloads({name.replace(version, wrong): value for name, value in files.items()}, rules, 'binary-linux_amd64-glibc')
        self.assertEqual(publisher.VERSION, PLAN['version'])
        for wrong in ['1.15.0-polaris-alpha.12', '1.15.0-polaris-alpha.12.1', '1.15.0-polaris-alpha.12.2', '1.15.0-polaris-alpha.12.3', '1.15.0-polaris-alpha.12.4', '1.15.0-polaris-alpha.12.5', '1.15.0-polaris-alpha.12.6', '1.15.0-polaris-alpha.13']:
            with self.assertRaises(ValueError):
                publisher.release_scope(wrong)

    def test_full_patch_tag_is_bound_to_actual_source_and_tag_object(self):
        source, obj = 'a' * 40, 'b' * 40
        for version in ['1.15.0-polaris-alpha.12.1', '1.15.0-polaris-alpha.12.2', '1.15.0-polaris-alpha.12.3', '1.15.0-polaris-alpha.12.4', '1.15.0-polaris-alpha.12.5', '1.15.0-polaris-alpha.12.6', '1.15.0-polaris-alpha.12.7', PLAN['version']]:
            tag = 'v' + version
            answers = [{'object': {'type': 'tag', 'sha': obj}},
                       {'sha': obj, 'tag': tag, 'object': {'type': 'commit', 'sha': source}}]
            with patch.object(identity, 'api', side_effect=answers) as api:
                self.assertEqual(identity.remote_tag_identity(tag, source, obj), obj)
                self.assertTrue(api.call_args_list[0].args[0].endswith('/' + tag))
            answers[1]['tag'] = 'v1.15.0-polaris-alpha.12'
            with patch.object(identity, 'api', side_effect=answers), self.assertRaises(ValueError):
                identity.remote_tag_identity(tag, source, obj)
        for tag in ['v1.15.0-alpha.12.1', 'v1.15.0-polaris-alpha.12.1;bad']:
            with patch.object(identity, 'api') as api, self.assertRaises(ValueError):
                identity.remote_tag_identity(tag, source, obj)
            api.assert_not_called()

    def test_producer_receipts_keep_patch_and_reject_unreviewed_rotation(self):
        source = 'a' * 40
        for version in [PLAN['version'], '1.15.0-polaris-alpha.12.2', '1.15.0-polaris-alpha.12.3', '1.15.0-polaris-alpha.12.4', '1.15.0-polaris-alpha.12.5', '1.15.0-polaris-alpha.12.6']:
            plan = dict(PLAN, version=version, tag='v' + version)
            for role in ['all']:
                with tempfile.TemporaryDirectory() as directory, chdir(directory):
                    Path('release/ci').mkdir(parents=True)
                    Path('release/ci/github-release.json').write_text(json.dumps(plan))
                    scope = json.loads((ROOT / 'release/ci/publisher-upstream-scope.json').read_text())
                    Path('release/ci/publisher-upstream-scope.json').write_text(json.dumps(scope))
                    needs = {name: {'result': 'success', 'outputs': {}}
                             for name in scope[role]['receiptJobs']}
                    env = {'PUBLISHER_ROLE': role, 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                           'GITHUB_REPOSITORY': PLAN['repository'], 'GITHUB_REPOSITORY_ID': str(PLAN['repositoryId']),
                           'RELEASE_BUILD': 'All', 'RELEASE_VERSION': version, 'GITHUB_SHA': source,
                           'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1',
                           'PUBLISH_STORES': 'false', 'PUBLISH_REGISTRY': 'false',
                           'GITHUB_REF': 'refs/tags/' + plan['tag'], 'NEEDS_JSON': json.dumps(needs),
                           'RECEIPT_EVIDENCE_MODE': 'final', 'RECEIPT_SOURCE_GENERATE_ONLY': 'false'}
                    script = ROOT / 'scripts/ci/publisher_run_receipt.py'
                    with patch.dict(os.environ, env), patch('subprocess.check_output', return_value=source + '\n'):
                        runpy.run_path(str(script))
                    receipt = json.loads(Path('publisher-run-receipt.json').read_text())
                    self.assertEqual(receipt['version'], version)
                    self.assertEqual(receipt['sourceCommit'], source)
                    rejected = ['1.15.0-polaris-alpha.12', version + '0']
                    if version == PLAN['version']:
                        rejected.append('1.15.0-polaris-alpha.12.6')
                    for wrong in rejected:
                        with patch.dict(os.environ, dict(env, RELEASE_VERSION=wrong)), self.assertRaises(AssertionError):
                            runpy.run_path(str(script))


if __name__ == '__main__':
    unittest.main()
