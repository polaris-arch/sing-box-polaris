"""One version contract across producers, identities, package metadata and scope."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import polaris_version as v
import release_identity as identity
import native_release_index as native
import github_release as publisher

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads((ROOT / 'scripts/ci/testdata/polaris-versions.json').read_text())
PLAN = json.loads((ROOT / 'release/ci/github-release.json').read_text())
VERSION = '1.15.0-polaris-alpha.12.22'
publisher.bind_release('v' + VERSION)


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
            with self.subTest(value=value):
                self.assertEqual(v.validate(value), value)
        for value in CONTRACT['invalid'] + [None, 12]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                v.validate(value)

    def test_self_contained_schemas_share_the_parser_contract(self):
        import jsonschema
        schema = json.loads((ROOT / 'release/ci/native-release-index.schema.json').read_text())
        validator = jsonschema.Draft202012Validator(schema)
        validator.check_schema(schema)
        for properties in [schema['properties'], schema['properties']['platforms']['items']['properties']]:
            for key in ['version', 'tag']:
                field = validator.evolve(schema=properties[key])
                prefix = 'v' if key == 'tag' else ''
                for value in CONTRACT['valid']:
                    field.validate(prefix + value)
                for value in CONTRACT['invalid']:
                    with self.subTest(value=value, key=key), self.assertRaises(jsonschema.ValidationError):
                        field.validate(prefix + value)

    def test_native_names_and_exact_plan_scope(self):
        for version in [VERSION, '1.15.0-polaris-alpha.13']:
            names = native.expected_native(version)
            self.assertTrue(all(name.startswith('sing-box-' + version + '-') for name in names))
            # Simulate a separately reviewed next plan; syntax never selects a release.
            with patch.object(publisher, 'VERSION', version):
                scope = publisher.release_scope(version)
                rules = scope['all']['payloadRules']['binary-linux_amd64-purego']
                files = {f'sing-box-{version}-linux-amd64.tar.gz': {}}
                publisher.verify_payloads(files, rules, 'binary-linux_amd64-purego')
                for wrong in ['1.15.0-polaris-alpha.12', version + '0', version + '.1']:
                    with self.assertRaises(ValueError):
                        publisher.verify_payloads({name.replace(version, wrong): value for name, value in files.items()}, rules, 'binary-linux_amd64-purego')
        for wrong in ['1.15.0-polaris-alpha.12', '1.15.0-polaris-alpha.12.2']:
            with self.assertRaises(ValueError):
                publisher.release_scope(wrong)

    def test_full_patch_tag_is_bound_to_actual_source_and_tag_object(self):
        source, obj = 'a' * 40, 'b' * 40
        tag = 'v' + VERSION
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


if __name__ == '__main__':
    unittest.main()
