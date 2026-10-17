"""Replay branding into the actual locked electron-builder configuration schema."""
import hashlib
import json
from pathlib import Path
import unittest

import jsonschema
import yaml
import client_source

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'scripts/ci/testdata/electron-builder-26.15.3'


class ClientBuilderSchemaTests(unittest.TestCase):
    def configuration(self, platform):
        raw = (FIXTURE / 'electron-builder.yml').read_bytes()
        spec = client_source.definition(platform)
        entry = next(e for e in spec['files'] if e['path'] == 'electron-builder.yml')
        return yaml.safe_load(client_source.edits(raw, entry))

    def validator(self):
        schema = json.loads((FIXTURE / 'scheme.json').read_bytes())
        return jsonschema.Draft7Validator(schema)

    def test_locked_schema_and_original_fixture_identity(self):
        provenance = json.loads((FIXTURE / 'provenance.json').read_bytes())
        self.assertEqual(provenance['package'], 'app-builder-lib@26.15.3')
        for name, field in [('scheme.json','schemaSHA256'), ('electron-builder.yml','desktopConfigSHA256')]:
            self.assertEqual(hashlib.sha256((FIXTURE / name).read_bytes()).hexdigest(), provenance[field])
        self.assertEqual(client_source.blob((FIXTURE / 'electron-builder.yml').read_bytes()), provenance['desktopConfigGitBlob'])
        self.validator().validate(yaml.safe_load((FIXTURE / 'electron-builder.yml').read_bytes()))

    def test_full_windows_and_linux_configurations(self):
        for platform in ('windows','linux'):
            with self.subTest(platform=platform):
                config = self.configuration(platform)
                self.validator().validate(config)
                self.assertEqual(config['linux']['desktop'], {'entry':{'Name':'sing-box-polaris', 'StartupWMClass':'sing-box'}})
                self.assertEqual(config['nsis']['shortcutName'], 'sing-box-polaris')
                self.assertEqual(config['nsis']['uninstallDisplayName'], 'sing-box-polaris')
                if platform == 'windows':
                    # These are the two literal overrides inserted into the package.ts config.
                    entry = next(e for e in client_source.definition(platform)['files'] if e['path']=='scripts/package.ts' and e['kind']=='branding')
                    for text in ['productName: "sing-box-polaris"', 'executableName: "sing-box"']:
                        self.assertTrue(any(text in change['new'] for change in entry['edits']))
                    config['productName'] = 'sing-box-polaris'
                    config['win']['executableName'] = 'sing-box'
                    self.validator().validate(config)

    def test_original_bad_nesting_and_invalid_name_fields_are_rejected(self):
        config = self.configuration('linux')
        config['linux']['desktop']['StartupWMClass'] = config['linux']['desktop']['entry'].pop('StartupWMClass')
        with self.assertRaises(jsonschema.ValidationError): self.validator().validate(config)
        for section, field in [('nsis','shortcutName'), ('nsis','uninstallDisplayName'), ('win','executableName')]:
            config = self.configuration('windows');config[section][field] = {'invalid':'object'}
            with self.subTest(section=section,field=field), self.assertRaises(jsonschema.ValidationError):
                self.validator().validate(config)


if __name__ == '__main__':
    unittest.main()
