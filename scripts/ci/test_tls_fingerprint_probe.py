"""Source-owned admission/identity negatives; actual binary checks run on CI."""
import json
from pathlib import Path
import tempfile
import unittest

import tls_fingerprint_probe as probe
from utls_gate import REQUIRED_FORK, REQUIRED_UPSTREAM, commands, require_tests
from mobile_fingerprint_exports import APPLE_DECLARATION, JAVA_DECLARATION


class FingerprintProbeControls(unittest.TestCase):
    def fixture(self):
        profiles = []
        versions = {'chrome':'155','chrome_155':'155','chrome_133':'133','firefox':'148','firefox_148':'148',
                    'firefox_120':'120','safari':'26.3','safari_26_3':'26.3','safari_16_0':'16.0'}
        aliases = ['chrome_psk','chrome_psk_shuffle','chrome_padding_psk_shuffle','chrome_pq','chrome_pq_psk']
        for name in sorted(probe.expected_profiles() - set(aliases)):
            profiles.append({'id':name,'displayName':name,'client':'fixture','templateVersion':versions.get(name,'fixture'),
                             'selection':'process-browser' if name=='random' else 'process-seeded-generator' if name=='randomized' else 'profile',
                             'templateOffersX25519MLKEM768':None if name=='randomized' else False})
        return {'schema':'polaris-tls-fingerprint-capabilities-v1','enabled':True,'sourceCommit':'1'*40,'sourceModified':False,
                'coreVersion':'1.15.0-polaris-alpha.12','goVersion':'go1.27.2','requiredGoVersion':'go1.27.2',
                'buildTags':'with_utls','os':'linux','arch':'amd64','defaultFingerprint':'chrome','profiles':profiles,
                'modules':[{'path':p,'version':v,'sum':s} for p,(v,s) in probe.source_module_pins().items()],
                'legacyChromeAliases':aliases,'randomSemantics':'process','randomizedSemantics':'process seed',
                'shadowTLSSessionIDWithECHSupported':False,'curvePreferencesSupported':False,
                'realityX25519MLKEM768':'filtered from supported groups and shares','negotiationEvidence':'offer only'}

    def validate(self, document):
        return probe.validate(document,source='1'*40,version='1.15.0-polaris-alpha.12',go_version='go1.27.2',target='linux/amd64')

    def test_original_identity_and_all_source_ids(self):
        self.assertEqual(self.validate(self.fixture())['sourceCommit'],'1'*40)

    def test_identity_unknown_dirty_or_cross_target_is_not_a_production_pin(self):
        for key,value in [('sourceCommit',''),('sourceCommit','2'*40),('sourceModified',None),('sourceModified',True),
                          ('enabled',1),('os','darwin'),('arch','arm64'),('goVersion','go1.27.1'),('coreVersion','other')]:
            doc=self.fixture();doc[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(Exception):self.validate(doc)

    def test_duplicate_alias_missing_template_or_module_is_rejected(self):
        mutations=[lambda d:d['profiles'].append(d['profiles'][0]),lambda d:d['profiles'].pop(),
                   lambda d:d['legacyChromeAliases'].pop(),lambda d:d['modules'].pop(),
                   lambda d:d['modules'][0].update(sum='h1:wrong'),
                   lambda d:d['modules'][0].update(replace={'path':'local','version':'','sum':''}),
                   lambda d:next(p for p in d['profiles'] if p['id']=='chrome').update(templateVersion='invented')]
        for change in mutations:
            doc=self.fixture();change(doc)
            with self.subTest(change=change),self.assertRaises(Exception):self.validate(doc)

    def test_stub_does_not_advertise_uTLS_but_may_link_meta_in_shadowtls(self):
        doc=self.fixture();doc.update(enabled=False,profiles=[],legacyChromeAliases=[])
        probe.validate(doc,source='1'*40,version=doc['coreVersion'],go_version='go1.27.2',target='linux/amd64',enabled=False)

    def test_runtime_suite_explicitly_covers_upstream_and_fork_with_race(self):
        items=dict(commands('production flags'))
        for name, command in items.items():self.assertIn('-race',command);self.assertIn('-count=1',command)
        self.assertIn('github.com/refraction-networking/utls',items['upstream'])
        self.assertIn('-tags=with_utls,badlinkname',items['fork']);self.assertNotIn('-tags=with_utls,badlinkname',items['stub'])
        self.assertIn('TestChrome155CapturedClientHello',REQUIRED_UPSTREAM)
        self.assertIn('TestRealityUpstreamClientMetaServerActualHandshake',REQUIRED_FORK)

    def test_green_package_does_not_replace_missing_or_skipped_runtime_cases(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'events.json'
            for events,valid in [([{'Action':'pass','Package':'fixture'}],False),
                                 ([{'Action':'skip','Test':'Required'}],False),
                                 ([{'Action':'pass','Test':'Required'}],True)]:
                path.write_text('\n'.join(json.dumps(e) for e in events))
                if valid:require_tests(path,{'Required'})
                else:self.assertRaises(ValueError,require_tests,path,{'Required'})

    def test_mobile_declarations_are_source_derived_not_version_guessed(self):
        self.assertRegex('FOUNDATION_EXPORT NSString* _Nonnull LibboxTLSFingerprintCapabilities(NSError* _Nullable* _Nullable error);',APPLE_DECLARATION)
        self.assertRegex('public static native java.lang.String tlsFingerprintCapabilities() throws java.lang.Exception;',JAVA_DECLARATION)
        self.assertIsNone(APPLE_DECLARATION.search('FOUNDATION_EXPORT BOOL LibboxTLSFingerprintCapabilities(void);'))
        self.assertIsNone(JAVA_DECLARATION.search('public static native boolean tlsFingerprintCapabilities();'))

    def test_disabled_and_default_are_serialized_as_enabled_not_invented_ids(self):
        self.assertEqual(probe.outbound_config()['outbounds'][0]['tls']['utls'],{'enabled':True})
        self.assertEqual(probe.outbound_config(enabled=False)['outbounds'][0]['tls']['utls'],{'enabled':False})
