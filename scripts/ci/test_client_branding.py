"""Display-only overlay and public naming regression controls; no product build."""
import json
from pathlib import Path
import unittest
import jsonschema
import client_source as c
import github_release as p

class ClientBrandingTests(unittest.TestCase):
    def test_name_mapping_idempotent_and_no_duplicate_product_prefix(self):
        for old,new in [('SFA-V.apk','sing-box-polaris-SFA-V.apk'),('SFW-V.exe','sing-box-polaris-SFW-V.exe'),('SFL-V.deb','sing-box-polaris-SFL-V.deb'),('SFM-V.pkg','sing-box-polaris-SFM-V.pkg'),('sing-box-V.ipa','sing-box-polaris-V.ipa'),('unsigned-V-ios.xcarchive.tar','sing-box-polaris-unsigned-V-ios.xcarchive.tar')]:
            self.assertEqual(p.branded_client_name(old),new)
            self.assertEqual(p.branded_client_name(new),new)
            self.assertEqual(Path(old).suffixes,Path(new).suffixes)
            self.assertNotIn('sing-box-polaris-sing-box-',new)
        # Non-client paths and provenance behavior stay unchanged.
        self.assertEqual(p.default_name('all','binary-linux_amd64','sing-box-V.tar.gz'),'sing-box-polaris-V.tar.gz')
        self.assertIsNone(p.default_name('all','binary-android-apks-other','polaris-candidate-manifest-x.json'))
        self.assertIsNone(p.default_name('signed','binary-windows-client-x64','SFW-V.exe'))

    def test_exact_upstream_scope_is_still_validated_before_public_mapping(self):
        s=p.release_scope(p.VERSION)
        examples=[('binary-android-apks-other',f'SFA-{p.VERSION}-arm64.apk'),('binary-windows-client-x64',f'SFW-{p.VERSION}-x64.exe'),('binary-linux-client-x64',f'SFL-{p.VERSION}-amd64.deb'),('binary-apple-standalone-all',f'SFM-{p.VERSION}-Universal.pkg'),('unsigned-apple-ios-archive',f'unsigned-{p.VERSION}-ios.xcarchive.tar')]
        names=[]
        import re
        for artifact,old in examples:
            self.assertTrue(any(re.fullmatch(r['pattern'],old) for r in s['all']['payloadRules'][artifact]))
            new=p.default_name('all',artifact,old);names.append(new)
            self.assertTrue(new.startswith('sing-box-polaris-'))
            self.assertFalse(any(re.fullmatch(r['pattern'],new) for r in s['all']['payloadRules'][artifact]))
        self.assertEqual(len(names),len({x.casefold() for x in names}))

    def test_all_public_product_prefixes_without_changing_library_names(self):
        from release_identity import public_product_name
        for name in ['sing-box-V-linux.tar.gz','sing-box-V-windows.zip','sing-box_V_linux.deb','sing-box_V_linux.rpm','sing-box-V-oci.tar','sing-box-V-container-linux']:
            new=public_product_name(name)
            self.assertTrue(new.startswith('sing-box-polaris'))
            self.assertEqual(public_product_name(new),new)
        for name in ['libbox.aar','Libbox-ios-arm64.tar','sing-box-polaris_V_linux.deb']:
            self.assertEqual(public_product_name(name),name)
        for name in ['../sing-box-V.zip','https://evil/sing-box-V.zip','a\\sing-box-V.zip','']:
            with self.assertRaises(ValueError):public_product_name(name)

    def test_new_native_index_requires_exact_public_basename_mapping(self):
        import test_github_release as gates
        fixture=gates.GateTests()
        index=fixture.final_index();fixture.check_index(index)
        original=index['platforms'][0]['archive']['releaseName']
        for bad in [None,'',original.replace('polaris-',''),original+'-other','../'+original,'https://example.com/'+original]:
            index['platforms'][0]['archive']['releaseName']=bad
            with self.assertRaises((ValueError,jsonschema.ValidationError)):fixture.check_index(index)
        del index['platforms'][0]['archive']['releaseName']
        with self.assertRaises((ValueError,jsonschema.ValidationError)):fixture.check_index(index)

    def test_parallel_distro_producers_remain_distinct_public_payloads(self):
        for ext in ['deb','rpm']:
            original=f'sing-box_{p.VERSION}_linux_amd64.{ext}'
            existing=original.replace('sing-box_','sing-box-polaris_')
            build=p.default_name('all','binary-linux_amd64-musl',original)
            linux=p.default_name('linux','binary-linux_amd64',existing)
            self.assertEqual(build,f'sing-box-polaris_{p.VERSION}_linux_amd64-build.{ext}')
            self.assertEqual(linux,existing)
            self.assertNotEqual(build.casefold(),linux.casefold())

    def test_branding_does_not_rewrite_author_license_permissions_or_ids(self):
        for platform in ['android','apple','windows','linux']:
            entries=[e for e in c.definition(platform)['files'] if e['kind']=='branding']
            self.assertTrue(entries)
            for e in entries:
                self.assertNotIn('LICENSE',e['path'])
                self.assertNotIn('entitlements',e['path'])
                for edit in e['edits']:
                    for protected in ['applicationId','PRODUCT_BUNDLE_IDENTIFIER','DEVELOPMENT_TEAM','CODE_SIGN','BASE_PACKAGE_IDENTIFIER','permission android:name','StartupWMClass: sing-box']:
                        if protected in edit['old']:self.assertIn(protected,edit['new'])
            self.assertTrue(all(e in c.selected(c.definition(platform),False) for e in entries))
        android=c.definition('android')['files'];locales=[e for e in android if e['kind']=='branding' and e['path'].endswith('/strings.xml')]
        self.assertEqual(len(locales),5)
        apple=next(e for e in c.definition('apple')['files'] if e['kind']=='branding' and e['path'].endswith('project.pbxproj'))
        self.assertEqual(apple['edits'][0]['count'],12)
        desktop=next(e for e in c.definition('linux')['files'] if e['path']=='electron-builder.yml')
        self.assertNotIn('productName:',str(desktop['edits']))

    def test_windows_display_product_keeps_executable_and_integrity_hook_in_agreement(self):
        entries=c.definition('windows')['files']
        package=next(e for e in entries if e['path']=='scripts/package.ts' and e['kind']=='branding')
        text='\n'.join(x['new'] for x in package['edits'])
        self.assertIn('productName: "sing-box-polaris"',text)
        self.assertIn('executableName: "sing-box"',text)
        hook=next(e for e in entries if e['path']=='scripts/afterSign.cjs')
        self.assertEqual(len(hook['edits']),1)
        self.assertIn('"sing-box.exe"',hook['edits'][0]['new'])
        self.assertNotIn('expectedFuses',str(hook['edits']))

    def test_android_historical_identity_is_not_relabelled_as_a_new_run(self):
        r=json.loads((c.ROOT/'release/dependency-sources/clients/runtime/android-resolved/reuse-reference.json').read_text())
        self.assertEqual(r['referenceDiagnostic']['runId'],'39031988065')
        self.assertEqual(r['referenceDiagnostic']['clientSourceOverlayManifestSHA256'],r['reviewedOverlayChange']['previousOverlayManifestSHA256'])
        self.assertNotEqual(r['referenceDiagnostic']['clientSourceOverlayManifestSHA256'],r['clientSource']['overlayManifestSHA256'])
        self.assertEqual(r['clientSource']['overlayManifestSHA256'],c.sha(c.MANIFEST.read_bytes()))
        self.assertTrue(all(not path.endswith(('.gradle','.kts','.properties')) for path in r['reviewedOverlayChange']['androidPaths']))

if __name__=='__main__':unittest.main()
