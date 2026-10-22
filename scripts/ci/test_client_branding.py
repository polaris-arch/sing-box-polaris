"""Display-only overlay and public naming regression controls; no product build."""
import json
from pathlib import Path
import unittest
import jsonschema
import client_source as c
import github_release as p

class ClientBrandingTests(unittest.TestCase):
    def test_all_unsigned_and_signed_client_producers_apply_before_version_and_build(self):
        import yaml
        jobs={'build_android':'android','build_windows_client':'windows','build_linux_client':'linux',
              'build_apple':'apple','build_apple_app_store':'apple'}
        for filename in ['build.yml','signed-release.yml']:
            workflow=yaml.safe_load((p.ROOT/'.github/workflows'/filename).read_bytes())
            checks=dict(jobs)
            if filename=='signed-release.yml':checks['publish_android']='android'
            for job,platform in checks.items():
                steps=workflow['jobs'][job]['steps']
                command=('unsigned_clients.py '+platform if filename=='build.yml' else
                         'owned_distribution.py apply '+('desktop' if platform in ('windows','linux') else platform))
                indices=[i for i,step in enumerate(steps) if command in step.get('run','')]
                self.assertEqual(len(indices),1,(filename,job))
                index=indices[0]
                self.assertTrue(any('submodule update' in step.get('run','') for step in steps[:index]),(filename,job))
                for i,step in enumerate(steps):
                    run=step.get('run','')
                    if any(marker in run for marker in ['cmd/internal/update_', 'pnpm -C clients/desktop package:', './gradlew', 'xcodebuild archive', 'make -C clients/apple build_', 'scripts/ci/record_candidate.py', 'client_source.py record-signed']):
                        self.assertLess(index,i,(filename,job,step.get('name')))

    def test_linux_producer_applies_declared_overlay_before_build_and_receipt(self):
        import yaml
        workflow=yaml.safe_load((p.ROOT/'.github/workflows/build.yml').read_bytes())
        steps=workflow['jobs']['build_linux_client']['steps']
        apply=[i for i,step in enumerate(steps) if step.get('run')=='python3 scripts/ci/unsigned_clients.py linux']
        self.assertEqual(len(apply),1)
        index=apply[0]
        self.assertNotIn('if',steps[index])
        self.assertLess(next(i for i,s in enumerate(steps) if s.get('name')=='Checkout desktop submodules'),index)
        for name in ['Update version','Install dependencies','Build','Record actual unsigned candidate files']:
            self.assertLess(index,next(i for i,s in enumerate(steps) if s.get('name')==name))
        self.assertEqual(c.definition('linux')['versionMetadata'],['version.json'])

    def test_name_mapping_idempotent_and_no_duplicate_product_prefix(self):
        for old,new in [('SFA-V.apk','sing-box-polaris-SFA-V.apk'),('SFW-V.exe','sing-box-polaris-SFW-V.exe'),('SFL-V.deb','sing-box-polaris-SFL-V.deb'),('SFM-V.pkg','sing-box-polaris-SFM-V.pkg'),('sing-box-V.ipa','sing-box-polaris-V.ipa'),('unsigned-V-ios.xcarchive.tar','sing-box-polaris-unsigned-V-ios.xcarchive.tar')]:
            self.assertEqual(p.branded_client_name(old),new)
            self.assertEqual(p.branded_client_name(new),new)
            self.assertEqual(Path(old).suffixes,Path(new).suffixes)
            self.assertNotIn('sing-box-polaris-sing-box-',new)
        # Non-client paths and provenance behavior stay unchanged.
        self.assertEqual(p.default_name('all','binary-linux_amd64',f'sing-box-{p.VERSION}.tar.gz'),f'sing-box-polaris-{p.PUBLIC_VERSION}.tar.gz')
        with self.assertRaises(ValueError):
            p.default_name('all','binary-linux_amd64','sing-box-V.tar.gz')
        self.assertIsNone(p.default_name('all','binary-android-apks-other','polaris-candidate-manifest-x.json'))
        self.assertIsNone(p.default_name('signed','binary-windows-client-x64','SFW-V.exe'))

    def test_exact_upstream_scope_is_still_validated_before_public_mapping(self):
        s=p.release_scope(p.VERSION)
        examples=[('binary-android-apks-other',f'SFA-{p.VERSION}-arm64.apk'),('binary-windows-client-x64',f'SFW-{p.VERSION}-x64.exe'),('binary-linux-client-x64',f'SFL-{p.VERSION}-amd64.deb'),('binary-apple-standalone-all',f'SFM-{p.VERSION}-Universal.pkg'),('unsigned-apple-ios-archive',f'unsigned-{p.VERSION}-ios.xcarchive.tar')]
        names=[]
        import re
        for artifact,old in examples:
            self.assertTrue(any(re.fullmatch(r['pattern'],old) for r in s['all']['payloadRules'][artifact]))
            new=p.default_name('all',artifact,old)
            if artifact.startswith('unsigned-apple-'):
                self.assertIsNone(new)
                self.assertEqual(p.producer_publication('all',artifact,old)[1],'internal-unsigned-archive')
                continue
            names.append(new)
            self.assertTrue(new.startswith(('SFA-','SFW-','SFL-','SFM-')))
            self.assertIn(p.PUBLIC_VERSION,new)
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

    def test_parallel_distro_producers_keep_separate_channels_and_exact_source_names(self):
        for ext in ['deb','rpm']:
            original=f'sing-box_{p.VERSION}_linux_amd64.{ext}'
            existing=original.replace('sing-box_','sing-box-polaris_')
            build=p.default_name('all','binary-linux_amd64-musl',original)
            linux=p.default_name('linux','binary-linux_amd64',existing)
            self.assertEqual(build,f'sing-box-polaris_{p.PUBLIC_VERSION}_linux_amd64.{ext}')
            self.assertIsNone(linux)
            self.assertEqual(p.producer_publication('all','binary-linux_amd64-musl',original),
                             (existing,'upstream-public-product'))
            self.assertEqual(p.producer_publication('linux','binary-linux_amd64',existing),
                             (None,'separate-distribution-channel'))

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
        # The original reference stays historical; Apple-only patch-version support
        # has a distinct, hash-bound transition and cannot redefine Android materials.
        transition=json.loads((c.ROOT/'release/ci/android-material-overlay-transition.json').read_text())
        self.assertEqual(r['clientSource']['overlayManifestSHA256'],transition['previousOverlayManifestSHA256'])
        self.assertNotEqual(r['clientSource']['overlayManifestSHA256'],c.sha(c.MANIFEST.read_bytes()))
        self.assertEqual(transition['currentOverlayManifestSHA256'],c.sha(c.MANIFEST.read_bytes()))
        self.assertEqual(transition['referenceSHA256'],c.sha((c.ROOT/'release/dependency-sources/clients/runtime/android-resolved/reuse-reference.json').read_bytes()))
        self.assertEqual(transition['unchangedAndroidDefinitionSHA256'],c.sha(json.dumps(c.definition('android'),sort_keys=True,separators=(',',':')).encode()))
        self.assertEqual(transition['changedPlatforms'],['apple'])
        self.assertTrue(transition['requiresActualRuntimeArtifactComparison'])
        self.assertTrue(all(not path.endswith(('.gradle','.kts','.properties')) for path in r['reviewedOverlayChange']['androidPaths']))
        transition=r['reviewedNDKSourceChange']
        self.assertEqual(transition['previousOverlayManifestSHA256'],r['reviewedOverlayChange']['currentOverlayManifestSHA256'])
        self.assertEqual(transition['currentOverlayManifestSHA256'],r['clientSource']['overlayManifestSHA256'])
        self.assertEqual(transition['ndkVersion'],'30.0.16248370')
        self.assertEqual(transition['androidPaths'],['app/build.gradle.kts','gradle.properties'])
        self.assertTrue(transition['historicalDiagnosticPreserved'])
        self.assertTrue(transition['requiresActualRuntimeArtifactComparison'])

if __name__=='__main__':unittest.main()
