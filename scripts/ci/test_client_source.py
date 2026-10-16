"""Consolidated source/unsigned/API controls. Private fixtures never publish."""
import base64
import copy
from contextlib import contextmanager
import difflib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import yaml

import client_source as client
import github_release as publisher

REAL_ROOT=client.ROOT


def patch(before,after):
    result=[]
    for name in sorted(set(before)|set(after)):
        old,new=before.get(name),after.get(name)
        if old==new:continue
        result.append('diff --git a/'+name+' b/'+name+'\n')
        if old is None:result.append('new file mode 100644\n')
        if new is None:result.append('deleted file mode 100644\n')
        result.append('index '+('0'*40 if old is None else client.blob(old))+'..'+('0'*40 if new is None else client.blob(new))+(' 100644' if old is not None and new is not None else '')+'\n')
        result.extend(difflib.unified_diff(('' if old is None else old.decode()).splitlines(keepends=True),
                                         ('' if new is None else new.decode()).splitlines(keepends=True),
                                         fromfile='/dev/null' if old is None else 'a/'+name,
                                         tofile='/dev/null' if new is None else 'b/'+name))
    return ''.join(result)


class ClientSourceControls(unittest.TestCase):
    @contextmanager
    def fixture(self,platform='windows',unsigned=True,owned_mode='100644'):
        # Known original -> compatibility -> unsigned OR reviewed identity;
        # generated version metadata is a final, independently recorded stage.
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'release/ci').mkdir(parents=True)
            def entry(before,after,kind):
                return {'path':'source.txt','kind':kind,'beforeMode':'100644','beforeGitBlob':client.blob(before),
                        'beforeSHA256':client.sha(before),'afterSHA256':client.sha(after),
                        'edits':[{'old':before.decode(),'new':after.decode(),'count':1}]}
            spec={'path':'clients/fixture','repository':'fixture/client','commit':'b'*40,'tree':'c'*40,
                  'versionMetadata':['version.txt'],'baselineFiles':{'version.txt':{'gitBlob':client.blob(b'v1\n'),'mode':'100644'}},
                  'files':[entry(b'base\n',b'compat\n','compatibility'),entry(b'compat\n',b'unsigned\n','unsigned')]}
            policy=root/'release/ci/client-overlays.json';policy.write_text(json.dumps({'platforms':{platform:spec}}))
            baseline={'source.txt':b'base\n','version.txt':b'v1\n'}
            desired={'source.txt':b'unsigned\n' if unsigned else b'owned\n','version.txt':b'v2\n'}
            if not unsigned:
                # Test-only public identity file is explicitly new/untracked.
                baseline['owned.txt']=None;desired['owned.txt']=b'public owned identity\n'
                identity_before={'source.txt':b'compat\n','owned.txt':None}
                identity_after={name:desired[name] for name in identity_before}
                raw=patch(identity_before,identity_after).replace('new file mode 100644','new file mode '+owned_mode).encode();path=root/'release/ci/private-fixture.patch';path.write_bytes(raw)
                files={name:{'baseGitBlob':None if baseline[name] is None else client.blob(baseline[name]),
                             'beforeSHA256':None if identity_before[name] is None else client.sha(identity_before[name]),
                             'afterSHA256':client.sha(identity_after[name]),'bytes':len(identity_after[name]),
                             'beforeMode':None if identity_before[name] is None else '100644',
                             'afterMode':owned_mode if name=='owned.txt' else '100644'} for name in identity_before}
                key='desktop' if platform in ('windows','linux') else platform
                config={'repository':'polaris-arch/sing-box-polaris','repositoryId':1421657509,'reviewed':True,
                        'clientIdentityPatches':{key:{'path':'release/ci/private-fixture.patch','sha256':client.sha(raw),'clientCommit':'b'*40,'files':files}}}
                (root/'release/ci/owned-distribution.json').write_text(json.dumps(config))
            with mock.patch.multiple(client,ROOT=root,MANIFEST=policy):
                identity=client.identity_definition(platform,unsigned)
                touched={e['path'] for e in client.selected(spec,unsigned)}|(set(identity['files']) if identity else set())
                diff=patch(baseline,desired)
                if not unsigned:diff=diff.replace('new file mode 100644','new file mode '+owned_mode)
                record={'schema':'polaris-client-source-v1','platform':platform,'repository':spec['repository'],'baseCommit':'b'*40,'baseTree':'c'*40,
                        'coreSourceCommit':'a'*40,'overlayManifestSHA256':client.sha(policy.read_bytes()),'unsigned':unsigned,'sourceOverlayCount':len(touched),
                        'identity':identity,'baseline':{name:None if raw is None else base64.b64encode(raw).decode() for name,raw in baseline.items()},
                        'files':[{'path':name,'beforeSHA256':None if baseline[name] is None else client.sha(baseline[name]),
                                  'afterSHA256':client.sha(raw),'bytes':len(raw)} for name,raw in sorted(desired.items())],
                        'diff':diff,'diffSHA256':client.sha(diff.encode())}
                yield record

    def check(self,record):
        client.validate(record,record['platform'],'a'*40,record['unsigned'])

    def test_actual_diff_replays_compatibility_unsigned_identity_new_file_and_metadata(self):
        for platform in ['windows','linux','android','apple']:
            for unsigned in [True,False]:
                with self.subTest(platform=platform,unsigned=unsigned),self.fixture(platform,unsigned) as record:
                    self.check(record)
                    artifact='signed-apple-store-ios' if not unsigned and platform=='apple' else {
                        'windows':'binary-windows-client-x64','linux':'binary-linux-client-x64',
                        'android':'binary-android-apks-other','apple':'unsigned-apple-ios-archive'}[platform]
                    self.assertEqual(publisher.validate_client_source({'clientSource':record},artifact,'all' if unsigned else 'signed','a'*40),record)
                    with self.assertRaises(ValueError):publisher.validate_client_source({},artifact,'all' if unsigned else 'signed','a'*40)

    def test_identity_source_tree_mode_config_and_count_are_not_interchangeable(self):
        with self.fixture(unsigned=False) as record:
            for key,bad in [('baseCommit','d'*40),('baseTree','e'*40),('coreSourceCommit','f'*40),('overlayManifestSHA256','0'*64),
                            ('sourceOverlayCount',0),('unsigned',True),('identity',None),('diffSHA256','0'*64)]:
                value=copy.deepcopy(record);value[key]=bad
                with self.subTest(key=key),self.assertRaises(ValueError):self.check(value)

    def test_diff_rows_and_original_baseline_are_verified_beyond_a_self_digest(self):
        with self.fixture() as record:
            mutations=[lambda d:d['files'][0].update(afterSHA256='0'*64),lambda d:d['files'][0].update(bytes=1),
                       lambda d:d['files'].pop(),lambda d:d['files'].append(d['files'][0]),
                       lambda d:d['baseline'].update({'source.txt':base64.b64encode(b'forged\n').decode()}),
                       lambda d:d['diff'].replace('+unsigned','+other')]
            for i,change in enumerate(mutations):
                value=copy.deepcopy(record)
                if i==5:value['diff']=change(value)
                else:change(value)
                value['diffSHA256']=client.sha(value['diff'].encode())
                with self.subTest(case=i),self.assertRaises(ValueError):self.check(value)

    def test_owned_patch_requires_inventory_exact_intermediate_bytes_and_raw_patch(self):
        with self.fixture(unsigned=False) as record:
            cfg=client.ROOT/'release/ci/owned-distribution.json';original=cfg.read_text()
            for kind in ['unreviewed','missing-files','wrong-stage','wrong-patch']:
                config=json.loads(original);entry=config['clientIdentityPatches']['desktop']
                if kind=='unreviewed':config['reviewed']=False
                elif kind=='missing-files':entry.pop('files')
                elif kind=='wrong-stage':entry['files']['source.txt']['beforeSHA256']=client.sha(b'base\n')
                else:entry['sha256']='0'*64
                cfg.write_text(json.dumps(config))
                value=copy.deepcopy(record)
                if kind=='wrong-stage':value['identity']=client.identity_definition('windows',False)
                with self.subTest(kind=kind),self.assertRaises(ValueError):self.check(value)
            cfg.write_text(original)

    def test_new_untracked_source_must_have_explicit_origin_not_a_permitted_name_only(self):
        with self.fixture() as record:
            value=copy.deepcopy(record);value['baseline']['surprise.kt']=None
            value['files'].append({'path':'surprise.kt','beforeSHA256':None,'afterSHA256':client.sha(b'new\n'),'bytes':4})
            value['diff']+=patch({'surprise.kt':None},{'surprise.kt':b'new\n'});value['diffSHA256']=client.sha(value['diff'].encode())
            with self.assertRaises(ValueError):self.check(value)
        with self.fixture(unsigned=False) as record:
            # New owned.txt is validated by its reviewed patch and cannot be
            # relabeled as an old baseline or replaced by arbitrary new bytes.
            value=copy.deepcopy(record);value['baseline']['owned.txt']=base64.b64encode(b'planted\n').decode()
            with self.assertRaises(ValueError):self.check(value)

    def test_source_resource_and_portable_path_boundaries(self):
        with self.fixture() as record:
            value=copy.deepcopy(record);value['baseline']['source.txt']='e'*(2*client.MAX_SOURCE_BYTES)
            with self.assertRaises(ValueError):self.check(value)
            value=copy.deepcopy(record);value['diff']='x'*(client.MAX_DIFF_BYTES+1)
            with self.assertRaises(ValueError):self.check(value)
        for name in ['../escape','/absolute','a\\b','.git/config','CON','trailing.']:
            with self.subTest(path=name),self.assertRaises(ValueError):client.portable(name)

    def test_crlf_is_rejected_instead_of_normalizing_a_wrong_blob(self):
        raw=b'raw baseline\n';entry={'path':'fixture','beforeGitBlob':client.blob(raw),'beforeSHA256':client.sha(raw),
             'afterSHA256':client.sha(b'changed\n'),'edits':[{'old':'raw baseline','new':'changed','count':1}]}
        self.assertEqual(client.edits(raw,entry),b'changed\n')
        with self.assertRaises(ValueError):client.edits(raw.replace(b'\n',b'\r\n'),entry)
        bad=copy.deepcopy(entry);bad['edits'][0]['count']=2
        with self.assertRaises(ValueError):client.edits(raw,bad)

    def test_final_modes_are_bound_for_transforms_identity_and_version_metadata(self):
        for unsigned in [True,False]:
            with self.fixture(unsigned=unsigned) as record:
                for name in ['source.txt','version.txt']+([] if unsigned else ['owned.txt']):
                    value=copy.deepcopy(record)
                    marker='diff --git a/'+name+' b/'+name+'\n'
                    if name=='owned.txt':
                        before=marker+'new file mode 100644\n'
                        after=marker+'new file mode 100755\n'
                    else:
                        # Git index contains the Git blob, not the SHA256 row identity.
                        body=value['diff'].split(marker,1)[1].split('\n',1)[0]
                        self.assertTrue(body.startswith('index ') and body.endswith(' 100644'))
                        before=marker+body+'\n';after=marker+'old mode 100644\nnew mode 100755\n'+body.removesuffix(' 100644')+'\n'
                    self.assertEqual(value['diff'].count(before),1)
                    value['diff']=value['diff'].replace(before,after,1);value['diffSHA256']=client.sha(value['diff'].encode())
                    with self.subTest(unsigned=unsigned,path=name),self.assertRaisesRegex(ValueError,'final mode'):
                        self.check(value)
        # An explicitly reviewed executable new identity file is allowed.
        with self.fixture(unsigned=False,owned_mode='100755') as record:self.check(record)

    def test_windows_unsigned_flag_covers_builder_and_nested_payloads_signed_stays_strict(self):
        spec=client.definition('windows');entries=spec['files']
        self.assertEqual(spec['commit'],'50f503849148dd73fa4f4bc231119acf5b2f3d7a')
        self.assertEqual({e['path'] for e in entries},{'scripts/package.ts','scripts/afterPack.cjs'})
        self.assertEqual(client.selected(spec,False),[])  # Signed uses the original strict sources.
        result={}
        original={}
        for entry in entries:
            raw=(REAL_ROOT/'scripts/ci/testdata/desktop-50f50384'/Path(entry['path']).name).read_bytes()
            self.assertEqual(client.blob(raw),entry['beforeGitBlob'])
            self.assertEqual(client.sha(raw),entry['beforeSHA256'])
            original[entry['path']]=raw.decode()
            result[entry['path']]=client.edits(raw,entry).decode()
        package=result['scripts/package.ts'];nested=result['scripts/afterPack.cjs']
        for fragment in ['unsignedWindowsPackage ? undefined : readWindowsSigningConfiguration()',
                         'forceCodeSigning: !unsignedWindowsPackage','signExecutable: unsignedWindowsPackage ? false : undefined']:
            self.assertIn(fragment,package)
        self.assertNotIn('signAndEditExecutable:',package)  # Keep resources and afterSign integrity/fuses.
        strict='const signed = await context.packager.signIf(executablePath);\n    if (!signed) {\n      throw new Error(`failed to sign ${relativePath.join("/")}`);'
        self.assertIn(strict,original['scripts/afterPack.cjs'])
        self.assertIn(strict,nested)  # Check the full patched source, including unchanged signed checks.
        for fragment in ['process.env.POLARIS_UNSIGNED_CLIENT === "1"','fs.statSync(executablePath).isFile()',
                         'continue; // Explicit unsigned candidate']:
            self.assertIn(fragment,nested)
        workflow=yaml.safe_load((REAL_ROOT/'.github/workflows/build.yml').read_text())
        steps=workflow['jobs']['build_windows_client']['steps'];first=next(s for s in steps if s.get('name')=='Checkout desktop client')
        self.assertIn('-c core.autocrlf=false -c core.eol=lf submodule update',first['run'])
        build=next(s for s in steps if s.get('name')=='Build')
        self.assertEqual(build['env']['POLARIS_UNSIGNED_CLIENT'],'1')
        self.assertIn('unsigned_clients.py windows\nif ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }',build['run'])
        signed=yaml.safe_load((REAL_ROOT/'.github/workflows/signed-release.yml').read_text())
        self.assertNotIn('POLARIS_UNSIGNED_CLIENT',json.dumps(signed))

    def test_android_min_api_guard_and_jvm_negative_controls_are_in_existing_producers(self):
        entries=client.definition('android')['files'];text='\n'.join(e.get('content','') or '\n'.join(c['new'] for c in e.get('edits',[])) for e in entries)
        for fragment in ['Build.VERSION.SDK_INT < Build.VERSION_CODES.M','@DoNotInline','@RequiresApi(Build.VERSION_CODES.M)',
                         'if (sdk < 23)','listOf(21, 22)','listOf(23, 24, 35)','SecurityException','resolve = { null }']:
            self.assertIn(fragment,text)
        for filename in ['build.yml','signed-release.yml']:
            workflow=yaml.safe_load((REAL_ROOT/'.github/workflows'/filename).read_text());steps=workflow['jobs']['build_android']['steps']
            build=next(s for s in steps if './gradlew --build-cache --parallel' in s.get('run',''))
            self.assertIn('testOtherLegacyReleaseUnitTest',build['run']);self.assertIn('testOtherReleaseUnitTest',build['run'])
            self.assertEqual([m['variant'] for m in workflow['jobs']['build_android']['strategy']['matrix']['include']],['other','other-legacy'])

    def test_signed_identity_entry_owns_composition_before_version_update(self):
        workflow=yaml.safe_load((REAL_ROOT/'.github/workflows/signed-release.yml').read_text())
        for name in ['build_android','publish_android','build_windows_client','build_linux_client','build_apple','build_apple_app_store']:
            steps=workflow['jobs'][name]['steps'];identities=[i for i,s in enumerate(steps) if 'owned_distribution.py apply' in s.get('run','')]
            self.assertEqual(len(identities),1,name)
            self.assertFalse(any('client_source.py apply' in s.get('run','') for s in steps),name)
            builds=[i for i,s in enumerate(steps) if './gradlew' in s.get('run','') or 'xcodebuild archive' in s.get('run','') or 'package:win' in s.get('run','')]
            if builds:self.assertLess(identities[0],min(builds))
