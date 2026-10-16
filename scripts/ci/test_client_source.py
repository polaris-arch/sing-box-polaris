"""Source/identity and unsigned-mode controls; run in the consolidated CI gate."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock
import yaml

import client_source as client
import github_release as publisher


class ClientSourceControls(unittest.TestCase):
    def fixture(self, platform='apple', unsigned=True):
        spec=client.definition(platform)
        selected=[e for e in spec['files'] if e['kind']!='unsigned' or unsigned]
        return {'schema':'polaris-client-source-v1','platform':platform,'repository':spec['repository'],
                'baseCommit':spec['commit'],'baseTree':spec['tree'],'coreSourceCommit':'a'*40,
                'overlayManifestSHA256':client.sha(client.MANIFEST.read_bytes()),'unsigned':unsigned,
                'sourceOverlayCount':len(selected),'files':[{'path':e['path'],'kind':e['kind'],
                'beforeSHA256':e['beforeSHA256'],'afterSHA256':e['afterSHA256'],'bytes':1} for e in selected],
                'diff':'fixture','diffSHA256':client.sha(b'fixture')}

    def test_all_client_artifacts_require_their_own_overlay_identity(self):
        for artifact,platform in [('binary-android-apks-other','android'),('binary-windows-client-x64','windows'),
                                  ('binary-linux-client-x64','linux'),('binary-apple-standalone','apple'),
                                  ('unsigned-apple-ios-archive','apple'),('signed-apple-store-ios','apple')]:
            role='signed' if artifact.startswith('signed-') else 'all'
            value=self.fixture(platform,role!='signed')
            self.assertEqual(publisher.validate_client_source({'clientSource':value},artifact,role,'a'*40),value)
            with self.assertRaises(ValueError):publisher.validate_client_source({},artifact,role,'a'*40)
            for key,bad in [('baseCommit','c'*40),('baseTree','e'*40),('coreSourceCommit','d'*40),('overlayManifestSHA256','0'*64),
                            ('sourceOverlayCount',0 if platform!='linux' else 1),('unsigned',role=='signed'),('diffSHA256','0'*64)]:
                changed=copy.deepcopy(value);changed[key]=bad
                with self.subTest(artifact=artifact,key=key),self.assertRaises(ValueError):
                    publisher.validate_client_source({'clientSource':changed},artifact,role,'a'*40)
        with self.assertRaises(ValueError):publisher.validate_client_source({'clientSource':self.fixture()},'binary-linux_amd64','all','a'*40)

    def test_missing_duplicate_wrong_source_or_unlisted_changes_rejected(self):
        value=self.fixture()
        mutations=[lambda d:d['files'].pop(),lambda d:d['files'].append(d['files'][0]),
                   lambda d:d['files'][0].update(afterSHA256='0'*64),
                   lambda d:d['files'].append({'path':'not-reviewed.swift','kind':'compatibility'})]
        for mutation in mutations:
            changed=copy.deepcopy(value);mutation(changed)
            with self.assertRaises(ValueError):client.validate(changed,'apple','a'*40,True)

    def test_strict_before_and_after_hashes_and_anchor_counts(self):
        raw=b'actual source\n';entry={'path':'fixture','beforeGitBlob':hashlib.sha1(b'blob 14\0'+raw).hexdigest(),
            'beforeSHA256':client.sha(raw),'afterSHA256':client.sha(b'changed source\n'),
            'edits':[{'old':'actual','new':'changed','count':1}]}
        self.assertEqual(client.edits(raw,entry),b'changed source\n')
        for key,value in [('beforeGitBlob','0'*40),('beforeSHA256','0'*64),('afterSHA256','0'*64)]:
            bad=copy.deepcopy(entry);bad[key]=value
            with self.assertRaises(ValueError):client.edits(raw,bad)
        bad=copy.deepcopy(entry);bad['edits'][0]['count']=2
        with self.assertRaises(ValueError):client.edits(raw,bad)

    def test_windows_unsigned_edits_cover_actual_per_arch_reader_signed_has_none(self):
        entries=client.definition('windows')['files'];self.assertEqual(len(entries),1)
        entry=entries[0];self.assertEqual(entry['kind'],'unsigned')
        edits='\n'.join(e['old']+'\n'+e['new'] for e in entry['edits'])
        self.assertIn('readWindowsSigningConfiguration()',edits)
        self.assertIn('const signingConfiguration = undefined;',edits)
        self.assertIn('signAndEditExecutable:',edits)
        self.assertEqual(self.fixture('windows',False)['sourceOverlayCount'],0)

    def test_both_workflows_apply_all_apple_and_android_compatibility_before_build(self):
        for filename,signed in [('build.yml',False),('signed-release.yml',True)]:
            workflow=yaml.safe_load((client.ROOT/'.github/workflows'/filename).read_text())
            for name in ['build_android','build_apple','build_apple_app_store']:
                steps=workflow['jobs'][name]['steps'];platform='android' if name=='build_android' else 'apple'
                invokes=[i for i,s in enumerate(steps) if ('client_source.py apply '+platform if signed else 'unsigned_clients.py '+platform) in s.get('run','')]
                self.assertEqual(len(invokes),1,(filename,name))
                builds=[i for i,s in enumerate(steps) if './gradlew' in s.get('run','') or 'xcodebuild archive' in s.get('run','') or 'make -C clients/apple build_' in s.get('run','')]
                self.assertTrue(builds);self.assertLess(invokes[0],min(builds))
