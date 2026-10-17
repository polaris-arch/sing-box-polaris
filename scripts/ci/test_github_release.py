import importlib.util
import copy
import jsonschema
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import re
import os
import runpy
from contextlib import chdir
import zipfile

spec=importlib.util.spec_from_file_location('publisher',Path(__file__).with_name('github_release.py'))
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)

class GateTests(unittest.TestCase):
    def test_scope_preserved(self):
        s=json.loads(p.SCOPE.read_text())
        self.assertEqual(len(s['all']['matrices']['build']['include']),38)
        for role,scope in s.items():
            self.assertEqual(set(scope['requiredArtifacts']),set(scope['payloadRules']))
            self.assertEqual(len(scope['requiredArtifacts']),len(set(scope['requiredArtifacts'])))
        self.assertEqual(len(s['docker']['matrices']['build_binary']['include']),10)
        self.assertEqual(len(s['docker']['matrices']['build_docker']['include']),9)

    def test_reviewed_current_version_renders_all_linux_and_signed_payloads(self):
        scope=p.release_scope(p.VERSION)
        old='1.15.0-polaris-alpha.11'
        for role in ['all','signed']:
            rules=scope[role]['payloadRules']['binary-windows-client-x64']
            current=f'SFW-{p.VERSION}-x64.exe';previous=f'SFW-{old}-x64.exe'
            p.verify_payloads({current:{}},rules,'binary-windows-client-x64')
            for files in [{previous:{}},{current:{},previous:{}},{current.replace('alpha.','alphaX'):{}},{}]:
                with self.subTest(role=role,files=files),self.assertRaises(ValueError):
                    p.verify_payloads(files,rules,'binary-windows-client-x64')
            android=scope[role]['payloadRules']['binary-android-apks-other']
            files={f'SFA-{p.VERSION}-{arch}.apk':{} for arch in ['universal','arm64','arm','x64','x86']}
            files[f'SFA-{p.VERSION}-other-version-metadata.json']={}
            p.verify_payloads(files,android,'binary-android-apks-other')
            previous=dict(files);previous[f'SFA-{old}-other-version-metadata.json']=previous.pop(f'SFA-{p.VERSION}-other-version-metadata.json')
            with self.assertRaises(ValueError):p.verify_payloads(previous,android,'binary-android-apks-other')
        rules=scope['linux']['payloadRules']['binary-linux_amd64']
        files={f'sing-box-polaris_{p.VERSION}_linux_amd64.deb':{},f'sing-box-polaris_{p.VERSION}_linux_x86_64.rpm':{}}
        p.verify_payloads(files,rules,'binary-linux_amd64')
        old_mix={name.replace(p.VERSION,old) if name.endswith('.rpm') else name:value for name,value in files.items()}
        with self.assertRaises(ValueError):p.verify_payloads(old_mix,rules,'binary-linux_amd64')
        from native_release_index import expected_native
        for role in ['all','signed']:
            patterns=[rule['pattern'] for rules in scope[role]['payloadRules'].values() for rule in rules]
            for name,value in expected_native(p.VERSION).items():
                archive=name+('.zip' if value['target'].startswith('windows/') else '.tar.gz')
                self.assertTrue(any(re.fullmatch(pattern,archive) for pattern in patterns),(role,archive))
                self.assertFalse(any(re.fullmatch(pattern,archive.replace(p.VERSION,old)) for pattern in patterns),(role,archive))
        self.assertRaises(ValueError,p.release_scope,old)
        self.assertRaises(ValueError,p.release_scope,'v'+p.VERSION)

    def test_client_payloads_bind_exact_version_and_target_architecture(self):
        scope=p.release_scope(p.VERSION)
        linux={'x64':{'deb':'amd64','rpm':'x86_64','pkg.tar.zst':'x64'},
               'arm64':{'deb':'arm64','rpm':'aarch64','pkg.tar.zst':'aarch64'},
               'armv7l':{'deb':'armv7l','rpm':'armv7l','pkg.tar.zst':'armv7l'}}
        for role in ['all','signed']:
            for arch in ['x64','x86','arm64']:
                artifact='binary-windows-client-'+arch;rules=scope[role]['payloadRules'][artifact]
                current=f'SFW-{p.VERSION}-{arch}.exe';p.verify_payloads({current:{}},rules,artifact)
                wrong='x86' if arch=='x64' else 'x64'
                for invalid in [f'SFW-{p.VERSION}0-{arch}.exe',f'SFW-{p.VERSION}-{wrong}.exe',f'SFW-{p.VERSION}-extra-{arch}.exe']:
                    with self.subTest(role=role,artifact=artifact,name=invalid),self.assertRaises(ValueError):
                        p.verify_payloads({invalid:{}},rules,artifact)
            for arch,formats in linux.items():
                artifact='binary-linux-client-'+arch;rules=scope[role]['payloadRules'][artifact]
                files={f'SFL-{p.VERSION}-{cpu}.{ext}':{} for ext,cpu in formats.items()}
                p.verify_payloads(files,rules,artifact)
                adjacent={name.replace(p.VERSION,p.VERSION+'0'):value for name,value in files.items()}
                wrong_cpu='arm64' if arch=='x64' else 'amd64'
                wrong=dict(files);wrong[f'SFL-{p.VERSION}-{wrong_cpu}.deb']=wrong.pop(f'SFL-{p.VERSION}-{formats["deb"]}.deb')
                for invalid in [adjacent,wrong]:
                    with self.subTest(role=role,artifact=artifact),self.assertRaises(ValueError):p.verify_payloads(invalid,rules,artifact)
        # Independent Linux packages have their own exact version/architecture contract.
        rules=scope['linux']['payloadRules']['binary-linux_amd64']
        files={f'sing-box-polaris_{p.VERSION}_linux_amd64.deb':{},f'sing-box-polaris_{p.VERSION}_linux_x86_64.rpm':{}}
        for invalid in [{name.replace(p.VERSION,p.VERSION+'0'):v for name,v in files.items()},
                        {name.replace('linux_amd64','linux_arm64'):v for name,v in files.items()}]:
            with self.assertRaises(ValueError):p.verify_payloads(invalid,rules,'binary-linux_amd64')

    def test_all_and_signed_require_each_exact_openwrt_ipk_and_apk_architecture(self):
        source=json.loads(p.SCOPE.read_text());rendered=p.release_scope(p.VERSION)
        for role in ['all','signed']:
            ipk_count=apk_count=0
            for artifact,rules in source[role]['payloadRules'].items():
                ipks=[x for x in rules if 'openwrt_' in x['pattern'] and x['pattern'].endswith(r'\.ipk')]
                if not ipks:continue
                files={}
                for ipk in ipks:
                    apk={'pattern':ipk['pattern'][:-len(r'\.ipk')]+r'\.apk','count':1}
                    self.assertEqual(ipk['count'],1);self.assertIn(apk,rules)
                    escaped=ipk['pattern'].removeprefix(r'sing\-box_{version}_openwrt_').removesuffix(r'\.ipk')
                    arch=re.sub(r'\\(.)',r'\1',escaped)
                    for ext in ['ipk','apk']:files[f'sing-box_{p.VERSION}_openwrt_{arch}.{ext}']={}
                    ipk_count+=1;apk_count+=1
                controls=[x for x in rendered[role]['payloadRules'][artifact] if 'openwrt_' in x['pattern']]
                p.verify_payloads(files,controls,artifact)
                chosen=next(name for name in files if name.endswith('.apk'))
                missing=dict(files);missing.pop(chosen)
                wrong=dict(files);wrong[chosen.removesuffix('.apk')+'-wrong.apk']=wrong.pop(chosen)
                old=dict(files);old[chosen.replace(p.VERSION,'1.15.0-polaris-alpha.11')]=old.pop(chosen)
                for invalid in [missing,wrong,old]:
                    with self.subTest(role=role,artifact=artifact),self.assertRaises(ValueError):p.verify_payloads(invalid,controls,artifact)
            self.assertEqual((ipk_count,apk_count),(32,32))

    def test_scope_rejects_literal_versions_unknown_tokens_and_bad_counts(self):
        raw=json.loads(p.SCOPE.read_text())
        for kind in ['literal','token','duplicate','count']:
            value=copy.deepcopy(raw);rule=value['all']['payloadRules']['binary-windows-client-x64'][0]
            if kind=='literal':rule['pattern']=rule['pattern'].replace('{version}',re.escape(p.VERSION))
            elif kind=='token':rule['pattern']=rule['pattern'].replace('{version}','{release_version}')
            elif kind=='duplicate':rule['pattern']+='{version}'
            else:rule['count']=True
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'scope.json';path.write_text(json.dumps(value))
                with self.subTest(kind=kind),mock.patch.object(p,'SCOPE',path),self.assertRaises(ValueError):p.release_scope(p.VERSION)

    def test_docker_keeps_exact_products_and_rejects_missing_extra_or_diagnostic_assets(self):
        scope=p.release_scope(p.VERSION);required=scope['docker']['requiredArtifacts']
        self.assertEqual(len(required),20)
        p.verify_artifact_names(list(required),required,'docker')
        for names in [required[:-1],required+['unexpected'],required+['repository~random.dockerbuild'],
                      required[:-1]+['repository~random.dockerbuild'],required+[required[0]]]:
            with self.subTest(names=names),self.assertRaises(ValueError):p.verify_artifact_names(names,required,'docker')

    def test_producer_receipt_uses_current_source_contract_and_rejects_old_or_tag_version(self):
        release=json.loads(p.CONFIG.read_text());source='a'*40
        env={'PUBLISHER_ROLE':'docker','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REPOSITORY':p.REPO,
             'GITHUB_REPOSITORY_ID':str(p.RID),'RELEASE_BUILD':'All','RELEASE_VERSION':p.VERSION,
             'GITHUB_SHA':source,'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':'1',
             'PUBLISH_STORES':'false','PUBLISH_REGISTRY':'false'}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'release/ci').mkdir(parents=True)
            (root/'release/ci/github-release.json').write_text(json.dumps(release))
            script=p.ROOT/'scripts/ci/publisher_run_receipt.py'
            with chdir(root),mock.patch.dict(os.environ,env),mock.patch('subprocess.check_output',return_value=source):
                runpy.run_path(str(script),run_name='__main__')
                receipt=json.loads((root/'publisher-run-receipt.json').read_text())
                self.assertEqual((receipt['version'],receipt['sourceCommit'],receipt['role']),(p.VERSION,source,'docker'))
                for version in ['1.15.0-polaris-alpha.11',p.VERSION+'0','v'+p.VERSION]:
                    with mock.patch.dict(os.environ,RELEASE_VERSION=version),self.assertRaises(AssertionError):
                        runpy.run_path(str(script),run_name='__main__')

    def test_path_traversal(self):
        for name in ['../bad','/bad','x/../../bad','C:/bad','x\\bad']:
            with self.assertRaises(ValueError):p.portable(name)

    def test_duplicate_zip(self):
        with tempfile.TemporaryDirectory() as d:
            z=Path(d)/'a.zip'
            with zipfile.ZipFile(z,'w') as f:
                f.writestr('A.txt','a');f.writestr('a.txt','b')
            with self.assertRaises(ValueError):p.extract(z,Path(d)/'out')

    def test_full_payload(self):
        rules=[{'pattern':'one','count':1},{'pattern':'two','count':1}]
        p.verify_payloads({'one':{},'two':{}},rules,'test')
        for files in [{'one':{}},{'one':{},'two':{},'extra':{}}]:
            with self.assertRaises(ValueError):p.verify_payloads(files,rules,'test')

    def test_library_mapping(self):
        self.assertEqual(p.default_name('all','libbox-android-arm64','arm64/libbox.aar'),f'libbox-{p.VERSION}-android-arm64.aar')
        self.assertEqual(p.default_name('docker','oci-linux-arm64','image.tar'),f'sing-box-{p.VERSION}-oci-linux-arm64.tar')
        self.assertIsNone(p.default_name('signed','binary-darwin_arm64','x.tar.gz'))

    def fixture(self, root):
        work=root/'work';work.mkdir()
        art=work/'all'/'a';art.mkdir(parents=True)
        name='sing-box-'+p.VERSION+'-linux-amd64.tar.gz';(art/name).write_bytes(b'actual bytes')
        f={'bytes':12,'sha256':p.sha(art/name),'releaseName':name}
        run={'id':'42','attempt':1,'artifacts':{'a':{'id':3,'archiveSha256':'a'*64,'files':{name:f}}}}
        actual={'repository':p.REPO,'repositoryId':p.RID,'version':p.VERSION,'sourceCommit':'a'*40,'scopeSha256':'b'*64,'sourceTree':'b'*40,'tag':p.TAG,'tagObject':'c'*40,'runs':{'all':run},'reviewed':False}
        config=json.loads(json.dumps(actual));config['reviewed']=True
        return work,actual,config,name

    def test_actual_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);work,actual,cfg,name=self.fixture(root)
            receipt=p.assemble(actual,cfg,work,root/'out')
            self.assertEqual(receipt['assets'][0]['sha256'],p.sha(root/'out'/name))
            self.assertFalse(receipt['fullSignedRelease'])

    def test_collision_and_omission(self):
        for failure in ['collision','omission','hash','unreviewed']:
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as d:
                root=Path(d);work,actual,cfg,name=self.fixture(root)
                if failure=='collision':
                    for obj in [actual,cfg]:obj['runs']['all']['artifacts']['b']=obj['runs']['all']['artifacts']['a']
                elif failure=='omission':cfg['runs']['all']['artifacts']['a']['files'][name]['releaseName']=None
                elif failure=='hash':cfg['runs']['all']['artifacts']['a']['files'][name]['sha256']='0'*64
                else:cfg['reviewed']=False
                with self.assertRaises(ValueError):p.assemble(actual,cfg,work,root/'out')


    def test_complete_upload_url(self):
        release={'id':12,'upload_url':f'https://uploads.github.com/repos/{p.REPO}/releases/12/assets{{?name,label}}'}
        self.assertEqual(p.upload_endpoint(release,'asset +.zip'),f'https://uploads.github.com/repos/{p.REPO}/releases/12/assets?name=asset%20%2B.zip')
        for endpoint in [f'https://api.uploads.github.com/repos/{p.REPO}/releases/12/assets',
                         f'https://uploads.github.com.evil.example/repos/{p.REPO}/releases/12/assets',
                         f'http://uploads.github.com/repos/{p.REPO}/releases/12/assets',
                         f'https://uploads.github.com/repos/other/repo/releases/12/assets',
                         f'https://uploads.github.com/repos/{p.REPO}/releases/13/assets',
                         f'https://uploads.github.com/repos/{p.REPO}/releases/12/assets?other=1',
                         f'https://uploads.github.com/repos/{p.REPO}/releases/12/assets#fragment']:
            with self.subTest(endpoint=endpoint),self.assertRaises(ValueError):
                p.upload_endpoint(dict(release,upload_url=endpoint),'asset.zip')

    def final_index(self):
        from native_release_index import expected_native
        expected=expected_native(p.VERSION);source='a'*40;tree='b'*40;rows=[]
        for ident,v in expected.items():
            rows.append({'schema':'polaris-upstream-native-receipt-v1','id':ident,'target':v['target'],'variant':v['variant'],
                         'version':p.VERSION,'tag':p.TAG,'sourceCommit':source,'sourceTree':tree,'goVersion':'go1.27.2',
                         'tags':'fixture','buildID':'','rawBuildInfo':'private test fixture',
                         'buildGraph':{'settings':{},'normalModules':[],'prebuiltAcquisitionModules':[],'localReplacements':[]},
                         'sourceIdentity':{'sourceOverlay':0,'goModSha256':'0'*64,'goSumSha256':'1'*64,'replacements':[]},
                         'archive':{'name':ident+('.zip' if v['target'].startswith('windows/') else '.tar.gz'),
                                    'bytes':1,'sha256':'2'*64,'root':ident,'members':{ident+'/sing-box':'3'*64}},
                         'core':{'member':'sing-box','bytes':1,'sha256':'3'*64},'sidecar':None,
                         'signatureObservation':None,'finalPackageCronetSmoke':None})
        index = {'schema':'polaris-upstream-native-assets-v1','repository':p.REPO,'repositoryId':p.RID,'version':p.VERSION,
                'tag':p.TAG,'tagObject':'c'*40,'sourceCommit':source,'sourceTree':tree,
                'producer':{'repository':p.REPO,'repositoryId':p.RID,'workflow':'.github/workflows/build.yml',
                            'workflowCommit':source,'runId':42,'runAttempt':1,
                            'nativeJobs':{k:{'id':i+1,'name':'private test fixture'} for i,k in enumerate(['linux','win','mac-x64','mac-arm64'])}},
                'legalFiles':[{'path':'licenses/LICENSE','content':'x','bytes':1,'sha256':'4'*64}],
                'sourceArchive':{'name':'sing-box-polaris-source-'+source+'.tar.gz','bytes':1,'sha256':'5'*64},'platforms':rows}
        from native_release_index import distribution_materials
        index['distributionMaterials'] = distribution_materials(index, p.ROOT)
        return index

    def check_index(self,index):
        p.validate_final_index(index,'a'*40,'b'*40,'c'*40,'42',1,'.github/workflows/build.yml')

    def test_final_index_and_staging_wrong_tag_schema_mixed_source_controls(self):
        index=self.final_index();self.check_index(index)
        for kind in ['staging','wrong-object','wrong-tag','malformed-schema','mixed-source','mixed-tree','missing-row','source-name']:
            x=copy.deepcopy(index)
            if kind=='staging':x.update(schema='polaris-upstream-native-staging-v1',tagObject=None)
            elif kind=='wrong-object':x['tagObject']='d'*40
            elif kind=='wrong-tag':x['tag']='v1.15.0-polaris-alpha.999'
            elif kind=='malformed-schema':x['producer']['runId']='42'
            elif kind=='mixed-source':x['platforms'][-1]['sourceCommit']='d'*40
            elif kind=='mixed-tree':x['platforms'][-1]['sourceTree']='d'*40
            elif kind=='missing-row':x['platforms'].pop()
            else:x['sourceArchive']['name']='other.tar.gz'
            with self.subTest(kind=kind),self.assertRaises((ValueError,jsonschema.ValidationError)):self.check_index(x)

    def test_index_and_source_basename_cannot_be_changed(self):
        for basename in ['polaris-upstream-native-assets.json','sing-box-polaris-source-'+'a'*40+'.tar.gz']:
            with self.subTest(basename=basename),tempfile.TemporaryDirectory() as d:
                root=Path(d);work,actual,cfg,name=self.fixture(root);data=b'private fixture'
                (work/'all'/'a'/basename).write_bytes(data)
                f={'bytes':len(data),'sha256':p.sha(work/'all'/'a'/basename),'releaseName':basename}
                actual['runs']['all']['artifacts']['a']['files'][basename]=dict(f)
                cfg['runs']['all']['artifacts']['a']['files'][basename]=dict(f,releaseName=p.VERSION+'-renamed-'+basename)
                with self.assertRaises(ValueError):p.assemble(actual,cfg,work,root/'out')


class DistributionMaterialsTests(unittest.TestCase):
    final_index = GateTests.final_index
    check_index = GateTests.check_index
    def test_current_scope_materials_tampering_fails(self):
        index=self.final_index()
        for field,value in [('sourceCommit','d'*40),('modules',{}),('legalFiles',{})]:
            candidate=copy.deepcopy(index)
            if field=='modules':candidate['distributionMaterials'][field]={'injected':{}}
            else:candidate['distributionMaterials'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.check_index(candidate)

    def test_remote_replacement_uses_actual_source_and_go_escape(self):
        from native_release_index import distribution_materials
        index=self.final_index()
        index['platforms'][0]['buildGraph']['localReplacements']=[{
            'module':'old/module','version':'v1.0.0','h1':'',
            'replacement':{'module':'github.com/SomeOwner/fork','version':'v2.0.0','h1':'h1:test'}}]
        material=distribution_materials(index,p.ROOT)
        record=next(iter(material['modules'].values()))
        self.assertEqual(record['sourceURL'],'https://proxy.golang.org/github.com/!some!owner/fork/@v/v2.0.0.zip')
        self.assertEqual(record['replaces']['module'],'old/module')
        self.assertFalse(record['availabilityVerified'])
        self.assertFalse(material['publicationEligible'])
        self.assertTrue(material['unmappedMaterialIdentities'])
        with mock.patch('native_release_index.validate_distribution_assessment', return_value=True):
            self.assertFalse(distribution_materials(index,p.ROOT)['publicationEligible'])

    def test_shared_materials_associate_every_public_file_and_keep_metadata_private(self):
        index=self.final_index()
        result={'sourceCommit':index['sourceCommit'],'sourceTree':index['sourceTree'],
                'runs':{'all':{'artifacts':{'test':{'files':{
                    'binary':{'releaseName':'binary'},'metadata':{'releaseName':None}}}}}}}
        p.associate_distribution_materials(result,index,'9'*64)
        files=result['runs']['all']['artifacts']['test']['files']
        self.assertEqual(files['binary']['distributionMaterials'],result['distributionMaterials'])
        self.assertNotIn('distributionMaterials',files['metadata'])
        wrong=copy.deepcopy(index);wrong['sourceCommit']='d'*40
        self.assertRaises(ValueError,p.associate_distribution_materials,result,wrong,'9'*64)

    def test_assessment_requires_explicit_valid_empty_open_items(self):
        from native_release_index import validate_distribution_assessment
        valid={'schema':1,'status':'reviewed-current-scope','openItems':[]}
        self.assertTrue(validate_distribution_assessment(valid))
        for value in [None,False,'',{},0]:
            with self.subTest(value=value),self.assertRaises(ValueError):
                validate_distribution_assessment(dict(valid,openItems=value))
        del valid['openItems']
        self.assertRaises(ValueError,validate_distribution_assessment,valid)
        self.assertRaises(ValueError,validate_distribution_assessment,{'schema':1,'status':'anything','openItems':[]})
        self.assertFalse(validate_distribution_assessment({'schema':1,'status':'current-scope-review-required','openItems':[]}))

if __name__=='__main__':
    unittest.main()
