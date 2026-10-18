import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import polaris_dns_identity as dns


class DNSIdentityTests(unittest.TestCase):
    def setUp(self):
        root=Path(__file__).resolve().parents[1]
        self.manifest=json.loads((root/'release/polaris-dns-candidate-inputs.json').read_text())
        self.fp={'schema':'fork-source-fingerprint-v1','sourceCommit':dns.SOURCE,'sourceTree':dns.TREE,
            'sourceOverlay':0,'goVersion':'go1.25.5','goModSha256':self.manifest['sourceFileSha256']['go.mod'],
            'goSumSha256':self.manifest['sourceFileSha256']['go.sum'],
            'replacement':dict(self.manifest['replacementBinding'],bindingSha256=self.manifest['sourceFileSha256']['release/dependency-sources/sing-tun-replacement.json']),
            'replacementFilesVerified':256,'isolatedGoSettings':{'GOENV':'off','GOWORK':'off','GOFLAGS':'','GOTOOLCHAIN':'local'}}
        self.identity=dns.source_identity(self.fp,self.manifest)

    def test_common_identity_excludes_observed_machine_and_absolute_paths(self):
        for machine in ['linux','windows','darwin']:
            fp=dict(self.fp,goExecutableSha256=machine,moduleListSha256=machine,scope=machine)
            self.assertEqual(dns.source_identity(fp,self.manifest),self.identity)

    def test_every_contract_drift_is_rejected(self):
        for key,value in [('sourceCommit','a01'),('sourceTree','wrong'),('sourceOverlay',1),('goVersion','go1.27.1'),('goModSha256','wrong'),('goSumSha256','wrong'),('replacementFilesVerified',255),('isolatedGoSettings',{}),('replacement',{})]:
            with self.subTest(key=key),self.assertRaises(ValueError):
                dns.source_identity(dict(self.fp,**{key:value}),self.manifest)
        for key in ['replacementTree','patchSha256','baselineModuleSum','bindingSha256']:
            fp=copy.deepcopy(self.fp);fp['replacement'][key]='wrong'
            with self.subTest(binding=key),self.assertRaises(ValueError):dns.source_identity(fp,self.manifest)

    def test_only_actual_four_consumers_and_distinct_buildids(self):
        platforms=[dns.platform_identity(self.identity,self.manifest,*t,'with_gvisor,with_quic') for t in dns.TARGETS]
        self.assertEqual(len({p['buildID'] for p in platforms}),4)
        for os_name,arch in [('windows','arm64'),('linux','arm64'),('linux','386'),('android','arm64')]:
            with self.assertRaises(ValueError):dns.platform_identity(self.identity,self.manifest,os_name,arch,'with_gvisor')

    def sample(self,platform):
        b=self.manifest['replacementBinding']
        return 'actual-core: go1.25.5\n\tpath\tgithub.com/sagernet/sing-box/cmd/sing-box\n\tmod\tgithub.com/sagernet/sing-box\t'+dns.ROOT_MODULE_VERSIONS[0]+'\t\n'+f'\tdep\t{b["module"]}\t{b["version"]}\n\t=>\t{b["replacementPath"]}\t(devel)\t\n'+''.join('\tbuild\t'+k+'='+v+'\n' for k,v in {'vcs':'git','vcs.time':dns.SOURCE_TIME,'vcs.revision':dns.SOURCE,'vcs.modified':'false','GOOS':platform['os'],'GOARCH':platform['arch'],'CGO_ENABLED':platform['CGO_ENABLED'],'-tags':','.join(platform['tags']),'-trimpath':'true','-buildmode':'exe','-compiler':'gc'}.items())

    def test_real_modinfo_shape_and_all_four_parameter_policies(self):
        for target in dns.TARGETS:
            p=dns.platform_identity(self.identity,self.manifest,*target,'with_gvisor,with_quic')
            for root_version in dns.ROOT_MODULE_VERSIONS:
                actual=self.sample(p).replace(dns.ROOT_MODULE_VERSIONS[0],root_version)
                result=dns.validate_build_info(actual,self.manifest,p,p['buildID'],'sing-box version '+self.manifest['candidateVersion']+'\n')
                self.assertTrue(result['validatedAgainstActualBinary'])

    def test_old_core_missing_wrong_extra_replace_and_parameter_drift_reject(self):
        p=dns.platform_identity(self.identity,self.manifest,'linux','amd64','with_gvisor,with_quic')
        text=self.sample(p);b=self.manifest['replacementBinding']
        mutants=[text.replace(dns.ROOT_MODULE_VERSIONS[0],'(devel)'),text.replace('20261010200656','20261010200655'),text.replace(dns.SOURCE_TIME,'2026-10-10T20:06:55Z'),text.replace('vcs=git','vcs=hg'),text.replace(dns.SOURCE,'a01'),text.replace('go1.25.5','go1.27.1'),text.replace('vcs.modified=false','vcs.modified=true'),text.replace('GOOS=linux','GOOS=windows'),text.replace('CGO_ENABLED=0','CGO_ENABLED=1'),text.replace('with_gvisor,with_quic','with_quic'),text.replace(b['version'],'v0.9.6'),text.replace(b['replacementPath'],'./other'),text.replace('\t=>\t'+b['replacementPath']+'\t(devel)\t\n',''),text+'\tdep\tother\tv1.0.0\n\t=>\t./other\t(devel)\n',text+'\tbuild\tvcs.modified=false\n']
        for index,t in enumerate(mutants):
            with self.subTest(index=index),self.assertRaises(ValueError):dns.validate_build_info(t,self.manifest,p,p['buildID'],'sing-box version '+self.manifest['candidateVersion'])
        for buildid,version in [('old',self.manifest['candidateVersion']),(p['buildID'],'old')]:
            with self.assertRaises(ValueError):dns.validate_build_info(text,self.manifest,p,buildid,'sing-box version '+version)

    def test_source_head_tree_dirty_and_ignored_stop_before_file_access(self):
        for values in [['wrong'],[dns.SOURCE,'wrong'],[dns.SOURCE,dns.TREE,'dirty'],[dns.SOURCE,dns.TREE,'','ignored.go']]:
            with patch.object(dns.subprocess,'check_output',side_effect=values):
                with self.assertRaises(ValueError):dns.check_source(Path('/not-read'),self.manifest)


if __name__=='__main__':unittest.main()
