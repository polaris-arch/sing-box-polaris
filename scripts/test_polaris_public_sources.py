import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import polaris_public_sources as sources
import polaris_production_release as production

REPO=Path(__file__).resolve().parents[1]
class PublicSourceTests(unittest.TestCase):
    def graph(self):
        template=json.loads((REPO/sources.INPUTS).read_bytes());normal=next(r for r in template['modules'] if r['role']=='source-module')
        acquisition=next(r for r in template['modules'] if '_musl' in r['module'])
        return {'normalModules':[{k:normal[k] for k in ['module','version','h1']}],
            'prebuiltAcquisitionModules':[{k:acquisition[k] for k in ['module','version','h1']}],
            'localReplacement':{'module':'github.com/sagernet/sing-tun','version':'frozen','h1':''}}
    def test_exact_actual_union_and_modified_replacement_have_public_sources(self):
        value=sources.delivery(REPO,production.plan(REPO),'a'*40,'b'*40,[self.graph()])
        self.assertEqual(len(value['modules']),2)
        self.assertEqual(value['normalSourceModuleCount'],1)
        self.assertEqual(value['prebuiltAcquisitionModuleCount'],1)
        self.assertEqual(value['productSource']['commit'],'a'*40)
        self.assertEqual(value['productSource']['sourceOwnedReplacement']['replacementFileCount'],256)
        self.assertNotIn('sourceAsset',value)
        self.assertEqual(value['openwrtToolchainCorrespondingSources']['openwrt']['commit'],'0b795ce79e23b553aa184080c390f9ce92a2b6d4')
    def test_unknown_module_or_mixed_replacement_blocks_source_assembly(self):
        for mutation in ['module','replacement']:
            graph=self.graph();other=copy.deepcopy(graph)
            if mutation=='module':other['normalModules'][0]['h1']='h1:unknown'
            else:other['localReplacement']['version']='different'
            with self.assertRaises(ValueError):sources.delivery(REPO,production.plan(REPO),'a'*40,'b'*40,[graph,other])
    def test_bad_public_size_or_digest_preserves_failure_input(self):
        import io
        with tempfile.TemporaryDirectory() as d:
            for expected in [{'bytes':1,'sha256':'a'*64},{'bytes':3,'sha256':'b'*64}]:
                path=Path(d)/str(expected['bytes'])
                with patch.object(sources.urllib.request,'urlopen',return_value=io.BytesIO(b'abc')),self.assertRaises(ValueError):
                    sources.fetch({'url':'https://example.invalid/pinned-source',**expected},path)
                self.assertTrue(path.exists())

class ExportRestorationRegressionTests(unittest.TestCase):
    def case(self):
        raw=b'<project>\nLF source\n</project>\n';archive=raw.replace(b'\n',b'\r\n');name='src/fullbench.vcproj'
        pin={'path':name,'gitBlob':sources.git_blob(raw),'bytes':len(raw),'sha256':sources.hashlib.sha256(raw).hexdigest()}
        return raw,archive,name,pin
    def test_existing_crlf_export_is_restored_before_git_blob_check(self):
        raw,archive,name,pin=self.case();result,record=sources.resolve_exported_blob({'commit':'be1be963131154ba82761a7ed85ba426b2027319'},name,archive,pin['gitBlob'],pin,lambda _: (raw,{'bytes':len(raw),'sha256':pin['sha256']}))
        self.assertEqual(result,raw);self.assertEqual(record['archiveBytes'],len(archive));self.assertNotEqual(record['archiveGitBlob'],pin['gitBlob'])
    def test_unlisted_export_wrong_git_blob_or_raw_pin_is_rejected(self):
        raw,archive,name,pin=self.case()
        for mutated in [None,{**pin,'gitBlob':'0'*40},{**pin,'sha256':'0'*64}]:
            with self.subTest(pin=mutated),self.assertRaises(ValueError):
                sources.resolve_exported_blob({'commit':'be1be963131154ba82761a7ed85ba426b2027319'},name,archive,pin['gitBlob'],mutated,lambda _: (raw,{}))
    def test_exact_export_is_not_mutated(self):
        raw,archive,name,pin=self.case();result,record=sources.resolve_exported_blob({'commit':'be1be963131154ba82761a7ed85ba426b2027319'},name,raw,pin['gitBlob'],pin,lambda _:self.fail('no replacement needed'))
        self.assertEqual(result,raw);self.assertIsNone(record)

if __name__=='__main__':unittest.main()
