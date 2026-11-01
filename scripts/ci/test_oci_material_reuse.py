import copy, hashlib, io, json, tarfile, tempfile, unittest
from pathlib import Path
import github_release as g

class OCIMaterialReuseTests(unittest.TestCase):
    def fixture(self, root, mutation=None):
        source='a'*40; platform={'os':'linux','architecture':'amd64'}
        package={'P':'fixture','V':'1','A':'x86_64','L':'MIT','o':'fixture','c':'b'*40,'C':'Q1fixture'}
        base=[{'uri':'pkg:docker/alpine@latest?platform=linux%2Famd64','digest':{'sha256':'c'*64}}]
        directory=root/'release/dependency-sources/oci';directory.mkdir(parents=True)
        materials=directory/'oci-source-notice-map.json';materials.write_text('{}\n')
        reference={'schema':1,'materialMapSHA256':g.sha(materials),'artifacts':{'oci-linux-amd64':{'platform':platform,'baseDependencies':base,'repositories':'https://dl-cdn.alpinelinux.org/alpine/v3.24/main\n','packages':[package]}}}
        (directory/'reuse-reference.json').write_text(json.dumps(reference))
        def tar(entries):
            output=io.BytesIO()
            with tarfile.open(fileobj=output,mode='w') as archive:
                for name,value,kind in entries:
                    member=tarfile.TarInfo(name);member.type=kind
                    if kind==tarfile.REGTYPE:member.size=len(value);archive.addfile(member,io.BytesIO(value))
                    else:member.linkname='elsewhere';archive.addfile(member)
            return output.getvalue()
        actual=dict(package)
        if mutation=='package':actual['V']='2'
        if mutation and mutation.startswith('package-'):actual[mutation.removeprefix('package-')]='unreviewed'
        entries=[('lib/apk/db/installed',('\n'.join(k+':'+v for k,v in actual.items())+'\n\n').encode(),tarfile.REGTYPE),('etc/apk/repositories',reference['artifacts']['oci-linux-amd64']['repositories'].encode(),tarfile.REGTYPE),('usr/local/bin/sing-box',b'fixture core bytes',tarfile.REGTYPE)]
        if mutation=='repositories':entries[1]=(entries[1][0],b'changed\n',tarfile.REGTYPE)
        if mutation=='whiteout':entries.append(('lib/apk/db/.wh.installed',b'',tarfile.REGTYPE))
        if mutation=='opaque':entries.append(('lib/.wh..wh..opq',b'',tarfile.REGTYPE))
        if mutation=='symlink':entries[0]=(entries[0][0],b'',tarfile.SYMTYPE)
        if mutation=='shadow':entries.append(('lib',b'',tarfile.SYMTYPE))
        if mutation=='root_symlink':entries.append(('.',b'',tarfile.SYMTYPE))
        if mutation=='alias_duplicate':entries.append(('lib//apk/./db/installed',b'alias',tarfile.REGTYPE))
        blobs={}
        def blob(value,media):
            raw=json.dumps(value,sort_keys=True).encode() if isinstance(value,dict) else value
            digest=hashlib.sha256(raw).hexdigest();blobs['blobs/sha256/'+digest]=raw
            return {'mediaType':media,'digest':'sha256:'+digest,'size':len(raw)}
        config=dict(platform,config={'Labels':{'org.opencontainers.image.revision':source,'org.opencontainers.image.source':'https://github.com/'+g.REPO}})
        if mutation=='platform':config['architecture']='arm64'
        if mutation=='source':config['config']['Labels']['org.opencontainers.image.revision']='d'*40
        cfg=blob(config,'application/vnd.oci.image.config.v1+json')
        if mutation=='size':cfg['size']+=1
        layer=blob(tar(entries),'application/vnd.oci.image.layer.v1.tar')
        if mutation=='media':layer['mediaType']='application/unknown'
        if mutation=='compression':layer['mediaType']+='+'+'gzip'
        layers = [layer]
        if mutation == 'earlier_layer':
            base_package = dict(package, V='old-base-version')
            base_entries = [('lib/apk/db/installed', ('\n'.join(k+':'+v for k,v in base_package.items())+'\n\n').encode(), tarfile.REGTYPE)]
            layers.insert(0, blob(tar(base_entries), 'application/vnd.oci.image.layer.v1.tar'))
        manifest=blob({'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json','config':cfg,'layers':layers},'application/vnd.oci.image.manifest.v1+json')
        manifest['platform']=platform
        actual_base=base if mutation!='base' else []
        predicate={'buildDefinition':{'buildType':'https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md','resolvedDependencies':actual_base,'externalParameters':{'configSource':{'path':'Dockerfile.binary'}}},'runDetails':{'builder':{'id':f'https://github.com/{g.REPO}/actions/runs/123/attempts/'+('2' if mutation=='attempt' else '1')},'metadata':{'buildkit_metadata':{'vcs':{'revision':source,'source':'https://github.com/'+g.REPO}}}}}
        statement={'_type':'https://in-toto.io/Statement/v1','subject':[],'predicateType':'https://slsa.dev/provenance/v1','predicate':predicate}
        if mutation=='statement_subject_missing':statement.pop('subject')
        if mutation=='statement_subject_wrong':statement['subject']=[{'name':'wrong','digest':{'sha256':'e'*64}}]
        if mutation=='statement_subject_ambiguous':statement['subject']=[{},{}]
        att=blob(statement,'application/vnd.in-toto+json')
        subject={key:manifest[key]for key in ('mediaType','digest','size')}
        if mutation=='artifact_subject_wrong':subject['digest']='sha256:'+'e'*64
        attestation=blob({'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json','artifactType':'application/vnd.docker.attestation.manifest.v1+json','subject':subject,'config':blob({},'application/vnd.oci.empty.v1+json'),'layers':[att,att] if mutation=='duplicate_provenance' else [att]},'application/vnd.oci.image.manifest.v1+json')
        attestation.update(platform={'architecture':'unknown','os':'unknown'},annotations={'vnd.docker.reference.type':'attestation-manifest','vnd.docker.reference.digest':manifest['digest'] if mutation!='attestation_target' else 'sha256:'+'e'*64})
        index={'schemaVersion':2,'mediaType':'application/vnd.oci.image.index.v1+json','manifests':[manifest,attestation]+([manifest] if mutation=='duplicate_image' else [])}
        if mutation=='hash':blobs[layer['digest'].replace('sha256:','blobs/sha256/')]+=b'bad'
        outer=[('oci-layout',b'{"imageLayoutVersion":"1.0.0"}',tarfile.REGTYPE),('index.json',json.dumps(index).encode(),tarfile.REGTYPE)]+[(k,v,tarfile.REGTYPE)for k,v in blobs.items()]
        if mutation=='alternate_manifest':outer.append(('manifest.json',b'[]',tarfile.REGTYPE))
        if mutation=='duplicate_member':outer.append(outer[0])
        if mutation=='outer_alias':outer.append(('././oci-layout',outer[0][1],tarfile.REGTYPE))
        path=root/'image.tar';path.write_bytes(tar(outer));return path,source
    def check(self, mutation=None):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path,source=self.fixture(root,mutation)
            return g.validate_oci_material_reuse(path,'oci-linux-amd64',source,'123',1,root)
    def test_valid_identity_reuse_measures_new_core(self):
        result=self.check();self.assertTrue(result['sourceMaterialsReusable']);self.assertEqual(result['packageCount'],1)
        self.assertEqual(result['coreSHA256'],hashlib.sha256(b'fixture core bytes').hexdigest());self.assertFalse(result['legalConclusion'])
    def test_final_installed_database_overrides_base_layer(self):
        single = self.check()
        layered = self.check('earlier_layer')
        self.assertEqual(single['installedSHA256'], layered['installedSHA256'])
        self.assertEqual(layered['packageCount'], 1)
        self.assertEqual(single['coreSHA256'], layered['coreSHA256'])
    def test_rejects_blob_graph_and_provenance_drift(self):
        for mutation in ['hash','size','media','platform','source','base','attempt','attestation_target','duplicate_provenance','duplicate_image','duplicate_member','outer_alias','compression','alternate_manifest','statement_subject_missing','statement_subject_wrong','statement_subject_ambiguous','artifact_subject_wrong']:
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.check(mutation)
    def test_rejects_deleted_or_shadowed_material_evidence(self):
        for mutation in ['whiteout','opaque','symlink','shadow','root_symlink','alias_duplicate']:
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.check(mutation)
    def test_rejects_package_and_repository_drift(self):
        for mutation in ['package','repositories']:
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.check(mutation)
    def test_resolved_reference_keeps_actual_graph_and_all_seven_package_fields_strict(self):
        for mutation in [None] + ['package-' + field for field in ('P', 'V', 'A', 'L', 'o', 'c', 'C')] + ['base', 'repositories', 'attempt', 'hash']:
            with tempfile.TemporaryDirectory() as tmp, self.subTest(mutation=mutation):
                root=Path(tmp);path,source=self.fixture(root,mutation)
                reference=json.loads((root/'release/dependency-sources/oci/reuse-reference.json').read_text())
                if mutation is None:
                    result=g.validate_oci_material_reuse(path,'oci-linux-amd64',source,'123',1,root,
                                                       resolved_reference=reference)
                    self.assertEqual(result['packageCount'],1)
                else:
                    with self.assertRaises(ValueError):
                        g.validate_oci_material_reuse(path,'oci-linux-amd64',source,'123',1,root,
                                                      resolved_reference=reference)
    def test_reviewed_receipt_cannot_change_derived_material_evidence(self):
        for field in ('ociMaterialReuse','androidRuntimeMaterials','androidMaterialReuse'):
            actual={key:'fixture' for key in ('repository','repositoryId','version','sourceCommit','sourceTree','tag','tagObject','scopeSha256')}
            record={'bytes':1,'sha256':'a'*64,'releaseName':'fixture-'+g.VERSION+'.tar',field:{'measured':True}}
            actual['runs']={'docker':{'id':'123','attempt':1,'artifacts':{'oci-linux-amd64':{'id':7,'archiveSha256':'b'*64,'files':{'image.tar':record}}}}}
            review=copy.deepcopy(actual);review['reviewed']=True
            review['runs']['docker']['artifacts']['oci-linux-amd64']['files']['image.tar'][field]={'tampered':True}
            with tempfile.TemporaryDirectory() as tmp,self.subTest(field=field),self.assertRaisesRegex(ValueError,'reviewed .* evidence differs'):
                g.assemble(actual,review,Path(tmp),Path(tmp)/'out')
if __name__=='__main__':unittest.main()
