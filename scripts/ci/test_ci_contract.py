from pathlib import Path
import json,re,unittest,yaml
ROOT=Path(__file__).resolve().parents[2]
class TestCIContract(unittest.TestCase):
 def test_complete_upstream_matrices(self):
  baseline=json.loads((ROOT/'release/ci/upstream-matrices.json').read_text())['matrices']
  for filename,up in [('build.yml','build.yml'),('signed-release.yml','build.yml'),('linux.yml','linux.yml'),('signed-linux.yml','linux.yml'),('docker.yml','docker.yml'),('publish-container.yml','docker.yml')]:
   w=yaml.safe_load((ROOT/'.github/workflows'/filename).read_text())
   self.assertEqual(set(w['on']),{'workflow_dispatch'},filename)
   for job,matrix in baseline[up].items():self.assertEqual(w['jobs'][job]['strategy']['matrix'],matrix,(filename,job))
 def test_every_workflow_has_actions_trigger(self):
  for p in (ROOT/'.github/workflows').glob('*.yml'):
   # BaseLoader prevents YAML 1.1 silently accepting the invalid boolean true key as on.
   w=yaml.load(p.read_text(),Loader=yaml.BaseLoader)
   self.assertIn('on',w,p.name);self.assertNotIn('true',w,p.name)
 def test_complete_signed_release_waits_for_store_exports(self):
  w=yaml.safe_load((ROOT/'.github/workflows/signed-release.yml').read_text())
  self.assertIn('build_apple_app_store',w['jobs']['upload']['needs'])
  self.assertTrue(any(s.get('with',{}).get('pattern')=='signed-apple-store-*' for s in w['jobs']['upload']['steps']))
 def test_registry_serializes_immutable_versions(self):
  w=yaml.safe_load((ROOT/'.github/workflows/publish-container.yml').read_text())
  self.assertFalse(w['concurrency']['cancel-in-progress'])
  self.assertIn('inputs.tag',w['concurrency']['group'])
  for name in ['merge','build_docker']:self.assertEqual(w['jobs'][name]['permissions']['packages'],'write')
 def test_unsigned_no_distribution(self):
  forbidden=['ghr --replace','app_store_connect','--upload-app','publish_testflight','push.fury.io','docker/login-action','push=true','notarytool','secrets.GPG_','secrets.ASC_','secrets.APPLE_','secrets.WINDOWS_','secrets.LOCAL_PROPERTIES']
  for name in ['build.yml','linux.yml','docker.yml']:
   text=(ROOT/'.github/workflows'/name).read_text()
   for item in forbidden:self.assertNotIn(item,text,(name,item))
 def test_owned_distribution_destinations(self):
  for name in ['signed-release.yml','signed-linux.yml','publish-container.yml']:
   text=(ROOT/'.github/workflows'/name).read_text()
   for item in ['ghcr.io/sagernet/sing-box','push.fury.io/sagernet','ghr --replace']:self.assertNotIn(item,text)
   self.assertIn('POLARIS_DISTRIBUTION_ENABLED',text)
 def test_source_identity_is_not_renamed_module(self):
  text=(ROOT/'.github/workflows/build.yml').read_text()
  self.assertIn('github.com/sagernet/sing-box/constant.Version',text)
  self.assertNotIn('github.com/polaris-arch/sing-box-polaris/constant.Version',text)
 def test_final_evidence_mode_is_declared_and_bound_before_builds(self):
  for filename in ['build.yml','signed-release.yml']:
   w=yaml.safe_load((ROOT/'.github/workflows'/filename).read_text())
   self.assertEqual(w['on']['workflow_dispatch']['inputs']['evidence_mode']['options'],['final','staging'])
   pre=w['jobs']['calculate_version'];self.assertIn('tag_object',pre['outputs'])
   self.assertTrue(any(x.get('id')=='release_source' and x.get('if')=="inputs.evidence_mode == 'final'" for x in pre['steps']))
   assembly=next(x for x in w['jobs']['native_index']['steps'] if 'REQUIRE_RELEASE_TAG' in x.get('env',{}))
   self.assertIn('inputs.evidence_mode',assembly['env']['REQUIRE_RELEASE_TAG'])
   self.assertIn('needs.calculate_version.outputs.tag_object',assembly['env']['EXPECTED_RELEASE_TAG_OBJECT'])
  signed=yaml.safe_load((ROOT/'.github/workflows/signed-release.yml').read_text())
  self.assertIn("inputs.evidence_mode == 'final'",signed['jobs']['upload']['if'])
  self.assertTrue(any(s.get('if')=='inputs.publish_github' and s.get('run')=='test \"$EVIDENCE_MODE\" = final' for s in signed['jobs']['calculate_version']['steps']))
  self.assertNotIn('inputs.publish_github',(ROOT/'.github/workflows/build.yml').read_text())
 def test_docker_actual_builds_bind_dispatch_and_recheck_before_upload(self):
  w=yaml.safe_load((ROOT/'.github/workflows/docker.yml').read_text())
  self.assertIn('source',w['jobs'])
  for name in ['build_binary','build_docker']:
   job=w['jobs'][name];self.assertIn('source',job['needs'])
   checkout=next(x for x in job['steps'] if x.get('uses','').startswith('actions/checkout@'))
   self.assertEqual(checkout['with']['ref'],'${{ github.sha }}')
   checks=[x for x in job['steps'] if 'scripts/ci/release_identity.py' in x.get('run','')]
   self.assertEqual(len(checks),2)
   for step in checks:self.assertEqual(step['env']['EXPECTED_TAG_OBJECT'],'${{ needs.source.outputs.tag_object }}')
 def test_exact_release_defaults_and_docker_diagnostic_upload_control(self):
  release=json.loads((ROOT/'release/ci/github-release.json').read_text())
  for name in ['build.yml','linux.yml','signed-release.yml','signed-linux.yml']:
   w=yaml.safe_load((ROOT/'.github/workflows'/name).read_text())
   self.assertEqual(w['on']['workflow_dispatch']['inputs']['version']['default'],release['version'],name)
  for name in ['docker.yml','publish-container.yml']:
   w=yaml.safe_load((ROOT/'.github/workflows'/name).read_text())
   self.assertEqual(w['on']['workflow_dispatch']['inputs']['tag']['default'],release['tag'],name)
  w=yaml.safe_load((ROOT/'.github/workflows/publish-github.yml').read_text())
  self.assertEqual(w['concurrency']['group'],'polaris-github-release-'+release['tag'])
  w=yaml.safe_load((ROOT/'.github/workflows/docker.yml').read_text())
  step=next(s for s in w['jobs']['build_docker']['steps'] if s.get('uses','').startswith('docker/build-push-action@'))
  self.assertEqual(step['env']['DOCKER_BUILD_RECORD_UPLOAD'],'false')
  self.assertFalse(step['with']['push']);self.assertIn('type=oci,dest=',step['with']['outputs'])
 def test_existing_build_entry_can_run_pretag_source_gates_without_products(self):
  w=yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text())
  self.assertIn('Source',w['on']['workflow_dispatch']['inputs']['build']['options'])
  self.assertEqual(w['jobs']['source_gate']['if'],"inputs.build == 'Source'")
  self.assertEqual(w['jobs']['calculate_version']['if'],"inputs.build != 'Source'")
  gate=w['jobs']['source_gate'];self.assertEqual(gate['strategy']['matrix']['os'],['ubuntu-24.04','macos-15'])
  self.assertTrue(any('unittest discover' in x.get('run','') for x in gate['steps']))
  self.assertTrue(any(x.get('run')=='python3 scripts/ci/g4_candidate.py' for x in gate['steps']))
  self.assertEqual(w['permissions']['contents'],'read')
 def test_go_utls_gate_is_part_of_one_existing_source_dispatch(self):
  w=yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text())
  gate=w['jobs']['utls_gate']
  self.assertEqual(gate['if'],"inputs.build == 'Source'")
  self.assertEqual(gate['strategy']['matrix']['os'],['ubuntu-24.04','windows-2025','macos-15'])
  self.assertFalse(gate['strategy']['fail-fast'])
  self.assertTrue(any(s.get('with',{}).get('go-version-file')=='release/GO_VERSION' for s in gate['steps']))
  self.assertTrue(any('utls_gate.py' in s.get('run','') for s in gate['steps']))
  cost=next(s for s in gate['steps'] if 'utls_cost.py' in s.get('run',''))
  self.assertEqual(cost['if'],"always() && matrix.os == 'ubuntu-24.04'")
 def test_new_capability_and_mobile_checks_use_original_product_jobs(self):
  for name in ['build.yml','signed-release.yml']:
   w=yaml.safe_load((ROOT/'.github/workflows'/name).read_text())
   for job,mode in [('build_android_library','android'),('build_apple_library','apple')]:
    self.assertTrue(any('mobile_fingerprint_exports.py '+mode in s.get('run','') for s in w['jobs'][job]['steps']))
   self.assertTrue(any('jsonschema==4.23.0' in s.get('run','') for s in w['jobs']['native_smoke']['steps']))
  text=(ROOT/'scripts/ci/native_release_index.py').read_text()
  self.assertIn('expected_sha=row[',text)
  self.assertIn('expected_modules=modules',text)
 def test_lint_compatibility_exclusion_is_exactly_scoped(self):
  config=yaml.safe_load((ROOT/'.golangci.yml').read_text())
  self.assertIn('staticcheck',config['linters']['enable'])
  self.assertIn('unused',config['linters']['enable'])
  self.assertIn('modernize',config['linters']['enable'])
  checks=config['linters']['settings']['staticcheck']['checks']
  self.assertIn('all',checks);self.assertNotIn('-SA1019',checks)
  rules=config['linters']['exclusions']['rules'];self.assertEqual(len(rules),1)
  rule=rules[0];self.assertEqual(rule['linters'],['staticcheck'])
  allowed={
   'common/httpclient/http2_config.go','common/httpclient/http2_fallback_transport.go',
   'common/httpclient/http2_transport.go','common/tls/reality_client.go',
   'transport/http/client.go','transport/http/client_h2_wrap.go',
   'transport/http/server.go','transport/http/server_h2.go',
   'transport/v2raygrpclite/client.go','transport/v2rayhttp/client.go',
   'transport/v2rayhttp/force_close.go','transport/v2rayhttp/force_close_go127.go',
   'transport/v2rayhttp/server.go'}
  path=re.compile(rule['path']);text=re.compile(rule['text'])
  matched={p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*.go') if path.search(p.relative_to(ROOT).as_posix())}
  self.assertEqual(matched,allowed)
  self.assertIsNotNone(text.search('SA1019: (*golang.org/x/net/http2.Transport).RoundTrip is deprecated'))
  for negative in ['SA4006: this value is never used','SA1019: unrelated.API is deprecated',
                   'ST1008: error result order','SA1019: golang.org/x/net/http2evil.API is deprecated']:
   self.assertIsNone(text.search(negative))
  for negative in ['unrelated.go','other/transport/http/client.go','transport/http/new_path.go']:
   self.assertIsNone(path.search(negative))
  lint=yaml.safe_load((ROOT/'.github/workflows/lint.yml').read_text())
  action=next(s for s in lint['jobs']['build']['steps'] if s.get('uses','').startswith('golangci/golangci-lint-action@'))
  self.assertEqual(action['with']['version'],'v2.15.0')
if __name__=='__main__':unittest.main()
