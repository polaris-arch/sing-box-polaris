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
 def lint_rules(self):
  config=yaml.safe_load((ROOT/'.golangci.yml').read_text())
  for name in ['staticcheck','unused','modernize']:self.assertIn(name,config['linters']['enable'])
  checks=config['linters']['settings']['staticcheck']['checks']
  self.assertIn('all',checks)
  for code in ['-SA1019','-ST1008']:self.assertNotIn(code,checks)
  rules=config['linters']['exclusions']['rules'];self.assertEqual(len(rules),2)
  by_code={code:[r for r in rules if r['text'].startswith('^'+code+':')] for code in ['SA1019','ST1008']}
  for matches in by_code.values():self.assertEqual(len(matches),1)
  return {code:matches[0] for code,matches in by_code.items()}
 def rule_matches(self,rule,linter,path,text,source=''):
  return (linter in rule['linters'] and re.search(rule['path'],path) is not None
          and re.search(rule['text'],text) is not None
          and ('source' not in rule or re.search(rule['source'],source) is not None))
 def test_http2_compatibility_exclusion_is_exactly_scoped(self):
  rule=self.lint_rules()['SA1019'];self.assertEqual(set(rule),{'linters','path','text'})
  self.assertEqual(rule['linters'],['staticcheck'])
  allowed={
   'common/httpclient/http2_config.go','common/httpclient/http2_fallback_transport.go',
   'common/httpclient/http2_transport.go','common/tls/reality_client.go',
   'dns/transport/https_transport.go',
   'transport/http/client.go','transport/http/client_h2_wrap.go',
   'transport/http/server.go','transport/http/server_h2.go',
   'transport/v2raygrpclite/client.go','transport/v2raygrpclite/server.go',
   'transport/v2rayhttp/client.go','transport/v2rayhttp/force_close.go',
   'transport/v2rayhttp/force_close_go127.go','transport/v2rayhttp/server.go'}
  self.assertEqual(len(allowed),15)
  path=re.compile(rule['path']);text=re.compile(rule['text'])
  matched={p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*.go') if path.search(p.relative_to(ROOT).as_posix())}
  self.assertEqual(matched,allowed)
  message='SA1019: (*golang.org/x/net/http2.Transport).RoundTrip is deprecated'
  for name in allowed:self.assertTrue(self.rule_matches(rule,'staticcheck',name,message))
  for negative in ['SA4006: this value is never used','SA1019: unrelated.API is deprecated',
                   'ST1008: error should be returned as the last argument',
                   'SA1019: golang.org/x/net/http2evil.API is deprecated']:
   self.assertIsNone(text.search(negative))
  for negative in ['box.go','unrelated.go','other/transport/http/client.go',
                   'transport/http/new_path.go','dns/transport/https_transport_extra.go',
                   'transport/v2raygrpclite/server_extra.go']:
   self.assertIsNone(path.search(negative))
  self.assertFalse(self.rule_matches(rule,'unused','transport/http/client.go',message))
 def test_public_compatibility_result_order_exclusion_requires_all_four_fields(self):
  rule=self.lint_rules()['ST1008'];self.assertEqual(set(rule),{'linters','path','text','source'})
  self.assertEqual(rule['linters'],['staticcheck'])
  signature='func NewWithConstructionReport(options Options) (instance *Box, err error, report ConstructionReport) {'
  actual=next(s for s in (ROOT/'box.go').read_text().splitlines() if s.startswith('func NewWithConstructionReport('))
  self.assertEqual(actual,signature)
  message='ST1008: error should be returned as the last argument'
  self.assertTrue(self.rule_matches(rule,'staticcheck','box.go',message,signature))
  for linter in ['unused','modernize']:
   self.assertFalse(self.rule_matches(rule,linter,'box.go',message,signature))
  for name in ['other.go','sub/box.go','box.go.backup']:
   self.assertFalse(self.rule_matches(rule,'staticcheck',name,message,signature))
  for text in ['SA4006: this value is never used','ST1008: another message',message+' extra']:
   self.assertFalse(self.rule_matches(rule,'staticcheck','box.go',text,signature))
  for source in [signature.replace('NewWithConstructionReport','New'),
                 signature.replace('options Options','other Options'),
                 signature.replace('instance *Box','instance Box'),
                 signature.replace('err error, report ConstructionReport','report ConstructionReport, err error'),
                 'return instance, err, report',signature+' // another line']:
   self.assertFalse(self.rule_matches(rule,'staticcheck','box.go',message,source))
 def test_lint_collects_uncapped_diagnostics_and_retains_failure_status(self):
  lint=yaml.safe_load((ROOT/'.github/workflows/lint.yml').read_text())
  job=lint['jobs']['build']
  action=next(s for s in job['steps'] if s.get('uses','').startswith('golangci/golangci-lint-action@'))
  self.assertEqual(action['with']['version'],'v2.15.0')
  self.assertEqual(action['with']['args'],'--timeout=30m --max-same-issues=0 --max-issues-per-linter=0')
  self.assertFalse(job.get('continue-on-error',False));self.assertFalse(action.get('continue-on-error',False))
 def test_patch_queue_selection_and_each_owned_module_remain_wired(self):
  w=yaml.safe_load((ROOT/'.github/workflows/polaris-selfcheck.yml').read_text())
  steps=w['jobs']['patch_tests']['steps']
  command=next(s['run'] for s in steps if s.get('name')=='Test packages changed by the queue')
  self.assertIn("python3 -B -m unittest discover -s scripts/ci -p 'test_patch_test_packages.py'",command)
  self.assertIn('scripts/ci/patch_test_packages.py --base "$BASE_COMMIT"',command)
  self.assertIn('mapfile -t packages < "$selection_dir/root-packages.txt"',command)
  self.assertIn('"${packages[@]}" | tee test.log',command)
  self.assertNotIn("| xargs -r -n1 dirname",command)
  for marker in ['sing-tun-selected','metacubex-utls-selected']:
   self.assertIn('"$selection_dir/'+marker+'"',command)
  self.assertIn("grep -qx 'module github.com/sagernet/sing-tun' third_party/sing-tun/go.mod",command)
  self.assertIn("grep -qx 'module github.com/metacubex/utls' third_party/metacubex-utls/go.mod",command)
  self.assertIn('cd third_party/metacubex-utls && go test -race -count=1 -tags "$tags" ./...',command)
  self.assertIn('"^($INSTANCE_TESTS)\\$"',command)
  self.assertIn('"^($SING_TUN_INSTANCE_TESTS)\\$"',command)
  self.assertIn("-run '^TestPing$/^(ipv4|ipv6)$/^unprivileged$' ./ping",command)
  instance=next(s for s in steps if s.get('name')=='Test instances in process')
  self.assertEqual(instance['if'],'${{ inputs.run_instance_tests }}')
  self.assertIn('"^($INSTANCE_TESTS)\\$"',instance['run'])
if __name__=='__main__':unittest.main()
