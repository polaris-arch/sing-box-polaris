from pathlib import Path
import json,re,unittest,yaml
import contextlib,copy,io,os,shlex,shutil,subprocess,sys,tempfile,urllib.error
from unittest import mock
ROOT=Path(__file__).resolve().parents[2]
class TestCIContract(unittest.TestCase):
 def test_signed_all_receipt_has_satisfiable_fail_closed_dependencies(self):
  w=yaml.safe_load((ROOT/'.github/workflows/signed-release.yml').read_text())
  jobs=w['jobs'];receipt=jobs['publisher_receipt']
  expected={'calculate_version','build','build_windows7','build_darwin','build_windows',
            'build_android_library','build_android','build_windows_client','build_linux_client',
            'build_apple_library','build_apple','build_apple_app_store','native_smoke','native_index'}
  self.assertEqual(set(receipt['needs']),expected)
  self.assertEqual(receipt['if'],"success() && inputs.build == 'All'")
  self.assertIn("inputs.build == 'publish-android'",jobs['publish_android']['if'])
  scope=json.loads((ROOT/'release/ci/publisher-upstream-scope.json').read_text())['signed']
  self.assertNotIn('publish_android',scope['requiredJobs'])
  self.assertEqual(set(scope['requiredJobs']),expected|{'prepare_windows7','upload'})
  self.assertIn('publisher-run-receipt',scope['requiredArtifacts'])
  # Evaluate only this exact conjunction against inert terminal job outcomes.
  # An optional store-only job may be skipped; every actual All producer must succeed.
  def admitted(build,outcomes):
   return build=='All' and all(outcomes[name]=='success' for name in receipt['needs'])
  outcomes={name:'success' for name in expected};outcomes['publish_android']='skipped'
  self.assertTrue(admitted('All',outcomes))
  self.assertFalse(admitted('publish-android',outcomes))
  for name in expected:
   for result in ('failure','skipped','cancelled'):
    with self.subTest(job=name,result=result):
     self.assertFalse(admitted('All',dict(outcomes,**{name:result})))
 def test_signed_apple_identity_skips_inactive_matrix_rows(self):
  w=yaml.safe_load((ROOT/'.github/workflows/signed-release.yml').read_text())
  for job_name in ('build_apple','build_apple_app_store'):
   job=w['jobs'][job_name]
   identity=[s for s in job['steps'] if s.get('name')=='Apply reviewed owned client identity']
   self.assertEqual(len(identity),1)
   self.assertEqual(identity[0].get('if'),'matrix.if')
   self.assertIn('verify-apple',identity[0]['run'])
   self.assertIn('apply apple',identity[0]['run'])
   checkout=next(s for s in job['steps'] if s.get('name')=='Checkout')
   self.assertEqual(checkout['if'],identity[0]['if'])
   for active in (False,True):
    with self.subTest(job=job_name,matrix_if=active):
     # Inert evaluation of the exact single-variable condition; no source or signing runs.
     step_admitted={'matrix.if':active}[identity[0]['if']]
     self.assertEqual(step_admitted,active)
   # Each partial selector leaves another row inactive; all rows stay available for All.
   for row in job['strategy']['matrix']['include']:
    self.assertIn('inputs.build',row['if'])
    self.assertIn("inputs.build == 'All'",row['if'])
 def test_native_package_signing_secret_inputs_remain_literal_environment_data(self):
  for filename,condition in [('signed-linux.yml',"matrix.debian != '' || matrix.rpm != ''"),
                             ('signed-release.yml',"fromJSON(toJSON(matrix)).debian != '' || fromJSON(toJSON(matrix)).rpm != ''")]:
   w=yaml.safe_load((ROOT/'.github/workflows'/filename).read_text())
   steps=w['jobs']['build']['steps'];by_name={s.get('name'):s for s in steps}
   setup=by_name['Setup package signing'];body=setup['run']
   self.assertLess(steps.index(setup),steps.index(by_name['Package DEB']))
   self.assertLess(steps.index(setup),steps.index(by_name['Package RPM']))
   self.assertEqual(setup['if'],condition)
   self.assertEqual(setup['env'],{name:'${{ secrets.'+name+' }}' for name in ('GPG_KEY','GPG_KEY_ID','GPG_PASSPHRASE')})
   self.assertIn('umask 077',body)
   self.assertIn('mkdir -m 700 "$SIGNING_GNUPG_HOME"',body)
   self.assertIn('chmod 600 "$SIGNING_PASSPHRASE_FILE"',body)
   self.assertIn("printf '%s' \"$GPG_PASSPHRASE\" > \"$SIGNING_PASSPHRASE_FILE\"",body)
   self.assertIn("printf '%s' \"$GPG_KEY\" | gpg",body)
   self.assertIn('--passphrase-file "$SIGNING_PASSPHRASE_FILE"',body)
   self.assertNotIn('set -x',body);self.assertNotIn('set -ex',body);self.assertNotIn('set -xe',body)
   for step in steps:
    self.assertNotRegex(step.get('run',''),r'\$\{\{\s*secrets\.GPG_')
   deb=by_name['Package DEB'];rpm=by_name['Package RPM']
   self.assertIn('-k "$GPG_KEY_ID"',deb['run'])
   self.assertIn('--passphrase-file $SIGNING_PASSPHRASE_FILE',deb['run'])
   self.assertEqual(deb['env']['GPG_KEY_ID'],'${{ secrets.GPG_KEY_ID }}')
   self.assertIn("echo '%_rpmformat 4' >> \"$HOME/.rpmmacros\"",rpm['run'])
   self.assertNotIn(' > "$HOME/.rpmmacros"',rpm['run'])
   self.assertNotIn('gpg --',rpm['run'])
   # Inert runner-binding model: values populate env only; no shell or GPG executes.
   for literal in ["single'quote",'double"quote','$HOME','$(printf synthetic)', '`printf synthetic`', 'space and \\ slash']:
    with self.subTest(literal=literal):
     bound=copy.deepcopy(setup)
     bound['env']={name:literal for name in setup['env']}
     self.assertEqual(bound['run'],body)
     self.assertEqual(bound['env']['GPG_PASSPHRASE'].encode('utf-8'),literal.encode('utf-8'))
 def test_complete_upstream_matrices(self):
  baseline=json.loads((ROOT/'release/ci/upstream-matrices.json').read_text())['matrices']
  for filename,up in [('build.yml','build.yml'),('signed-release.yml','build.yml'),('linux.yml','linux.yml'),('signed-linux.yml','linux.yml'),('docker.yml','docker.yml'),('publish-container.yml','docker.yml')]:
   w=yaml.safe_load((ROOT/'.github/workflows'/filename).read_text())
   self.assertEqual(set(w['on']),{'workflow_dispatch'},filename)
   for job,matrix in baseline[up].items():
    actual=copy.deepcopy(w['jobs'][job]['strategy']['matrix'])
    if job=='build' and filename in ('build.yml','signed-release.yml'):
     actual['include']+=w['jobs']['build_windows7']['strategy']['matrix']['include']
     self.assertCountEqual(actual['include'],matrix['include'],(filename,job))
    else:self.assertEqual(actual,matrix,(filename,job))
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
  self.assertTrue(any(s.get('if')=='inputs.publish_github || inputs.publish_stores' and s.get('run')=='test \"$EVIDENCE_MODE\" = final' for s in signed['jobs']['calculate_version']['steps']))
  self.assertNotIn('inputs.publish_github',(ROOT/'.github/workflows/build.yml').read_text())
 def test_staging_never_admits_store_publication(self):
  workflow=yaml.safe_load((ROOT/'.github/workflows/signed-release.yml').read_text())
  pre=workflow['jobs']['calculate_version']
  gate=next(step for step in pre['steps'] if step.get('name')=='Reject publication of staging evidence')
  self.assertEqual(gate['if'],'inputs.publish_github || inputs.publish_stores')
  self.assertEqual(gate['run'],'test "$EVIDENCE_MODE" = final')
  self.assertEqual(gate['env']['EVIDENCE_MODE'],'${{ inputs.evidence_mode }}')
  operations=('publishPlayReleaseBundle','--upload-app','publish_testflight')
  observed=[]
  for name,job in workflow['jobs'].items():
   for step in job.get('steps',[]):
    if any(operation in step.get('run','') for operation in operations):
     self.assertIn('calculate_version',job['needs'])
     condition=step.get('if','')
     self.assertTrue(condition.startswith("inputs.evidence_mode == 'final' && ("),(name,condition))
     self.assertIn('inputs.publish_stores',condition)
     observed.append((name,step['name']))
  self.assertEqual(len(observed),4)
  # Pure contract truth table. No shell, workflow execution, credentials or
  # remote operation is invoked by this fixture.
  for mode in ['staging','final']:
   for github in [False,True]:
    for stores in [False,True]:
     rejected=(github or stores) and mode!='final'
     writes=[]
     if not rejected and mode=='final' and stores:
      writes.extend(observed)
     if mode=='staging' or not stores:self.assertEqual(writes,[])
     else:self.assertEqual(writes,observed)
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
  self.assertEqual(w['jobs']['source_gate']['if'],"inputs.build == 'Source' && !inputs.source_generate_only")
  self.assertEqual(w['jobs']['calculate_version']['if'],"inputs.build != 'Source' && !inputs.source_generate_only")
  gate=w['jobs']['source_gate'];self.assertEqual(gate['strategy']['matrix']['os'],['ubuntu-24.04','macos-15'])
  self.assertTrue(any('unittest discover' in x.get('run','') for x in gate['steps']))
  self.assertTrue(any(x.get('run')=='python3 scripts/ci/g4_candidate.py' for x in gate['steps']))
  self.assertEqual(w['permissions']['contents'],'read')
 def test_runtime_protobuf_bootstrap_is_isolated_from_native_products(self):
  w=yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text())
  option=w['on']['workflow_dispatch']['inputs']['source_generate_only']
  self.assertEqual(option['type'],'boolean');self.assertIs(option['default'],False)
  bootstrap=w['jobs']['source_proto']
  self.assertEqual(bootstrap['if'],"inputs.build == 'Source' && inputs.source_generate_only")
  self.assertEqual(bootstrap['runs-on'],'ubuntu-24.04')
  self.assertEqual(bootstrap['env']['PYTHONDONTWRITEBYTECODE'],'1')
  for name,job in w['jobs'].items():
   if name!='source_proto':
    self.assertIn('!inputs.source_generate_only',job['if'],name)
  runs='\n'.join(step.get('run','') for step in bootstrap['steps'])
  self.assertIn('runtime_proto.py generate',runs)
  self.assertNotIn('make proto',runs);self.assertNotIn('go test',runs)
  artifact=next(step for step in bootstrap['steps'] if step.get('uses','').startswith('actions/upload-artifact@'))
  self.assertEqual(artifact['with']['path'].splitlines(),[
   '${{ runner.temp }}/runtime-protobuf/daemon/runtime_config.pb.go',
   '${{ runner.temp }}/runtime-protobuf/daemon/runtime_config_grpc.pb.go',
   '${{ runner.temp }}/runtime-protobuf/receipt.json'])
  self.assertEqual(artifact['with']['if-no-files-found'],'error')
  checks=[step for step in w['jobs']['source_gate']['steps'] if 'runtime_proto.py check' in step.get('run','')]
  self.assertEqual(len(checks),1);self.assertEqual(checks[0]['if'],"matrix.os == 'ubuntu-24.04'")
 def test_runtime_graph_fixtures_execute_in_existing_native_matrix(self):
  w=yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text())
  steps=w['jobs']['utls_gate']['steps']
  step=next(step for step in steps if step.get('name')=='Execute focused runtime coordinator and resource regressions natively')
  run=step['run']
  for fragment in ['go test -json -race','-count=1','./internal/runtimegraph','./daemon','./experimental/cachefile','./route','./dns/transport/...','./protocol/openconnect','./protocol/openvpn','./protocol/tailscale','with_purego','-X github.com/sagernet/sing-box/constant.SourceRevision=$GITHUB_SHA','test "$(git rev-parse HEAD)" = "$GITHUB_SHA"','required native runtime tests or package PASS missing']:
   self.assertIn(fragment,run)
  self.assertNotIn('-run ',run)
  self.assertIn(' . ',run.replace('\n',' '))
 def test_go_utls_gate_is_part_of_one_existing_source_dispatch(self):
  w=yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text())
  gate=w['jobs']['utls_gate']
  self.assertEqual(gate['if'],"inputs.build == 'Source' && !inputs.source_generate_only")
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
 def expected_lint_rules(self):
  # Keep each reviewed boundary explicit: five SA1019 rules have distinct
  # path/diagnostic identities, so the diagnostic code alone is not a key.
  return {
   'http2':{
    'linters':['staticcheck'],
    'path':r'^(common/httpclient/http2_(config|fallback_transport|transport)\.go|common/tls/reality_client\.go|dns/transport/https_transport\.go|transport/http/(client|client_h2_wrap|server|server_h2)\.go|transport/v2raygrpclite/(client|server)\.go|transport/v2rayhttp/(client|force_close|force_close_go127|server)\.go)$',
    'text':r'^SA1019:.*golang\.org/x/net/http2\.'},
   'tls-rand':{
    'linters':['staticcheck'],
    'path':r'^common/httpclient/runtime_quic_tls\.go$',
    'text':r'^SA1019: \(crypto/tls\.Config\)\.Rand has been deprecated since Go 1\.27 and an alternative has been available since Go 1\.26: this should be left nil in production\. Not all TLS configurations are guaranteed to use Rand\. Test code can use \[testing/cryptotest\.SetGlobalRandom\] instead\. $',
    'source':r'^\s*(?:if value := config\.Rand; value != nil \{|config\.Rand = runtimeQUICReader\{value, fence\})$'},
   'h2c-import':{
    'linters':['staticcheck'],
    'path':r'^protocol/naive/inbound_runtime_tcp\.go$',
    'text':r'^SA1019: golang\.org/x/net/http2/h2c is deprecated: This package is deprecated\. It is not maintained and should not be used\. $',
    'source':r'^\s*(?:"golang\.org/x/net/http2/h2c")$'},
   'h2c-handler':{
    'linters':['staticcheck'],
    'path':r'^protocol/naive/inbound_runtime_tcp\.go$',
    'text':r'^SA1019: golang\.org/x/net/http2/h2c\.NewHandler is deprecated: Set the \[http\.Server\] Protocols field to use unencrypted HTTP/2 instead\. $',
    'source':r'^\s*(?:Handler:     h2c\.NewHandler\(n, &http2\.Server\{\}\),)$'},
   'shadowsocks-metadata':{
    'linters':['staticcheck'],
    'path':r'^protocol/shadowsocks/inbound_runtime_packet\.go$',
    'text':r'^SA1019: github\.com/sagernet/sing/common/metadata\.Metadata is deprecated: wtf is this\? $',
    'source':r'^\s*(?:err = h\.service\.NewPacket\(ctx, &stubPacketConn\{h\.listener\.PacketWriter\(\)\}, buffer, M\.Metadata\{Source: source\}\))$'},
   'result-order':{
    'linters':['staticcheck'],
    'path':r'^box\.go$',
    'text':r'^ST1008: error should be returned as the last argument$',
    'source':r'^func NewWithConstructionReport\(options Options\) \(instance \*Box, err error, report ConstructionReport\) \{$'}}
 def lint_rules(self):
  config=yaml.safe_load((ROOT/'.golangci.yml').read_text())
  for name in ['staticcheck','unused','modernize']:self.assertIn(name,config['linters']['enable'])
  checks=config['linters']['settings']['staticcheck']['checks']
  self.assertIn('all',checks)
  for code in ['-SA1019','-ST1008']:self.assertNotIn(code,checks)
  rules=config['linters']['exclusions']['rules'];self.assertEqual(len(rules),6)
  expected=self.expected_lint_rules()
  self.assertCountEqual(rules,list(expected.values()))
  by_scope={(rule['path'],rule['text']):rule for rule in rules}
  self.assertEqual(len(by_scope),len(rules))
  return {name:by_scope[(rule['path'],rule['text'])] for name,rule in expected.items()}
 def rule_matches(self,rule,linter,path,text,source=''):
  # Go regexp's terminal $ means end of text, unlike Python's allowance for
  # a final newline. Keep this fixture faithful to the native filter.
  def search(pattern,value):
   return re.search(pattern[:-1]+r'\Z' if pattern.endswith('$') else pattern,value)
  return (linter in rule['linters'] and search(rule['path'],path) is not None
          and search(rule['text'],text) is not None
          and ('source' not in rule or search(rule['source'],source) is not None))
 def test_http2_compatibility_exclusion_is_exactly_scoped(self):
  rule=self.lint_rules()['http2'];self.assertEqual(set(rule),{'linters','path','text'})
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
  rule=self.lint_rules()['result-order'];self.assertEqual(set(rule),{'linters','path','text','source'})
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
 def test_reviewed_compatibility_exclusions_match_only_seven_exact_diagnostics(self):
  rules=self.lint_rules()
  fixtures=[
   ('tls-rand','common/httpclient/runtime_quic_tls.go',
    'SA1019: (crypto/tls.Config).Rand has been deprecated since Go 1.27 and an alternative has been available since Go 1.26: this should be left nil in production. Not all TLS configurations are guaranteed to use Rand. Test code can use [testing/cryptotest.SetGlobalRandom] instead.',
    ['if value := config.Rand; value != nil {','config.Rand = runtimeQUICReader{value, fence}']),
   ('h2c-import','protocol/naive/inbound_runtime_tcp.go',
    'SA1019: golang.org/x/net/http2/h2c is deprecated: This package is deprecated. It is not maintained and should not be used.',
    ['"golang.org/x/net/http2/h2c"']),
   ('h2c-handler','protocol/naive/inbound_runtime_tcp.go',
    'SA1019: golang.org/x/net/http2/h2c.NewHandler is deprecated: Set the [http.Server] Protocols field to use unencrypted HTTP/2 instead.',
    ['Handler:     h2c.NewHandler(n, &http2.Server{}),']),
   ('shadowsocks-metadata','protocol/shadowsocks/inbound_runtime_packet.go',
    'SA1019: github.com/sagernet/sing/common/metadata.Metadata is deprecated: wtf is this?',
    ['err = h.service.NewPacket(ctx, &stubPacketConn{h.listener.PacketWriter()}, buffer, M.Metadata{Source: source})']*3)]
  matched=[]
  for name,path,message,statements in fixtures:
   with self.subTest(rule=name):
    rule=rules[name]
    self.assertEqual(set(rule),{'linters','path','text','source'})
    # honnef.co/go/tools v0.8.2 folds CommentGroup.Text()'s final newline
    # into one ASCII space. golangci v2.15.0 matches issue.Text unchanged;
    # its text printer applies TrimSpace only after exclusion processing.
    rendered=message
    message+=' '
    self.assertEqual(message.strip(),rendered)
    actual=[line for line in (ROOT/path).read_text().splitlines() if re.search(rule['source'],line)]
    self.assertEqual([line.strip() for line in actual],statements)
    for source in actual:
     # Every approved diagnostic has exactly one matching rule, even when two
     # rules share a path or several diagnostics share a code and statement.
     self.assertEqual([key for key,value in rules.items()
                       if self.rule_matches(value,'staticcheck',path,message,source)],[name])
     matched.append((name,path,message,source))
     for linter in ['unused','modernize']:
      self.assertFalse(self.rule_matches(rule,linter,path,message,source))
     for other_path in ['other/'+path,path+'.backup',path.replace('.go','_test.go')]:
      self.assertFalse(self.rule_matches(rule,'staticcheck',other_path,message,source))
     for other_message in [message.replace('SA1019','SA4000'),'prefix '+message,
                           message+' extra','SA1019: unrelated.API is deprecated',
                           rendered,message+' ',message+'\n']:
      self.assertFalse(self.rule_matches(rule,'staticcheck',path,other_message,source))
     for other_source in ['',source+' // another statement','prefix '+source,'unrelated()']:
      self.assertFalse(self.rule_matches(rule,'staticcheck',path,message,other_source))
  self.assertEqual(len(matched),7)
  # The rejected server-only field must not inherit the client Rand exception.
  message='SA1019: (crypto/tls.Config).NameToCertificate has been deprecated since Go 1.14: NameToCertificate only allows associating a single certificate with a given name. Leave this field nil to let the library select the first compatible chain from Certificates.'
  self.assertFalse(any(self.rule_matches(rule,'staticcheck','common/httpclient/runtime_quic_tls.go',
                                       message,'if config.NameToCertificate != nil {') for rule in rules.values()))
 def test_lint_rule_inventory_rejects_missing_duplicate_or_widened_boundaries(self):
  original=yaml.safe_load((ROOT/'.golangci.yml').read_text())
  rules=original['linters']['exclusions']['rules']
  mutations=[]
  for index,rule in enumerate(rules):
   mutations.extend([(index,'remove',None),(index,'duplicate',None),
                     (index,'linters',['staticcheck','unused']),
                     (index,'path','.*'),(index,'text','^SA1019:')])
   if 'source' in rule:
    mutations.extend([(index,'source','.*'),(index,'remove-source',None)])
  for index,field,value in mutations:
   with self.subTest(rule=index,mutation=field):
    config=copy.deepcopy(original);changed=config['linters']['exclusions']['rules']
    if field=='remove':changed.pop(index)
    elif field=='duplicate':changed.append(copy.deepcopy(changed[index]))
    elif field=='remove-source':changed[index].pop('source')
    else:changed[index][field]=value
    with mock.patch.object(yaml,'safe_load',return_value=config),self.assertRaises(AssertionError):
     self.lint_rules()
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
  # The queue must retain every ordinary package and isolate the exact netns
  # package. Runtime contracts below check selection, flags and privilege scope.
  self.assertIn('"${ordinary_packages[@]}" | tee test.log',command)
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


class TestUpstreamReleaseTrack(unittest.TestCase):
    def run_track(self, branches, tag=None, version=None, tag_on_parent=False,
                  env_contents=None, refs_on_parent=False):
        """Exercise the real helper with local Git refs; no remote is configured."""
        bash = shutil.which('bash')
        git = shutil.which('git')
        if not bash or not git:
            self.skipTest('release track contract requires Bash and Git')
        with tempfile.TemporaryDirectory(prefix='polaris-track-contract-') as directory:
            root = Path(directory)
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith('GIT_') and key != 'VERSION'}
            env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_TERMINAL_PROMPT='0', GITHUB_ENV=str(root / 'github-env'))
            if version is not None:
                env['VERSION'] = version
            def local_git(*args):
                return subprocess.run([git, '-c', 'user.name=Track contract',
                                       '-c', 'user.email=track@example.invalid',
                                       '-c', 'core.hooksPath=' + str(root / 'no-hooks'),
                                       '-c', 'commit.gpgsign=false', *args],
                                      cwd=root, env=env, check=True,
                                      capture_output=True, text=True)
            local_git('init', '-q', '-b', 'fixture')
            local_git('commit', '-q', '--allow-empty', '-m', 'Track fixture')
            if tag:
                local_git('tag', tag)
            if tag_on_parent:
                local_git('commit', '-q', '--allow-empty', '-m', 'After tagged commit')
            for branch in branches:
                local_git('update-ref', 'refs/remotes/origin/' + branch, 'HEAD')
            if refs_on_parent:
                local_git('commit', '-q', '--allow-empty', '-m', 'Outside release branches')
            self.assertEqual(local_git('remote').stdout, '')
            target = root / 'github-env'
            if env_contents is not None:
                target.write_text(env_contents)
            result = subprocess.run([bash, str(ROOT / '.github/detect_track.sh')],
                                    cwd=root, env=env, capture_output=True, text=True)
            return result, target.read_text() if target.exists() else None

    def assert_track(self, branches, track, **kwargs):
        result, contents = self.run_track(branches, **kwargs)
        suffix = '' if track == 'stable' else '-' + track
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(contents, 'TRACK=' + track + '\nNAME=sing-box-polaris' + suffix +
                         '\nPACKAGE_NAME=sing-box' + suffix + '\nDOCKER_TAG=latest' + suffix + '\n')

    def test_stable_requires_exact_hyphenated_tag_to_be_beta(self):
        for tag in [None, 'v1.15.0', 'alpha']:
            with self.subTest(tag=tag):
                self.assert_track(['stable'], 'stable', tag=tag)
        for tag in ['v1.15.0-alpha.1', 'v1.15.0-polaris-alpha.12', 'v1.15.0-custom']:
            with self.subTest(tag=tag):
                self.assert_track(['stable'], 'beta', tag=tag)
        self.assert_track(['stable'], 'stable', tag='v1.15.0-alpha.1', tag_on_parent=True)

    def test_testing_and_polaris_main_alias_ignore_release_tag_kind(self):
        for branch in ['testing', 'polaris-main']:
            for tag in [None, 'v1.15.0', 'v1.15.0-alpha.1', 'v1.15.0-polaris-alpha.12', 'alpha']:
                with self.subTest(branch=branch, tag=tag):
                    self.assert_track([branch], 'testing', tag=tag)

    def test_oldstable_ignores_release_tag_kind(self):
        for tag in [None, 'v1.14.0', 'v1.14.0-alpha.1']:
            with self.subTest(tag=tag):
                self.assert_track(['oldstable'], 'oldstable', tag=tag)

    def test_containing_remote_refs_keep_upstream_priority(self):
        for branches in [['stable', 'testing'], ['stable', 'polaris-main'],
                         ['stable', 'testing', 'polaris-main', 'oldstable']]:
            for tag, track in [(None, 'stable'), ('v1.15.0-alpha.1', 'beta')]:
                with self.subTest(branches=branches, tag=tag):
                    self.assert_track(branches, track, tag=tag)
        for branches in [['testing', 'oldstable'], ['polaris-main', 'oldstable'],
                         ['testing', 'polaris-main', 'oldstable']]:
            with self.subTest(branches=branches):
                self.assert_track(branches, 'testing', tag='v1.15.0-alpha.1')

    def test_unknown_branch_rejects_without_writing_github_env(self):
        for branches in [[], ['feature'], ['main'], ['polaris-main-extra'],
                         ['polaris-main2'], ['polaris-main/feature'], ['other-polaris-main']]:
            for contents in [None, 'PREEXISTING=keep\n']:
                with self.subTest(branches=branches, existing=contents):
                    result, actual = self.run_track(branches, tag='v1.15.0-alpha.1',
                                                    env_contents=contents)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('not on any known release branch', result.stderr)
                    self.assertEqual(actual, contents)
        result, contents = self.run_track(['polaris-main'], refs_on_parent=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(contents)

    def test_version_environment_never_selects_track(self):
        for version in ['1.15.0', '1.15.0-polaris-alpha.12', 'testing', 'oldstable', 'beta']:
            for branches, tag, track in [(['stable'], None, 'stable'),
                                         (['stable'], 'v1.15.0-alpha.1', 'beta'),
                                         (['polaris-main'], 'v1.15.0', 'testing'),
                                         (['oldstable'], 'v1.15.0-alpha.1', 'oldstable')]:
                with self.subTest(version=version, branches=branches, tag=tag):
                    self.assert_track(branches, track, tag=tag, version=version)

    def test_three_release_workflows_use_only_shared_track_helper(self):
        for filename, job_name in [('linux.yml', 'build'), ('signed-linux.yml', 'build'),
                                   ('publish-container.yml', 'merge')]:
            workflow = yaml.safe_load((ROOT / '.github/workflows' / filename).read_text())
            calls = [(name, step) for name, job in workflow['jobs'].items()
                     for step in job['steps'] if '.github/detect_track.sh' in step.get('run', '')]
            with self.subTest(workflow=filename):
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0][0], job_name)
                self.assertEqual(calls[0][1]['run'].strip(), 'bash .github/detect_track.sh')
                self.assertEqual(calls[0][1]['name'], 'Detect track')
                for job in workflow['jobs'].values():
                    for step in job['steps']:
                        self.assertNotRegex(step.get('run', ''), r'(?<![A-Z_])(TRACK|NAME|PACKAGE_NAME|DOCKER_TAG)=')
                checkout = next(step for step in workflow['jobs'][job_name]['steps']
                                if step.get('uses', '').startswith('actions/checkout@'))
                self.assertEqual(checkout['with']['fetch-depth'], 0)

    def test_linux_package_identity_is_separate_from_asset_name(self):
        for filename in ['linux.yml', 'signed-linux.yml']:
            workflow = yaml.safe_load((ROOT / '.github/workflows' / filename).read_text())
            steps = workflow['jobs']['build']['steps']
            packages = [step for step in steps if step['name'] in ['Package DEB', 'Package RPM']]
            with self.subTest(workflow=filename):
                self.assertEqual(len(packages), 2)
                for step in packages:
                    script = step['run']
                    self.assertEqual(script.count('--name "${PACKAGE_NAME}"'), 1)
                    self.assertNotIn('--name "${NAME}"', script)
                    self.assertIn('-p "dist/${NAME}_', script)
                    self.assertIn('dist/sing-box=/usr/bin/sing-box', script)
                    self.assertIn('cp .fpm_systemd .fpm', script)

    def test_track_change_keeps_owned_distribution_opt_in_and_unsigned_docker(self):
        guard = "github.repository == 'polaris-arch/sing-box-polaris' && vars.POLARIS_DISTRIBUTION_ENABLED == 'true'"
        signed = yaml.safe_load((ROOT / '.github/workflows/signed-linux.yml').read_text())
        container = yaml.safe_load((ROOT / '.github/workflows/publish-container.yml').read_text())
        self.assertFalse(signed['on']['workflow_dispatch']['inputs']['publish_packages']['default'])
        self.assertFalse(container['on']['workflow_dispatch']['inputs']['publish_registry']['default'])
        for name, job in signed['jobs'].items():
            self.assertEqual(job['environment'], 'polaris-distribution')
            self.assertEqual(job['if'], guard + (' && inputs.publish_packages' if name == 'upload' else ''))
        for job in container['jobs'].values():
            self.assertEqual(job['environment'], 'polaris-distribution')
            self.assertEqual(job['if'], guard + ' && inputs.publish_registry')
        self.assertEqual(container['env']['REGISTRY_IMAGE'], 'ghcr.io/polaris-arch/sing-box-polaris')
        publish = next(step for step in signed['jobs']['upload']['steps'] if step.get('name') == 'Publish packages')
        self.assertEqual(publish['run'], 'python3 scripts/ci/owned_distribution.py publish-packages')
        self.assertEqual(publish['env']['FURY_TOKEN'], '${{ secrets.POLARIS_FURY_TOKEN }}')
        for job in container['jobs'].values():
            for step in job['steps']:
                if step.get('uses', '').startswith('docker/login-action@'):
                    self.assertEqual(step['with'], {'registry': 'ghcr.io',
                                     'username': '${{ github.repository_owner }}',
                                     'password': '${{ secrets.GITHUB_TOKEN }}'})
        unsigned = yaml.safe_load((ROOT / '.github/workflows/docker.yml').read_text())
        for job in unsigned['jobs'].values():
            for step in job['steps']:
                self.assertFalse(step.get('uses', '').startswith('docker/login-action@'))
                self.assertNotIn('push=true', step.get('with', {}).get('outputs', ''))
                if step.get('uses', '').startswith('docker/build-push-action@'):
                    self.assertIs(step['with']['push'], False)


class TestPatchQueueNetnsContract(unittest.TestCase):
    NETNS = 'github.com/sagernet/sing-box/common/netns'
    ORDINARY = ['github.com/sagernet/sing-box/adapter',
                'github.com/sagernet/sing-box/daemon']
    TAGS = 'with_fixture,with_other,with_purego'
    LDFLAGS = '-X fixture.Version=contract -s'

    @classmethod
    def setUpClass(cls):
        cls.workflow = ROOT / '.github/workflows/polaris-selfcheck.yml'
        cls.document = yaml.safe_load(cls.workflow.read_text())
        cls.steps = cls.document['jobs']['patch_tests']['steps']
        cls.step = next(s for s in cls.steps if s.get('name') == 'Test packages changed by the queue')
        cls.authorization = next(s for s in cls.steps if s.get('id') == 'netns_batch_authorization')

    def run_queue(self, selected=None, resolved=None, authorized='false', modules=(),
                  statuses=None, outputs=None):
        """Run the real post-selection shell with fake Go and a non-elevating sudo.

        No real Go, sudo, git, network, or product test is reachable through PATH.
        Only package-selection inputs are synthetic; the partition and all test
        commands are extracted unchanged from the workflow.
        """
        bash = shutil.which('bash')
        if os.name != 'posix' or not bash:
            self.skipTest('Linux patch gate shell requires Bash with mapfile')
        probe = subprocess.run([bash, '--noprofile', '--norc', '-c', 'type mapfile'],
                               capture_output=True, text=True)
        if probe.returncode:
            self.skipTest('Linux patch gate shell requires Bash with mapfile')
        command = self.step['run']
        body, runner = command.split("<<'POLARIS_COMMAND'\n", 1)[1].split('\nPOLARIS_COMMAND\n', 1)
        launch = shlex.split(runner)
        launch = launch[launch.index('--') + 1:]
        self.assertEqual(launch, ['$POLARIS_RUNNER_BASH', '--noprofile', '--norc', '-e', '-o', 'pipefail',
                                  '$RUNNER_TEMP/polaris-command-selfcheck-patch-tests-0.sh'])
        start = 'mapfile -t packages < "$selection_dir/root-packages.txt"'
        self.assertEqual(body.count(start), 1)
        body = body[body.index(start):]
        selected = ['./...'] if selected is None else selected
        resolved = self.ORDINARY + [self.NETNS] if resolved is None else resolved
        with tempfile.TemporaryDirectory(prefix='polaris-netns-contract-') as directory:
            root = Path(directory)
            bin_dir = root / 'bin'
            bin_dir.mkdir()
            selection = root / 'selection'
            selection.mkdir()
            (selection / 'root-packages.txt').write_text(''.join(p + '\n' for p in selected))
            for module in modules:
                (selection / (module + '-selected')).touch()
            for module, owner in [('sing-tun', 'sagernet/sing-tun'), ('metacubex-utls', 'metacubex/utls'), ('cronet-go', 'sagernet/cronet-go'), ('fswatch', 'sagernet/fswatch'), ('sing', 'sagernet/sing')]:
                path = root / 'third_party' / module
                path.mkdir(parents=True)
                (path / 'go.mod').write_text('module github.com/' + owner + '\n')
            (root / 'release').mkdir()
            (root / 'release/DEFAULT_BUILD_TAGS').write_text('with_fixture,with_other\n')
            (root / 'release/LDFLAGS').write_text(self.LDFLAGS + '\n')
            config = root / 'config.json'
            config.write_text(json.dumps({'resolved': resolved, 'statuses': statuses or {}, 'outputs': outputs or {}}))
            log = root / 'calls.jsonl'
            # The sudo fixture records the wrapper request without executing any
            # binary or changing privileges. It rejects sudo-go orchestration.
            stub = '''import json, os, shlex, subprocess, sys
from pathlib import Path
args = sys.argv[1:]
tool = Path(sys.argv[0]).name
config = json.loads(Path(os.environ['FIXTURE_CONFIG']).read_text())
cwd = Path.cwd().relative_to(Path(os.environ['FIXTURE_ROOT'])).as_posix()
with open(os.environ['FIXTURE_CALLS'], 'a') as stream:
    stream.write(json.dumps({'tool': tool, 'args': args, 'cwd': cwd}) + '\\n')
if tool == 'sudo':
    if args != ['-n', '--', 'fixture-netns.test']:
        raise SystemExit(96)
    group = 'netns'
elif args and args[0] == 'list':
    sys.stdout.write(''.join(package + '\\n' for package in config['resolved']))
    raise SystemExit(config['statuses'].get('list', 0))
elif args and args[0] == 'test':
    group = ('netns' if 'github.com/sagernet/sing-box/common/netns' in args
             else 'sing-tun-ping' if cwd == 'third_party/sing-tun' and './ping' in args
             else Path(cwd).name if cwd != '.' else 'ordinary')
    if '-exec' in args:
        if group != 'netns':
            raise SystemExit(95)
        wrapper = shlex.split(args[args.index('-exec') + 1])
        # Absolute or alternate executables can never escape the fixture.
        if wrapper != ['sudo', '-n', '--']:
            raise SystemExit(94)
        raise SystemExit(subprocess.run([os.environ['FIXTURE_SUDO'], '-n', '--', 'fixture-netns.test']).returncode)
else:
    raise SystemExit(93)
output = ('--- PASS: TestUnshareNamespace (0.00s)\\nok fixture/netns\\n'
          if group == 'netns' else '--- PASS: TestNaiveAdmissionSealsBeforeJoin (0.00s)\\n--- PASS: TestNaiveDialCreationBarrierAndTerminalOwnership (0.00s)\\nok fixture/cronet-go\\n'
          if group == 'cronet-go' else '--- PASS: TestFailedAddClosesUnpublishedWatcher (0.00s)\\n--- PASS: TestSuccessfulAddTransfersWithoutClosing (0.00s)\\n--- PASS: TestFailedAddPreservesCleanupFailure (0.00s)\\nok fixture/fswatch\\n'
          if group == 'fswatch' else '--- PASS: TestRuntimePacketContextRetainsBeforeLaunchAndJoinsTerminalTail (0.00s)\\n--- PASS: TestRuntimePacketContextFailureDoesNotPublishSession (0.00s)\\nok fixture/sing\\n'
          if group == 'sing' else 'ok fixture/' + group + '\\n')
sys.stdout.write(config['outputs'].get(group, output))
raise SystemExit(config['statuses'].get(group, 0))
'''
            for name in ['go', 'sudo']:
                path = bin_dir / name
                path.write_text('#!' + sys.executable + '\n' + stub)
                path.chmod(0o755)
            for name in ['cat', 'tee', 'grep']:
                executable = shutil.which(name)
                self.assertIsNotNone(executable, name)
                (bin_dir / name).symlink_to(executable)
            env = {'PATH': str(bin_dir), 'HOME': str(root), 'TMPDIR': str(root),
                   'LC_ALL': 'C', 'selection_dir': str(selection), 'BASE_REF': 'v1.2.3',
                   'INSTANCE_TESTS': 'TestInstanceOne|TestInstanceTwo',
                   'SING_TUN_INSTANCE_TESTS': 'TestTunOne|TestPing',
                   'NETNS_BATCH_ELEVATION': authorized, 'FIXTURE_CONFIG': str(config),
                   'FIXTURE_ROOT': str(root), 'FIXTURE_CALLS': str(log),
                   'FIXTURE_SUDO': str(bin_dir / 'sudo')}
            result = subprocess.run([bash] + launch[1:-1] + ['-c', body],
                                    cwd=root, env=env, capture_output=True, text=True, timeout=15)
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            return result, calls

    def test_cronet_selected_module_runs_fake_native_barriers_without_root_scope(self):
        result, calls = self.run_queue(selected=[], resolved=[], modules=['cronet-go'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [{'tool': 'go', 'cwd': 'third_party/cronet-go',
                                 'args': ['test', '-race', '-count=1', '-v', '-tags', 'with_purego', './...']}])
        for kwargs in [{'statuses': {'cronet-go': 29}},
                       {'outputs': {'cronet-go': 'ok fixture/no-tests\n'}}]:
            with self.subTest(kwargs=kwargs):
                result, calls = self.run_queue(selected=[], resolved=[], modules=['cronet-go'], **kwargs)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(calls), 1)

    def test_fswatch_selected_module_requires_cleanup_regressions(self):
        result, calls = self.run_queue(selected=[], resolved=[], modules=['fswatch'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [{'tool': 'go', 'cwd': 'third_party/fswatch',
                                 'args': ['test', '-race', '-count=1', '-v', './...']}])
        for kwargs in [{'statuses': {'fswatch': 29}},
                       {'outputs': {'fswatch': 'ok fixture/no-tests\n'}}]:
            with self.subTest(kwargs=kwargs):
                result, calls = self.run_queue(selected=[], resolved=[], modules=['fswatch'], **kwargs)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(calls), 1)

    def test_sing_selected_module_requires_owned_session_regressions(self):
        result, calls = self.run_queue(selected=[], resolved=[], modules=['sing'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [{'tool': 'go', 'cwd': 'third_party/sing',
                                 'args': ['test', '-race', '-count=1', '-v', './...']}])
        for kwargs in [{'statuses': {'sing': 29}},
                       {'outputs': {'sing': 'ok fixture/no-tests\n'}}]:
            with self.subTest(kwargs=kwargs):
                result, calls = self.run_queue(selected=[], resolved=[], modules=['sing'], **kwargs)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(calls), 1)

    def assert_root_test(self, call, packages, elevated=False):
        args = ['test', '-race', '-count=1']
        if packages == [self.NETNS]:
            args += ['-v']
        if elevated:
            args += ['-exec', 'sudo -n --']
        args += ['-skip', '^(TestInstanceOne|TestInstanceTwo)$', '-tags', self.TAGS,
                 '-ldflags', self.LDFLAGS] + packages
        self.assertEqual(call, {'tool': 'go', 'args': args, 'cwd': '.'})

    def test_authorization_output_is_the_only_elevation_input(self):
        self.assertEqual(self.authorization['shell'], 'python')
        self.assertEqual(self.step['env']['NETNS_BATCH_ELEVATION'],
                         '${{ steps.netns_batch_authorization.outputs.authorized }}')
        self.assertLess(self.steps.index(self.authorization), self.steps.index(self.step))
        for name, value in [('GH_TOKEN', '${{ github.token }}'), ('EVENT_NAME', '${{ github.event_name }}'),
                            ('EVENT_REF', '${{ github.ref }}'), ('EVENT_REPOSITORY', '${{ github.repository }}')]:
            self.assertEqual(self.authorization['env'][name], value)
        self.assertFalse(self.authorization.get('continue-on-error', False))
        self.assertFalse(self.step.get('continue-on-error', False))
        self.assertFalse(self.document['jobs']['patch_tests'].get('continue-on-error', False))
        instance = next(s['run'] for s in self.steps if s.get('name') == 'Test instances in process')
        executable_lines = '\n'.join(line for line in instance.splitlines() if not line.lstrip().startswith('#'))
        self.assertNotIn('sudo', executable_lines)
        self.assertNotIn('-exec', executable_lines)

    def test_wildcard_selection_runs_ordinary_group_then_only_netns_wrapper(self):
        result, calls = self.run_queue(authorized='true')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 4)
        self.assertEqual(calls[0], {'tool': 'go', 'args': ['list', '-tags', self.TAGS, './...'], 'cwd': '.'})
        self.assert_root_test(calls[1], self.ORDINARY)
        self.assert_root_test(calls[2], [self.NETNS], elevated=True)
        self.assertEqual(calls[3], {'tool': 'sudo', 'args': ['-n', '--', 'fixture-netns.test'], 'cwd': '.'})

    def test_elevation_requires_exact_package_and_exact_true(self):
        for approved in ['false', '', 'TRUE', 'true ', '1']:
            with self.subTest(authorized=approved):
                result, calls = self.run_queue(authorized=approved)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(calls), 3)
                self.assert_root_test(calls[1], self.ORDINARY)
                self.assert_root_test(calls[2], [self.NETNS])
        packages = self.ORDINARY + [self.NETNS + '/child', self.NETNS + 'extra']
        result, calls = self.run_queue(selected=['./adapter', './daemon', './common/netns...'],
                                       resolved=packages, authorized='true')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[0]['args'][-3:], ['./adapter', './daemon', './common/netns...'])
        self.assertEqual(len(calls), 2)
        self.assert_root_test(calls[1], packages)

    def test_empty_and_netns_only_selection_never_expand_test_scope(self):
        result, calls = self.run_queue(selected=[], resolved=[], authorized='true')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [])
        result, calls = self.run_queue(selected=['./common/netns'], resolved=[self.NETNS], authorized='true')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 3)
        self.assert_root_test(calls[1], [self.NETNS], elevated=True)

    def test_list_errors_and_empty_resolution_fail_before_tests(self):
        for resolved, statuses in [(self.ORDINARY + [self.NETNS], {'list': 17}), ([], {})]:
            with self.subTest(resolved=resolved, statuses=statuses):
                result, calls = self.run_queue(resolved=resolved, statuses=statuses, authorized='true')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0]['args'][0], 'list')

    def test_test_failures_survive_tee_and_stop_later_groups(self):
        for group, approved, count in [('ordinary', 'true', 2), ('netns', 'true', 4), ('netns', 'false', 3)]:
            with self.subTest(group=group, authorized=approved):
                result, calls = self.run_queue(authorized=approved, statuses={group: 23},
                                               modules=['sing-tun', 'metacubex-utls'])
                self.assertEqual(result.returncode, 23, result.stderr)
                self.assertEqual(len(calls), count)
                self.assertTrue(all(c['cwd'] == '.' for c in calls))

    def test_success_requires_ordinary_ok_and_real_named_netns_pass(self):
        cases = [('ordinary', '? fixture [no test files]\n'),
                 ('netns', '--- SKIP: TestUnshareNamespace (0.00s)\nok fixture/netns\n'),
                 ('netns', '--- PASS: TestAnotherNamespace (0.00s)\nok fixture/netns\n'),
                 ('netns', '--- PASS: TestUnshareNamespace (0.00s)\n')]
        for group, output in cases:
            with self.subTest(group=group, output=output):
                result, calls = self.run_queue(authorized='true', outputs={group: output},
                                               modules=['sing-tun', 'metacubex-utls'])
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(all(c['cwd'] == '.' for c in calls))

    def test_selected_owned_modules_keep_separate_unprivileged_coverage(self):
        expected = [
            {'tool': 'go', 'cwd': 'third_party/sing-tun',
             'args': ['test', '-race', '-count=1', '-skip', '^(TestTunOne|TestPing)$', '-tags', self.TAGS, './...']},
            {'tool': 'go', 'cwd': 'third_party/sing-tun',
             'args': ['test', '-race', '-count=1', '-v', '-tags', self.TAGS,
                      '-run', '^TestPing$/^(ipv4|ipv6)$/^unprivileged$', './ping']},
            {'tool': 'go', 'cwd': 'third_party/metacubex-utls',
             'args': ['test', '-race', '-count=1', '-tags', self.TAGS, './...']}]
        # Check nested owners both alone and after netns configured its wrapper:
        # reusing netns_exec in a later module must never inherit elevation.
        for selected in [[], ['./...']]:
            with self.subTest(root_selection=selected):
                result, calls = self.run_queue(selected=selected, authorized='true',
                                               modules=['sing-tun', 'metacubex-utls'])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(calls), 7 if selected else 3)
                self.assertEqual(calls[-3:], expected)
                self.assertEqual(sum(c['tool'] == 'sudo' for c in calls), 1 if selected else 0)
        for module in ['sing-tun', 'sing-tun-ping', 'metacubex-utls']:
            with self.subTest(failing_module=module):
                result, calls = self.run_queue(selected=[], authorized='true',
                                               modules=['sing-tun', 'metacubex-utls'], statuses={module: 29})
                self.assertEqual(result.returncode, 29, result.stderr)
                self.assertTrue(all(c['tool'] == 'go' and '-exec' not in c['args'] for c in calls))


class TestNetnsBatchAuthorization(unittest.TestCase):
    # Sanitized GitHub PR #2 and Git commit responses observed 2026-10-17:
    # https://github.com/polaris-arch/sing-box-polaris/pull/2
    # https://github.com/polaris-arch/sing-box-polaris/commit/48977ba52bcb4920bd4cd87abcbe31e5b59005f7
    # Preserve real IDs, refs, SHAs, parents and trees; omit unrelated personal
    # and signature fields. The original Actions event payload was unavailable;
    # null/stale event merge values below are explicit regression scenarios.
    HEAD = '846406cb04529cd942c6c12829c83fd99d6e878e'
    MERGE = '48977ba52bcb4920bd4cd87abcbe31e5b59005f7'
    TREE = 'd5cbf3a6b0e07fb355971cd476f868e5e33b1625'
    BASE = '46eb46721034564b05ae321aa21761a2e4c7b0f6'
    OTHER = 'd' * 40
    REPO = {'id': 1421657509, 'full_name': 'polaris-arch/sing-box-polaris'}
    OBSERVED_PR = {
        'number': 2, 'merge_commit_sha': MERGE,
        'base': {'ref': 'polaris-main', 'sha': BASE, 'repo': dict(REPO)},
        'head': {'ref': 'collab/dots-audit-remediation-20261017', 'sha': HEAD, 'repo': dict(REPO)},
    }
    OBSERVED_MERGE = {'sha': MERGE, 'tree': {'sha': TREE}, 'parents': [{'sha': BASE}, {'sha': HEAD}]}
    OBSERVED_HEAD = {'sha': HEAD, 'tree': {'sha': TREE}}

    def authorize(self, kind='pull_request', actual=None, source=None, change_pr=None,
                  event_number=2, ref=None, repository=None, tree=None, parents=None,
                  merge=..., commit_sha=None, fail_api=None, message='message\n', extra_env=None, dirty=False):
        workflow = ROOT / '.github/workflows/polaris-selfcheck.yml'
        document = yaml.safe_load(workflow.read_text())
        code = next(s['run'] for s in document['jobs']['patch_tests']['steps']
                    if s.get('id') == 'netns_batch_authorization')
        pr = copy.deepcopy(self.OBSERVED_PR)
        if change_pr:
            change_pr(pr)
        event = {'number': event_number, 'pull_request': {'merge_commit_sha': self.MERGE if merge is ... else merge}}
        actual = actual or self.HEAD
        urls, git = [], []

        def urlopen(request, timeout):
            urls.append(request.full_url)
            self.assertEqual(request.get_method(), 'GET')
            self.assertEqual(timeout, 30)
            self.assertEqual(request.get_header('Authorization'), 'Bearer fixture-token-never-network')
            prefix = 'https://api.github.com/repos/' + self.REPO['full_name']
            self.assertIn(request.full_url, [prefix + '/pulls/2', prefix + '/git/commits/' + self.HEAD])
            if fail_api == len(urls):
                raise urllib.error.HTTPError(request.full_url, 403, 'Forbidden', {}, None)
            payload = pr if request.full_url.endswith('/pulls/2') else {
                'sha': commit_sha or self.HEAD, 'tree': {'sha': tree or self.TREE}}
            return io.BytesIO(json.dumps(payload).encode())

        def check_output(args, **kwargs):
            git.append(args)
            self.assertEqual(kwargs, {'text': True})
            if args == ['git', 'rev-parse', 'HEAD']:
                return actual + '\n'
            if args == ['git', 'status', '--porcelain', '--untracked-files=no']:
                return ' M go.mod\n' if dirty else ''
            if args == ['git', 'rev-parse', 'HEAD^{tree}']:
                return self.TREE + '\n'
            if args == ['git', 'cat-file', '-p', 'HEAD']:
                parent_list = [p['sha'] for p in self.OBSERVED_MERGE['parents']] if parents is None else parents
                return 'tree ' + self.TREE + '\n' + ''.join('parent ' + sha + '\n' for sha in parent_list) + '\n' + message
            self.fail('Unexpected subprocess: ' + repr(args))

        with tempfile.TemporaryDirectory(prefix='polaris-netns-auth-') as directory:
            path = Path(directory)
            event_path, output = path / 'event.json', path / 'output'
            event_path.write_text(json.dumps(event))
            env = {'GITHUB_EVENT_PATH': str(event_path), 'GITHUB_OUTPUT': str(output),
                   'EVENT_NAME': kind, 'EVENT_REF': ref or ('refs/heads/polaris-main' if kind == 'push' else 'refs/pull/2/merge'),
                   'EVENT_REPOSITORY': repository or self.REPO['full_name'],
                   'SOURCE_COMMIT': source or actual, 'GH_TOKEN': 'fixture-token-never-network'}
            env.update(extra_env or {})
            log, failure = io.StringIO(), None
            with mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch('urllib.request.urlopen', side_effect=urlopen), \
                 mock.patch('subprocess.check_output', side_effect=check_output), \
                 mock.patch('subprocess.Popen', side_effect=AssertionError('No real subprocess allowed')), \
                 contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
                try:
                    exec(compile(code, str(workflow), 'exec'), {})
                except SystemExit as error:
                    failure = str(error)
            result = output.read_bytes() if output.exists() else b''
        self.assertNotIn('fixture-token', log.getvalue())
        self.assertNotIn('fixture-token', failure or '')
        return result, failure, urls, git

    def test_governance_window_requires_exact_approved_hosted_source_and_never_widens_the_binary(self):
        sha = self.OTHER
        env = {'GOVERNANCE_NETNS_SHA': sha, 'GITHUB_SHA': sha, 'GITHUB_REPOSITORY_ID': str(self.REPO['id']),
               'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux'}
        for kind in ['push', 'workflow_dispatch']:
            for ref in ['refs/heads/polaris-main', 'refs/heads/ci/governance']:
                result, failure, urls, git = self.authorize(kind=kind, ref=ref, actual=sha, extra_env=env)
                self.assertEqual(result,b'authorized=true\n');self.assertIsNone(failure);self.assertEqual(urls,[])
                self.assertEqual(git,[['git','rev-parse','HEAD'],['git','status','--porcelain','--untracked-files=no']])
        for change in [{'GOVERNANCE_NETNS_SHA': ''}, {'GOVERNANCE_NETNS_SHA': sha.upper()},
                       {'GOVERNANCE_NETNS_SHA': self.BASE}, {'GITHUB_SHA': self.BASE},
                       {'GITHUB_REPOSITORY_ID': '1'}, {'RUNNER_ENVIRONMENT': 'self-hosted'}, {'RUNNER_OS': 'Windows'}]:
            result,failure,_,_=self.authorize(kind='workflow_dispatch',ref='refs/heads/ci/governance',actual=sha,extra_env={**env,**change})
            self.assertEqual(result,b'authorized=false\n');self.assertIsNone(failure)
        for options in [{'kind':'pull_request','event_number':3}, {'ref':'refs/heads/unapproved'}, {'ref':'refs/tags/v1.0.0'},
                        {'repository':'other/sing-box-polaris'}, {'source':self.BASE}, {'actual':self.BASE}]:
            args={'kind':'workflow_dispatch','ref':'refs/heads/ci/governance','actual':sha,'extra_env':env,**options}
            result,failure,_,_=self.authorize(**args)
            self.assertEqual(result,b'authorized=false\n');self.assertIsNone(failure)
        result,failure,_,_=self.authorize(kind='workflow_dispatch',ref='refs/heads/ci/governance',actual=sha,extra_env=env,dirty=True)
        self.assertEqual(result,b'');self.assertIn('source is dirty',failure)

    def test_current_head_exact_merge_and_main_fast_forward_are_authorized(self):
        for options in [{}, {'actual': self.MERGE}, {'kind': 'push'}]:
            with self.subTest(options=options):
                result, failure, urls, git = self.authorize(**options)
                self.assertIsNone(failure)
                self.assertEqual(result, b'authorized=true\n')
                self.assertEqual(len(urls), 2 if options.get('actual') == self.MERGE else 1)
                self.assertTrue(git)

    def test_observed_pr2_merge_ignores_null_or_stale_merge_metadata(self):
        # The actual checkout has the current PR head as a parent and the same
        # complete tree. Mutable merge metadata must not veto this identity.
        for event_merge in [None, self.OTHER]:
            for api_merge in [self.MERGE, None, self.OTHER]:
                with self.subTest(event_merge=event_merge, api_merge=api_merge):
                    result, failure, urls, git = self.authorize(
                        actual=self.OBSERVED_MERGE['sha'], merge=event_merge,
                        change_pr=lambda pr: pr.update(merge_commit_sha=api_merge))
                    self.assertIsNone(failure)
                    self.assertEqual(result, b'authorized=true\n')
                    self.assertEqual(len(urls), 2)
                    self.assertIn(['git', 'cat-file', '-p', 'HEAD'], git)
                    self.assertIn(['git', 'rev-parse', 'HEAD^{tree}'], git)

    def test_stale_merge_metadata_never_overrides_source_parent_or_tree(self):
        for options in [{'parents': [self.BASE]}, {'tree': self.OTHER},
                        {'commit_sha': self.OTHER}, {'source': self.OTHER}, {'fail_api': 2}]:
            with self.subTest(options=options):
                result, failure, _, _ = self.authorize(actual=self.MERGE, merge=None, **options)
                if 'source' in options or 'fail_api' in options:
                    self.assertIsNotNone(failure)
                    self.assertEqual(result, b'')
                else:
                    self.assertIsNone(failure)
                    self.assertEqual(result, b'authorized=false\n')

    def test_wrong_repository_pr_or_branch_identity_is_rejected(self):
        mutations = [
            ('PR number', lambda p: p.update(number=3)),
            ('base ref', lambda p: p['base'].update(ref='other')),
            ('head ref', lambda p: p['head'].update(ref='other')),
        ]
        for side in ['base', 'head']:
            mutations += [
                (side + ' repository ID', lambda p, side=side: p[side]['repo'].update(id=1)),
                (side + ' repository name', lambda p, side=side: p[side]['repo'].update(full_name='fork/repo')),
            ]
        for name, mutation in mutations:
            with self.subTest(identity=name):
                result, failure, urls, git = self.authorize(change_pr=mutation)
                self.assertIsNone(failure)
                self.assertEqual(result, b'authorized=false\n')
                self.assertEqual(len(urls), 1)
                self.assertEqual(git, [])

    def test_unapproved_events_do_not_query_api_or_git(self):
        for options in [{'event_number': 3}, {'kind': 'workflow_dispatch'},
                        {'kind': 'pull_request_target'}, {'kind': 'push', 'ref': 'refs/heads/other'},
                        {'kind': 'push', 'ref': 'refs/tags/polaris-test'}, {'repository': 'fork/repo'}]:
            with self.subTest(options=options):
                result, failure, urls, git = self.authorize(**options)
                self.assertIsNone(failure)
                self.assertEqual(result, b'authorized=false\n')
                self.assertEqual((urls, git), ([], []))

    def test_commit_tree_and_parent_scope_reject_same_tree_substitutes(self):
        for options in [{'kind': 'push', 'actual': self.OTHER},
                        {'actual': self.OTHER, 'parents': [self.BASE]}, {'actual': self.MERGE, 'tree': self.OTHER},
                        {'actual': self.MERGE, 'parents': [self.OTHER]},
                        {'actual': self.MERGE, 'parents': []},
                        {'actual': self.MERGE, 'parents': [self.OTHER], 'message': 'parent ' + self.HEAD + '\n'},
                        {'actual': self.MERGE, 'commit_sha': self.OTHER}]:
            with self.subTest(options=options):
                result, failure, _, _ = self.authorize(**options)
                self.assertIsNone(failure)
                self.assertEqual(result, b'authorized=false\n')

    def test_checkout_mismatch_and_api_failure_never_emit_authorization(self):
        for options in [{'source': self.OTHER}, {'fail_api': 1},
                        {'actual': self.MERGE, 'fail_api': 2}]:
            with self.subTest(options=options):
                result, failure, _, _ = self.authorize(**options)
                self.assertIsNotNone(failure)
                self.assertEqual(result, b'')


class TestFinalSourceEntrypoints(unittest.TestCase):
    EXPECTED = {
        'TestAutoRedirectCloseBeforeFirewallSetupPreservesRunningInstance',
        'TestAutoRedirectAttemptedFirewallRetainsLegacyCleanup',
        'TestAutoRedirectNFTCloseWithoutSetupDoesNotEnterCleanup',
    }

    def test_manual_test_and_lint_keep_complete_jobs_behind_full_classifier(self):
        for filename, count in [('test.yml', 3), ('lint.yml', 10)]:
            workflow = yaml.safe_load((ROOT / '.github/workflows' / filename).read_text())
            self.assertEqual(set(workflow['on']), {'push', 'pull_request', 'workflow_dispatch'})
            self.assertEqual(workflow['on']['workflow_dispatch'], {})
            self.assertEqual(workflow['permissions'], {'contents': 'read'})
            self.assertEqual(set(workflow['jobs']), {'classify', 'test' if filename == 'test.yml' else 'build'})
            job = workflow['jobs']['test' if filename == 'test.yml' else 'build']
            self.assertEqual(job['needs'], 'classify')
            self.assertEqual(job['if'], "${{ needs.classify.outputs.run_full == 'true' }}")
            self.assertNotIn('paths-ignore', workflow['on']['push'])
            matrix = job['strategy']['matrix']
            self.assertEqual(len(matrix.get('include', matrix.get('os', []))), count)
            for step in job['steps']:
                self.assertNotIn('github.event_name', step.get('if', ''))

    def test_test_and_lint_reuse_original_classifier_and_contract_checks_cover_lightweight_paths(self):
        selfcheck = yaml.safe_load((ROOT / '.github/workflows/polaris-selfcheck.yml').read_text())
        expected = copy.deepcopy(selfcheck['jobs']['classify'])
        expected['steps'] = expected['steps'][:3]
        for filename in ('test.yml', 'lint.yml'):
            workflow = yaml.safe_load((ROOT / '.github/workflows' / filename).read_text())
            self.assertEqual(workflow['jobs']['classify'], expected)
        contract = yaml.safe_load((ROOT / '.github/workflows/ci-contract.yml').read_text())
        for event in ('push', 'pull_request'):
            for path in ('scripts/polaris_ci_impact.py', 'scripts/test_polaris_ci_impact.py',
                         'scripts/test_polaris_runner_resources.py', 'scripts/test_polaris_production_release.py',
                         'scripts/testdata/historical-workflows/**', 'scripts/ci/**'):
                self.assertIn(path, contract['on'][event]['paths'])
        commands = '\n'.join(step.get('run', '') for step in contract['jobs']['contract']['steps'])
        for name in ('test_polaris_ci_impact.py', 'test_polaris_runner_resources.py',
                     'test_polaris_production_release.ProductionTests.test_historical_workflow'):
            self.assertIn(name, commands)

    def test_linux_exact_package_partition_and_elevation_scope(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/test.yml').read_text())
        steps = workflow['jobs']['test']['steps']
        ordinary = next(s for s in steps if s.get('name') == 'Test (Linux ordinary packages)')
        elevated = next(s for s in steps if s.get('name') == 'Test (Linux netns binary only)')
        self.assertEqual(ordinary['if'], "matrix.os == 'ubuntu-latest'")
        self.assertEqual(elevated['if'], "matrix.os == 'ubuntu-latest'")
        for name in ['Test (macOS ordinary packages)', 'Test (windows)']:
            step = next(s for s in steps if s.get('name') == name)
            self.assertEqual(step['run'], 'go test -v -tags "$BUILD_TAGS" -ldflags "$LDFLAGS_SHARED" ./...')
        self.assertNotIn('sudo', ordinary['run'])
        sudo_lines = [line.strip() for step in steps for line in step.get('run', '').splitlines() if line.strip().startswith('sudo ')]
        self.assertEqual(sudo_lines, ['sudo -n -- "$binary_dir/netns.test" -test.v | tee "$binary_dir/result.log"'])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = root / 'calls.jsonl'
            fake = root / 'go'
            fake.write_text('#!' + sys.executable + '\n' +
                'import json,os,sys\nfrom pathlib import Path\n' +
                'args=sys.argv[1:]\nwith open(' + repr(str(calls)) + ',"a") as f:f.write(json.dumps(args)+"\\n")\n' +
                'if args[0]=="list":\n print(os.environ["FAKE_PACKAGES"])\n raise SystemExit(int(os.environ.get("LIST_RC","0")))\n' +
                'if "-c" in args:\n Path(args[args.index("-o")+1]).write_text("fixture")\n' +
                'raise SystemExit(int(os.environ.get("GO_RC","0")))\n')
            fake.chmod(0o700)
            sudo = root / 'sudo'
            sudo.write_text('#!' + sys.executable + '\nimport json,os,sys\nfrom pathlib import Path\n' +
                'args=sys.argv[1:]\nassert args[:2]==["-n","--"] and args[3:]==["-test.v"]\n' +
                'assert Path(args[2]).name=="netns.test" and Path(args[2]).is_file()\n' +
                'print(os.environ.get("SUDO_LOG","--- PASS: TestUnshareNamespace (0.01s)\\nPASS"))\n' +
                'raise SystemExit(int(os.environ.get("SUDO_RC","0")))\n')
            sudo.chmod(0o700)
            env = {**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'], 'RUNNER_TEMP': str(root),
                   'BUILD_TAGS': 'with_tailscale', 'LDFLAGS_SHARED': '-checklinkname=0',
                   'FAKE_PACKAGES': 'github.com/sagernet/sing-box/adapter\ngithub.com/sagernet/sing-box/common/netns\ngithub.com/sagernet/sing-box/common/netns_extra'}
            def run(step, **changes):
                return subprocess.run(['bash', '-c', step['run']], env={**env, **changes}, capture_output=True, text=True).returncode
            self.assertEqual(run(ordinary), 0)
            args = [json.loads(line) for line in calls.read_text().splitlines()][-1]
            self.assertEqual(args[-2:], ['github.com/sagernet/sing-box/adapter', 'github.com/sagernet/sing-box/common/netns_extra'])
            for changes in [{'LIST_RC': '1'}, {'GO_RC': '1'}, {'FAKE_PACKAGES': 'github.com/sagernet/sing-box/adapter'},
                            {'FAKE_PACKAGES': 'github.com/sagernet/sing-box/common/netns'}]:
                with self.subTest(ordinary_failure=changes): self.assertNotEqual(run(ordinary, **changes), 0)
            self.assertEqual(run(elevated), 0)
            args = [json.loads(line) for line in calls.read_text().splitlines()][-1]
            self.assertEqual(args[:2], ['test', '-c'])
            self.assertEqual(args[-1], 'github.com/sagernet/sing-box/common/netns')
            for changes in [{'GO_RC': '1'}, {'SUDO_RC': '1'}, {'SUDO_LOG': 'PASS'}, {'SUDO_LOG': '--- SKIP: TestUnshareNamespace (0.01s)\nPASS'}]:
                with self.subTest(elevated_failure=changes): self.assertNotEqual(run(elevated, **changes), 0)

    def nested_step(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/build.yml').read_text())
        job = workflow['jobs']['source_gate']
        self.assertEqual(job['if'], "inputs.build == 'Source' && !inputs.source_generate_only")
        self.assertEqual(job['env']['GOFLAGS'], '-mod=readonly')
        self.assertEqual(job['env']['GOTOOLCHAIN'], 'local')
        step = next(s for s in job['steps'] if s.get('name') == 'Verify nested sing-tun cleanup regressions through the root replacement')
        self.assertEqual(step['if'], "matrix.os == 'ubuntu-24.04'")
        self.assertEqual(step['shell'], 'bash')
        return step['run']

    def run_nested(self, passed, package_pass=True, returncode=0):
        script = self.nested_step()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / 'go'
            events = [{'Action': 'pass', 'Package': 'github.com/sagernet/sing-tun', 'Test': name} for name in passed]
            if package_pass:
                events.append({'Action': 'pass', 'Package': 'github.com/sagernet/sing-tun'})
            fake.write_text('#!' + sys.executable + '\nimport json,sys\nfrom pathlib import Path\n' +
                            'Path(' + repr(str(root / 'argv.json')) + ').write_text(json.dumps(sys.argv[1:]))\n' +
                            'print(' + repr('\n'.join(json.dumps(e) for e in events)) + ')\n' +
                            'raise SystemExit(' + str(returncode) + ')\n')
            fake.chmod(0o700)
            result = subprocess.run(['bash', '-c', script], cwd=ROOT,
                                    env={**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'], 'RUNNER_TEMP': str(root)},
                                    capture_output=True, text=True)
            args = json.loads((root / 'argv.json').read_text())
            self.assertEqual(args[:5], ['test', '-json', '-race', '-count=1', '-timeout=10m'])
            self.assertEqual(args[-1], 'github.com/sagernet/sing-tun')
            pattern = args[args.index('-run') + 1]
            self.assertEqual({name for name in self.EXPECTED if re.fullmatch(pattern, name)}, self.EXPECTED)
            self.assertIsNone(re.fullmatch(pattern, 'TestUnrelatedNetworkOperation'))
            self.assertNotIn('sudo', script)
            return result.returncode

    def test_nested_actual_shell_accepts_all_required_passes(self):
        self.assertEqual(self.run_nested(self.EXPECTED), 0)

    def test_nested_actual_shell_rejects_missing_or_skipped_test(self):
        for name in self.EXPECTED:
            with self.subTest(missing=name):
                self.assertNotEqual(self.run_nested(self.EXPECTED - {name}), 0)

    def test_nested_actual_shell_rejects_missing_package_pass_and_go_failure(self):
        self.assertNotEqual(self.run_nested(self.EXPECTED, package_pass=False), 0)
        self.assertNotEqual(self.run_nested(self.EXPECTED, returncode=1), 0)


if __name__=='__main__':unittest.main()

