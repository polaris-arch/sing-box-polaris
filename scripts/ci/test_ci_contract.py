from pathlib import Path
import json,re,unittest,yaml
import copy,os,shlex,shutil,subprocess,sys,tempfile
from unittest import mock
ROOT=Path(__file__).resolve().parents[2]
def source_cost_steps_contract(gate):
 # Retention is unconditional input metadata; only the later observation measures.
 steps=gate['steps']
 names=('Retain exact Source inputs before compatibility gates (not a test or native PASS)',
        'Measure whole-migration binary and idle RSS costs')
 selected=[]
 for name in names:
  matches=[step for step in steps if step.get('name')==name]
  if len(matches)!=1:raise AssertionError('unique exact cost phase step required: '+name)
  selected.append(matches[0])
 early,cost=selected
 commands=(['python','-B','scripts/ci/utls_cost.py','--retain-source-input','--output',
            '${{ runner.temp }}/tls-fingerprint-evidence'],
           ['python','scripts/ci/utls_cost.py','--output','${{ runner.temp }}/tls-fingerprint-evidence/cost'])
 for step,command in zip(selected,commands):
  try:argv=shlex.split(step.get('run',''))
  except (ValueError,TypeError) as error:raise AssertionError('cost phase command is not well formed') from error
  if argv!=command:raise AssertionError('cost phase command differs')
 calls=[step for step in steps if 'utls_cost.py' in step.get('run','')]
 if calls!=selected:raise AssertionError('exact input then measurement invocations required')
 if 'if' in early or 'continue-on-error' in early or 'env' in early:
  raise AssertionError('early input-only receipt must run unconditionally on all Source platforms')
 if cost.get('if')!="always() && matrix.os == 'ubuntu-24.04'" or cost.get('continue-on-error') is not True:
  raise AssertionError('measurement remains a nonblocking Ubuntu always observation')
 early_index=steps.index(early)
 for prefix in ('actions/checkout@','actions/setup-python@'):
  before=[step for step in steps if step.get('uses','').startswith(prefix)]
  if len(before)!=1 or steps.index(before[0])>=early_index:
   raise AssertionError('input receipt must follow exact checkout and Python setup')
 boundaries=([step for step in steps if step.get('uses','').startswith('actions/setup-go@')],
             [step for step in steps if 'pip install' in step.get('run','')],
             [step for step in steps if 'test_client_encoding.py' in step.get('run','')])
 if any(len(group)!=1 or steps.index(group[0])<=early_index for group in boundaries):
  raise AssertionError('input receipt must precede Go, pip and Unicode gates')
 required={'SOURCE_BUILD':'${{ inputs.build }}',
           'SOURCE_GENERATE_ONLY':"${{ inputs.source_generate_only && 'true' || 'false' }}",
           'SOURCE_WINDOWS_NATIVE_PROOF':"${{ inputs.windows_native_proof && 'true' || 'false' }}",
           'SOURCE_EVIDENCE_MODE':'${{ inputs.evidence_mode }}','SOURCE_VERSION':'${{ inputs.version }}',
           'SOURCE_RUNNER':'${{ matrix.os }}'}
 if any(gate.get('env',{}).get(key)!=value for key,value in required.items()):
  raise AssertionError('early receipt must retain exact dispatched Source inputs')
 uploads=[step for step in steps if step.get('uses','').startswith('actions/upload-artifact@')]
 if len(uploads)!=1 or uploads[0].get('if')!='always()' or uploads[0].get('with',{}).get('if-no-files-found')!='error' or uploads[0].get('with',{}).get('path')!='${{ runner.temp }}/tls-fingerprint-evidence':
  raise AssertionError('always-upload exact evidence directory must keep no-files failure')
 return early,cost

class TestVisionSourceContract(unittest.TestCase):
 def test_every_source_boundary_rejects_tampering(self):
  from vision_source import validate, BINDING
  for kind in ('bytes','mode','extra','missing','link','root-replace','provider-version','patch','notice','tree'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp)
    from test_vision_source import fixture,git
    fixture(root)
    target=root/'third_party/sing-vmess/vless/vision.go'
    if kind=='bytes':target.write_bytes(target.read_bytes()+b'\n')
    elif kind=='mode':
     if sys.platform=='win32':git(root,'update-index','--chmod=+x','third_party/sing-vmess/vless/vision.go')
     else:target.chmod(0o755)
    elif kind=='extra':(target.parent/'foreign.go').write_text('package vless\n')
    elif kind=='missing':target.unlink()
    elif kind=='link':target.unlink();target.symlink_to(ROOT/'third_party/sing-vmess/vless/vision.go')
    elif kind=='root-replace':
     target=root/'go.mod';target.write_text(target.read_text().replace('=> ./third_party/sing-vmess','=> ../foreign'))
    elif kind=='provider-version':
     target=root/'go.mod';target.write_text(target.read_text().replace('ff1b50fbbe9a','000000000000'))
    elif kind=='patch':
     target=root/'release/dependency-sources/sing-vmess-vision.patch';target.write_bytes(target.read_bytes()+b'\n')
    elif kind=='notice':
     target=root/'release/licenses/CURRENT44-NOTICE-CANDIDATE.txt';target.write_bytes(b'wrong')
    else:
     target=root/BINDING;doc=json.loads(target.read_text());doc['replacementTree']='0'*40;target.write_text(json.dumps(doc))
    expected={'bytes':'worktree bytes|complete source', 'mode':'HEAD/index|complete source',
              'extra':'worktree bytes|complete source', 'missing':'worktree bytes|complete source',
              'link':'replacement link', 'root-replace':'root replacement',
              'provider-version':'provider pin', 'patch':'patch identity', 'notice':'upstream notice',
              'tree':'complete source'}[kind]
    with self.assertRaisesRegex(ValueError,expected):validate(root)

class TestCIContract(unittest.TestCase):
 def test_owned_packet_metadata_source_binding_preserves_history(self):
  import hashlib
  document=json.loads((ROOT/'release/dependency-sources/sing-packet-metadata.json').read_bytes())
  self.assertEqual(document['baseProductCommit'],'28f848c936608e2ad0fabd0ec5bcc32cf317a526')
  self.assertEqual(document['version'],'v0.9.7-0.20260929150544-6f21f2425a95')
  self.assertEqual(document['replacementPath'],'./third_party/sing')
  self.assertEqual({x['path'] for x in document['changes']},{'common/network/thread.go','common/network/buffer_metadata.go','common/network/buffer_metadata_test.go'})
  self.assertEqual(hashlib.sha256((ROOT/document['patch']).read_bytes()).hexdigest(),document['patchSHA256'])
  for change in document['changes']:
   raw=(ROOT/'third_party/sing'/change['path']).read_bytes()
   self.assertEqual(hashlib.sha256(raw).hexdigest(),change['afterSHA256'])
   self.assertEqual(len(raw),change['bytes'])
  historical=json.loads((ROOT/document['historicalOwnershipReceipt']).read_bytes())
  for path,field in [('LICENSE','license_sha256'),('go.mod','go_mod_sha256'),('go.sum','go_sum_sha256')]:
   value=hashlib.sha256((ROOT/'third_party/sing'/path).read_bytes()).hexdigest()
   self.assertEqual(value,document['unchangedUpstreamFiles'][path]);self.assertEqual(value,historical[field])
  self.assertIn('replace github.com/sagernet/sing => ./third_party/sing',(ROOT/'go.mod').read_text())
 def test_vision_vendor_source_and_product_graph_gates_are_complete(self):
  from vision_source import validate
  identity=validate(ROOT)
  self.assertEqual(identity['module'],'github.com/sagernet/sing-vmess')
  workflow=yaml.safe_load((ROOT/'.github/workflows/test.yml').read_text())
  job=workflow['jobs']['test']
  step=next(s for s in job['steps'] if s.get('name')=='Test Vision providers through the product dependency graph')
  self.assertEqual(step['shell'],'bash')
  for flag in ('-mod=readonly','-race','-gcflags=all=-d=checkptr=2','-count=1','github.com/sagernet/sing-vmess/...'):
   self.assertIn(flag,step['run'])
  self.assertNotIn('cd third_party',step['run'])
  self.assertNotIn('sudo',step['run'])
  self.assertNotIn('if',step)
  self.assertNotIn('continue-on-error',step)
  self.assertEqual(set(job['strategy']['matrix']['os']),{'ubuntu-latest','windows-latest','macos-latest','xcode-27'})
  mac=next(s for s in job['steps'] if s.get('name')=='Test (macOS ordinary packages)')
  self.assertEqual(mac['if'],"matrix.os == 'macos-latest' || matrix.os == 'xcode-27'")
  source=(ROOT/'scripts/ci/utls_gate.py').read_text()
  self.assertIn("receipt['visionSource'] = validate_vision_source(ROOT, diagnostics=vision_diagnostics)",source)
 def test_automatic_ci_runs_candidate_track_and_peer_admission_regressions(self):
  workflow=yaml.safe_load((ROOT/'.github/workflows/ci-contract.yml').read_text())
  job=workflow['jobs']['contract']
  for filename in ('test_linux_candidate_track.py','test_native_peer_metadata.py','test_protocol_peer.py','test_windows_native_execution.py','test_windows_native_admission.py','test_cronet_windows_overlay.py'):
   command="python -B -m unittest discover -s scripts/ci -p '"+filename+"'"
   steps=[s for s in job['steps'] if s.get('run')==command]
   self.assertEqual(len(steps),1,filename)
   for control in (job,steps[0]):
    self.assertNotIn('if',control)
    self.assertNotIn('continue-on-error',control)
   self.assertNotIn('env',steps[0])
  self.assertEqual(workflow['permissions'],{'contents':'read'})
 def test_windows_native_proof_is_separate_manual_protection_and_kernel_execution(self):
  workflow=yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text());jobs=workflow['jobs']
  field=workflow['on']['workflow_dispatch']['inputs']['windows_native_proof']
  self.assertEqual(field['type'],'boolean');self.assertIs(field['default'],False)
  admission=jobs['windows_native_admission'];native=jobs['native_windows_proof']
  for job in (admission,native):
   self.assertIn("github.event_name == 'workflow_dispatch'",job['if']);self.assertIn('inputs.windows_native_proof == true',job['if'])
   self.assertNotIn('continue-on-error',job)
   self.assertIn('!inputs.source_generate_only',job['if'])
   self.assertIn("(inputs.build == 'All' || inputs.build == 'Binary')",job['if'])
   self.assertIn("inputs.evidence_mode == 'final'",job['if'])
   self.assertIn('!failure()',job['if']);self.assertIn('!cancelled()',job['if'])
  self.assertEqual(admission['permissions'],{'contents':'read','actions':'read'})
  self.assertNotIn('environment',admission);self.assertEqual(admission['runs-on'],'ubuntu-24.04')
  acquire=next(s for s in admission['steps'] if s.get('id')=='admission')
  self.assertEqual(acquire['run'],'python3 -B scripts/ci/windows_native_admission.py --acquire')
  self.assertIn('EXPECTED_RELEASE_TAG_OBJECT',acquire['env']);self.assertIn('GH_TOKEN',acquire['env'])
  self.assertEqual(native['environment'],'polaris-windows-native-proof')
  self.assertIn('polaris-windows-system-proof',native['runs-on'])
  self.assertIn("needs.windows_native_admission.result == 'success'",native['if'])
  self.assertIn("inputs.evidence_mode == 'final'",native['if'])
  execution=next(s for s in native['steps'] if s.get('env',{}).get('POLARIS_WINDOWS_NATIVE_PROOF_AUTHORIZED')=='true')
  self.assertEqual(execution['env'],{'POLARIS_WINDOWS_NATIVE_PROOF_AUTHORIZED':'true'})
  self.assertNotIn('GH_TOKEN',native.get('env',{}));self.assertNotIn('GITHUB_TOKEN',native.get('env',{}))
  self.assertTrue(native['steps'][0]['run'].startswith('$identity = [Security.Principal.WindowsIdentity]::GetCurrent()'))
  joined='\n'.join(s.get('run','') for s in native['steps'])
  for forbidden in ('New-Service','Register-ScheduledTask','schtasks','psexec','sc.exe create','Set-Acl'):
   self.assertNotIn(forbidden,joined)
  self.assertIn('-buildvcs=true',joined);self.assertIn('main.producerSource=',joined);self.assertIn('main.producerTree=',joined)
  index=jobs['native_index'];self.assertIn('native_windows_proof',index['needs'])
  self.assertIn("inputs.windows_native_proof != true || needs.native_windows_proof.result == 'success'",index['if'])
  smoke=jobs['native_smoke']
  for name in ('Execute final-package Cronet smoke','Upload actual smoke receipt'):
   step=next(s for s in smoke['steps'] if s.get('name')==name)
   self.assertIn("!(inputs.windows_native_proof == true && matrix.id == 'windows-amd64')",step['if'])
  controls=next(s for s in jobs['utls_gate']['steps'] if s.get('name')=='Compile Windows native producer and execute unprivileged rejection controls')
  self.assertEqual(controls['if'],"matrix.os == 'windows-2025'")
  self.assertEqual(controls['env']['POLARIS_WINDOWS_NATIVE_PROOF_AUTHORIZED'],'false')
  self.assertIn('./cmd/internal/windows_native_execution github.com/sagernet/cronet-go/internal/cronet',controls['run'])
  for name in ('TestNativeOutputAndExplicitAdmissionFailClosedWithoutExecution','TestWindowsLibraryDigestMismatchCannotEnterNativeLoad',
               'TestNativeCustodyRecordRejectsAmbiguousAndTruncatedDebt','TestNativeCustodyRejectsForeignObjectAndJobRecoveryTargets',
               'TestNativeCustodyReconciliationNeverGrantsAdmission','TestNativeCooperativeControlFramesOnlyCancelOriginalOwner',
               'TestNativeCleanupRequiresActualWaitAndReaderClosure'):
   self.assertIn(name,controls['run'])
  source=(ROOT/'cmd/internal/windows_native_execution/process_windows.go').read_text()
  self.assertIn('0x0002000d',source);self.assertIn('PROC_THREAD_ATTRIBUTE_HANDLE_LIST',source)
  self.assertNotIn('AssignProcessToJobObject',source)
  self.assertIn('c.custody.newJob()',source)
  owner=(ROOT/'cmd/internal/windows_native_execution/main_windows.go').read_text()
  self.assertLess(owner.index('openCustody(r, actor)'),owner.index('newCohort(journal.record.CohortID)'))
  self.assertIn('go watchNativeCancellation(reader, cancel)',owner)
  custody=(ROOT/'cmd/internal/windows_native_execution/custody_windows.go').read_text()
  for token in ('custody-next.json','owner.lock','MOVEFILE_WRITE_THROUGH','reconcileBeforeAdmission','jobSecurity','ownerExited','exact owned member bytes/FileID differ'):
   self.assertIn(token,custody)
 def test_windows_native_overlay_is_complete_and_cold_reversible_without_rewriting_history(self):
  import hashlib
  from cronet_windows_overlay import validate_overlay
  inputs=validate_overlay(ROOT)
  self.assertEqual(len(inputs),141)
  for name in ('release/dependency-sources/cronet-go-windows-native-observation.json',
               'release/dependency-sources/cronet-go-windows-native-observation.patch'):
   self.assertEqual(inputs[name],hashlib.sha256((ROOT/name).read_bytes()).hexdigest())
  self.assertEqual(len([name for name in inputs if name.startswith('third_party/cronet-go/')]),137)

 def test_exact_publisher_peer_and_oci_regressions_and_dual_checkout_remain_in_the_existing_gate(self):
  contract=yaml.safe_load((ROOT/'.github/workflows/ci-contract.yml').read_text())
  commands=[s.get('run','') for s in contract['jobs']['contract']['steps']]
  self.assertIn("python -m unittest discover -s scripts/ci -p 'test_github_release.py'",commands)
  suite=(ROOT/'scripts/ci/test_github_release.py').read_text()
  self.assertIn('from publisher_peer_evidence_12_9_tests import Alpha129PeerEvidenceTests',suite)
  self.assertIn('from publisher_peer_successor_tests import SuccessorPeerPreparationTests',suite)
  self.assertIn('from oci_material_selection_12_9_tests import Alpha129OCISelectionTests',suite)
  workflow=yaml.safe_load((ROOT/'.github/workflows/publish-github.yml').read_text())
  for name in ('validate','publish'):
   steps=workflow['jobs'][name]['steps']
   runner=next(s for s in steps if s.get('name')=='Checkout reviewed publisher revision')
   product=next(s for s in steps if s.get('name')=='Checkout exact build source separately')
   self.assertEqual(runner['with'],{'ref':'${{ github.sha }}','persist-credentials':False})
   self.assertEqual(product['with'],{'ref':'${{ inputs.source_sha }}','path':'reviewed-source','persist-credentials':False})
 def test_automatic_ci_runs_cold_go_patch_controls_with_required_patch(self):
  workflow=yaml.safe_load((ROOT/'.github/workflows/ci-contract.yml').read_text())
  job=workflow['jobs']['contract']
  steps=[s for s in job['steps'] if s.get('name')=='Require cold zero-fuzz Go patch controls']
  self.assertEqual(len(steps),1)
  step=steps[0]
  self.assertEqual(step['shell'],'bash')
  self.assertEqual(step['run'].splitlines(),[
   'set -euo pipefail','command -v patch',
   "python -B -m unittest discover -s scripts/ci -p 'test_go_toolchain.py'"])
  self.assertEqual(job['runs-on'],'ubuntu-latest')
  for control in (job,step):
   self.assertNotIn('if',control)
   self.assertNotIn('continue-on-error',control)
  self.assertEqual(workflow['permissions'],{'contents':'read'})
  for event in ('push','pull_request'):
   self.assertEqual(workflow['on'][event]['branches'],['polaris-main'])
  self.assertNotIn('paths',workflow['on']['push'])
  self.assertNotIn('paths-ignore',workflow['on']['push'])
  for path in ('.github/go-toolchains.json','.github/patches/**'):
   self.assertIn(path,workflow['on']['pull_request']['paths'])
 def test_unsigned_apple_package_overlays_cover_all_rows_and_preserve_trust(self):
  workflow=yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text())
  expected={'build_apple':{'macOS-standalone','iOS-jailbreak'},'build_apple_app_store':{'iOS','macOS','tvOS'}}
  overlay="${{ hashFiles('release/ci/apple-swift-package-overlays.json') }}"
  for name,rows in expected.items():
   job=workflow['jobs'][name];steps=job['steps'];by_name={s.get('name'):s for s in steps}
   self.assertEqual({r['name'] for r in job['strategy']['matrix']['include']},rows)
   self.assertEqual(sum(s.get('name')=='Resolve and apply exact unsigned Apple package overlays' for s in steps),1)
   helper=by_name['Resolve and apply exact unsigned Apple package overlays']
   self.assertEqual(helper['if'],'matrix.if');self.assertEqual(helper['shell'],'bash')
   self.assertTrue(helper['run'].startswith('set -euo pipefail\n'))
   self.assertIn('apple_package_overlays.py check-lock\n',helper['run'])
   self.assertIn('xcodebuild -version\nxcrun swift --version\n',helper['run'])
   self.assertIn('xcodebuild -resolvePackageDependencies',helper['run'])
   self.assertEqual(helper['run'].count('-disableAutomaticPackageResolution'),1)
   self.assertIn('-scheme "$APPLE_RESOLVE_SCHEME"',helper['run'])
   self.assertIn('-clonedSourcePackagesDirPath "$RUNNER_TEMP/SourcePackages"',helper['run'])
   self.assertTrue(helper['run'].rstrip().endswith('apple_package_overlays.py apply --source-packages "$RUNNER_TEMP/SourcePackages"'))
   self.assertEqual(helper['env']['APPLE_RESOLVE_SCHEME'],"${{ matrix.type == 'standalone' && 'SFM.System' || matrix.type == 'jailbreak' && 'SFI' || matrix.scheme }}")
   self.assertEqual(helper['env']['DISABLE_SWIFTLINT'],'1')
   self.assertNotIn('continue-on-error',helper)
   self.assertLess(steps.index(by_name['Update version']),steps.index(helper))
   preflight=by_name['Verify actual unsigned Apple sources before build']
   self.assertEqual(preflight['if'],'matrix.if')
   self.assertEqual(preflight['run'],'python3 scripts/ci/client_source.py preflight apple --unsigned')
   self.assertNotIn('continue-on-error',preflight)
   self.assertLess(steps.index(helper),steps.index(preflight))
   self.assertEqual(by_name['Archive App Store build']['run'].count('-disableAutomaticPackageResolution'),1)
   self.assertEqual(by_name['Build standalone packages']['env']['XCODEBUILD_FLAGS'].count('-disableAutomaticPackageResolution'),1)
   for build in ('Archive App Store build','Build standalone packages','Build jailbreak package'):
    self.assertLess(steps.index(helper),steps.index(by_name[build]))
    self.assertLess(steps.index(preflight),steps.index(by_name[build]))
   diagnostic=by_name['Diagnose failed unsigned Apple sources']
   self.assertEqual(diagnostic['if'],'matrix.if && failure()')
   self.assertEqual(diagnostic['run'],'python3 scripts/ci/client_source.py diagnose apple --unsigned')
   self.assertNotIn('continue-on-error',diagnostic)
   records=[s for s in steps if s.get('name')=='Record actual unsigned candidate files']
   self.assertEqual(len(records),1 if name=='build_apple' else 2)
   self.assertEqual([s['if'] for s in records],
                    ["matrix.if && (matrix.type == 'standalone' || matrix.type == 'jailbreak')"]+
                    ([] if name=='build_apple' else ['matrix.if']))
   for record in records:
    self.assertIn('scripts/ci/record_candidate.py dist',record['run'])
    for build in ('Archive App Store build','Build standalone packages','Build jailbreak package'):
     self.assertLess(steps.index(by_name[build]),steps.index(record))
    self.assertLess(steps.index(record),steps.index(diagnostic))
   for upload in [s for s in steps if s.get('uses','').startswith('actions/upload-artifact@')]:
    self.assertEqual(upload['with']['path'],'dist')
    self.assertEqual(upload['with']['if-no-files-found'],'error')
    self.assertTrue(any(steps.index(record)<steps.index(upload) for record in records))
    self.assertLess(steps.index(upload),steps.index(diagnostic))
   self.assertNotIn('Prune Swift package repositories',by_name)
   for step in steps:
    self.assertNotIn('SourcePackages/repositories',step.get('run',''))
   self.assertEqual(by_name['Cache Swift packages']['with']['path'],'${{ runner.temp }}/SourcePackages')
   for step in (helper,*records,by_name['Cache Swift packages']):
    self.assertNotIn('continue-on-error',step)
   self.assertNotIn('chmod',helper['run'])
   self.assertNotIn('sudo',helper['run'])
   self.assertNotIn('skipPackagePluginValidation',helper['run'])
   for cache,prefix in [('Cache Swift packages','polaris-unsigned-apple-spm-'),('Cache Xcode build data','polaris-unsigned-apple-derived-data-')]:
    for key in ('key','restore-keys'):
     actual=by_name[cache]['with'][key]
     self.assertTrue(actual.startswith(prefix+overlay+'-'))
     self.assertNotIn('\napple-',actual)
  signed=(ROOT/'.github/workflows/signed-release.yml').read_text()
  self.assertNotIn('apple_package_overlays.py',signed)
  self.assertNotIn('polaris-unsigned-apple-',signed)
  contract=yaml.safe_load((ROOT/'.github/workflows/ci-contract.yml').read_text())
  commands=[s.get('run','') for s in contract['jobs']['contract']['steps']]
  for suite in ('test_apple_package_overlays.py','test_client_source.py'):
   self.assertIn("python -B -m unittest discover -s scripts/ci -p '"+suite+"'",commands)
 def test_unsigned_apple_lifecycle_mutations_are_rejected_for_both_jobs(self):
  workflow=yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text())
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary);(root/'.github/workflows').mkdir(parents=True)
   for name in ('signed-release.yml','ci-contract.yml'):
    shutil.copyfile(ROOT/'.github/workflows'/name,root/'.github/workflows'/name)
   for job_name in ('build_apple','build_apple_app_store'):
    for case in ('prune','early-collect','missing-collect','readonly-cache','foreign-cache','ignore-failure','trust-bypass','chmod',
                 'resolve-unlocked','archive-unlocked','standalone-unlocked','missing-preflight','late-preflight','preflight-ignored',
                 'missing-diagnostic','diagnostic-always','diagnostic-dump','upload-before-collect'):
     with self.subTest(job=job_name,case=case):
      mutated=copy.deepcopy(workflow);steps=mutated['jobs'][job_name]['steps']
      by_name={s.get('name'):s for s in steps}
      helper=by_name['Resolve and apply exact unsigned Apple package overlays']
      if case=='prune':steps.append({'name':'Renamed cleanup','run':'rm -r "$RUNNER_TEMP/SourcePackages/repositories"'})
      elif case=='early-collect':
       record=by_name['Record actual unsigned candidate files'];steps.remove(record);steps.insert(0,record)
      elif case=='missing-collect':steps.remove(by_name['Record actual unsigned candidate files'])
      elif case=='readonly-cache':by_name['Cache Swift packages']['with']['path']+=' /checkouts'
      elif case=='foreign-cache':by_name['Cache Swift packages']['with']['restore-keys']='apple-spm-'
      elif case=='ignore-failure':helper['continue-on-error']=True
      elif case=='trust-bypass':helper['run']=helper['run'].replace('xcodebuild -resolve','xcodebuild -skipPackagePluginValidation -resolve')
      elif case=='chmod':helper['run']=helper['run'].replace('set -euo pipefail','set -euo pipefail\nchmod -R u+w "$RUNNER_TEMP/SourcePackages"')
      elif case=='resolve-unlocked':helper['run']=helper['run'].replace('-disableAutomaticPackageResolution','')
      elif case=='archive-unlocked':by_name['Archive App Store build']['run']=by_name['Archive App Store build']['run'].replace('-disableAutomaticPackageResolution','')
      elif case=='standalone-unlocked':by_name['Build standalone packages']['env']['XCODEBUILD_FLAGS']=by_name['Build standalone packages']['env']['XCODEBUILD_FLAGS'].replace('-disableAutomaticPackageResolution','')
      elif case=='missing-preflight':steps.remove(by_name['Verify actual unsigned Apple sources before build'])
      elif case=='late-preflight':
       step=by_name['Verify actual unsigned Apple sources before build'];steps.remove(step);steps.append(step)
      elif case=='preflight-ignored':by_name['Verify actual unsigned Apple sources before build']['continue-on-error']=True
      elif case=='missing-diagnostic':steps.remove(by_name['Diagnose failed unsigned Apple sources'])
      elif case=='diagnostic-always':by_name['Diagnose failed unsigned Apple sources']['if']='always()'
      elif case=='diagnostic-dump':by_name['Diagnose failed unsigned Apple sources']['run']+='\nenv'
      elif case=='upload-before-collect':
       upload=next(s for s in steps if s.get('uses','').startswith('actions/upload-artifact@'));steps.remove(upload);steps.insert(0,upload)
      (root/'.github/workflows/build.yml').write_text(json.dumps(mutated))
      with mock.patch.object(sys.modules[__name__],'ROOT',root),self.assertRaises((AssertionError,KeyError)):
       self.test_unsigned_apple_package_overlays_cover_all_rows_and_preserve_trust()
 def _assert_all_producer_receipt_contract(self,workflow):
  # This checks the real workflow configuration, not GitHub's scheduler.
  jobs=workflow['jobs'];receipt=jobs['publisher_receipt']
  expected=('calculate_version','build','build_windows7','build_darwin','build_windows',
            'build_android_library','build_android','build_windows_client','build_linux_client',
            'build_apple_library','build_apple','build_apple_app_store','native_smoke','native_index','debian_materials')
  self.assertEqual(receipt['needs'],list(expected))
  clauses=('!failure()','!cancelled()',"inputs.build == 'All'",'!inputs.source_generate_only')
  clauses+=tuple("needs."+name+".result == 'success'" for name in expected[:-1])
  clauses+=("(needs.calculate_version.outputs.material_required == 'false' || (needs.calculate_version.outputs.material_required == 'true' && needs.debian_materials.result == 'success'))",)
  self.assertEqual(receipt['if'],'${{ '+' && '.join(clauses)+' }}')
  self.assertNotIn('continue-on-error',receipt)
  self.assertIn('prepare_windows7',jobs['build_windows7']['needs'])
  index=jobs['native_index']
  self.assertEqual(index['needs'],['calculate_version','build','build_windows7',
                                 'build_darwin','build_windows','native_smoke','native_windows_proof','debian_materials'])
  self.assertEqual(index['if'],"${{ !inputs.source_generate_only && !failure() && !cancelled() && (inputs.build == 'All' || inputs.build == 'Binary') && (inputs.windows_native_proof != true || needs.native_windows_proof.result == 'success') && needs.calculate_version.result == 'success' && needs.build.result == 'success' && needs.build_windows7.result == 'success' && needs.build_darwin.result == 'success' && needs.build_windows.result == 'success' && needs.native_smoke.result == 'success' && (needs.calculate_version.outputs.material_required == 'false' || (needs.calculate_version.outputs.material_required == 'true' && needs.debian_materials.result == 'success')) }}")
  field=workflow['on']['workflow_dispatch']['inputs']['windows_native_proof']
  self.assertEqual(field['type'],'boolean');self.assertIs(field['default'],False)
  native=jobs['native_windows_proof']
  self.assertEqual(native['environment'],'polaris-windows-native-proof')
  self.assertEqual(native['runs-on'],['self-hosted','Windows','X64','polaris-windows-system-proof'])
  steps=receipt['steps'];self.assertEqual(len(steps),3)
  self.assertEqual(steps[0],{'uses':'actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8',
                            'with':{'fetch-depth':0}})
  record=steps[1];upload=steps[2]
  self.assertEqual(record['name'],'Record exact completed scope')
  self.assertEqual(record['run'],'python3 scripts/ci/publisher_run_receipt.py')
  self.assertEqual(record['env'],{'PUBLISHER_ROLE':'all','RELEASE_BUILD':'${{ inputs.build }}',
                                'RELEASE_VERSION':'${{ inputs.version }}',
                                'PUBLISH_STORES':'false','PUBLISH_REGISTRY':'false',
                                 'POLARIS_DEBIAN_REQUIRED':'${{ needs.calculate_version.outputs.material_required }}',
                                 'POLARIS_DEBIAN_RAW_ID':'${{ needs.debian_materials.outputs.raw_id }}',
                                 'POLARIS_DEBIAN_RAW_DIGEST':'${{ needs.debian_materials.outputs.raw_digest }}',
                                 'POLARIS_DEBIAN_READY_ID':'${{ needs.debian_materials.outputs.ready_id }}',
                                 'POLARIS_DEBIAN_READY_DIGEST':'${{ needs.debian_materials.outputs.ready_digest }}',
                                 'GH_TOKEN':'${{ github.token }}'})
  self.assertEqual(upload['uses'],'actions/upload-artifact@v4')
  self.assertEqual(upload['with'],{'name':'publisher-run-receipt','path':'publisher-run-receipt.json',
                                 'if-no-files-found':'error'})
  for step in steps:
   self.assertNotIn('if',step);self.assertNotIn('continue-on-error',step)
 def test_all_receipt_requires_explicit_complete_producer_success(self):
  workflow=yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text())
  self._assert_all_producer_receipt_contract(workflow)
 def test_all_receipt_configuration_mutations_are_rejected(self):
  workflow=yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text())
  self._assert_all_producer_receipt_contract(workflow)
  receipt=workflow['jobs']['publisher_receipt'];condition=receipt['if'];cases=[]
  self.assertTrue(receipt['needs'])
  for name in receipt['needs'][:-1]:
   self.assertEqual(receipt['needs'].count(name),1)
   clause="needs."+name+".result == 'success'"
   self.assertEqual(condition.count(clause),1)
   cases.append((name+':missing-need','needs',[n for n in receipt['needs'] if n!=name]))
   cases.append((name+':missing-result','if',condition.replace(' && '+clause,'',1)))
   cases.append((name+':nonfailure-result','if',condition.replace(clause,"needs."+name+".result != 'failure'",1)))
   cases.append((name+':foreign-result-owner','if',condition.replace(clause,"needs.unregistered_producer.result == 'success'",1)))
   for status in ('failure','skipped','cancelled','unknown'):
    cases.append((name+':'+status+'-result','if',condition.replace(clause,"needs."+name+".result == '"+status+"'",1)))
  for label,anchor in (('missing-no-failure','!failure() && '),
                       ('missing-no-cancel','!cancelled() && '),
                       ('missing-All',"inputs.build == 'All' && "),
                       ('missing-source-only',' && !inputs.source_generate_only')):
   self.assertEqual(condition.count(anchor),1)
   cases.append((label,'if',condition.replace(anchor,'',1)))
  cases.append(('generic-success','if',"success() && inputs.build == 'All' && !inputs.source_generate_only"))
  cases.append(('unconditional-always','if','always()'))
  for label,index,key,value in (('synthetic-record',1,'run',"printf '{}' > publisher-run-receipt.json"),
                                ('foreign-role',1,'env',dict(receipt['steps'][1]['env'],PUBLISHER_ROLE='linux')),
                                ('foreign-version',1,'env',dict(receipt['steps'][1]['env'],RELEASE_VERSION='1.15.0-polaris-alpha.12.10')),
                                ('publish-stores',1,'env',dict(receipt['steps'][1]['env'],PUBLISH_STORES='true')),
                                ('publish-registry',1,'env',dict(receipt['steps'][1]['env'],PUBLISH_REGISTRY='true')),
                                ('conditional-upload',2,'if','false'),
                                ('ignore-record-failure',1,'continue-on-error',True),
                                ('allow-missing-receipt',2,'with',dict(receipt['steps'][2]['with'],**{'if-no-files-found':'ignore'}))):
   steps=copy.deepcopy(receipt['steps']);steps[index][key]=value
   cases.append((label,'steps',steps))
  for label,field,value in cases:
   with self.subTest(case=label):
    # A broken unmodified producer must fail outside assertRaises, never feed a negative green.
    self._assert_all_producer_receipt_contract(workflow)
    changed=copy.deepcopy(workflow);changed['jobs']['publisher_receipt'][field]=value
    self.assertNotEqual(value,receipt[field])
    restored=copy.deepcopy(changed);restored['jobs']['publisher_receipt'][field]=copy.deepcopy(receipt[field])
    self.assertEqual(restored,workflow)
    self.assertNotEqual(changed,workflow)
    with self.assertRaises((AssertionError,KeyError)):
     self._assert_all_producer_receipt_contract(changed)
  # These are configuration controls. Only a later hosted run can prove actual
  # scheduling after a skipped optional ancestor and upload the genuine receipt.
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
    if filename=='build.yml' and job=='build':
     from test_protocol_peer import normal_build_matrix
     actual=normal_build_matrix(actual)
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
 def test_unsigned_annotated_identity_checkouts_pin_dispatch_sha(self):
  self.assert_local_annotated_checkouts('build.yml',{'calculate_version','native_index'})
 def test_signed_source_annotated_identity_checkouts_pin_dispatch_sha(self):
  self.assert_local_annotated_checkouts('signed-release.yml',{'calculate_version','native_index','upload'})
 def assert_local_annotated_checkouts(self,filename,expected):
  workflow=yaml.safe_load((ROOT/'.github/workflows'/filename).read_text())
  bridge_call="assemble('artifacts', measure_debian=producer_debian_materials)"
  # Both local annotated-tag gates must keep the full-history tag objects.
  # An implicit tag ref lets checkout overwrite the tag with the event commit.
  gates={name:job for name,job in workflow['jobs'].items() if any(
   'scripts/ci/release_identity.py' in step.get('run','') or
   'scripts/ci/owned_distribution.py verify-tag' in step.get('run','') or
   'scripts/ci/native_release_index.py assemble' in step.get('run','') or bridge_call in step.get('run','')
   for step in job['steps'])}
  self.assertEqual(set(gates),expected)
  for name,job in gates.items():
   with self.subTest(job=name):
    checkouts=[step for step in job['steps'] if step.get('uses','').startswith('actions/checkout@')]
    self.assertEqual(len(checkouts),1)
    checkout=checkouts[0]
    self.assertEqual(checkout['uses'],'actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8')
    self.assertEqual(checkout['with'].get('ref'),'${{ github.sha }}')
    self.assertEqual(checkout['with'].get('fetch-depth'),0)
    for index,step in enumerate(job['steps']):
     if any(command in step.get('run','') for command in ('scripts/ci/release_identity.py','scripts/ci/native_release_index.py assemble','scripts/ci/owned_distribution.py verify-tag',bridge_call)):
      self.assertLess(job['steps'].index(checkout),index)
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
  import publisher_peer_successor
  self.assertEqual(publisher_peer_successor.VERSION,release['version'])
  self.assertEqual((ROOT/'constant/version.go').read_text(),'package constant\n\nvar Version = \"unknown\"\n')
  self.assertIn('return C.Version',(ROOT/'experimental/libbox/setup.go').read_text())
  self.assertIn('github.com/sagernet/sing-box/constant.Version=${{ needs.calculate_version.outputs.version }}',(ROOT/'.github/workflows/build.yml').read_text())
  w=yaml.safe_load((ROOT/'.github/workflows/docker.yml').read_text())
  step=next(s for s in w['jobs']['build_docker']['steps'] if s.get('uses','').startswith('docker/build-push-action@'))
  self.assertEqual(step['env']['DOCKER_BUILD_RECORD_UPLOAD'],'false')
  self.assertFalse(step['with']['push']);self.assertIn('type=oci,dest=',step['with']['outputs'])
 def test_unsigned_packaging_preserves_plugin_validation_and_private_apk_tools(self):
  text=(ROOT/'.github/workflows/build.yml').read_text()
  self.assertNotIn('IDESkipPackagePluginFingerprintValidatation',text)
  self.assertNotIn('-skipPackagePluginValidation',text)
  w=yaml.safe_load(text)
  standalone=[s for job in w['jobs'].values() for s in job['steps'] if s.get('name')=='Build standalone packages']
  self.assertEqual(len(standalone),2)
  for step in standalone:
   # Upstream Makefile defaults include a validation skip: retain this explicit override.
   self.assertEqual(step['env']['XCODEBUILD_FLAGS'],
                    '-disableAutomaticPackageResolution -clonedSourcePackagesDirPath "${{ runner.temp }}/SourcePackages" CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY=""')
  step=next(s for s in w['jobs']['build']['steps'] if s.get('name')=='Install apk-tools')
  self.assertEqual(step['if'],"fromJSON(toJSON(matrix)).openwrt != '' || fromJSON(toJSON(matrix)).alpine != ''")
  steps=w['jobs']['build']['steps']
  for name in ['Package OpenWrt APK','Package Alpine APK']:
   consumer=next(s for s in steps if s.get('name')==name)
   self.assertLess(steps.index(step),steps.index(consumer))
  run=step['run']
  for fragment in ['apk add --no-cache apk-tools-static && cp /sbin/apk.static /mnt/apk && chmod 755 /mnt/apk',
                   'set -euo pipefail','mktemp -d "$RUNNER_TEMP/apk-tools.XXXXXX"',
                   'docker run --rm -v "$apk_tools_dir:/mnt" alpine:edge',
                   'test -x "$apk_tools_dir/apk"','echo "$apk_tools_dir" >> "$GITHUB_PATH"']:
   self.assertIn(fragment,run)
  self.assertNotIn('/usr/local/bin',run);self.assertNotIn('--privileged',run)
  for name in ['build_alpine_apk.sh','build_openwrt_apk.sh']:
   self.assertIn('apk --root ',(ROOT/'.github'/name).read_text())
 def test_existing_build_entry_can_run_pretag_source_gates_without_products(self):
  w=yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text())
  self.assertIn('Source',w['on']['workflow_dispatch']['inputs']['build']['options'])
  self.assertEqual(w['jobs']['source_gate']['if'],"inputs.build == 'Source' && !inputs.source_generate_only")
  self.assertEqual(w['jobs']['calculate_version']['if'],"(inputs.build != 'Source' && !inputs.source_generate_only) || inputs.build == 'NativePeerDiagnostic' || inputs.build == 'NativePeerLinux'")
  gate=w['jobs']['source_gate'];self.assertEqual(gate['strategy']['matrix']['os'],['ubuntu-24.04','macos-15','xcode-27'])
  self.assertTrue(any('unittest discover' in x.get('run','') for x in gate['steps']))
  self.assertTrue(any(x.get('run')=='python3 scripts/ci/g4_candidate.py' for x in gate['steps']))
  self.assertEqual(w['permissions']['contents'],'read')
 def test_four_material_callers_prepare_before_download(self):
  for file,name in [('build.yml','build'),('build.yml','build_linux_client'),('linux.yml','build'),('docker.yml','build_binary')]:
   steps=yaml.safe_load((ROOT/'.github/workflows'/file).read_text())['jobs'][name]['steps']
   clone,keyring,download=[next(s for s in steps if s.get('name')==n) for n in ('Clone cronet-go','Regenerate Debian keyring','Download Chromium toolchain')]
   self.assertTrue(steps.index(clone)<steps.index(keyring)<steps.index(download))
   self.assertTrue(clone['run'].rstrip().endswith('python3 "$GITHUB_WORKSPACE/scripts/ci/cronet_material_bootstrap.py" prepare --cronet-root "$HOME/cronet-go"'))
   self.assertEqual((clone.get('timeout-minutes'),download.get('timeout-minutes')),(10,20))
   for step in (clone,keyring,download):self.assertNotIn('continue-on-error',step)
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
  for fragment in ['./service/api', 'TestRuntimePublicCapabilityRequiresStartedGraphAndPreservesReplay', 'TestRuntimeCapabilityBuildInventoryIsCanonicalAndHonest', 'TestRuntimePublicCommandRegenerationPersistenceChain', "os.environ['RUNNER_OS'] == 'Linux'", "os.environ['RUNNER_OS'] in {'Linux', 'macOS'}"]:
   self.assertIn(fragment,run)
  self.assertNotIn('TestRuntimePublicCapabilityGateDoesNotInvokePrivateApply',run)
 def test_go_utls_gate_is_part_of_one_existing_source_dispatch(self):
  w=yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text())
  gate=w['jobs']['utls_gate']
  self.assertEqual(gate['if'],"inputs.build == 'Source' && !inputs.source_generate_only")
  self.assertEqual(gate['strategy']['matrix']['os'],['ubuntu-24.04','windows-2025','macos-15','xcode-27'])
  self.assertFalse(gate['strategy']['fail-fast'])
  self.assertTrue(any(s.get('with',{}).get('go-version-file')=='release/GO_VERSION' for s in gate['steps']))
  self.assertTrue(any('utls_gate.py' in s.get('run','') for s in gate['steps']))
  early,cost=source_cost_steps_contract(gate)
  self.assertEqual(cost['if'],"always() && matrix.os == 'ubuntu-24.04'")
 def test_cost_input_and_measurement_invocations_coexist_without_first_match_ambiguity(self):
  gate=yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text())['jobs']['utls_gate']
  early,cost=source_cost_steps_contract(gate)
  calls=[step for step in gate['steps'] if 'utls_cost.py' in step.get('run','')]
  self.assertEqual(calls,[early,cost]);self.assertIsNot(early,cost)
  self.assertIn('--retain-source-input',shlex.split(early['run']))
  self.assertNotIn('--retain-source-input',shlex.split(cost['run']))
  self.assertNotIn('if',early);self.assertNotIn('continue-on-error',early)
  self.assertEqual(cost['name'],'Measure whole-migration binary and idle RSS costs')
  self.assertEqual(cost['if'],"always() && matrix.os == 'ubuntu-24.04'")
  self.assertIs(cost['continue-on-error'],True)
 def test_cost_step_duplicate_missing_renamed_and_wrong_phase_commands_are_rejected(self):
  original=yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text())['jobs']['utls_gate']
  for mutation in ('duplicate-early','duplicate-cost','missing-early','missing-cost','renamed-cost',
                   'early-as-measurement','measurement-as-early','wrong-cost-program','malformed-command','third-invocation','reversed'):
   gate=copy.deepcopy(original);steps=gate['steps'];early,cost=source_cost_steps_contract(gate)
   if mutation=='duplicate-early':steps.append(copy.deepcopy(early))
   elif mutation=='duplicate-cost':steps.append(copy.deepcopy(cost))
   elif mutation=='missing-early':steps.remove(early)
   elif mutation=='missing-cost':steps.remove(cost)
   elif mutation=='renamed-cost':cost['name']='Unreviewed cost observation'
   elif mutation=='early-as-measurement':cost['run']=early['run']
   elif mutation=='measurement-as-early':early['run']=cost['run']
   elif mutation=='wrong-cost-program':cost['run']=cost['run'].replace('scripts/ci/utls_cost.py','scripts/ci/unreviewed.py')
   elif mutation=='malformed-command':cost['run']+=" '"
   elif mutation=='third-invocation':steps.append(dict(cost,name='Unreviewed extra invocation'))
   else:
    a,b=steps.index(early),steps.index(cost);steps[a],steps[b]=steps[b],steps[a]
   with self.subTest(mutation=mutation),self.assertRaises(AssertionError):source_cost_steps_contract(gate)
 def test_early_cost_receipt_scope_order_and_measurement_only_predicate_cannot_cross(self):
  original=yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text())['jobs']['utls_gate']
  for mutation in ('early-if','early-ignore','early-env','before-checkout','before-python',
                   'after-go','after-pip','after-unicode','foreign-input','measurement-if','measurement-fatal','shared-output','upload-ignore'):
   gate=copy.deepcopy(original);steps=gate['steps'];early,cost=source_cost_steps_contract(gate)
   if mutation=='early-if':early['if']=cost['if']
   elif mutation=='early-ignore':early['continue-on-error']=True
   elif mutation=='early-env':early['env']={'SOURCE_BUILD':'Binary'}
   elif mutation in ('before-checkout','before-python','after-go','after-pip','after-unicode'):
    if mutation=='before-checkout':target=next(step for step in steps if step.get('uses','').startswith('actions/checkout@'))
    elif mutation=='before-python':target=next(step for step in steps if step.get('uses','').startswith('actions/setup-python@'))
    elif mutation=='after-go':target=next(step for step in steps if step.get('uses','').startswith('actions/setup-go@'))
    elif mutation=='after-pip':target=next(step for step in steps if 'pip install' in step.get('run',''))
    else:target=next(step for step in steps if 'test_client_encoding.py' in step.get('run',''))
    steps.remove(early);steps.insert(steps.index(target)+(0 if mutation.startswith('before-') else 1),early)
   elif mutation=='foreign-input':gate['env']['SOURCE_WINDOWS_NATIVE_PROOF']='true'
   elif mutation=='measurement-if':cost['if']="matrix.os == 'ubuntu-24.04'"
   elif mutation=='measurement-fatal':cost['continue-on-error']=False
   elif mutation=='shared-output':cost['run']=cost['run'].replace('/tls-fingerprint-evidence/cost','/tls-fingerprint-evidence')
   else:next(step for step in steps if step.get('uses','').startswith('actions/upload-artifact@'))['with']['if-no-files-found']='ignore'
   with self.subTest(mutation=mutation),self.assertRaises(AssertionError):source_cost_steps_contract(gate)
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
  # Keep each reviewed boundary explicit: six SA1019 rules have distinct
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
   'h2c-server':{
    'linters':['staticcheck'],
    'path':r'^protocol/naive/inbound_runtime_tcp\.go$',
    'text':r'^SA1019: golang\.org/x/net/http2\.Server is deprecated: Use \[http\.Server\] instead\. $',
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
  rules=config['linters']['exclusions']['rules'];self.assertEqual(len(rules),7)
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
 def test_reviewed_compatibility_exclusions_match_only_eight_exact_diagnostics(self):
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
   ('h2c-server','protocol/naive/inbound_runtime_tcp.go',
    'SA1019: golang.org/x/net/http2.Server is deprecated: Use [http.Server] instead.',
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
    actual=[(number,line) for number,line in enumerate((ROOT/path).read_text().splitlines(),1) if re.search(rule['source'],line)]
    self.assertEqual([line.strip() for _,line in actual],statements)
    for line_number,source in actual:
     # Every approved diagnostic has exactly one matching rule, even when two
     # rules share a path or several diagnostics share a code and statement.
     self.assertEqual([key for key,value in rules.items()
                       if self.rule_matches(value,'staticcheck',path,message,source)],[name])
     matched.append((name,path,line_number,message,source))
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
  self.assertEqual(len(matched),8)
  self.assertEqual(len({(row[1],row[2]) for row in matched}),7)
  # The rejected server-only field must not inherit the client Rand exception.
  message='SA1019: (crypto/tls.Config).NameToCertificate has been deprecated since Go 1.14: NameToCertificate only allows associating a single certificate with a given name. Leave this field nil to let the library select the first compatible chain from Certificates.'
  self.assertFalse(any(self.rule_matches(rule,'staticcheck','common/httpclient/runtime_quic_tls.go',
                                       message,'if config.NameToCertificate != nil {') for rule in rules.values()))
 def test_same_line_deprecations_are_filtered_before_line_deduplication(self):
  # v2.15.0 runs exclusion_rules before uniq_by_line, whose key omits text
  # and column. Review the complete symbol inventory, not only displayed rows.
  rules=self.lint_rules()
  path='protocol/naive/inbound_runtime_tcp.go'
  source='\t\tHandler:     h2c.NewHandler(n, &http2.Server{}),'
  messages=[
   'SA1019: golang.org/x/net/http2/h2c.NewHandler is deprecated: Set the [http.Server] Protocols field to use unencrypted HTTP/2 instead. ',
   'SA1019: golang.org/x/net/http2.Server is deprecated: Use [http.Server] instead. ']
  def exclude(rows,selected):
   return [row for row in rows if not any(self.rule_matches(rule,'staticcheck',path,row[2],source) for rule in selected)]
  def unique(rows):
   seen=set();result=[]
   for row in rows:
    key=(path,row[0])
    if key not in seen:result.append(row);seen.add(key)
   return result
  rows=[(45,16,messages[0]),(45,35,messages[1])]
  for ordered in [rows,list(reversed(rows))]:
   with self.subTest(order=[row[1] for row in ordered]):
    self.assertEqual(len(unique(ordered)),1)
    old=[rule for name,rule in rules.items() if name!='h2c-server']
    self.assertEqual(unique(exclude(ordered,old)),[rows[1]])
    self.assertEqual(unique(exclude(ordered,rules.values())),[])
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

    def test_production_release_workflows_keep_shared_branch_track_guard(self):
        for filename, job_name in [('signed-linux.yml', 'build'),
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

    def run_queue(self, selected=None, resolved=None, authorized='false', modules=(),
                  statuses=None, outputs=None, recheck=0, artifact='regular', identity=None):
        """Run the unchanged workflow shell with inert Go/forbidden-command fixtures."""
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
            config.write_text(json.dumps({'resolved': resolved, 'statuses': statuses or {},
                                          'outputs': outputs or {}, 'artifact': artifact}))
            log = root / 'calls.jsonl'
            # Executing sudo, the retired guard or a compiled fixture records a
            # forbidden call and fails. None can escape to real external tools.
            stub = r"""import json, os, sys
from pathlib import Path
args = sys.argv[1:]
tool = Path(sys.argv[0]).name
config = json.loads(Path(os.environ['FIXTURE_CONFIG']).read_text())
cwd = Path.cwd().relative_to(Path(os.environ['FIXTURE_ROOT'])).as_posix()
record = {'tool': tool, 'args': args, 'cwd': cwd}
if tool == 'go' and '-c' in args:
    record['compileGOMAXPROCS'] = os.environ.get('GOMAXPROCS')
with open(os.environ['FIXTURE_CALLS'], 'a') as stream:
    stream.write(json.dumps(record) + '\n')
if tool != 'go':
    raise SystemExit(96)
if args and args[0] == 'list':
    sys.stdout.write(''.join(package + '\n' for package in config['resolved']))
    raise SystemExit(config['statuses'].get('list', 0))
if not args or args[0] != 'test' or '-exec' in args:
    raise SystemExit(95)
group = ('netns' if 'github.com/sagernet/sing-box/common/netns' in args
         else 'sing-tun-ping' if cwd == 'third_party/sing-tun' and './ping' in args
         else Path(cwd).name if cwd != '.' else 'ordinary')
if group == 'netns':
    if '-c' not in args or '-race' not in args:
        raise SystemExit(94)
    status = config['statuses'].get(group, 0)
    if status:
        raise SystemExit(status)
    target = Path(args[args.index('-o') + 1])
    kind = config['artifact']
    if kind == 'symlink':
        target.symlink_to(Path(sys.argv[0]).resolve())
    elif kind != 'missing':
        target.write_bytes(b'' if kind == 'empty' else Path(sys.argv[0]).read_bytes())
        target.chmod(0o600 if kind == 'non-executable' else 0o700)
    raise SystemExit(0)
output = ('--- PASS: TestNaiveAdmissionSealsBeforeJoin (0.00s)\n--- PASS: TestNaiveDialCreationBarrierAndTerminalOwnership (0.00s)\nok fixture/cronet-go\n'
          if group == 'cronet-go' else '--- PASS: TestFailedAddClosesUnpublishedWatcher (0.00s)\n--- PASS: TestSuccessfulAddTransfersWithoutClosing (0.00s)\n--- PASS: TestFailedAddPreservesCleanupFailure (0.00s)\nok fixture/fswatch\n'
          if group == 'fswatch' else '--- PASS: TestRuntimePacketContextRetainsBeforeLaunchAndJoinsTerminalTail (0.00s)\n--- PASS: TestRuntimePacketContextFailureDoesNotPublishSession (0.00s)\nok fixture/sing\n'
          if group == 'sing' else 'ok fixture/' + group + '\n')
sys.stdout.write(config['outputs'].get(group, output))
raise SystemExit(config['statuses'].get(group, 0))
"""
            for name in ['go', 'sudo', 'python3']:
                path = bin_dir / name
                path.write_text('#!' + sys.executable + '\n' + stub)
                path.chmod(0o755)
            for name in ['cat', 'tee', 'grep', 'mktemp', 'rm']:
                executable = shutil.which(name)
                self.assertIsNotNone(executable, name)
                (bin_dir / name).symlink_to(executable)
            env = {'PATH': str(bin_dir), 'HOME': str(root), 'TMPDIR': str(root),
                   'LC_ALL': 'C', 'selection_dir': str(selection), 'BASE_REF': 'v1.2.3',
                   'POLARIS_COMPILE_GOMAXPROCS': '1', 'POLARIS_GO_JOBS': '3',
                   'INSTANCE_TESTS': 'TestInstanceOne|TestInstanceTwo',
                   'SING_TUN_INSTANCE_TESTS': 'TestTunOne|TestPing',
                   'NETNS_BATCH_ELEVATION': authorized, 'FIXTURE_CONFIG': str(config),
                   'FIXTURE_ROOT': str(root), 'FIXTURE_CALLS': str(log), 'RUNNER_TEMP': str(root),
                   'GITHUB_STEP_SUMMARY': str(root / 'summary'),
                   'GOVERNANCE_NETNS_SHA': 'd' * 40, 'POLARIS_CI_GOVERNANCE_NETNS_SHA': 'd' * 40,
                   'GITHUB_SHA': 'd' * 40, 'SOURCE_COMMIT': 'd' * 40,
                   'GITHUB_REPOSITORY': 'polaris-arch/sing-box-polaris', 'GITHUB_REPOSITORY_ID': '1421657509',
                   'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/ci/governance',
                   'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux',
                   'FIXTURE_AUTH_RC': str(recheck)}
            for name, value in (identity or {}).items():
                if value is None:
                    env.pop(name, None)
                else:
                    env[name] = value
            result = subprocess.run([bash] + launch[1:-1] + ['-c', body],
                                    cwd=root, env=env, capture_output=True, text=True, timeout=15)
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            self.authorization_calls = [c for c in calls if c['tool'] == 'python3']
            self.assertTrue(all(c['tool'] == 'go' and '-exec' not in c['args'] for c in calls), calls)
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
        self.assertFalse(elevated, 'CI may never elevate a netns test')
        args = ['test']
        record = dict(call)
        actual = list(record['args'])
        if packages == [self.NETNS]:
            self.assertEqual(record.pop('compileGOMAXPROCS'), '1')
            args += ['-p', '3']
        args += ['-race', '-count=1']
        if packages == [self.NETNS]:
            args += ['-v', '-c']
            at = actual.index('-o')
            self.assertEqual(Path(actual[at + 1]).name, 'netns.test')
            del actual[at:at + 2]
        args += ['-skip', '^(TestInstanceOne|TestInstanceTwo)$', '-tags', self.TAGS,
                 '-ldflags', self.LDFLAGS] + packages
        self.assertEqual({**record, 'args': actual}, {'tool': 'go', 'args': args, 'cwd': '.'})

    def test_retired_authorization_has_no_elevation_input(self):
        self.assertFalse(any(s.get('id') == 'netns_batch_authorization' for s in self.steps))
        self.assertNotIn('env', self.step)
        self.assertFalse(self.step.get('continue-on-error', False))
        self.assertFalse(self.document['jobs']['patch_tests'].get('continue-on-error', False))
        for command in [self.step['run'], next(s['run'] for s in self.steps if s.get('name') == 'Test instances in process')]:
            executable = '\n'.join(line for line in command.splitlines() if not line.lstrip().startswith('#'))
            self.assertNotIn('sudo', executable)
            self.assertNotIn('-exec', executable)
            self.assertNotIn('GOVERNANCE_NETNS_SHA', command)
        self.assertIn('raced compilation only', self.step['run'])
        self.assertIn('GITHUB_STEP_SUMMARY', self.step['run'])

    def test_wildcard_selection_runs_ordinary_group_then_only_netns_compile(self):
        result, calls = self.run_queue(authorized='true')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[0], {'tool': 'go', 'args': ['list', '-tags', self.TAGS, './...'], 'cwd': '.'})
        self.assert_root_test(calls[1], self.ORDINARY)
        self.assert_root_test(calls[2], [self.NETNS])
        self.assertNotIn('PASS: TestUnshareNamespace', result.stdout)

    def test_old_approval_never_executes_and_exact_package_partition_is_preserved(self):
        for approved in ['true', 'false', '', 'TRUE', 'true ', '1']:
            with self.subTest(authorized=approved):
                result, calls = self.run_queue(authorized=approved)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(calls), 3)
                self.assertEqual(self.authorization_calls, [])
                self.assert_root_test(calls[1], self.ORDINARY)
                self.assert_root_test(calls[2], [self.NETNS])
        packages = self.ORDINARY + [self.NETNS + '/child', self.NETNS + 'extra']
        result, calls = self.run_queue(selected=['./adapter', './daemon', './common/netns...'],
                                       resolved=packages, authorized='true')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[0]['args'][-3:], ['./adapter', './daemon', './common/netns...'])
        self.assertEqual(len(calls), 2)
        self.assert_root_test(calls[1], packages)

    def test_old_recheck_status_cannot_change_compile_only_or_hide_compile_failure(self):
        for recheck in [0, 1, 2, 23]:
            with self.subTest(recheck=recheck):
                result, calls = self.run_queue(authorized='true', recheck=recheck,
                                               modules=['sing-tun', 'metacubex-utls'], statuses={'netns': 29})
                self.assertEqual(result.returncode, 29, result.stderr)
                self.assertEqual(self.authorization_calls, [])
                self.assertEqual(len(calls), 6)
                self.assert_root_test(calls[-1], [self.NETNS])
        for artifact in ['missing', 'empty', 'non-executable', 'symlink']:
            result, calls = self.run_queue(authorized='false', artifact=artifact)
            self.assertNotEqual(result.returncode, 0, artifact)
            self.assert_root_test(calls[-1], [self.NETNS])

    def test_empty_and_netns_only_selection_never_expand_test_scope(self):
        result, calls = self.run_queue(selected=[], resolved=[], authorized='true')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [])
        result, calls = self.run_queue(selected=['./common/netns'], resolved=[self.NETNS], authorized='true')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2)
        self.assert_root_test(calls[1], [self.NETNS])

    def test_list_errors_and_empty_resolution_fail_before_tests(self):
        for resolved, statuses in [(self.ORDINARY + [self.NETNS], {'list': 17}), ([], {})]:
            with self.subTest(resolved=resolved, statuses=statuses):
                result, calls = self.run_queue(resolved=resolved, statuses=statuses, authorized='true')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0]['args'][0], 'list')

    def test_test_and_compile_failures_survive_tee_and_stop_later_groups(self):
        for group, approved, count in [('ordinary', 'true', 2), ('netns', 'true', 6), ('netns', 'false', 6)]:
            with self.subTest(group=group, authorized=approved):
                result, calls = self.run_queue(authorized=approved, statuses={group: 23},
                                               modules=['sing-tun', 'metacubex-utls'])
                self.assertEqual(result.returncode, 23, result.stderr)
                self.assertEqual(len(calls), count)
                owners = ['.', '.']
                if group == 'netns':
                    owners += ['third_party/sing-tun', 'third_party/sing-tun', 'third_party/metacubex-utls', '.']
                self.assertEqual([c['cwd'] for c in calls], owners)

    def test_success_requires_ordinary_ok_and_a_real_nonempty_compile_artifact(self):
        result, calls = self.run_queue(outputs={'ordinary': '? fixture [no test files]\n'},
                                       modules=['sing-tun', 'metacubex-utls'])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([c['cwd'] for c in calls], ['.', '.'])
        for artifact in ['missing', 'empty', 'non-executable', 'symlink']:
            with self.subTest(artifact=artifact):
                result, calls = self.run_queue(authorized='true', artifact=artifact,
                                               modules=['sing-tun', 'metacubex-utls'])
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual([c['cwd'] for c in calls], ['.', '.', 'third_party/sing-tun',
                                                          'third_party/sing-tun', 'third_party/metacubex-utls', '.'])
                self.assertNotIn('PASS: TestUnshareNamespace', result.stdout)

    def test_selected_owned_modules_keep_separate_unprivileged_coverage(self):
        expected = [
            {'tool': 'go', 'cwd': 'third_party/sing-tun',
             'args': ['test', '-race', '-count=1', '-skip', '^(TestTunOne|TestPing)$', '-tags', self.TAGS, './...']},
            {'tool': 'go', 'cwd': 'third_party/sing-tun',
             'args': ['test', '-race', '-count=1', '-v', '-tags', self.TAGS,
                      '-run', '^TestPing$/^(ipv4|ipv6)$/^unprivileged$', './ping']},
            {'tool': 'go', 'cwd': 'third_party/metacubex-utls',
             'args': ['test', '-race', '-count=1', '-tags', self.TAGS, './...']}]
        # Nested owners execute before the separately compiled netns test binary.
        for selected in [[], ['./...']]:
            with self.subTest(root_selection=selected):
                result, calls = self.run_queue(selected=selected, authorized='true',
                                               modules=['sing-tun', 'metacubex-utls'])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(calls), 6 if selected else 3)
                self.assertEqual(calls[2:5] if selected else calls, expected)
                if selected:
                    self.assert_root_test(calls[1], self.ORDINARY)
                    self.assert_root_test(calls[-1], [self.NETNS])
                self.assertEqual(sum(c['tool'] == 'sudo' for c in calls), 0)
        for module in ['sing-tun', 'sing-tun-ping', 'metacubex-utls']:
            with self.subTest(failing_module=module):
                result, calls = self.run_queue(selected=[], authorized='true',
                                               modules=['sing-tun', 'metacubex-utls'], statuses={module: 29})
                self.assertEqual(result.returncode, 29, result.stderr)
                self.assertTrue(all(c['tool'] == 'go' and '-exec' not in c['args'] for c in calls))


class TestNetnsBatchAuthorization(unittest.TestCase):
    """Historical authorization inputs are now inert, including formerly valid ones."""
    SHA = 'd' * 40
    OTHER = 'e' * 40
    HELPER = ROOT / 'scripts/ci/netns_authorization.py'

    def assert_compile_only(self, changes=None):
        fixture = TestPatchQueueNetnsContract()
        fixture.setUpClass()
        result, calls = fixture.run_queue(authorized='true', identity=changes)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(fixture.authorization_calls, [])
        self.assertEqual(len(calls), 3)
        fixture.assert_root_test(calls[-1], [fixture.NETNS])
        self.assertNotIn('PASS: TestUnshareNamespace', result.stdout)

    def test_even_exact_approved_hosted_workflow_and_source_cannot_authorize_execution(self):
        for kind in ['push', 'workflow_dispatch']:
            for ref in ['refs/heads/polaris-main', 'refs/heads/ci/governance']:
                with self.subTest(kind=kind, ref=ref):
                    self.assert_compile_only({'GITHUB_EVENT_NAME': kind, 'GITHUB_REF': ref})

    def test_missing_malformed_wrong_or_untrusted_identity_never_authorizes(self):
        changes = [{'GOVERNANCE_NETNS_SHA': value} for value in
                   [None, '', self.SHA.upper(), self.SHA[:-1], self.SHA + '0', self.SHA + '\n', self.OTHER]]
        changes += [{name: value} for name, value in [
            ('GITHUB_REPOSITORY', 'fork/sing-box-polaris'), ('GITHUB_REPOSITORY_ID', '1'),
            ('GITHUB_SHA', self.OTHER), ('SOURCE_COMMIT', self.OTHER),
            ('RUNNER_ENVIRONMENT', 'self-hosted'), ('RUNNER_OS', 'Windows'), ('RUNNER_OS', 'macOS'),
            ('GITHUB_EVENT_NAME', 'pull_request'), ('GITHUB_EVENT_NAME', 'pull_request_target'),
            ('GITHUB_EVENT_NAME', 'schedule'), ('GITHUB_REF', 'refs/heads/other'),
            ('GITHUB_REF', 'refs/tags/polaris-test')]]
        changes += [{name: None} for name in ['GITHUB_REPOSITORY', 'GITHUB_REPOSITORY_ID',
                    'GITHUB_EVENT_NAME', 'GITHUB_REF', 'GITHUB_SHA', 'SOURCE_COMMIT',
                    'RUNNER_ENVIRONMENT', 'RUNNER_OS']]
        for change in changes:
            with self.subTest(change=change):
                self.assert_compile_only(change)

    def test_head_mismatch_dirty_checkout_and_git_errors_cannot_restore_the_retired_guard(self):
        self.assertFalse(self.HELPER.exists())
        for change in [{'GITHUB_SHA': self.OTHER}, {'SOURCE_COMMIT': self.OTHER},
                       {'FIXTURE_AUTH_RC': '1'}, {'FIXTURE_AUTH_RC': '23'}]:
            with self.subTest(change=change):
                self.assert_compile_only(change)
        # The compile step has no guard/Git command to fall back to, even on a
        # dirty checkout or a Git lookup error; source admission remains separate.
        for filename in ['test.yml', 'polaris-selfcheck.yml']:
            text = (ROOT / '.github/workflows' / filename).read_text()
            for token in ['netns_authorization.py', 'NETNS_BATCH_ELEVATION', 'GOVERNANCE_NETNS_SHA']:
                self.assertNotIn(token, text)

    def test_old_pr2_head_and_merge_are_never_an_alternate_authorization(self):
        for sha in ['846406cb04529cd942c6c12829c83fd99d6e878e',
                    '48977ba52bcb4920bd4cd87abcbe31e5b59005f7']:
            for kind in ['pull_request', 'push']:
                self.assert_compile_only({'GOVERNANCE_NETNS_SHA': None,
                    'SOURCE_COMMIT': sha, 'GITHUB_SHA': sha, 'GITHUB_EVENT_NAME': kind})
        workflow = (ROOT / '.github/workflows/polaris-selfcheck.yml').read_text()
        for forbidden in ['GH_TOKEN', 'api.github.com', '/pulls/2', 'collab/dots-audit-remediation-20261017']:
            self.assertNotIn(forbidden, workflow)

    def test_both_workflows_have_no_guard_or_privileged_netns_consumer(self):
        self.assertFalse(self.HELPER.exists())
        for filename, job in [('test.yml', 'test'), ('polaris-selfcheck.yml', 'patch_tests')]:
            document = yaml.safe_load((ROOT / '.github/workflows' / filename).read_text())
            steps = document['jobs'][job]['steps']
            self.assertFalse(any(s.get('id') == 'netns_batch_authorization' for s in steps))
            command = next(s['run'] for s in steps if 'netns.test' in s.get('run', ''))
            for forbidden in ['sudo', '-exec', 'GOVERNANCE_NETNS_SHA', 'netns_authorization.py']:
                self.assertNotIn(forbidden, command)
            self.assertIn('compilation only', command)
            self.assertIn('GITHUB_STEP_SUMMARY', command)
            self.assertIn('go test -p 2 -c' if filename == 'test.yml' else 'go test -p "$POLARIS_GO_JOBS" -race -count=1 -v -c', command)
        # The real native case remains a developer-machine requirement, unskipped.
        native = (ROOT / 'common/netns/manager_test.go').read_text()
        self.assertIn('func TestUnshareNamespace(t *testing.T)', native)
        self.assertNotIn('t.Skip', native)


class TestFinalSourceEntrypoints(unittest.TestCase):
    EXPECTED = {
        'TestAutoRedirectCloseBeforeFirewallSetupPreservesRunningInstance',
        'TestAutoRedirectAttemptedFirewallRetainsLegacyCleanup',
        'TestAutoRedirectNFTCloseWithoutSetupDoesNotEnterCleanup',
    }

    def test_manual_test_and_lint_keep_complete_jobs_behind_full_classifier(self):
        for filename, count in [('test.yml', 4), ('lint.yml', 10)]:
            workflow = yaml.safe_load((ROOT / '.github/workflows' / filename).read_text())
            self.assertEqual(set(workflow['on']), {'pull_request', 'workflow_dispatch'})
            self.assertEqual(workflow['on']['workflow_dispatch'], {})
            self.assertEqual(workflow['permissions'], {'contents': 'read'})
            self.assertEqual(set(workflow['jobs']), {'classify', 'test' if filename == 'test.yml' else 'build'})
            job = workflow['jobs']['test' if filename == 'test.yml' else 'build']
            self.assertEqual(job['needs'], 'classify')
            self.assertEqual(job['if'], "${{ needs.classify.outputs.run_full == 'true' }}")
            self.assertNotIn('push', workflow['on'])
            self.assertEqual(workflow['on']['pull_request']['branches'], ['polaris-main'])
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
        self.assertEqual(contract['on']['push'], {'branches': ['polaris-main']})
        for event in ('pull_request',):
            for path in ('scripts/polaris_ci_impact.py', 'scripts/test_polaris_ci_impact.py',
                         'scripts/test_polaris_runner_resources.py', 'scripts/test_polaris_production_release.py',
                         'scripts/testdata/historical-workflows/**', 'scripts/ci/**'):
                self.assertIn(path, contract['on'][event]['paths'])
        commands = '\n'.join(step.get('run', '') for step in contract['jobs']['contract']['steps'])
        for name in ('test_polaris_ci_impact.py', 'test_polaris_runner_resources.py',
                     'test_polaris_production_release.ProductionTests.test_historical_workflow'):
            self.assertIn(name, commands)

    def test_linux_exact_package_partition_and_compile_only_scope(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/test.yml').read_text())
        steps = workflow['jobs']['test']['steps']
        ordinary = next(s for s in steps if s.get('name') == 'Test (Linux ordinary packages)')
        compiled = next(s for s in steps if s.get('name', '').startswith('Compile Linux netns tests'))
        self.assertLess(steps.index(ordinary), steps.index(compiled))
        self.assertEqual(ordinary['if'], "matrix.os == 'ubuntu-latest'")
        self.assertEqual(compiled['if'], "matrix.os == 'ubuntu-latest'")
        for name in ['Test (macOS ordinary packages)', 'Test (windows)']:
            step = next(s for s in steps if s.get('name') == name)
            self.assertEqual(step['run'], 'go test -v -tags "$BUILD_TAGS" -ldflags "$LDFLAGS_SHARED" ./...')
        for step in [ordinary, compiled]:
            self.assertNotIn('sudo', step['run'])
            self.assertNotIn('-exec', step['run'])
        self.assertEqual(compiled['env'], {'GOMAXPROCS': '2'})
        bash = shutil.which('bash')
        self.assertIsNotNone(bash)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = root / 'calls.jsonl'
            common = ('import json,os,sys\nfrom pathlib import Path\n'
                      'args=sys.argv[1:]\n'
                      'with open(os.environ["FIXTURE_CALLS"],"a") as f:f.write(json.dumps({"tool":Path(sys.argv[0]).name,"args":args,"gomaxprocs":os.environ.get("GOMAXPROCS")})+"\\n")\n')
            binary = '#!' + sys.executable + '\n' + common + 'raise SystemExit(96)\n'
            fake = root / 'go'
            fake.write_text('#!' + sys.executable + '\n' + common +
                'if args[0]=="list":\n print(os.environ["FAKE_PACKAGES"])\n raise SystemExit(int(os.environ.get("LIST_RC","0")))\n' +
                'if int(os.environ.get("GO_RC","0")):raise SystemExit(int(os.environ["GO_RC"]))\n' +
                'if "-c" in args:\n' +
                ' target=Path(args[args.index("-o")+1]);kind=os.environ.get("ARTIFACT","regular")\n' +
                ' if kind=="symlink":target.symlink_to(Path(sys.argv[0]).resolve())\n' +
                ' elif kind!="missing":\n  target.write_text("" if kind=="empty" else ' + repr(binary) + ');target.chmod(0o600 if kind=="non-executable" else 0o700)\n')
            fake.chmod(0o700)
            for name in ['sudo', 'python3']:
                forbidden = root / name
                forbidden.write_text('#!' + sys.executable + '\n' + common + 'raise SystemExit(96)\n')
                forbidden.chmod(0o700)
            # No real Go, sudo, guard, Git or network tool is reachable.
            for name in ['mktemp', 'rm', 'tee', 'grep']:
                executable = shutil.which(name)
                self.assertIsNotNone(executable, name)
                (root / name).symlink_to(executable)
            env = {'PATH': str(root), 'HOME': str(root), 'TMPDIR': str(root), 'RUNNER_TEMP': str(root),
                   'BUILD_TAGS': 'with_tailscale', 'LDFLAGS_SHARED': '-checklinkname=0',
                   'GITHUB_STEP_SUMMARY': str(root / 'summary'),
                   'FIXTURE_CALLS': str(calls), 'NETNS_BATCH_ELEVATION': 'true',
                   'GOVERNANCE_NETNS_SHA': 'd' * 40, 'POLARIS_CI_GOVERNANCE_NETNS_SHA': 'd' * 40,
                   'GITHUB_SHA': 'd' * 40, 'SOURCE_COMMIT': 'd' * 40,
                   'GITHUB_REPOSITORY': 'polaris-arch/sing-box-polaris', 'GITHUB_REPOSITORY_ID': '1421657509',
                   'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/ci/governance',
                   'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux',
                   'FAKE_PACKAGES': 'github.com/sagernet/sing-box/adapter\ngithub.com/sagernet/sing-box/common/netns\ngithub.com/sagernet/sing-box/common/netns_extra'}
            def run(step, **changes):
                calls.write_text('')
                result = subprocess.run([bash, '--noprofile', '--norc', '-c', step['run']],
                                        env={**env, **step.get('env', {}), **changes}, capture_output=True, text=True, timeout=15)
                self.fixture_calls = [json.loads(line) for line in calls.read_text().splitlines()]
                return result.returncode
            self.assertEqual(run(ordinary), 0)
            args = self.fixture_calls[-1]['args']
            self.assertEqual(args[-2:], ['github.com/sagernet/sing-box/adapter', 'github.com/sagernet/sing-box/common/netns_extra'])
            for changes in [{'LIST_RC': '1'}, {'GO_RC': '1'}, {'FAKE_PACKAGES': 'github.com/sagernet/sing-box/adapter'},
                            {'FAKE_PACKAGES': 'github.com/sagernet/sing-box/common/netns'}]:
                with self.subTest(ordinary_failure=changes):
                    self.assertNotEqual(run(ordinary, **changes), 0)
            for approved in ['true', 'false', '', 'TRUE', 'true ', '1']:
                self.assertEqual(run(compiled, NETNS_BATCH_ELEVATION=approved), 0)
                self.assertEqual([call['tool'] for call in self.fixture_calls], ['go'])
                args = self.fixture_calls[0]['args']
                self.assertEqual(args[:8], ['test', '-p', '2', '-c', '-tags', 'with_tailscale', '-ldflags', '-checklinkname=0'])
                self.assertEqual(self.fixture_calls[0]['gomaxprocs'], '2')
                self.assertEqual(args[-1], 'github.com/sagernet/sing-box/common/netns')
            for changes in [{'GO_RC': '1'}, {'ARTIFACT': 'missing'}, {'ARTIFACT': 'empty'},
                            {'ARTIFACT': 'non-executable'}, {'ARTIFACT': 'symlink'}]:
                with self.subTest(compile_failure=changes):
                    self.assertNotEqual(run(compiled, **changes), 0)
                    self.assertEqual([call['tool'] for call in self.fixture_calls], ['go'])

    def test_main_push_has_only_the_unfiltered_contract_workflow(self):
        import fnmatch
        automatic = []
        for path in sorted((ROOT / '.github/workflows').glob('*.yml')):
            workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
            events = workflow.get('on', {})
            if 'push' not in events:
                continue
            push = events['push'] or {}
            if 'branches' in push:
                matches = any(fnmatch.fnmatchcase('polaris-main', pattern) for pattern in push['branches'])
            else:
                matches = 'tags' not in push
            if matches:
                automatic.append(path.name)
        self.assertEqual(automatic, ['ci-contract.yml'])
        contract = yaml.load((ROOT / '.github/workflows/ci-contract.yml').read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(contract['on']['push'], {'branches': ['polaris-main']})
        selfcheck = yaml.load((ROOT / '.github/workflows/polaris-selfcheck.yml').read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(selfcheck['on']['push'], {'tags': ['polaris-*']})
        self.assertEqual(selfcheck['on']['pull_request'], {'branches': ['polaris-main']})
        inputs = selfcheck['on']['workflow_dispatch']['inputs']
        self.assertEqual(inputs['source_role']['default'], 'all')
        self.assertEqual(inputs['patch_only']['default'], 'false')

    def test_fast_contract_reuses_the_exact_pinned_formatter_without_product_builds(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/ci-contract.yml').read_text())
        job = workflow['jobs']['contract']
        full = yaml.safe_load((ROOT / '.github/workflows/polaris-selfcheck.yml').read_text())
        steps = job['steps']
        for name in ['Restore pinned official formatter archive',
                     'Verify and extract pinned official formatter (no product compilation)']:
            expected = copy.deepcopy(next(s for s in full['jobs']['classify']['steps'] if s.get('name') == name))
            expected.pop('if')
            self.assertEqual(next(s for s in steps if s.get('name') == name), expected)
        formatter = next(s for s in steps if s.get('name') == 'Check pinned owned-source formatting without product compilation')
        self.assertEqual(formatter['env'], {'GOLANGCI_LINT': '${{ runner.temp }}/polaris-format-bin/golangci-lint'})
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', formatter['run'])
        self.assertIn('python3 -B scripts/ci/check_remediation_format.py', formatter['run'])
        checkout = steps[0]
        self.assertEqual(checkout['with'], {'ref': '${{ github.sha }}', 'persist-credentials': False})
        for control in [job, formatter]:
            self.assertNotIn('if', control)
            self.assertNotIn('continue-on-error', control)
        commands = '\n'.join(s.get('run', '') for s in steps)
        self.assertIn("-p 'test_patch_test_packages.py'", commands)
        self.assertNotRegex(commands, r'(?m)^\s*(?:sudo\s+|go\s+(?:test|build|run)\b)')

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




# The old selector strings are a source-pinned pre-supply contract. Exact needs
# and explicit status functions below make optional skipped dependencies visible.
_MATERIAL_OLD_SELECTORS = {'prepare_windows7': "!inputs.source_generate_only && (github.event_name != 'workflow_dispatch' || inputs.build == 'All' || inputs.build == 'Binary')", 'build': "!inputs.source_generate_only && (github.event_name != 'workflow_dispatch' || inputs.build == 'All' || inputs.build == 'Binary' || inputs.build == 'NativePeerLinux')", 'build_darwin': "!inputs.source_generate_only && !failure() && !cancelled() && (github.event_name != 'workflow_dispatch' || inputs.build == 'All' || inputs.build == 'Binary')", 'build_windows': "!inputs.source_generate_only && (github.event_name != 'workflow_dispatch' || inputs.build == 'All' || inputs.build == 'Binary')", 'build_android_library': "!inputs.source_generate_only && (github.event_name != 'workflow_dispatch' || inputs.build == 'All' || inputs.build == 'Android' || inputs.build == 'publish-android') && github.ref != 'refs/heads/oldstable'", 'build_windows_client': "!inputs.source_generate_only && (github.event_name != 'workflow_dispatch' || inputs.build == 'All' || inputs.build == 'Windows') && github.ref != 'refs/heads/oldstable'", 'build_linux_client': "!inputs.source_generate_only && (github.event_name != 'workflow_dispatch' || inputs.build == 'All' || inputs.build == 'Linux') && github.ref != 'refs/heads/oldstable'", 'build_apple_library': "!inputs.source_generate_only && (github.event_name != 'workflow_dispatch' || inputs.build == 'All' || inputs.build == 'Apple' || inputs.build == 'Apple-release' || inputs.build == 'iOS' || inputs.build == 'macOS' || inputs.build == 'tvOS' || inputs.build == 'macOS-standalone' || inputs.build == 'iOS-jailbreak')"}
_MATERIAL_REQUIRED_EXPRESSIONS = {'.github/workflows/build.yml': "github.event_name == 'workflow_dispatch' && inputs.build == 'All' && inputs.evidence_mode == 'final' && !inputs.source_generate_only && startsWith(github.ref, 'refs/tags/')", '.github/workflows/linux.yml': "github.event_name == 'workflow_dispatch' && startsWith(github.ref, 'refs/tags/')", '.github/workflows/docker.yml': "github.event_name == 'workflow_dispatch' && startsWith(github.ref, 'refs/tags/')"}
_MATERIAL_CALLERS = [['.github/workflows/build.yml', 'build', 'all', 'calculate_version', 'C1_ALL_BINARY', '${{ matrix.arch }}', "${{ fromJSON(toJSON(matrix)).variant == 'musl' && 'musl' || 'glibc' }}", "fromJSON(toJSON(matrix)).naive && fromJSON(toJSON(matrix)).variant != 'purego'", 'dist'], ['.github/workflows/build.yml', 'build_linux_client', 'all', 'calculate_version', 'C2_ALL_LINUX_CLIENT', '${{ matrix.go_arch }}', 'glibc', 'true', 'dist'], ['.github/workflows/linux.yml', 'build', 'linux', 'calculate_version', 'C3_LINUX', '${{ matrix.arch }}', 'musl', 'matrix.naive', 'dist'], ['.github/workflows/docker.yml', 'build_binary', 'docker', 'source', 'C4_DOCKER', '${{ matrix.arch }}', 'musl', 'matrix.naive', '.']]


def _material_gate(parent):
 return "(needs."+parent+".outputs.material_required == 'false' || (needs."+parent+".outputs.material_required == 'true' && needs.debian_materials.result == 'success'))"


def _material_expression(expression, bindings):
 # Finite inert evaluation of the source expression, without importing the
 # supplier or running products. This does not model GitHub's implicit success().
 text=expression.strip()
 if text.startswith('${{'):text=text[3:-2].strip()
 for key in sorted(bindings,key=len,reverse=True):text=text.replace(key,repr(bindings[key]))
 text=text.replace('&&',' and ').replace('||',' or ')
 text=re.sub(r'!(?!=)','not ',text)
 return eval(text,{'__builtins__':{},'true':True,'false':False,
                  'startsWith':lambda value,prefix:value.startswith(prefix)},{})


class TestDebianMaterialWiring(unittest.TestCase):
 def workflows(self):
  return {name:yaml.safe_load((ROOT/'.github/workflows'/name).read_text())
          for name in ('build.yml','linux.yml','docker.yml')}
 def assert_frontier(self,job,parent,old_selector=None):
  self.assertEqual(job['needs'],[parent,'debian_materials'])
  condition="!cancelled() && needs."+parent+".result == 'success' && "+_material_gate(parent)
  if old_selector is not None:
   selector=old_selector.replace('!failure() && ','').replace('!cancelled() && ','')
   condition+=' && ('+selector+')'
  self.assertEqual(job['if'],'${{ '+condition+' }}')
  self.assertNotIn('always()',job['if']);self.assertNotIn('success()',job['if'])
  self.assertNotIn('continue-on-error',job)
 def test_required_classification_is_single_source_and_checkpoint_defaults_are_empty(self):
  for filename,workflow in self.workflows().items():
   parent='source' if filename=='docker.yml' else 'calculate_version'
   source=workflow['jobs'][parent]
   self.assertEqual(source['outputs']['material_required'],'${{ steps.material_scope.outputs.required }}')
   mode=[s for s in source['steps'] if s.get('id')=='material_scope'];self.assertEqual(len(mode),1)
   expected=_MATERIAL_REQUIRED_EXPRESSIONS['.github/workflows/'+filename]
   self.assertEqual(mode[0]['env']['REQUIRED'],"${{ "+expected+" && 'true' || 'false' }}")
   self.assertEqual(mode[0]['shell'],'bash');self.assertNotIn('if',mode[0])
   self.assertNotIn('continue-on-error',mode[0])
   for key in ('debian_checkpoint_artifact_id','debian_checkpoint_digest'):
    field=workflow['on']['workflow_dispatch']['inputs'][key]
    self.assertEqual(field['type'],'string');self.assertIs(field['required'],False);self.assertEqual(field['default'],'')
   if filename=='docker.yml':
    self.assertEqual(workflow['jobs']['build_binary']['outputs']['material_required'],'${{ needs.source.outputs.material_required }}')
   # All selectors, source generation, staging and branch paths retain their
   # old behavior. Only the exact current-tag full Final mode requests supply.
   for event in ('workflow_dispatch','push'):
    for ref in ('refs/tags/v1.15.0-polaris-alpha.12.14','refs/heads/fix/current'):
     for build in ('All','Source','Binary','NativePeerDiagnostic','NativePeerLinux','Android','Windows','Linux','Apple','Apple-release','iOS','macOS','tvOS','macOS-standalone','iOS-jailbreak','publish-android'):
      for evidence in ('final','staging'):
       for source_only in (False,True):
        values={'github.event_name':event,'github.ref':ref,'inputs.build':build,
                'inputs.evidence_mode':evidence,'inputs.source_generate_only':source_only}
        actual=_material_expression(mode[0]['env']['REQUIRED'],values)
        required=event=='workflow_dispatch' and ref.startswith('refs/tags/')
        if filename=='build.yml':required=required and build=='All' and evidence=='final' and not source_only
        self.assertEqual(actual,'true' if required else 'false',(filename,values))
 def test_preexisting_all_skip_invalid_source_generation_combination_does_not_consume_checkpoint(self):
  # Root retains the original invalid All+source_generate_only all-skip shape.
  # This is not a second admission path or an accepted checkpoint selection.
  workflow=self.workflows()['build.yml']
  values={'inputs.build':'All','inputs.source_generate_only':True,
          'inputs.evidence_mode':'final','inputs.windows_native_proof':False,
          'github.event_name':'workflow_dispatch','github.ref':'refs/tags/v1.15.0-polaris-alpha.12.14',
          'cancelled()':False,'failure()':False}
  for name,job in workflow['jobs'].items():
   self.assertIn('if',job,name)
   context=dict(values)
   for token in re.findall(r'needs\.[A-Za-z0-9_]+(?:\.outputs\.[A-Za-z0-9_]+|\.result)',job['if']):
    context[token]='skipped' if token.endswith('.result') else ''
   with self.subTest(job=name):self.assertFalse(bool(_material_expression(job['if'],context)))
  self.assertEqual(workflow['jobs']['source_proto']['if'],"inputs.build == 'Source' && inputs.source_generate_only")
  self.assertEqual(workflow['jobs']['source_gate']['if'],"inputs.build == 'Source' && !inputs.source_generate_only")
  self.assertEqual(workflow['jobs']['utls_gate']['if'],"inputs.build == 'Source' && !inputs.source_generate_only")
  self.assertEqual(workflow['jobs']['calculate_version']['if'],"(inputs.build != 'Source' && !inputs.source_generate_only) || inputs.build == 'NativePeerDiagnostic' || inputs.build == 'NativePeerLinux'")
 def test_checkpoint_rejection_runs_the_actual_bounded_preflight_shell(self):
  for filename,workflow in self.workflows().items():
   parent='source' if filename=='docker.yml' else 'calculate_version'
   mode=next(s for s in workflow['jobs'][parent]['steps'] if s.get('id')=='material_scope')
   self.assertIn('printf',mode['run']);self.assertIn('$GITHUB_OUTPUT',mode['run'])
   for required in ('true','false','', 'unknown'):
    for artifact_id,digest in (('',''),('123',''),('','a'*64),('123','a'*64)):
     with self.subTest(workflow=filename,required=required,id_present=bool(artifact_id),digest_present=bool(digest)),tempfile.TemporaryDirectory() as tmp:
      out=Path(tmp)/'output'
      env=dict(os.environ,REQUIRED=required,CHECKPOINT_ARTIFACT_ID=artifact_id,CHECKPOINT_DIGEST=digest,GITHUB_OUTPUT=str(out))
      result=subprocess.run(['bash','-euo','pipefail','-c',mode['run']],env=env,capture_output=True,text=True,timeout=10)
      allowed=required in ('true','false') and bool(artifact_id)==bool(digest) and (required=='true' or not artifact_id)
      self.assertEqual(result.returncode==0,allowed)
      self.assertEqual(out.read_text() if out.exists() else '',('required='+required+'\n') if allowed else '')
  # Source/Source-generate never reaches calculate_version; each real Source
  # entry therefore rejects nonempty seed inputs before checkout/preparation.
  for name in ('source_proto','source_gate','utls_gate'):
   first=self.workflows()['build.yml']['jobs'][name]['steps'][0]
   self.assertEqual(first['name'],'Reject checkpoint outside material Final');self.assertEqual(first['shell'],'bash')
   for a,b in (('',''),('123',''),('','a'*64),('123','a'*64)):
    result=subprocess.run(['bash','-euo','pipefail','-c',first['run']],
                          env=dict(os.environ,CHECKPOINT_ARTIFACT_ID=a,CHECKPOINT_DIGEST=b),capture_output=True,timeout=10)
    self.assertEqual(result.returncode==0,not a and not b)
 def test_every_heavy_frontier_preserves_old_ancestors_and_handles_optional_ready(self):
  workflows=self.workflows()
  frontier=[('build.yml',name,'calculate_version',old) for name,old in _MATERIAL_OLD_SELECTORS.items()]
  frontier+=[('linux.yml','build','calculate_version',None),('docker.yml','build_binary','source',None)]
  for filename,name,parent,old in frontier:
   candidate=workflows[filename]['jobs'][name];self.assert_frontier(candidate,parent,old)
   for mode in ('true','false','','unknown'):
    for ancestor in ('success','failure','skipped','cancelled','','unknown'):
     for ready in ('success','failure','skipped','cancelled','','unknown'):
      for cancelled in (False,True):
       for build in ('All','Source','Binary','NativePeerDiagnostic','NativePeerLinux','Android','Windows','Linux','Apple','Apple-release','iOS','macOS','tvOS','macOS-standalone','iOS-jailbreak','publish-android'):
        values={'needs.'+parent+'.result':ancestor,'needs.'+parent+'.outputs.material_required':mode,
                'needs.debian_materials.result':ready,'cancelled()':cancelled,'failure()':ancestor=='failure',
                'inputs.source_generate_only':False,'github.event_name':'workflow_dispatch','github.ref':'refs/tags/v1.15.0-polaris-alpha.12.14','inputs.build':build}
        selector=True if old is None else _material_expression(old,values)
        expected=bool(selector and not cancelled and ancestor=='success' and (mode=='false' or mode=='true' and ready=='success'))
        self.assertEqual(bool(_material_expression(candidate['if'],values)),expected,(filename,name,mode,ancestor,ready,cancelled,build))
   # Mutate actual needs and conditions; every change must be rejected by the
   # same assertion which first accepts the complete unmodified candidate.
   changes=[]
   for status in ('failure','skipped','cancelled','','unknown'):
    changes.append(('if',candidate['if'].replace("needs."+parent+".result == 'success'","needs."+parent+".result == '"+status+"'",1)))
   changes += [('needs',[parent]),('needs',['debian_materials']),('if','always()'),('if','success()'),
               ('if',candidate['if'].replace(_material_gate(parent),"needs.debian_materials.result != 'failure'")),
               ('if',candidate['if'].replace("needs."+parent+".outputs.material_required == 'false'","needs."+parent+".outputs.material_required != 'true'",1))]
   for field,value in changes:
    wrong=copy.deepcopy(candidate);wrong[field]=value
    with self.assertRaises(AssertionError):self.assert_frontier(wrong,parent,old)
 def test_three_suppliers_use_one_raw_then_ready_action_without_circular_evidence(self):
  workflows=self.workflows();action=yaml.safe_load((ROOT/'.github/actions/prepare-debian-materials/action.yml').read_text())
  self.assertEqual(action['runs']['using'],'composite')
  steps=action['runs']['steps'];prepare=next(s for s in steps if s.get('id')=='prepare')
  raw=next(s for s in steps if s.get('id')=='raw-upload');ready=next(s for s in steps if s.get('id')=='ready-upload')
  binding=next(s for s in steps if 'cronet_material_supply.py ready ' in s.get('run',''))
  keyring=next(s for s in steps if 'generate_keyring.sh' in s.get('run',''))
  self.assertLess(steps.index(keyring),steps.index(prepare));self.assertLess(steps.index(prepare),steps.index(raw))
  self.assertLess(steps.index(raw),steps.index(binding));self.assertLess(steps.index(binding),steps.index(ready))
  self.assertEqual(raw['if'],'always()')
  self.assertEqual(binding['if'],"success() && steps.prepare.outcome == 'success' && steps.raw-upload.outcome == 'success'")
  self.assertNotIn('if',ready) # Implicit success keeps failed raw/auth/bind from emitting READY.
  self.assertEqual(binding['env'],{'RAW_ID':'${{ steps.raw-upload.outputs.artifact-id }}','RAW_DIGEST':'${{ steps.raw-upload.outputs.artifact-digest }}'})
  self.assertIn('--checkpoint-artifact-id "$CHECKPOINT_ARTIFACT_ID" --checkpoint-artifact-digest "$CHECKPOINT_DIGEST"',prepare['run'])
  self.assertNotIn('--checkpoint-digest',prepare['run'])
  for step,name in ((raw,'debian-candidate-raw'),(ready,'debian-material-ready')):
   self.assertEqual(step['uses'],'actions/upload-artifact@v4');self.assertEqual(step['with']['name'],name)
   self.assertEqual(step['with']['retention-days'],7);self.assertIs(step['with']['overwrite'],False)
   self.assertEqual(step['with']['if-no-files-found'],'error')
  for step in steps:
   self.assertNotIn('continue-on-error',step)
   self.assertNotIn('timeout-minutes',step) # Workflow step key is not composite metadata.
   self.assertFalse(step.get('uses','').startswith(('actions/cache','actions/download-artifact')))
  for filename,workflow in workflows.items():
   parent='source' if filename=='docker.yml' else 'calculate_version';role={'build.yml':'all','linux.yml':'linux','docker.yml':'docker'}[filename]
   supplier=workflow['jobs']['debian_materials'];self.assertEqual(supplier['name'],'Supply verified Debian raw inputs')
   self.assertEqual(supplier['needs'],[parent]);self.assertEqual(supplier['permissions'],{'contents':'read','actions':'read'})
   expected="needs."+parent+".outputs.material_required == 'true'"
   if role=='all':expected='!inputs.source_generate_only && '+expected
   self.assertEqual(supplier['if'],'${{ '+expected+' }}')
   call=next(s for s in supplier['steps'] if s.get('id')=='materials');self.assertEqual(call['uses'],'./.github/actions/prepare-debian-materials')
   self.assertEqual(call['with']['role'],role)
   self.assertEqual(call['with']['checkpoint-artifact-id'],'${{ inputs.debian_checkpoint_artifact_id }}')
   self.assertEqual(call['with']['checkpoint-artifact-digest'],'${{ inputs.debian_checkpoint_digest }}')
   for key,step,field in (('raw_id','raw-upload','artifact-id'),('raw_digest','raw-upload','artifact-digest'),('ready_id','ready-upload','artifact-id'),('ready_digest','ready-upload','artifact-digest')):
    self.assertEqual(supplier['outputs'][key],'${{ steps.materials.outputs.'+key+' }}')
    self.assertEqual(action['outputs'][key]['value'],'${{ steps.'+step+'.outputs.'+field+' }}')
 def test_all_four_real_callers_reauthenticate_before_unchanged_go_download_and_keep_use_private(self):
  workflows=self.workflows()
  for path,name,role,parent,caller,arch,libc,eligible,dest in _MATERIAL_CALLERS:
   job=workflows[Path(path).name]['jobs'][name];steps=job['steps']
   clone,keyring,download=[next(s for s in steps if s.get('name')==n) for n in ('Clone cronet-go','Regenerate Debian keyring','Download Chromium toolchain')]
   self.assertLess(steps.index(clone),steps.index(keyring));self.assertLess(steps.index(keyring),steps.index(download))
   self.assertEqual((clone['timeout-minutes'],download['timeout-minutes']),(10,20))
   run=download['run'];self.assertLess(run.index('cronet_material_supply.py" consume'),run.index('export POLARIS_CRONET_RAW_STORE='))
   self.assertLess(run.index('export POLARIS_CRONET_RAW_STORE='),run.index('go run ./cmd/build-naive'))
   self.assertIn('--caller '+caller+' --target-arch "$MATERIAL_TARGET_ARCH" --libc "$MATERIAL_LIBC"',run)
   self.assertEqual(download['env']['MATERIAL_TARGET_ARCH'],arch);self.assertEqual(download['env']['MATERIAL_LIBC'],libc)
   self.assertEqual(download['env']['POLARIS_DEBIAN_REQUIRED'],'${{ needs.'+parent+'.outputs.material_required }}')
   self.assertEqual(download['env']['GH_TOKEN'],'${{ github.token }}')
   self.assertEqual(job['permissions'],{'contents':'read','actions':'read'})
   keep=next(s for s in steps if s.get('name')=='Retain exact Debian material use')
   self.assertEqual(keep['if'],"${{ needs."+parent+".outputs.material_required == 'true' && ("+eligible+') }}')
   self.assertEqual(keep['run'],'cp "$RUNNER_TEMP/debian-material-use/use.json" '+dest+'/debian-material-use.json')
   self.assertLess(steps.index(download),steps.index(keep))
   packing=[i for i,s in enumerate(steps) if s.get('name') in ('Archive','Package DEB','Package RPM','Prepare upload','Prepare artifact')]
   self.assertTrue(packing);self.assertLess(max(packing),steps.index(keep))
   if role=='all':
    record=next(s for s in steps if s.get('name')=='Record actual unsigned candidate files');self.assertLess(steps.index(keep),steps.index(record))
   for s in steps:
    if s.get('name') in ('Archive','Package DEB','Package RPM'):self.assertNotIn('debian-material-use.json',s.get('run',''))
   self.assertFalse(any(s.get('uses','').startswith('actions/download-artifact') and s.get('with',{}).get('name') in ('debian-candidate-raw','debian-material-ready') for s in steps))
  commands='\n'.join(s.get('run','') for s in workflows['build.yml']['jobs']['source_gate']['steps'])
  self.assertIn("python3 -m unittest discover -s scripts/ci -p 'test_*.py'",commands)
  self.assertTrue((ROOT/'scripts/ci/test_cronet_material_supply.py').is_file())
 def test_original_receipt_success_and_native_proof_exceptions_survive_the_new_edge(self):
  workflows=self.workflows()
  for filename,workflow in workflows.items():
   receipt=workflow['jobs']['publisher_receipt'];self.assertEqual(receipt['needs'][-1],'debian_materials')
   self.assertEqual(len(receipt['needs']),15 if filename=='build.yml' else 3)
   for name in receipt['needs'][:-1]:self.assertIn("needs."+name+".result == 'success'",receipt['if'])
   parent='build_binary' if filename=='docker.yml' else 'calculate_version'
   self.assertIn(_material_gate(parent),receipt['if']);self.assertIn('!cancelled()',receipt['if'])
   self.assertNotIn('always()',receipt['if']);self.assertNotIn('success()',receipt['if'])
   record=next(s for s in receipt['steps'] if s.get('name')=='Record exact completed scope')
   self.assertEqual(record['env']['POLARIS_DEBIAN_REQUIRED'],'${{ needs.'+parent+'.outputs.material_required }}')
   for key,out in (('RAW_ID','raw_id'),('RAW_DIGEST','raw_digest'),('READY_ID','ready_id'),('READY_DIGEST','ready_digest')):
    self.assertEqual(record['env']['POLARIS_DEBIAN_'+key],'${{ needs.debian_materials.outputs.'+out+' }}')
   self.assertEqual(record['env']['GH_TOKEN'],'${{ github.token }}')
  index=workflows['build.yml']['jobs']['native_index'];self.assertEqual(len(index['needs']),8)
  self.assertIn("inputs.windows_native_proof != true || needs.native_windows_proof.result == 'success'",index['if'])
  for name in index['needs']:
   if name not in ('native_windows_proof','debian_materials'):self.assertIn("needs."+name+".result == 'success'",index['if'])
  self.assertIn(_material_gate('calculate_version'),index['if'])



class TestSupplierCloneBudget(unittest.TestCase):
 def test_real_supplier_script_preserves_primary_status_and_kills_term_ignoring_grandchild(self):
  # Existing Source/CI-contract discovery runs this GNU/Linux control on Ubuntu.
  # Tool fixtures replace external Git/bootstrap work, never the timeout or bash.
  # SIGALRM drives GNU timeout's real expiry handler; this is not a natural
  # 590-second wall-clock measurement, nor material authentication evidence.
  import selectors,signal,time
  wall_deadline=time.monotonic()+90
  def budget(cap):
   remaining=wall_deadline-time.monotonic()
   self.assertGreater(remaining,0,'overall supplier-script fixture watchdog expired')
   return min(cap,remaining)
  self.assertTrue(sys.platform.startswith('linux'))
  timeout=shutil.which('timeout');self.assertIsNotNone(timeout)
  version=subprocess.run([timeout,'--version'],capture_output=True,text=True,timeout=budget(3))
  self.assertEqual(version.returncode,0);self.assertIn('GNU coreutils',version.stdout)
  action=yaml.safe_load((ROOT/'.github/actions/prepare-debian-materials/action.yml').read_text())
  selected=[s for s in action['runs']['steps'] if s.get('name')=='Clone and prepare pinned original creator']
  self.assertEqual(len(selected),1);step=selected[0]
  self.assertEqual(step['shell'],'bash');self.assertNotIn('timeout-minutes',step)
  run=step['run']
  self.assertIn("timeout --signal=TERM --kill-after=5s 590s bash -euo pipefail <<'CRONET_CLONE'",run)
  self.assertNotIn('--foreground',run);self.assertNotIn('--preserve-status',run)
  self.assertIn("trap 'trap \"\" TERM; exec sleep inf' TERM",run)
  pin=(ROOT/'.github/CRONET_GO_VERSION').read_text().rstrip('\n')
  fixture=r"""import json,os,signal,subprocess,sys
from pathlib import Path
def event(kind,**fields):
 fields.update(kind=kind,pid=os.getpid(),ppid=os.getppid(),pgid=os.getpgrp())
 os.write(1,(json.dumps(fields)+'\n').encode())
if sys.argv[1:]==['--fixture-child']:
 def term(signum,frame):event('term',role='child')
 signal.signal(signal.SIGTERM,term)
 event('ready',role='child')
 while True:signal.pause()
tool=Path(sys.argv[0]).name;args=sys.argv[1:]
event('call',tool=tool,argv=args)
if tool=='git' and args[:1]==['init']:Path(args[1]).mkdir(parents=True)
stage='bootstrap' if tool=='python3' else ('fetch' if 'fetch' in args else '')
if stage and stage==os.environ['FIXTURE_STAGE']:
 mode=os.environ['FIXTURE_MODE']
 if mode=='primary':
  sys.stderr.write('primary-'+stage+'\n');sys.exit(37 if stage=='fetch' else 43)
 if mode=='timeout':
  # Parent exits on TERM, while its child records TERM and remains blocked.
  # Without the real shell hold-open trap, GNU timeout could finish too early.
  def term(signum,frame):
   event('term',role='parent');os._exit(93)
  signal.signal(signal.SIGTERM,term)
  subprocess.Popen([sys.executable,sys.argv[0],'--fixture-child'])
  event('ready',role='parent')
  while True:signal.pause()
"""
  def process_state(pid):
   try:return (Path('/proc')/str(pid)/'stat').read_text().rpartition(') ')[2].split()[0]
   except (FileNotFoundError,ProcessLookupError):return None
  def kill_session(session):
   # Bounded best-effort cleanup of this isolated test session only. GNU timeout
   # uses a different process group, so killing only the caller's group is wrong.
   for unused in range(2):
    for entry in Path('/proc').iterdir():
     if entry.name.isdecimal():
      pid=int(entry.name)
      try:
       if os.getsid(pid)==session:os.kill(pid,signal.SIGKILL)
      except (ProcessLookupError,FileNotFoundError):pass
  for stage,mode,expected in (('fetch','success',0),('fetch','primary',37),
                              ('bootstrap','primary',43),('fetch','timeout',None),
                              ('bootstrap','timeout',None)):
   with self.subTest(stage=stage,mode=mode),tempfile.TemporaryDirectory() as temporary:
    root=Path(temporary);workspace=root/'workspace';home=root/'home';bindir=root/'bin'
    (workspace/'.github').mkdir(parents=True);home.mkdir();bindir.mkdir()
    (workspace/'.github/CRONET_GO_VERSION').write_text(pin+'\n')
    for tool in ('git','python3'):
     path=bindir/tool;path.write_text('#!'+sys.executable+'\n'+fixture);path.chmod(0o700)
    env={key:value for key,value in os.environ.items()
         if key not in ('BASH_ENV','ENV') and not key.startswith('BASH_FUNC_')}
    env.update(HOME=str(home),GITHUB_WORKSPACE=str(workspace),
               PATH=str(bindir)+os.pathsep+env['PATH'],FIXTURE_STAGE=stage,FIXTURE_MODE=mode)
    process=subprocess.Popen(['bash','-euo','pipefail','-c',run],cwd=workspace,env=env,
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,bufsize=0)
    selector=None;prefix=b'';ready={}
    try:
     if mode=='timeout':
      selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
      pending=b'';deadline=time.monotonic()+budget(10)
      while len(ready)!=2:
       remaining=deadline-time.monotonic()
       self.assertGreater(remaining,0,'real fixture did not reach both parent/child entries')
       self.assertTrue(selector.select(remaining),'fixture entry watchdog expired')
       block=os.read(process.stdout.fileno(),65536)
       self.assertTrue(block,'script exited before both real fixture entries')
       prefix+=block;pending+=block
       while b'\n' in pending:
        line,pending=pending.split(b'\n',1);event=json.loads(line)
        if event['kind']=='ready':ready[event['role']]=event
      selector.close();selector=None
      group=ready['parent']['pgid']
      self.assertEqual(ready['child']['pgid'],group)
      self.assertEqual(ready['child']['ppid'],ready['parent']['pid'])
      self.assertEqual(os.getsid(group),process.pid)
      self.assertEqual((Path('/proc')/str(group)/'comm').read_text().strip(),'timeout')
      argv=(Path('/proc')/str(group)/'cmdline').read_bytes().split(b'\0')
      self.assertIn(b'590s',argv);self.assertIn(b'--kill-after=5s',argv)
      # Deliver to the actual GNU monitor, not its children or a replacement.
      os.kill(group,signal.SIGALRM)
     stdout,stderr=process.communicate(timeout=budget(15))
     events=[json.loads(line) for line in (prefix+stdout).splitlines()]
     calls=[(e['tool'],e['argv']) for e in events if e['kind']=='call']
     clone=[('git',['init',str(home/'cronet-go')]),
            ('git',['-C',str(home/'cronet-go'),'remote','add','origin','https://github.com/sagernet/cronet-go.git']),
            ('git',['-C',str(home/'cronet-go'),'sparse-checkout','set','--no-cone','/*','!/lib']),
            ('git',['-C',str(home/'cronet-go'),'fetch','--depth=1','--filter=blob:none','origin',pin]),
            ('git',['-C',str(home/'cronet-go'),'checkout','FETCH_HEAD']),
            ('git',['-C',str(home/'cronet-go'),'submodule','update','--init','--recursive','--depth=1']),
            ('python3',[str(workspace/'scripts/ci/cronet_material_bootstrap.py'),'prepare','--cronet-root',str(home/'cronet-go')])]
     reached=4 if stage=='fetch' and mode!='success' else 7
     self.assertEqual(calls,clone[:reached])
     if mode=='timeout':
      self.assertIn(process.returncode,(-signal.SIGKILL,128+signal.SIGKILL))
      terms={e['role']:e for e in events if e['kind']=='term'}
      self.assertEqual(set(terms),{'parent','child'})
      for role in ('parent','child'):
       self.assertEqual(terms[role]['pid'],ready[role]['pid'])
       # Check before finally cleanup: EOF and no runnable process are the
       # actual group-termination postcondition, rather than cleanup's effect.
       self.assertIn(process_state(ready[role]['pid']),(None,'Z'))
     else:
      self.assertEqual(process.returncode,expected)
      if mode=='primary':self.assertIn(('primary-'+stage+'\n').encode(),stderr)
    finally:
     if selector is not None:selector.close()
     kill_session(process.pid)
     if process.poll() is None:process.kill()
     process.communicate(timeout=3)



_NATIVE_INDEX_BRIDGE = """python3 -B - <<'PY'
import sys
sys.path.insert(0, 'scripts/ci')
from github_release import producer_debian_materials
from native_release_index import assemble
assemble('artifacts', measure_debian=producer_debian_materials)
PY"""

class TestNativeIndexProducerBridge(unittest.TestCase):
 def assert_bridge(self,workflow):
  job=workflow['jobs']['native_index'];steps=job['steps']
  matches=[step for step in steps if step.get('name')=='Assemble explicitly selected final or staging index']
  self.assertEqual(len(matches),1);step=matches[0]
  self.assertEqual(step['run'].strip(),_NATIVE_INDEX_BRIDGE)
  self.assertNotIn('if',step);self.assertNotIn('continue-on-error',step)
  expression=lambda s:'$'+'{{ '+s+' }}'
  self.assertEqual(step['env'],{
   'VERSION':expression('needs.calculate_version.outputs.version'),
   'REQUIRE_RELEASE_TAG':expression("inputs.evidence_mode == 'final' && 'true' || 'false'"),
   'EXPECTED_RELEASE_TAG_OBJECT':expression('needs.calculate_version.outputs.tag_object'),
   'POLARIS_DEBIAN_REQUIRED':expression('needs.calculate_version.outputs.material_required'),
   'POLARIS_DEBIAN_RAW_ID':expression('needs.debian_materials.outputs.raw_id'),
   'POLARIS_DEBIAN_RAW_DIGEST':expression('needs.debian_materials.outputs.raw_digest'),
   'POLARIS_DEBIAN_READY_ID':expression('needs.debian_materials.outputs.ready_id'),
   'POLARIS_DEBIAN_READY_DIGEST':expression('needs.debian_materials.outputs.ready_digest'),
   'GH_TOKEN':expression('github.token')})
  self.assertNotIn('GH_TOKEN',workflow.get('env',{}));self.assertNotIn('GH_TOKEN',job.get('env',{}))
  self.assertEqual(job['permissions'],{'contents':'read','actions':'read'})
  self.assertEqual(job['needs'],['calculate_version','build','build_windows7',
   'build_darwin','build_windows','native_smoke','native_windows_proof','debian_materials'])
  checkouts=[s for s in steps if s.get('uses','').startswith('actions/checkout@')]
  self.assertEqual(len(checkouts),1);checkout=checkouts[0]
  self.assertEqual(checkout['uses'],'actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8')
  self.assertEqual(checkout['with']['ref'],expression('github.sha'))
  self.assertEqual(checkout['with']['fetch-depth'],0)
  self.assertLess(steps.index(checkout),steps.index(step))
  # Execute the actual configured fixed bridge with only its product entry
  # intercepted. This checks the imported real capability object and arguments.
  import github_release,native_release_index
  with mock.patch.object(native_release_index,'assemble') as assemble, \
       mock.patch.object(sys,'path',list(sys.path)):
   exec(compile('\n'.join(step['run'].strip().splitlines()[1:-1]),
                '<configured-native-index-bridge>','exec'),{})
  assemble.assert_called_once_with('artifacts',measure_debian=github_release.producer_debian_materials)
 def test_fixed_producer_step_passes_the_actual_measurement_function(self):
  self.assert_bridge(yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text()))
 def test_no_cli_provider_copied_binding_or_reordered_checkout_can_replace_the_bridge(self):
  workflow=yaml.safe_load((ROOT/'.github/workflows/build.yml').read_text())
  for case in ('old-cli','missing-measurement','copied-json','dynamic-provider','wrong-role',
               'missing-required','missing-token','job-token','shallow-checkout','late-checkout','ignored'):
   with self.subTest(case=case):
    bad=copy.deepcopy(workflow);job=bad['jobs']['native_index'];steps=job['steps']
    step=next(s for s in steps if s.get('name')=='Assemble explicitly selected final or staging index')
    checkout=next(s for s in steps if s.get('uses','').startswith('actions/checkout@'))
    if case=='old-cli':step['run']='python3 scripts/ci/native_release_index.py assemble artifacts'
    elif case=='missing-measurement':step['run']=step['run'].replace('measure_debian=producer_debian_materials','measure_debian=None')
    elif case=='copied-json':step['run']=step['run'].replace('measure_debian=producer_debian_materials',"measure_debian=lambda *a: json.loads(open('binding.json').read())")
    elif case=='dynamic-provider':step['run']=step['run'].replace('from github_release import producer_debian_materials',"producer_debian_materials=getattr(__import__(os.environ['PROVIDER']),'producer_debian_materials')")
    elif case=='wrong-role':step['run']=step['run'].replace("assemble('artifacts',","assemble('other-role',")
    elif case=='missing-required':del step['env']['POLARIS_DEBIAN_REQUIRED']
    elif case=='missing-token':del step['env']['GH_TOKEN']
    elif case=='job-token':job['env']={'GH_TOKEN':step['env']['GH_TOKEN']}
    elif case=='shallow-checkout':checkout['with']['fetch-depth']=1
    elif case=='late-checkout':steps.remove(checkout);steps.append(checkout)
    elif case=='ignored':step['continue-on-error']=True
    with self.assertRaises((AssertionError,KeyError)):self.assert_bridge(bad)

if __name__=='__main__':unittest.main()

