"""One concentrated remote-only Go/uTLS source gate; never dispatches CI itself."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import shutil
import signal
import time

from tls_fingerprint_probe import probe
from vision_source import validate as validate_vision_source

ROOT = Path(__file__).resolve().parents[2]
VERSION = '1.15.0-polaris-alpha.12'  # validation binary only, never a release asset
UPSTREAM_TESTS = ('TestChrome155.*|TestChrome133CapabilitiesPreserved|TestUTLSMLDSAAndLocalCertificate|'
                  'TestUTLSMLKEM1024|TestUTLSPSKResumptionWithHelloRetryRequest|TestUTLSHelloGolangECHResumption|'
                  'TestUTLSECH.*|TestTrustAnchors.*|TestMLDSASignatureSchemeJSON|'
                  'TestParrotFingerprintsReuseHybridClassicalKeyShare|TestHybridClassicalKeySharesAreIndependentByDefault|'
                  'TestClientHelloSpecCloneDeepCopy|TestApplyPresetDoesNotMutateOriginalSpec|TestClientHandshakeContextCancellation')
REQUIRED_UPSTREAM = {'TestChrome155CapturedClientHello', 'TestChrome155MLDSAHandshake',
                     'TestUTLSMLDSAAndLocalCertificate', 'TestUTLSMLKEM1024',
                     'TestUTLSPSKResumptionWithHelloRetryRequest', 'TestUTLSHelloGolangECHResumption',
                     'TestUTLSECHPreSharedKeyPrivacy', 'TestUTLSECHCachedSessionPrivacy',
                     'TestTrustAnchorsExtensionRejectsMalformedData', 'TestClientHandshakeContextCancellation'}
REQUIRED_FORK = {'TestUTLSMappedProfilesAreRealAndMatchSchema', 'TestUTLSProfilesActualTLSAndNegotiatedGroup',
                 'TestUTLSSessionIDGeneratorCloneAndImplicitHandshake', 'TestUTLSSessionIDFailureCancellationAndCloneECH',
                 'TestUTLSPinningSNIAndIgnoredCurveControl', 'TestRealityFiltersTemplatePQButPreservesClassicalShare',
                 'TestUTLSRealECHHandshakeAndSessionIDConflict', 'TestRealityUpstreamClientMetaServerActualHandshake',
                 'TestFingerprintCapabilitiesDescribeLoadedCore', 'TestTLSFingerprintCapabilitiesMatchCoreContract', 'TestUTLSHostnameAndMutualTLS',
                 'TestUTLSConcurrentWaitingHandshakeCancellation', 'TestTLSReadWaitAndCipherMethodsStayInOwningLibrary',
                 'TestFingerprintCapabilitiesRejectConflictingOrInvalidSourceStamps',
                 'TestRealityExplicitALPNWireAndClone', 'TestShadowTLSV3ActualAuthenticationAndForwarding',
                 'TestShadowTLSV3RejectsWrongPasswordAndTamperedSession', 'TestShadowTLSV3ConcurrentConfigIsolation',
                 'TestShadowTLSV3RejectsRealECH', 'TestOOMHeapRuntimeRecordLayout'}

REQUIRED_FORK.update({'TestUTLSExplicitALPNUpsertAbsentAndPSKLast','TestOOMAdjacentRuntimeProfilesEncode','TestUTLSAuthenticationNegativesRejectTransportFailures'})
REQUIRED_FORK.update('TestUTLSHostnameAndMutualTLS/' + profile + '/' + case
                     for profile in ('chrome_155', 'safari_26_3')
                     for case in ('good', 'missing-client-identity', 'wrong-hostname'))
REQUIRED_FORK.update('TestUTLSRealECHHandshakeAndSessionIDConflict/' + profile + '/' + case
                     for profile in ('chrome_155', 'safari_26_3')
                     for case in ('accepted', 'session-id-conflict'))

REQUIRED_FORK.update('TestRealityExplicitALPNWireAndClone/' + name for name in ('http1-only', 'custom', 'mismatch', 'clone-set-next-protos', 'server-policy-independent-of-camouflage', 'server-long-alpn-exceeds-camouflage', 'server-shorter-alpn-keeps-camouflage-budget'))
REQUIRED_FORK.update('TestShadowTLSV3RejectsWrongPasswordAndTamperedSession/' + name for name in ('wrong-password', 'tampered-session'))
REQUIRED_FORK.update('TestShadowTLSV3ActualAuthenticationAndForwarding/' + name for name in ('chrome_155', 'safari_26_3'))


# A provider handshake alone cannot prove the Vision adapter or direct path.
REQUIRED_FORK.update({'TestRealityVisionActualHandshakeAndDirect',
                      'TestRealityVisionRejectsWrongKeyBeforePayload',
                      'TestRuntimeVisionActualTCPAndXUDP',
                      'TestRuntimeVisionActualRejectsUnsupportedUDPAndFlow',
                      'TestRuntimeVisionRejectsActualUpgradedTransports',
                      'TestVisionTLSProvidersActualHandshakeAndDirect',
                      'TestVisionTLSProvidersRejectBadCertificate',
                      'TestVisionTLSBufferLayoutAndGCLifetime',
                      'TestVisionTLSBufferLayoutRejectsUnknownShapes',
                      'TestVisionTLSProviderUnknownAndNilRejected',
                      'TestVisionUTLSNilProvidersRejected', 'TestVisionConcurrentPlainTraffic',
                      'TestVisionTLS12RemainsRecordMode', 'TestVisionTLSFragmentedProviderBuffers',
                      'TestVisionTLSFragmentedDetectionFallsBackSafely'})
REQUIRED_FORK.update('TestRealityVisionActualHandshakeAndDirect/' + profile + '/owned-' + owned
                     for profile in ('chrome_155', 'safari_26_3') for owned in ('false', 'true'))
REQUIRED_FORK.update('TestVisionTLSProvidersActualHandshakeAndDirect/' + provider + '/wrapped-' + wrapped
                     for provider in ('standard-Conn', 'meta-Conn', 'meta-UConn', 'refraction-Conn', 'refraction-UConn')
                     for wrapped in ('false', 'true'))
REQUIRED_FORK.update(test + '/' + provider
                     for test in ('TestVisionTLS12RemainsRecordMode', 'TestVisionTLSFragmentedProviderBuffers',
                                  'TestVisionTLSFragmentedDetectionFallsBackSafely')
                     for provider in ('standard-Conn', 'meta-Conn', 'meta-UConn', 'refraction-Conn', 'refraction-UConn'))


# Both modes run real Tailscale constructors and generic validation/lifecycle
# controls. Stub means no with_utls; it does not omit the constructor feature.
REQUIRED_LIBBOX = {
    'TestValidationParseRejectHasNoConstruction',
    'TestValidationNeverPromotesUnreviewedConstruction',
    'TestValidationTailscaleOriginalConstructorNoStoreAndCachedFile',
    'TestValidationTailscalePartialAndEmptyRemainUnknown',
    'TestValidationTailscaleCanonicalImplicitScope',
    'TestValidationTailscaleOriginalDuplicateMembershipRemainsUnknown',
    'TestValidationTailscaleConstructionPanicAfterActualDisposal',
    'TestValidationMembershipActualCanonicalOrderedTargetsAndCache',
    'TestValidationMembershipActualFailureRemainsUnknown',
    'TestValidationMembershipOriginalScopeDoesNotProveWriterTerminal',
    'TestValidationMembershipLateOriginalGuardBeforeAndAfterCommit',
    'TestValidationMembershipActualDifferentTagsSameCanonicalFileUnknown',
    'TestValidationMembershipCleanupErrorDoesNotSignGlobalRetirement',
    'TestFingerprintCapabilitiesDescribeLoadedCore',
    'TestTLSFingerprintCapabilitiesMatchCoreContract',
    'TestMonitorClosedAIsolatedFromReloadB',
    'TestMonitorAlreadyDeliveringAIsolatedFromReloadB',
    'TestMonitorPartialConstructionCloseCannotDetachLive',
    'TestMonitorCallbackSelfCloseAndFirstErrors',
    'TestMonitorNativeIdentityAndSynchronousInitialUpdate',
    'TestMonitorRejectForeignAndUnbound',
    'TestMonitorDNSChangeWithoutInterfaceEvent',
    'TestMonitorDNSWatcherCallbackCanCloseItself',
    'TestMonitorDNSReadClosedAIsolatedFromB',
    'TestMonitorDNSWatcherCreationRacingClose',
    'TestMonitorDNSWatcherCloseErrorRetained',
    'TestMonitorDNSReadCannotOverwriteChangedInterface',
    'TestMonitorDNSWatcherStartFailureRevokesProjection',
    'TestMonitorPlatformStartFailureClosesDNSWatcher',
}


def commands(ldflags):
    common = ['go', 'test', '-json', '-race', '-p=2', '-parallel=2', '-count=1', '-timeout=15m', '-ldflags=' + ldflags]
    return [
        ('fork', common + ['-gcflags=all=-d=checkptr=2', '-tags=with_utls,badlinkname,with_tailscale', './protocol/vless', 'github.com/sagernet/sing-vmess/...', './common/tls', './common/badtls', './common/ktls', './protocol/shadowtls', './experimental/libbox', './experimental/libbox/internal/oomprofile', './cmd/sing-box']),
        ('stub', common + ['-tags=with_tailscale', './common/tls', './experimental/libbox', './experimental/libbox/internal/oomprofile', './cmd/sing-box']),
        ('upstream', common + ['-run=^(' + UPSTREAM_TESTS + ')$', 'github.com/refraction-networking/utls']),
    ]


def require_tests(path, expected):
    passed, skipped = set(), set()
    with Path(path).open() as stream:
        for line in stream:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get('Action') == 'pass' and 'Test' in event:
                passed.add(event['Test'])
            if event.get('Action') == 'skip' and 'Test' in event:
                skipped.add(event['Test'])
    if expected - passed or expected & skipped:
        raise ValueError('required runtime tests missing/skipped: ' + repr(sorted(expected - passed | expected & skipped)))


def run_logged(command, *, cwd, env, logfile, timeout):
    """Own and retire the command's process tree before another heavy command."""
    with Path(logfile).open('wb') as stream:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT,
                                   start_new_session=sys.platform != 'win32',
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0)
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None
        finally:
            if process.poll() is None:
                if sys.platform == 'win32':
                    subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], stdout=stream, stderr=subprocess.STDOUT, timeout=15)
                else:
                    try: os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError: pass
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        try: os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError: pass
                process.wait(timeout=15)


def finalize_evidence(output, receipt, source_status, primary_error):
    """Try both records, but never hide the original gate failure with I/O failure."""
    errors = []
    for name, operation in (
            ('source status', lambda: source_status('final')),
            ('gate receipt', lambda: (output / 'gate.json').write_text(json.dumps(receipt, indent=2) + '\n'))):
        try:
            operation()
        except Exception as error:
            errors.append(error)
            if primary_error is not None:
                primary_error.add_note('final ' + name + ' also failed: ' + type(error).__name__)
    if errors and primary_error is None:
        raise errors[0]


def main():
    parser = argparse.ArgumentParser();parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('GITHUB_REPOSITORY') != 'polaris-arch/sing-box-polaris':
        raise RuntimeError('project compile/runtime gates are remote CI only')
    output = args.output.resolve();output.mkdir(parents=True, exist_ok=True)
    os.environ['GOCACHE'] = str(Path(os.environ['RUNNER_TEMP']).resolve() / 'tls-fingerprint-go-cache')
    deadline = time.monotonic() + 45 * 60
    (output / 'gate-input.json').write_text(json.dumps({'repository': os.environ['GITHUB_REPOSITORY'], 'expectedSource': os.environ['GITHUB_SHA'], 'runId': os.environ['GITHUB_RUN_ID'], 'attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'workBudgetSeconds': 45 * 60, 'cache': os.environ.get('GOCACHE')}, indent=2) + '\n')
    scratch = Path(os.environ['RUNNER_TEMP']).resolve() / 'tls-fingerprint-scratch'
    scratch.mkdir(exist_ok=True)
    os.environ['TMPDIR'] = str(scratch)
    def source_status(name):
        status = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=ROOT, text=True)
        (output / (name + '-source-status.log')).write_text(status)
        return status
    # Per isolated CI VM: 8GiB cache/build growth + 6GiB system headroom.
    if shutil.disk_usage(output).free < 14 * 1024**3:
        raise RuntimeError('Go/uTLS gate lacks its 8GiB growth plus 6GiB headroom budget')
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if source != os.environ['GITHUB_SHA'] or source_status('initial'):
        raise RuntimeError('gate requires exact clean dispatch source')
    required_go = 'go' + (ROOT / 'release/GO_VERSION').read_text().strip()
    env = dict(os.environ, GOTOOLCHAIN='local', GOFLAGS='-mod=readonly', GOMAXPROCS='2')
    actual_go = subprocess.check_output(['go', 'env', 'GOVERSION'], env=env, text=True).strip()
    if actual_go != required_go:
        raise RuntimeError('gate Go version differs from source-owned exact pin')
    target = subprocess.check_output(['go', 'env', 'GOOS', 'GOARCH'], env=env, text=True).strip().splitlines()
    ldflags = (ROOT / 'release/LDFLAGS').read_text().strip()
    receipt = {'sourceCommit': source, 'actualGoVersion': actual_go, 'target': '/'.join(target), 'commands': [], 'errors': []}

    def execute(name, command, timeout=1200):
        logfile = output / (name + '.log');print('+', ' '.join(map(str, command)), flush=True)
        start = time.monotonic();code = None
        remaining = int(deadline - time.monotonic())
        if remaining <= 0:
            receipt['errors'].append(name + ': concentrated job work budget exhausted; not started')
        else:
            code = run_logged(command, cwd=ROOT, env=env, logfile=logfile, timeout=min(timeout, remaining))
            if code is None: receipt['errors'].append(name + ': timeout; owned process tree retired')
        receipt['commands'].append({'name': name, 'command': list(map(str, command)), 'exitCode': code,
                                    'elapsedSeconds': time.monotonic() - start, 'log': logfile.name})
        source_status(name + '-after')
        if code != 0:
            receipt['errors'].append(name + ': failed; preserve original log')
        return code == 0

    try:
        vision_diagnostics = {}
        vision_error = None
        try:
            receipt['visionSource'] = validate_vision_source(ROOT, diagnostics=vision_diagnostics)
        except Exception as error:
            vision_error = error
            receipt['errors'].append('vision-source: ' + str(error))
            vision_diagnostics['error'] = str(error)
            raise
        finally:
            try:
                (output / 'vision-source.json').write_text(json.dumps(vision_diagnostics, indent=2) + '\n')
            except OSError as diagnostic_error:
                receipt['errors'].append('vision-source diagnostics: ' + str(diagnostic_error))
                if vision_error is None:
                    raise
        execute('verify-modules', ['go', 'mod', 'verify'])
        for name, command in commands(ldflags):
            if execute(name, command):
                try:
                    if name in ('fork', 'stub'): require_tests(output / (name + '.log'), REQUIRED_LIBBOX)
                    if name == 'fork': require_tests(output / 'fork.log', REQUIRED_FORK)
                    if name == 'upstream': require_tests(output / 'upstream.log', REQUIRED_UPSTREAM)
                except ValueError as error:
                    receipt['errors'].append(str(error))
        if sys.platform == 'win32':
            if execute('windows-root', [sys.executable, 'scripts/ci/windows_root_gate.py', '--output', str(output / 'windows-root')], timeout=300):
                try:
                    required = {'TestPolarisRootRemoveAllConfinement/' + mode + '/' + kind
                                for mode in ('native', 'legacy-fallback') for kind in ('ordinary', 'junction', 'symlink')}
                    require_tests(output / 'windows-root.log', required)
                except ValueError as error:
                    receipt['errors'].append(str(error))
        # Python caches belong in runner.temp, never in the source whose VCS
        # identity the actual core queries. Check all untracked inputs too.
        status = source_status('pre-core')
        if status:
            raise RuntimeError('core source became dirty before capability build: ' + status)
        suffix = '.exe' if sys.platform == 'win32' else ''
        for enabled in [True, False]:
            name = 'selected-core' if enabled else 'stub-core';core = output / (name + suffix)
            flags = ldflags + ' -X github.com/sagernet/sing-box/constant.SourceRevision=' + source + ' -X github.com/sagernet/sing-box/constant.Version=' + VERSION
            command = ['go', 'build', '-p=2', '-trimpath', '-ldflags=' + flags, '-o', str(core)]
            if enabled: command.append('-tags=with_utls,badlinkname')
            if execute(name, command + ['./cmd/sing-box']):
                try:
                    observed = probe(core, source=source, version=VERSION, go_version=actual_go, target='/'.join(target), enabled=enabled)
                    (output / (name + '-probe.json')).write_text(json.dumps(observed, indent=2) + '\n')
                except Exception as error:
                    receipt['errors'].append(name + ': ' + repr(error))
        execute('module-source-clean', ['git', 'diff', '--exit-code', '--', 'go.mod', 'go.sum'])
    finally:
        finalize_evidence(output, receipt, source_status, sys.exc_info()[1])
    if receipt['errors']:
        raise RuntimeError('; '.join(receipt['errors']))


if __name__ == '__main__':
    main()
