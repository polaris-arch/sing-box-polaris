package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
)

const tlsGateVersion = "1.15.0-polaris-alpha.12" // Validation binary, never a release asset.

func sourceOutputArguments(args []string, cost bool) (string, bool, error) {
	flags := flag.NewFlagSet("source-gate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	output := flags.String("output", "", "evidence directory")
	retain := false
	if cost {
		flags.BoolVar(&retain, "retain-source-input", false, "retain Source inputs without measurements")
	}
	if err := flags.Parse(args); err != nil {
		return "", false, err
	}
	if flags.NArg() != 0 || *output == "" {
		return "", false, fmt.Errorf("expected an evidence output directory and no positional arguments")
	}
	directory, err := filepath.Abs(*output)
	return directory, retain, err
}

func sourceGateEnvironment() ([]string, error) {
	temporary, err := nativeEnvironment("RUNNER_TEMP")
	if err != nil {
		return nil, err
	}
	if temporary["RUNNER_TEMP"] == "" {
		return nil, fmt.Errorf("runner temporary directory missing")
	}
	root, err := filepath.Abs(temporary["RUNNER_TEMP"])
	if err != nil {
		return nil, err
	}
	scratch := filepath.Join(root, "tls-fingerprint-scratch")
	if err := os.MkdirAll(scratch, 0o700); err != nil {
		return nil, err
	}
	if err := os.Setenv("TMPDIR", scratch); err != nil {
		return nil, err
	}
	return append(os.Environ(), "GOCACHE="+filepath.Join(root, "tls-fingerprint-go-cache"), "GOTOOLCHAIN=local", "GOFLAGS=-mod=readonly", "GOMAXPROCS=2", "GIT_TERMINAL_PROMPT=0", "GIT_NO_REPLACE_OBJECTS=1"), nil
}

func sourceForkTests() []string {
	names := slices.Clone(sourceRequiredForkBase)
	for _, profile := range []string{"chrome_155", "safari_26_3"} {
		for _, name := range []string{"good", "missing-client-identity", "wrong-hostname"} {
			names = append(names, "TestUTLSHostnameAndMutualTLS/"+profile+"/"+name)
		}
		for _, name := range []string{"accepted", "session-id-conflict"} {
			names = append(names, "TestUTLSRealECHHandshakeAndSessionIDConflict/"+profile+"/"+name)
		}
		for _, owned := range []string{"false", "true"} {
			names = append(names, "TestRealityVisionActualHandshakeAndDirect/"+profile+"/owned-"+owned)
		}
		names = append(names, "TestShadowTLSV3ActualAuthenticationAndForwarding/"+profile)
	}
	for _, name := range []string{"http1-only", "custom", "mismatch", "clone-set-next-protos", "server-policy-independent-of-camouflage", "server-long-alpn-exceeds-camouflage", "server-shorter-alpn-keeps-camouflage-budget"} {
		names = append(names, "TestRealityExplicitALPNWireAndClone/"+name)
	}
	for _, name := range []string{"wrong-password", "tampered-session"} {
		names = append(names, "TestShadowTLSV3RejectsWrongPasswordAndTamperedSession/"+name)
	}
	for _, provider := range []string{"standard-Conn", "meta-Conn", "meta-UConn", "refraction-Conn", "refraction-UConn"} {
		for _, wrapped := range []string{"false", "true"} {
			names = append(names, "TestVisionTLSProvidersActualHandshakeAndDirect/"+provider+"/wrapped-"+wrapped)
		}
		for _, test := range []string{"TestVisionTLS12RemainsRecordMode", "TestVisionTLSFragmentedProviderBuffers", "TestVisionTLSFragmentedDetectionFallsBackSafely"} {
			names = append(names, test+"/"+provider)
		}
	}
	return names
}

func tlsGate(args []string) (err error) {
	output, _, err := sourceOutputArguments(args, false)
	if err != nil {
		return err
	}
	contextRecord, err := sourceGateContext()
	if err != nil {
		return err
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(output, 0o700); err != nil {
		return err
	}
	environment, err := sourceGateEnvironment()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	input := map[string]any{"repository": repository, "expectedSource": contextRecord["sourceCommit"], "runId": os.Getenv("GITHUB_RUN_ID"), "attempt": os.Getenv("GITHUB_RUN_ATTEMPT"), "workBudgetSeconds": 2700, "cache": filepath.Join(os.Getenv("RUNNER_TEMP"), "tls-fingerprint-go-cache")}
	if err := sourceReceipt(filepath.Join(output, "gate-input.json"), input, false, 16384); err != nil {
		return err
	}
	status := func(name string) (string, error) {
		text, diagnostic, code, readError := sourceGitResult(context.Background(), root, environment, "status", "--porcelain", "--untracked-files=all")
		if readError != nil {
			return "", readError
		}
		if code == nil || *code != 0 {
			return "", fmt.Errorf("source status failed: %s", diagnostic)
		}
		return text, os.WriteFile(filepath.Join(output, name+"-source-status.log"), []byte(text), 0o600)
	}
	free, err := sourceDiskFree(output)
	if err != nil {
		return err
	}
	if free < 14*1024*1024*1024 {
		return fmt.Errorf("Go/uTLS gate lacks its 8GiB growth plus 6GiB headroom budget")
	}
	source, err := sourceGitText(ctx, root, environment, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	initial, err := status("initial")
	if err != nil {
		return err
	}
	if source != contextRecord["sourceCommit"] || initial != "" {
		return fmt.Errorf("gate requires exact clean dispatch source")
	}
	goVersion, err := sourceGoVersion(ctx, root, environment)
	if err != nil {
		return err
	}
	target, err := sourceGoEnvironment(ctx, root, environment, "GOOS", "GOARCH")
	if err != nil {
		return err
	}
	goOS, goArch := target[0], target[1]
	linker, err := os.ReadFile(filepath.Join(root, "release/LDFLAGS"))
	if err != nil {
		return err
	}
	ldflags := strings.TrimSpace(string(linker))
	receipt := map[string]any{"sourceCommit": source, "actualGoVersion": goVersion, "target": goOS + "/" + goArch, "commands": []map[string]any{}, "errors": []string{}}
	problem := func(message string) { receipt["errors"] = append(receipt["errors"].([]string), message) }
	defer func() {
		_, statusError := status("final")
		recordError := sourceReceipt(filepath.Join(output, "gate.json"), receipt, false, 1024*1024)
		err = errors.Join(err, statusError, recordError)
	}()
	execute := func(name string, command []string) (bool, error) {
		started := time.Now()
		commandContext, stop := context.WithTimeout(ctx, 20*time.Minute)
		code, runError := sourceLogged(commandContext, root, environment, filepath.Join(output, name+".log"), command...)
		stop()
		record := map[string]any{"name": name, "command": command, "exitCode": code, "elapsedSeconds": time.Since(started).Seconds(), "log": name + ".log"}
		receipt["commands"] = append(receipt["commands"].([]map[string]any), record)
		if runError != nil {
			problem(name + ": " + runError.Error())
		}
		if code == nil || *code != 0 {
			problem(name + ": failed; preserve original log")
		}
		_, statusError := status(name + "-after")
		return runError == nil && code != nil && *code == 0, statusError
	}
	diagnostics := map[string]any{}
	vision, visionError := validateVisionSource(root, diagnostics)
	if visionError == nil {
		receipt["visionSource"] = vision
	}
	if visionError != nil {
		problem("vision-source: " + visionError.Error())
		diagnostics["error"] = visionError.Error()
	}
	if saveError := sourceReceipt(filepath.Join(output, "vision-source.json"), diagnostics, false, 1024*1024); saveError != nil {
		return errors.Join(visionError, saveError)
	}
	if visionError != nil {
		return visionError
	}
	if _, err := execute("verify-modules", []string{"go", "mod", "verify"}); err != nil {
		return err
	}
	common := []string{"go", "test", "-json", "-race", "-p=2", "-parallel=2", "-count=1", "-timeout=15m", "-ldflags=" + ldflags}
	for _, suite := range []struct {
		name                string
		arguments, required []string
	}{
		{"fork", []string{"-gcflags=all=-d=checkptr=2", "-tags=with_utls,badlinkname,with_tailscale", "./protocol/vless", "github.com/sagernet/sing-vmess/...", "./common/tls", "./common/badtls", "./common/ktls", "./protocol/shadowtls", "./experimental/libbox", "./experimental/libbox/internal/oomprofile", "./cmd/sing-box"}, append(sourceForkTests(), sourceRequiredLibbox...)},
		{"stub", []string{"-tags=with_tailscale", "./common/tls", "./experimental/libbox", "./experimental/libbox/internal/oomprofile", "./cmd/sing-box"}, sourceRequiredLibbox},
		{"upstream", []string{"-run=^(" + sourceUpstreamPattern + ")$", "github.com/refraction-networking/utls"}, sourceRequiredUpstream},
	} {
		passed, err := execute(suite.name, slices.Concat(common, suite.arguments))
		if err != nil {
			return err
		}
		if passed {
			if err := requireSourceTests(filepath.Join(output, suite.name+".log"), suite.required); err != nil {
				problem(err.Error())
			}
		}
	}
	beforeCore, err := status("pre-core")
	if err != nil {
		return err
	}
	if beforeCore != "" {
		return fmt.Errorf("core source became dirty before capability build: %s", beforeCore)
	}
	for _, enabled := range []bool{true, false} {
		name := "selected-core"
		if !enabled {
			name = "stub-core"
		}
		core := filepath.Join(output, name)
		if runtime.GOOS == "windows" {
			core += ".exe"
		}
		flags := ldflags + " -X github.com/sagernet/sing-box/constant.SourceRevision=" + source + " -X github.com/sagernet/sing-box/constant.Version=" + tlsGateVersion
		command := []string{"go", "build", "-p=2", "-trimpath", "-ldflags=" + flags, "-o", core}
		if enabled {
			command = append(command, "-tags=with_utls,badlinkname")
		}
		command = append(command, "./cmd/sing-box")
		passed, err := execute(name, command)
		if err != nil {
			return err
		}
		if passed {
			observed, probeError := probeTLSRuntime(ctx, root, core, environment, source, tlsGateVersion, goVersion, goOS+"/"+goArch, enabled)
			if probeError != nil {
				problem(name + ": " + probeError.Error())
				continue
			}
			if err := sourceReceipt(filepath.Join(output, name+"-probe.json"), observed, false, 8*1024*1024); err != nil {
				problem(name + ": " + err.Error())
			}
		}
	}
	if _, err := execute("module-source-clean", []string{"git", "diff", "--exit-code", "--", "go.mod", "go.sum"}); err != nil {
		return err
	}
	if failures := receipt["errors"].([]string); len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return nil
}

func requireSourceTests(filename string, required []string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	passed, skipped := map[string]bool{}, map[string]bool{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		var event struct{ Action, Test string }
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		if event.Test == "" {
			continue
		}
		if event.Action == "pass" {
			passed[event.Test] = true
		}
		if event.Action == "skip" {
			skipped[event.Test] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	missing := []string{}
	for _, name := range required {
		if !passed[name] || skipped[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) != 0 {
		slices.Sort(missing)
		return fmt.Errorf("required runtime tests missing/skipped: %v", missing)
	}
	return nil
}

var sourceRequiredForkBase = []string{
	"TestFingerprintCapabilitiesDescribeLoadedCore",
	"TestFingerprintCapabilitiesRejectConflictingOrInvalidSourceStamps",
	"TestOOMAdjacentRuntimeProfilesEncode",
	"TestOOMHeapRuntimeRecordLayout",
	"TestRealityExplicitALPNWireAndClone",
	"TestRealityFiltersTemplatePQButPreservesClassicalShare",
	"TestRealityUpstreamClientMetaServerActualHandshake",
	"TestRealityVisionActualHandshakeAndDirect",
	"TestRealityVisionRejectsWrongKeyBeforePayload",
	"TestRuntimeVisionActualRejectsUnsupportedUDPAndFlow",
	"TestRuntimeVisionActualTCPAndXUDP",
	"TestRuntimeVisionRejectsActualUpgradedTransports",
	"TestShadowTLSV3ActualAuthenticationAndForwarding",
	"TestShadowTLSV3ConcurrentConfigIsolation",
	"TestShadowTLSV3RejectsRealECH",
	"TestShadowTLSV3RejectsWrongPasswordAndTamperedSession",
	"TestTLSReadWaitAndCipherMethodsStayInOwningLibrary",
	"TestUTLSAuthenticationNegativesRejectTransportFailures",
	"TestUTLSConcurrentWaitingHandshakeCancellation",
	"TestUTLSExplicitALPNUpsertAbsentAndPSKLast",
	"TestUTLSHostnameAndMutualTLS",
	"TestUTLSMappedProfilesAreRealAndMatchSchema",
	"TestUTLSPinningSNIAndIgnoredCurveControl",
	"TestUTLSProfilesActualTLSAndNegotiatedGroup",
	"TestUTLSRealECHHandshakeAndSessionIDConflict",
	"TestUTLSSessionIDFailureCancellationAndCloneECH",
	"TestUTLSSessionIDGeneratorCloneAndImplicitHandshake",
	"TestVisionConcurrentPlainTraffic",
	"TestVisionTLS12RemainsRecordMode",
	"TestVisionTLSBufferLayoutAndGCLifetime",
	"TestVisionTLSBufferLayoutRejectsUnknownShapes",
	"TestVisionTLSFragmentedDetectionFallsBackSafely",
	"TestVisionTLSFragmentedProviderBuffers",
	"TestVisionTLSProviderUnknownAndNilRejected",
	"TestVisionTLSProvidersActualHandshakeAndDirect",
	"TestVisionTLSProvidersRejectBadCertificate",
	"TestVisionUTLSNilProvidersRejected",
}

var sourceRequiredLibbox = []string{
	"TestFingerprintCapabilitiesDescribeLoadedCore",
	"TestMonitorAlreadyDeliveringAIsolatedFromReloadB",
	"TestMonitorCallbackSelfCloseAndFirstErrors",
	"TestMonitorClosedAIsolatedFromReloadB",
	"TestMonitorDNSChangeWithoutInterfaceEvent",
	"TestMonitorDNSReadCannotOverwriteChangedInterface",
	"TestMonitorDNSReadClosedAIsolatedFromB",
	"TestMonitorDNSWatcherCallbackCanCloseItself",
	"TestMonitorDNSWatcherCloseErrorRetained",
	"TestMonitorDNSWatcherCreationRacingClose",
	"TestMonitorDNSWatcherStartFailureRevokesProjection",
	"TestMonitorNativeIdentityAndSynchronousInitialUpdate",
	"TestMonitorPartialConstructionCloseCannotDetachLive",
	"TestMonitorPlatformStartFailureClosesDNSWatcher",
	"TestMonitorRejectForeignAndUnbound",
	"TestValidationMembershipActualCanonicalOrderedTargetsAndCache",
	"TestValidationMembershipActualDifferentTagsSameCanonicalFileUnknown",
	"TestValidationMembershipActualFailureRemainsUnknown",
	"TestValidationMembershipCleanupErrorDoesNotSignGlobalRetirement",
	"TestValidationMembershipLateOriginalGuardBeforeAndAfterCommit",
	"TestValidationMembershipOriginalScopeDoesNotProveWriterTerminal",
	"TestValidationNeverPromotesUnreviewedConstruction",
	"TestValidationParseRejectHasNoConstruction",
	"TestValidationTailscaleCanonicalImplicitScope",
	"TestValidationTailscaleConstructionPanicAfterActualDisposal",
	"TestValidationTailscaleOriginalConstructorNoStoreAndCachedFile",
	"TestValidationTailscaleOriginalDuplicateMembershipRemainsUnknown",
	"TestValidationTailscalePartialAndEmptyRemainUnknown",
}

var sourceRequiredUpstream = []string{
	"TestChrome155CapturedClientHello",
	"TestChrome155MLDSAHandshake",
	"TestClientHandshakeContextCancellation",
	"TestTrustAnchorsExtensionRejectsMalformedData",
	"TestUTLSECHCachedSessionPrivacy",
	"TestUTLSECHPreSharedKeyPrivacy",
	"TestUTLSHelloGolangECHResumption",
	"TestUTLSMLDSAAndLocalCertificate",
	"TestUTLSMLKEM1024",
	"TestUTLSPSKResumptionWithHelloRetryRequest",
}

const sourceUpstreamPattern = "TestChrome155.*|TestChrome133CapabilitiesPreserved|TestUTLSMLDSAAndLocalCertificate|TestUTLSMLKEM1024|TestUTLSPSKResumptionWithHelloRetryRequest|TestUTLSHelloGolangECHResumption|TestUTLSECH.*|TestTrustAnchors.*|TestMLDSASignatureSchemeJSON|TestParrotFingerprintsReuseHybridClassicalKeyShare|TestHybridClassicalKeySharesAreIndependentByDefault|TestClientHelloSpecCloneDeepCopy|TestApplyPresetDoesNotMutateOriginalSpec|TestClientHandshakeContextCancellation"
