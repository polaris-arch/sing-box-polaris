package libbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

func TestValidationParseRejectHasNoConstruction(t *testing.T) {
	config := "{ malformed 中文"
	result := checkConfigWithResult(config, "request-parse", 1000, func(context.Context, option.Options) (error, error) {
		t.Error("constructor entered after parse rejection")
		return nil, nil
	})
	digest := sha256.Sum256([]byte(config))
	if result.requestID != "request-parse" || result.configDigest != hex.EncodeToString(digest[:]) || result.contractVersion != ConfigValidationContractVersion {
		t.Fatalf("binding = %+v", result)
	}
	if result.validation != "Rejected" || result.cleanup != "NoConstruction" || !strings.HasPrefix(result.validationError, "decode config:") {
		t.Fatalf("result = %+v", result)
	}
	if err := CheckConfig(config); err == nil || err.Error() != result.validationError {
		t.Fatalf("legacy error changed: %v / %s", err, result.validationError)
	}
}

func TestValidationNeverPromotesUnreviewedConstruction(t *testing.T) {
	for _, test := range []struct {
		name                string
		validation, cleanup error
		want                string
	}{
		{"accepted", nil, nil, "Accepted"},
		{"rejected", errors.New("initialize endpoint[0]: injected"), nil, "Rejected"},
		{"close-error", nil, errors.New("injected close failure"), "Accepted"},
		{"rejected-close-error", errors.New("initialize endpoint[0]: injected"), errors.New("injected close failure"), "Rejected"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := checkConfigWithResult("{}", "request-"+test.name, 1000, func(context.Context, option.Options) (error, error) { return test.validation, test.cleanup })
			if result.validation != test.want || result.cleanup != "CleanupUnknown" {
				t.Fatalf("result = %+v", result)
			}
			if test.validation != nil && result.validationError != test.validation.Error() {
				t.Fatal("validation error attribution changed")
			}
			if test.cleanup != nil && result.cleanupError != test.cleanup.Error() {
				t.Fatal("cleanup error discarded")
			}
		})
	}
	result := CheckConfigWithResult(`{"log":{"disabled":true}}`, "complete-build", 1000)
	if result.validation != "Accepted" || result.cleanup != "CleanupUnknown" {
		t.Fatalf("complete unstarted build = %+v", result)
	}
}

func TestValidationBlockingCleanupAndLateCompletionKeepOriginalBinding(t *testing.T) {
	entered, release, disposed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	result := checkConfigWithResult("{}", "request-original", 100, func(ctx context.Context, _ option.Options) (error, error) {
		close(entered)
		<-release // model a cleanup callback that ignores cancellation
		if ctx.Err() == nil {
			return errors.New("timeout did not cancel"), nil
		}
		close(disposed)
		return nil, nil
	})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not enter")
	}
	if result.validation != "InternalFailure" || result.cleanup != "CleanupUnknown" {
		t.Fatalf("timeout = %+v", result)
	}
	snapshot := *result
	next := checkConfigWithResult("{", "request-next", 1000, func(context.Context, option.Options) (error, error) {
		t.Error("parse reject constructed")
		return nil, nil
	})
	if next.requestID != "request-next" || next.cleanup != "NoConstruction" {
		t.Fatalf("next = %+v", next)
	}
	close(release)
	select {
	case <-disposed:
	case <-time.After(time.Second):
		t.Fatal("late cleanup worker did not complete")
	}
	if *result != snapshot {
		t.Fatal("late completion mutated an old receipt")
	}
	if result.requestID == next.requestID || result.configDigest == next.configDigest {
		t.Fatal("late work acquired new binding")
	}
}

func TestValidationPanicRemainsUnknown(t *testing.T) {
	result := checkConfigWithResult("{}", "panic", 1000, func(context.Context, option.Options) (error, error) { panic("injected constructor panic") })
	if result.validation != "InternalFailure" || result.cleanup != "CleanupUnknown" {
		t.Fatalf("panic = %+v", result)
	}
}

func validationTailscaleDocument(t *testing.T, result *ConfigValidationResult) []validationTailscaleInstance {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(result.GetTailscaleStoreRetirement()), &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 3 || string(fields["contractVersion"]) != `"polaris-ts-auth-writer-retirement-v1"` || string(fields["globalCleanupEvidence"]) != `"CleanupUnknown"` || string(fields["instances"]) == "null" {
		t.Fatalf("bad envelope: %s", result.GetTailscaleStoreRetirement())
	}
	var instances []validationTailscaleInstance
	if err := json.Unmarshal(fields["instances"], &instances); err != nil {
		t.Fatal(err)
	}
	return instances
}

func validationTailscaleConfig(t *testing.T, directory string) string {
	t.Helper()
	bytes, err := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "endpoints": []any{map[string]any{"type": "tailscale", "tag": "target", "state_directory": directory, "auth_key": "synthetic-auth-key-do-not-export"}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(bytes)
}

// t.TempDir may itself have symlink parents (macOS /var -> /private/var).
// Expectations use the physical fixture root independently of the product's
// state-directory canonicalization, while the explicit alias remains in inputs.
func validationPhysicalTempDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestValidationTailscaleOriginalConstructorNoStoreAndCachedFile(t *testing.T) {
	requireValidationTailscaleRegistry(t)
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprint(existing), func(t *testing.T) {
			directory := filepath.Join(validationPhysicalTempDir(t), "lazy")
			var original []byte
			if existing {
				if err := os.Mkdir(directory, 0o700); err != nil {
					t.Fatal(err)
				}
				original = []byte(`{"synthetic":"old-state-secret"}`)
				if err := os.WriteFile(filepath.Join(directory, "tailscaled.state"), original, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			config := validationTailscaleConfig(t, directory)
			result := CheckConfigWithResult(config, "real-original", 2000)
			if result.validation != "Accepted" || result.cleanup != "CleanupUnknown" {
				t.Fatalf("original admission: %+v", result)
			}
			instances := validationTailscaleDocument(t, result)
			if len(instances) != 1 || !instances[0].CensusComplete || instances[0].Terminal != "NoStoreConstruction" || len(instances[0].Nodes) != 1 {
				t.Fatalf("real original census: %+v", instances)
			}
			run := instances[0]
			node := run.Nodes[0]
			if len(run.RunNonce) != 64 || run.ConfigDigest != result.configDigest || node.Tag != "target" || node.StateDirectory != directory || node.WriterState != "NoStoreConstruction" {
				t.Fatalf("binding: %+v", run)
			}
			if strings.Contains(result.GetTailscaleStoreRetirement(), "synthetic-auth-key") || strings.Contains(result.GetTailscaleStoreRetirement(), "old-state-secret") {
				t.Fatal("secret leaked")
			}
			// No Start/lease occurred. G4 must not inspect the authentication file
			// to improve a witness, even when this fixture knows the file exists.
			if node.StateFileState != "Unknown" || node.ProfileState != "Unknown" || node.ProfileFingerprint != "" || node.StateFileRevision != "" {
				t.Fatalf("unleased authentication witness: %+v", node)
			}
			if existing {
				b, err := os.ReadFile(filepath.Join(directory, "tailscaled.state"))
				if err != nil || string(b) != string(original) {
					t.Fatal("validation changed cached state")
				}
			} else {
				if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("lazy directory created: %v", err)
				}
			}
			snapshot := *result
			if result.GetTailscaleStoreRetirement() != snapshot.tailscaleStoreRetirement || *result != snapshot {
				t.Fatal("getter changed original snapshot")
			}
			next := CheckConfigWithResult(config, "fresh-next", 2000)
			nextRuns := validationTailscaleDocument(t, next)
			if len(nextRuns) != 1 || nextRuns[0].RunNonce == run.RunNonce {
				t.Fatal("original run nonce reused")
			}
		})
	}
}

func TestValidationTailscalePartialAndEmptyRemainUnknown(t *testing.T) {
	requireValidationTailscaleRegistry(t)
	directory := t.TempDir()
	partial, _ := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "endpoints": []any{map[string]any{"type": "tailscale", "tag": "first", "state_directory": filepath.Join(directory, "first")}, map[string]any{"type": "tailscale", "tag": "second", "state_directory": filepath.Join(directory, "second"), "advertise_exit_node": true, "exit_node": "100.64.0.2"}}})
	for _, config := range []string{"{}", "{", string(partial)} {
		result := CheckConfigWithResult(config, "unknown-original", 2000)
		runs := validationTailscaleDocument(t, result)
		if len(runs) != 1 || runs[0].Terminal != "Unknown" || runs[0].CensusComplete {
			t.Fatalf("incomplete became proof: %+v", runs)
		}
		if config == string(partial) && (result.validation != "Rejected" || len(runs[0].Nodes) != 1) {
			t.Fatalf("partial original guard lost: %+v / %+v", result, runs)
		}
	}
}

func TestValidationTailscaleCensusRejectsUnboundScopes(t *testing.T) {
	requireValidationTailscaleRegistry(t)
	directory := t.TempDir()
	config := validationTailscaleConfig(t, directory)
	for _, kind := range []string{"missing", "duplicate", "foreign-nonce", "foreign-digest", "foreign-path", "unknown-writer", "partial"} {
		t.Run(kind, func(t *testing.T) {
			result := checkConfigWithResult(config, "binding-"+kind, 2000, func(ctx context.Context, _ option.Options) (error, error) {
				binding := service.PtrFromContext[adapter.TailscaleStoreRunBinding](ctx)
				observer := service.PtrFromContext[adapter.TailscaleStoreConstructionObserver](ctx)
				if binding == nil || observer == nil {
					t.Fatal("missing pre-constructor binding")
				}
				if kind == "missing" {
					return nil, nil
				}
				node := adapter.TailscaleStoreNode{Tag: "target", StateDirectory: directory, StateFile: filepath.Join(directory, "tailscaled.state"), RunNonce: binding.RunNonce, ConfigDigest: binding.ConfigDigest, WriterState: "NoStoreConstruction", StateFileState: "Missing", ProfileState: "None"}
				switch kind {
				case "foreign-nonce":
					node.RunNonce = "foreign"
				case "foreign-digest":
					node.ConfigDigest = "foreign"
				case "foreign-path":
					node.StateFile = filepath.Join(directory, "other.state")
				case "unknown-writer":
					node.WriterState = "Unknown"
				}
				if !observer.Observe(node, func(time.Time) adapter.TailscaleStoreNode { return node }) {
					t.Fatal("original guard denied before freeze")
				}
				if kind == "duplicate" {
					observer.Observe(node, func(time.Time) adapter.TailscaleStoreNode { return node })
				}
				if kind == "partial" {
					return errors.New("synthetic later constructor failure"), nil
				}
				return nil, nil
			})
			runs := validationTailscaleDocument(t, result)
			if len(runs) != 1 || runs[0].CensusComplete || runs[0].Terminal != "Unknown" {
				t.Fatalf("bad scope passed: %+v", runs)
			}
		})
	}
}

type validationBlockedEntropy struct{ release <-chan struct{} }

func (r validationBlockedEntropy) Read(p []byte) (int, error) {
	<-r.release
	clear(p)
	return len(p), nil
}

func TestValidationTailscaleRandomFailureAndBlockedEntropy(t *testing.T) {
	var constructed atomic.Int32
	result := checkConfigWithResultRandom("{}", "random-failed", 1000, func(context.Context, option.Options) (error, error) { constructed.Add(1); return nil, nil }, strings.NewReader(""))
	if result.validation != "Accepted" || result.cleanup != "CleanupUnknown" || len(validationTailscaleDocument(t, result)) != 0 || constructed.Load() != 1 {
		t.Fatalf("random failure changed original admission: %+v", result)
	}
	release := make(chan struct{})
	defer close(release)
	result = checkConfigWithResultRandom("{}", "random-blocked", 25, func(context.Context, option.Options) (error, error) { constructed.Add(1); return nil, nil }, validationBlockedEntropy{release})
	snapshot := *result
	if result.validation != "InternalFailure" || result.cleanup != "CleanupUnknown" || len(validationTailscaleDocument(t, result)) != 0 || constructed.Load() != 1 {
		t.Fatalf("blocked entropy became proof: %+v", result)
	}
	if *result != snapshot {
		t.Fatal("mutable timeout")
	}
}

func TestValidationTailscaleObserverClosedAfterOriginalCompletion(t *testing.T) {
	requireValidationTailscaleRegistry(t)
	var original context.Context
	result := checkConfigWithResult(validationTailscaleConfig(t, t.TempDir()), "observer-original", 2000, func(ctx context.Context, _ option.Options) (error, error) { original = ctx; return nil, nil })
	snapshot := *result
	observer := service.PtrFromContext[adapter.TailscaleStoreConstructionObserver](original)
	if observer == nil || observer.Observe(adapter.TailscaleStoreNode{}, func(time.Time) adapter.TailscaleStoreNode { return adapter.TailscaleStoreNode{} }) {
		t.Fatal("late observer admission reopened")
	}
	if *result != snapshot || validationTailscaleDocument(t, result)[0].Terminal != "Unknown" {
		t.Fatal("late observation changed old receipt")
	}
}

func requireValidationTailscaleRegistry(t *testing.T) {
	t.Helper()
	registry := service.FromContext[option.EndpointOptionsRegistry](baseContext(nil))
	if registry == nil {
		t.Fatal("missing original endpoint registry")
	}
	if _, ok := registry.CreateOptions("tailscale"); !ok {
		t.Skip("requires original with_tailscale build tag")
	}
}

func TestValidationTailscaleCanonicalImplicitScope(t *testing.T) {
	requireValidationTailscaleRegistry(t)
	directory := validationPhysicalTempDir(t)
	real := filepath.Join(directory, "real")
	alias := filepath.Join(directory, "alias")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POLARIS_VALIDATION_TS_DIRECTORY", alias)
	configBytes, err := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "endpoints": []any{map[string]any{"type": "tailscale", "state_directory": "$POLARIS_VALIDATION_TS_DIRECTORY/lazy"}}})
	if err != nil {
		t.Fatal(err)
	}
	result := CheckConfigWithResult(string(configBytes), "canonical-original", 2000)
	runs := validationTailscaleDocument(t, result)
	if len(runs) != 1 || !runs[0].CensusComplete || len(runs[0].Nodes) != 1 || runs[0].Nodes[0].Tag != "0" || runs[0].Nodes[0].StateDirectory != filepath.Join(real, "lazy") {
		t.Fatalf("canonical original: %+v / %+v", result, runs)
	}
	if _, err := os.Stat(filepath.Join(real, "lazy")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canonical census created lazy path: %v", err)
	}
	// Original all-endpoint index, not TS-only index, and default state directory.
	run := &validationTailscaleRun{}
	ctx := baseContext(nil)
	run.prepare(ctx, option.Options{Endpoints: []option.Endpoint{{Type: "not-tailscale"}, {Type: "tailscale", Options: &option.TailscaleEndpointOptions{}}}})
	expectedDefault, err := adapter.CanonicalTailscaleStateDirectory("tailscale")
	if err != nil {
		t.Fatal(err)
	}
	if !run.expectedValid || len(run.expected) != 1 || run.expected[0].tag != "1" || run.expected[0].directory != expectedDefault {
		t.Fatalf("default/index census: %+v", run.expected)
	}
}

func TestValidationTailscaleOriginalDuplicateMembershipRemainsUnknown(t *testing.T) {
	requireValidationTailscaleRegistry(t)
	for _, kind := range []string{"duplicate-tag", "duplicate-path"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			firstTag, secondTag := "first", "second"
			firstDirectory, secondDirectory := filepath.Join(directory, "first"), filepath.Join(directory, "second")
			if kind == "duplicate-tag" {
				secondTag = firstTag
			} else {
				secondDirectory = firstDirectory
			}
			config, err := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "endpoints": []any{map[string]any{"type": "tailscale", "tag": firstTag, "state_directory": firstDirectory}, map[string]any{"type": "tailscale", "tag": secondTag, "state_directory": secondDirectory}}})
			if err != nil {
				t.Fatal(err)
			}
			result := CheckConfigWithResult(string(config), "duplicate-original", 2000)
			runs := validationTailscaleDocument(t, result)
			wantValidation, wantGuards := "Accepted", 2
			if kind == "duplicate-tag" {
				wantValidation, wantGuards = "Rejected", 0
				if result.cleanup != "NoConstruction" || !strings.Contains(result.validationError, "duplicate outbound/endpoint tag") {
					t.Fatalf("original parse guard changed: %+v", result)
				}
			}
			if result.validation != wantValidation || len(runs) != 1 || runs[0].Terminal != "Unknown" || runs[0].CensusComplete || len(runs[0].Nodes) != wantGuards {
				t.Fatalf("duplicate membership manufactured census: %+v / %+v", result, runs)
			}
			for _, node := range runs[0].Nodes {
				if node.WriterState != "NoStoreConstruction" {
					t.Fatalf("original captured guard not retired: %+v", node)
				}
			}
		})
	}
}

func TestValidationTailscaleConstructionPanicAfterActualDisposal(t *testing.T) {
	requireValidationTailscaleRegistry(t)
	result := checkConfigWithResult(validationTailscaleConfig(t, filepath.Join(t.TempDir(), "lazy")), "panic-original", 2000, func(ctx context.Context, options option.Options) (error, error) {
		validationErr, cleanupErr := constructAndDisposeConfig(ctx, options)
		if validationErr != nil {
			return validationErr, cleanupErr
		}
		panic("synthetic constructor panic after original actual disposal")
	})
	runs := validationTailscaleDocument(t, result)
	if result.validation != "InternalFailure" || result.cleanup != "CleanupUnknown" || len(runs) != 1 || runs[0].Terminal != "Unknown" || runs[0].CensusComplete || len(runs[0].Nodes) != 1 {
		t.Fatalf("constructor panic became complete receipt: %+v / %+v", result, runs)
	}
}

func TestValidationTailscaleExpiredCompletionCannotPassCensus(t *testing.T) {
	directory := t.TempDir()
	run := &validationTailscaleRun{binding: adapter.TailscaleStoreRunBinding{RunNonce: strings.Repeat("a", 64), ConfigDigest: strings.Repeat("b", 64)}}
	options := option.Options{Endpoints: []option.Endpoint{{Type: "tailscale", Tag: "target", Options: &option.TailscaleEndpointOptions{StateDirectory: directory}}}}
	run.prepare(baseContext(nil), options)
	node := adapter.TailscaleStoreNode{Tag: "target", StateDirectory: directory, StateFile: filepath.Join(directory, "tailscaled.state"), RunNonce: run.binding.RunNonce, ConfigDigest: run.binding.ConfigDigest, WriterState: "NoStoreConstruction", StateFileState: "Missing", ProfileState: "None"}
	if !run.observe(node, func(time.Time) adapter.TailscaleStoreNode { return node }) {
		t.Fatal("original scope not observed")
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	result := &ConfigValidationResult{tailscaleStoreRetirement: run.finish(ctx, true)}
	runs := validationTailscaleDocument(t, result)
	if len(runs) != 1 || runs[0].Terminal != "Unknown" || runs[0].CensusComplete {
		t.Fatalf("expired select branch became positive: %+v", runs)
	}
	if run.observe(node, func(time.Time) adapter.TailscaleStoreNode { return node }) {
		t.Fatal("expired observation reopened")
	}
}

func validationMembershipDocument(t *testing.T, result *ConfigValidationResult) validationTailscaleMembership {
	t.Helper()
	payload := result.GetTailscaleStoreMembership()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payload), &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 6 || string(fields["contractVersion"]) != `"polaris-ts-store-target-membership-v1"` || string(fields["targets"]) == "null" {
		t.Fatalf("membership schema: %s", payload)
	}
	for _, name := range []string{"contractVersion", "requestID", "configDigest", "runNonce", "membershipState", "targets"} {
		if _, exists := fields[name]; !exists {
			t.Fatalf("missing %s: %s", name, payload)
		}
	}
	var document validationTailscaleMembership
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatal(err)
	}
	var targets []map[string]json.RawMessage
	if err := json.Unmarshal(fields["targets"], &targets); err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		if len(target) != 3 || target["tag"] == nil || target["stateDirectory"] == nil || target["stateFile"] == nil {
			t.Fatalf("target schema: %s", payload)
		}
	}
	if document.RequestID != result.GetRequestID() || document.ConfigDigest != result.GetConfigDigest() {
		t.Fatalf("membership acquired foreign outer binding: %s", payload)
	}
	return document
}

func TestValidationMembershipActualNoTailscaleAndOriginalBinding(t *testing.T) {
	config := `{"log":{"disabled":true}}`
	first := CheckConfigWithResult(config, "native-membership-first", 2000)
	document := validationMembershipDocument(t, first)
	runs := validationTailscaleDocument(t, first)
	if first.GetValidation() != "Accepted" || first.GetCleanup() != "CleanupUnknown" || document.MembershipState != "Complete" || len(document.Targets) != 0 || !validationTailscaleHex64(document.RunNonce) {
		t.Fatalf("actual empty constructor membership: %+v / %+v", first, document)
	}
	if len(runs) != 1 || runs[0].RunNonce != document.RunNonce || runs[0].ConfigDigest != document.ConfigDigest || runs[0].Terminal != "Unknown" || runs[0].CensusComplete {
		t.Fatalf("empty membership changed retirement: %+v / %+v", runs, document)
	}
	second := CheckConfigWithResult(config, "native-membership-second", 2000)
	next := validationMembershipDocument(t, second)
	if next.MembershipState != "Complete" || next.ConfigDigest != document.ConfigDigest || next.RunNonce == document.RunNonce || next.RequestID == document.RequestID {
		t.Fatal("same SHA acquired another original invocation's scope")
	}
	snapshot := *first
	for range 4 {
		if first.GetTailscaleStoreMembership() != snapshot.tailscaleStoreMembership || first.GetTailscaleStoreRetirement() != snapshot.tailscaleStoreRetirement || *first != snapshot {
			t.Fatal("read-only getter mutated its original comparable result")
		}
	}
}

func TestValidationMembershipActualCanonicalOrderedTargetsAndCache(t *testing.T) {
	requireValidationTailscaleRegistry(t)
	directory := validationPhysicalTempDir(t)
	real, alias := filepath.Join(directory, "real"), filepath.Join(directory, "alias")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	firstDirectory := filepath.Join(real, "cached")
	if err := os.Mkdir(firstDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	state := []byte(`{"synthetic":"membership-old-state-secret"}`)
	stateFile := filepath.Join(firstDirectory, "tailscaled.state")
	if err := os.WriteFile(stateFile, state, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POLARIS_MEMBERSHIP_DIRECTORY", alias)
	config, err := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "endpoints": []any{
		map[string]any{"type": "tailscale", "tag": "first", "state_directory": "$POLARIS_MEMBERSHIP_DIRECTORY/cached", "auth_key": "membership-auth-key-secret"},
		map[string]any{"type": "tailscale", "state_directory": "$POLARIS_MEMBERSHIP_DIRECTORY/lazy", "control_url": "https://membership-control-secret.invalid"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	result := CheckConfigWithResult(string(config), "native-two-targets", 2000)
	document := validationMembershipDocument(t, result)
	runs := validationTailscaleDocument(t, result)
	if document.MembershipState != "Complete" || len(document.Targets) != 2 || len(runs) != 1 || len(runs[0].Nodes) != 2 || document.RunNonce != runs[0].RunNonce {
		t.Fatalf("actual complete original target census: %+v / %+v", document, runs)
	}
	want := []validationTailscaleTarget{{"first", firstDirectory, stateFile}, {"1", filepath.Join(real, "lazy"), filepath.Join(real, "lazy", "tailscaled.state")}}
	for i, target := range document.Targets {
		node := runs[0].Nodes[i]
		if target != want[i] || target.Tag != node.Tag || target.StateDirectory != node.StateDirectory || target.StateFile != node.StateFile {
			t.Fatalf("original order/canonical target changed: %+v / %+v", document.Targets, runs)
		}
	}
	if bytes, err := os.ReadFile(stateFile); err != nil || string(bytes) != string(state) {
		t.Fatal("membership changed cached state")
	}
	if _, err := os.Stat(filepath.Join(real, "lazy")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("membership/getter constructed lazy Store: %v", err)
	}
	for _, secret := range []string{"membership-old-state-secret", "membership-auth-key-secret", "membership-control-secret", "profileFingerprint", "writerState"} {
		if strings.Contains(result.GetTailscaleStoreMembership(), secret) {
			t.Fatalf("membership leaked non-scope data: %s", secret)
		}
	}
}

func TestValidationMembershipActualFailureRemainsUnknown(t *testing.T) {
	requireValidationTailscaleRegistry(t)
	directory := t.TempDir()
	valid := validationTailscaleConfig(t, filepath.Join(directory, "valid"))
	partial, err := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "endpoints": []any{
		map[string]any{"type": "tailscale", "tag": "first", "state_directory": filepath.Join(directory, "first")},
		map[string]any{"type": "tailscale", "tag": "second", "state_directory": filepath.Join(directory, "second"), "advertise_exit_node": true, "exit_node": "100.64.0.2"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"parse", "partial", "invalid-request", "random-failure", "panic-after-disposal"} {
		t.Run(kind, func(t *testing.T) {
			var result *ConfigValidationResult
			switch kind {
			case "parse":
				result = CheckConfigWithResult("{", "membership-parse", 2000)
			case "partial":
				result = CheckConfigWithResult(string(partial), "membership-partial", 2000)
			case "invalid-request":
				result = CheckConfigWithResult(valid, "", 2000)
			case "random-failure":
				result = checkConfigWithResultRandom(valid, "membership-random", 2000, constructAndDisposeConfig, strings.NewReader(""))
			default:
				result = checkConfigWithResult(valid, "membership-"+kind, 2000, func(ctx context.Context, options option.Options) (error, error) {
					validationErr, cleanupErr := constructAndDisposeConfig(ctx, options)
					if validationErr != nil {
						return validationErr, cleanupErr
					}
					panic("synthetic failure after original actual disposal")
				})
			}
			document := validationMembershipDocument(t, result)
			if document.MembershipState != "Unknown" || len(document.Targets) != 0 {
				t.Fatalf("failure became complete membership: %+v / %+v", result, document)
			}
			if kind == "panic-after-disposal" && (result.GetValidation() != "InternalFailure" || !strings.Contains(result.GetValidationError(), "synthetic failure after original actual disposal")) {
				t.Fatal("actual original construction did not reach injected panic")
			}
		})
	}
}

func TestValidationMembershipOriginalGuardsRejectForeignCensus(t *testing.T) {
	requireValidationTailscaleRegistry(t)
	config := validationTailscaleConfig(t, filepath.Join(t.TempDir(), "lazy"))
	for _, kind := range []string{"missing", "duplicate", "foreign-nonce", "foreign-digest", "foreign-tag", "foreign-path"} {
		t.Run(kind, func(t *testing.T) {
			result := checkConfigWithResult(config, "membership-census-"+kind, 2000, func(ctx context.Context, options option.Options) (error, error) {
				original := service.PtrFromContext[adapter.TailscaleStoreConstructionObserver](ctx)
				if original == nil {
					t.Fatal("missing original invocation observer")
				}
				observer := adapter.TailscaleStoreConstructionObserver{Observe: func(node adapter.TailscaleStoreNode, retire func(time.Time) adapter.TailscaleStoreNode) bool {
					switch kind {
					case "missing":
						return false
					case "foreign-nonce":
						node.RunNonce = strings.Repeat("f", 64)
					case "foreign-digest":
						node.ConfigDigest = strings.Repeat("f", 64)
					case "foreign-tag":
						node.Tag = "foreign"
					case "foreign-path":
						node.StateFile = filepath.Join(node.StateDirectory, "foreign.state")
					}
					accepted := original.Observe(node, retire)
					if kind == "duplicate" {
						original.Observe(node, retire)
					}
					return accepted
				}}
				return constructAndDisposeConfig(service.ContextWithPtr(ctx, &observer), options)
			})
			document := validationMembershipDocument(t, result)
			if document.MembershipState != "Unknown" || len(document.Targets) != 0 {
				t.Fatalf("foreign original guard metadata supplied full membership: %+v", document)
			}
		})
	}
}

func TestValidationMembershipOriginalScopeDoesNotProveWriterTerminal(t *testing.T) {
	requireValidationTailscaleRegistry(t)
	result := checkConfigWithResult(validationTailscaleConfig(t, filepath.Join(t.TempDir(), "lazy")), "membership-writer-unknown", 2000, func(ctx context.Context, options option.Options) (error, error) {
		original := service.PtrFromContext[adapter.TailscaleStoreConstructionObserver](ctx)
		if original == nil {
			t.Fatal("missing original invocation observer")
		}
		observer := adapter.TailscaleStoreConstructionObserver{Observe: func(node adapter.TailscaleStoreNode, retire func(time.Time) adapter.TailscaleStoreNode) bool {
			return original.Observe(node, func(deadline time.Time) adapter.TailscaleStoreNode {
				terminal := retire(deadline)
				terminal.WriterState = "Unknown" // Inject less evidence, never a forged positive.
				return terminal
			})
		}}
		return constructAndDisposeConfig(service.ContextWithPtr(ctx, &observer), options)
	})
	document := validationMembershipDocument(t, result)
	runs := validationTailscaleDocument(t, result)
	if document.MembershipState != "Complete" || len(document.Targets) != 1 || len(runs) != 1 || runs[0].Terminal != "Unknown" || runs[0].CensusComplete || runs[0].Nodes[0].WriterState != "Unknown" {
		t.Fatalf("writer and member facts conflated: %+v / %+v", document, runs)
	}
}

func TestValidationMembershipTimeoutAndLateCompletionAreImmutable(t *testing.T) {
	requireValidationTailscaleRegistry(t)
	for _, kind := range []string{"cleanup", "entropy"} {
		t.Run(kind, func(t *testing.T) {
			release, done := make(chan struct{}), make(chan struct{})
			config := validationTailscaleConfig(t, filepath.Join(t.TempDir(), "lazy"))
			construct := func(ctx context.Context, options option.Options) (error, error) {
				defer close(done)
				validationErr, cleanupErr := constructAndDisposeConfig(ctx, options)
				<-release
				return validationErr, cleanupErr
			}
			var result *ConfigValidationResult
			if kind == "cleanup" {
				result = checkConfigWithResult(config, "membership-late-cleanup", 50, construct)
			} else {
				result = checkConfigWithResultRandom(config, "membership-late-entropy", 50, constructAndDisposeConfig, validationBlockedEntropy{release})
			}
			snapshot := *result
			document := validationMembershipDocument(t, result)
			if document.MembershipState != "Unknown" || len(document.Targets) != 0 || result.GetValidation() != "InternalFailure" {
				t.Fatalf("unobserved completion acquired membership: %+v", document)
			}
			close(release)
			if kind == "cleanup" {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("original late cleanup did not return")
				}
			}
			if *result != snapshot || result.GetTailscaleStoreMembership() != snapshot.tailscaleStoreMembership {
				t.Fatal("late completion upgraded original result")
			}
		})
	}
}

func TestValidationMembershipLateOriginalGuardBeforeAndAfterCommit(t *testing.T) {
	requireValidationTailscaleRegistry(t)
	type originalCall struct {
		ctx     context.Context
		options option.Options
	}
	for _, timing := range []string{"before-commit", "after-commit"} {
		t.Run(timing, func(t *testing.T) {
			calls := make(chan originalCall, 1)
			entered, release := make(chan struct{}), make(chan struct{})
			t.Cleanup(func() {
				select {
				case <-release:
				default:
					close(release)
				}
			})
			results := make(chan *ConfigValidationResult, 1)
			config := validationTailscaleConfig(t, filepath.Join(t.TempDir(), "lazy"))
			go func() {
				results <- checkConfigWithResult(config, "membership-"+timing, 2000, func(ctx context.Context, options option.Options) (error, error) {
					original := service.PtrFromContext[adapter.TailscaleStoreConstructionObserver](ctx)
					observer := adapter.TailscaleStoreConstructionObserver{Observe: func(node adapter.TailscaleStoreNode, retire func(time.Time) adapter.TailscaleStoreNode) bool {
						return original.Observe(node, func(deadline time.Time) adapter.TailscaleStoreNode {
							close(entered)
							<-release
							return retire(deadline)
						})
					}}
					ctx = service.ContextWithPtr(ctx, &observer)
					calls <- originalCall{ctx, options}
					return constructAndDisposeConfig(ctx, options)
				})
			}()
			call := <-calls
			select {
			case <-entered: // Original finish has cut off registration, before snapshot commit.
			case <-time.After(time.Second):
				t.Fatal("original guard retirement did not enter")
			}
			if timing == "before-commit" {
				validationErr, cleanupErr := constructAndDisposeConfig(call.ctx, call.options)
				t.Logf("pre-commit fault original cleanup retained: %v", cleanupErr)
				if validationErr != nil {
					t.Fatalf("late fault construction failed: %v", validationErr)
				}
			}
			close(release)
			result := <-results
			document := validationMembershipDocument(t, result)
			want := "Complete"
			if timing == "before-commit" {
				want = "Unknown"
			}
			if document.MembershipState != want {
				t.Fatalf("late registration at %s: %+v", timing, document)
			}
			snapshot := *result
			if call.ctx.Err() == nil {
				t.Fatal("original returned validation did not cancel its worker context")
			}
			// Simulate a late constructor that ignores cancellation while retaining
			// precisely the original binding and observer, not a new validation.
			validationErr, cleanupErr := constructAndDisposeConfig(context.WithoutCancel(call.ctx), call.options)
			t.Logf("post-commit fault original cleanup retained: %v", cleanupErr)
			if validationErr != nil {
				t.Fatalf("post-commit fault construction failed: %v", validationErr)
			}
			if *result != snapshot || result.GetTailscaleStoreMembership() != snapshot.tailscaleStoreMembership {
				t.Fatal("post-commit original guard changed returned payload")
			}
		})
	}
}

func TestValidationMembershipActualDifferentTagsSameCanonicalFileUnknown(t *testing.T) {
	requireValidationTailscaleRegistry(t)
	directory := t.TempDir()
	real, alias := filepath.Join(directory, "real"), filepath.Join(directory, "alias")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "endpoints": []any{
		map[string]any{"type": "tailscale", "tag": "first", "state_directory": real},
		map[string]any{"type": "tailscale", "tag": "second", "state_directory": alias},
	}})
	if err != nil {
		t.Fatal(err)
	}
	result := CheckConfigWithResult(string(config), "membership-alias", 2000)
	document := validationMembershipDocument(t, result)
	runs := validationTailscaleDocument(t, result)
	if result.GetValidation() != "Accepted" || document.MembershipState != "Unknown" || len(document.Targets) != 0 || len(runs) != 1 || len(runs[0].Nodes) != 2 || runs[0].Nodes[0].StateFile != runs[0].Nodes[1].StateFile {
		t.Fatalf("different tags concealed same original file: %+v / %+v", document, runs)
	}
}

func TestValidationMembershipExpiredOrUnboundedCommitUnknown(t *testing.T) {
	for _, kind := range []string{"expired", "unbounded", "unobserved-cutoff", "invalid-native-nonce"} {
		t.Run(kind, func(t *testing.T) {
			run := &validationTailscaleRun{requestID: "membership-" + kind, binding: adapter.TailscaleStoreRunBinding{RunNonce: strings.Repeat("a", 64), ConfigDigest: strings.Repeat("b", 64)}}
			run.prepare(baseContext(nil), option.Options{})
			ctx := context.Background()
			if kind == "expired" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			} else if kind != "unbounded" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Second)
				defer cancel()
			}
			if kind == "invalid-native-nonce" {
				run.binding.RunNonce = strings.Repeat("A", 64)
			}
			if kind != "unobserved-cutoff" {
				run.finish(ctx, true)
			}
			result := &ConfigValidationResult{requestID: run.requestID, configDigest: run.binding.ConfigDigest, tailscaleStoreMembership: run.membershipSnapshot(ctx, true)}
			document := validationMembershipDocument(t, result)
			if document.MembershipState != "Unknown" || len(document.Targets) != 0 {
				t.Fatalf("unobserved or invalid scope completion: %+v", document)
			}
		})
	}
}

func TestValidationMembershipUnknownGetterIsReadOnly(t *testing.T) {
	result := CheckConfigWithResult("{", "membership-readonly-unknown", 2000)
	document := validationMembershipDocument(t, result)
	if document.MembershipState != "Unknown" || result.GetValidation() != "Rejected" {
		t.Fatalf("parse rejection unexpectedly had membership: %+v", document)
	}
	snapshot := *result
	for range 20 {
		if result.GetTailscaleStoreMembership() != snapshot.tailscaleStoreMembership || *result != snapshot {
			t.Fatal("Unknown getter changed immutable original result")
		}
	}
	if strings.Contains(result.GetTailscaleStoreMembership(), "decode config") || strings.Contains(result.GetTailscaleStoreMembership(), "validationError") {
		t.Fatal("membership exported inner validation errors")
	}
}

func TestValidationMembershipCleanupErrorDoesNotSignGlobalRetirement(t *testing.T) {
	requireValidationTailscaleRegistry(t)
	originalCleanup := errors.New("synthetic construction cleanup failure")
	result := checkConfigWithResult(validationTailscaleConfig(t, filepath.Join(t.TempDir(), "lazy")), "membership-observed-cleanup-error", 2000, func(ctx context.Context, options option.Options) (error, error) {
		validationErr, cleanupErr := constructAndDisposeConfig(ctx, options)
		if cleanupErr != nil {
			t.Errorf("clean retirement reported a cleanup failure: %v", cleanupErr)
		}
		return validationErr, originalCleanup
	})
	document := validationMembershipDocument(t, result)
	if originalCleanup == nil || result.GetCleanupError() != originalCleanup.Error() || result.GetValidation() != "Accepted" || result.GetCleanup() != "CleanupUnknown" || document.MembershipState != "Complete" || len(document.Targets) != 1 {
		t.Fatalf("census changed original cleanup facts: %+v / %+v", result, document)
	}
	runs := validationTailscaleDocument(t, result)
	if len(runs) != 1 || runs[0].RunNonce != document.RunNonce || !runs[0].CensusComplete || runs[0].Terminal != "NoStoreConstruction" {
		t.Fatalf("separate original writer proof changed: %+v", runs)
	}
}

func TestValidationPublicEntryNeverReportsExactDisposal(t *testing.T) {
	for _, config := range []string{`{}`, `{"outbounds":[{"type":"direct","tag":"direct"}]}`} {
		result := CheckConfigWithResult(config, "request", 10000)
		if result.GetValidation() != "Accepted" || result.GetCleanup() != "CleanupUnknown" || result.GetCleanupError() != "" {
			t.Fatalf("%s: validation %q cleanup %q error %q", config, result.GetValidation(), result.GetCleanup(), result.GetCleanupError())
		}
		err := CheckConfig(config)
		if err != nil {
			t.Fatal(err)
		}
	}
}

// Runtime startup can defer native endpoint construction until staging. Public
// constructor-only validation must still reject errors from that constructor,
// without starting the node merely to obtain an original census.
func TestValidationTailscalePublicEntryRunsOriginalOptionValidation(t *testing.T) {
	requireValidationTailscaleRegistry(t)
	for _, test := range []struct {
		name   string
		fields map[string]any
		want   string
	}{
		{"default-advertised-route", map[string]any{"advertise_routes": []string{"0.0.0.0/0"}}, "advertise_routes"},
		{"conflicting-exit-node", map[string]any{"advertise_exit_node": true, "exit_node": "100.100.100.100"}, "cannot advertise an exit node"},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := filepath.Join(validationPhysicalTempDir(t), "unstarted")
			endpoint := map[string]any{"type": "tailscale", "tag": "target", "state_directory": directory}
			maps.Copy(endpoint, test.fields)
			content, err := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "endpoints": []any{endpoint}})
			if err != nil {
				t.Fatal(err)
			}
			config := string(content)
			legacyErr := CheckConfig(config)
			if legacyErr == nil || !strings.Contains(legacyErr.Error(), test.want) {
				t.Fatalf("public validation skipped original constructor: %v", legacyErr)
			}
			result := CheckConfigWithResult(config, "original-option-validation", 2000)
			if result.GetValidation() != "Rejected" || !strings.Contains(result.GetValidationError(), test.want) || result.GetCleanup() != "CleanupUnknown" {
				t.Fatalf("original constructor failure lost: %+v", result)
			}
			digest := sha256.Sum256(content)
			if result.GetConfigDigest() != hex.EncodeToString(digest[:]) {
				t.Fatal("validation changed original config identity")
			}
			membership := validationMembershipDocument(t, result)
			if membership.MembershipState != "Unknown" || len(membership.Targets) != 0 {
				t.Fatalf("failed constructor manufactured membership: %+v", membership)
			}
			if _, err = os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("constructor-only validation started native state: %v", err)
			}
		})
	}
}
