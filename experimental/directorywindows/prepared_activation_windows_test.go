//go:build windows && with_tailscale

package directorywindows

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

// These fixtures author only in-memory activation/mapping operations. No lease,
// SDK, store, root marker, native API, directory or disk poison operation is used.
// Explicit clean provenance exercises the production validation core without
// depending on the eventual test binary's release ldflags or VCS build settings.
func preparedActivationFixture(t *testing.T) (context.Context, option.Options, string, *debug.BuildInfo) {
	t.Helper()
	source := strings.Repeat("a", 40)
	info := &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "vcs", Value: "git"},
		{Key: "vcs.revision", Value: source},
		{Key: "vcs.modified", Value: "false"},
	}}
	root := `C:\polaris-activation-fixture`
	options := option.Options{
		PolarisWindowsDirectory: &option.WindowsDirectoryOptions{Version: 1, Root: root, RunNonce: strings.Repeat("1", 32), ExpectedSource: source},
		Endpoints: []option.Endpoint{{Type: C.TypeTailscale, Options: &option.TailscaleEndpointOptions{
			StateDirectory:    filepath.Join(root, "tailscale", "node"),
			TaildropDirectory: filepath.Join(root, "tailscale", "node", "Taildrop"),
			SSHServer:         &option.TailscaleSSHServerOptions{DisableSFTP: true},
		}}},
	}
	ctx := context.Background()
	setActivationFixtureRaw(t, ctx, &options)
	sum := sha256.Sum256(options.RawMessage)
	ctx = service.ContextWithPtr(ctx, &adapter.TailscaleStoreRunBinding{RunNonce: strings.Repeat("2", 64), ConfigDigest: hex.EncodeToString(sum[:])})
	return ctx, options, source, info
}

func setActivationFixtureRaw(t *testing.T, ctx context.Context, options *option.Options) {
	t.Helper()
	raw, err := sjson.MarshalContext(ctx, *options)
	if err != nil {
		t.Fatal(err)
	}
	options.RawMessage = raw
}

func mustPrepareActivationFixture(t *testing.T, ctx context.Context, options option.Options, source string, info *debug.BuildInfo) context.Context {
	t.Helper()
	prepared, err := prepareActivationWithSource(ctx, options, func(string) error {
		t.Error("valid in-memory activation unexpectedly poisoned a domain")
		return nil
	}, source, info)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func TestPreparedActivationSingleUseAndOriginalBinding(t *testing.T) {
	ctx, options, source, info := preparedActivationFixture(t)
	original := service.PtrFromContext[adapter.TailscaleStoreRunBinding](ctx)
	prepared := mustPrepareActivationFixture(t, ctx, options, source, info)
	activation := prepared.Value(preparedActivationKey{}).(*PreparedActivation)
	if !HasPreparedActivation(prepared) || activation.projection.endpoints[0].Tag != "0" {
		t.Fatal("missing private token or incorrect index-based normalized tag")
	}
	if service.PtrFromContext[adapter.TailscaleStoreRunBinding](prepared) != original || activation.binding != *original {
		t.Fatal("original run binding replaced")
	}
	if err := validatePreparedActivation(prepared, options, source, info, false); err != nil {
		t.Fatal(err)
	}
	if activation.consumed {
		t.Fatal("non-consuming validation consumed token")
	}
	if err := validatePreparedActivation(prepared, options, source, info, true); err != nil {
		t.Fatal(err)
	}
	if err := validatePreparedActivation(prepared, options, source, info, true); err == nil {
		t.Fatal("replayed token accepted")
	}
	if err := validatePreparedActivation(prepared, options, source, info, false); err == nil || !HasPreparedActivation(prepared) {
		t.Fatal("consumed token became a fresh-activation fallback")
	}
	// The public dispatch must select the private-token path even after consume.
	if _, err := Prepare(prepared, options, nil); err == nil {
		t.Fatal("public Prepare accepted replay")
	}
}

func TestPreparedActivationConcurrentConsumeHasOneWinner(t *testing.T) {
	ctx, options, source, info := preparedActivationFixture(t)
	prepared := mustPrepareActivationFixture(t, ctx, options, source, info)
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			results <- validatePreparedActivation(prepared, options, source, info, true)
		}()
	}
	workers.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("got %d consumption winners", succeeded)
	}
}

func TestPreparedActivationRejectsMismatchesWithoutConsuming(t *testing.T) {
	for _, name := range []string{"raw", "envelope", "source", "dirty-provenance", "nonce", "digest", "domain", "mapping", "missing-domain", "missing-mapping", "path", "taildrop", "ssh-enabled", "ssh-options", "tag", "endpoint-count", "endpoint-type", "runtime-options"} {
		t.Run(name, func(t *testing.T) {
			ctx, options, source, info := preparedActivationFixture(t)
			prepared := mustPrepareActivationFixture(t, ctx, options, source, info)
			candidate := options
			candidateContext, candidateSource, candidateInfo := prepared, source, info
			endpoint := *options.Endpoints[0].Options.(*option.TailscaleEndpointOptions)
			candidate.Endpoints = append([]option.Endpoint(nil), options.Endpoints...)
			candidate.Endpoints[0].Options = &endpoint
			envelope := *options.PolarisWindowsDirectory
			candidate.PolarisWindowsDirectory = &envelope
			originalBinding := *service.PtrFromContext[adapter.TailscaleStoreRunBinding](prepared)
			binding := originalBinding
			switch name {
			case "raw":
				candidate.RawMessage = append(append([]byte(nil), options.RawMessage...), ' ')
			case "envelope":
				envelope.RunNonce = strings.Repeat("4", 32)
			case "source":
				candidateSource = strings.Repeat("b", 40)
			case "dirty-provenance":
				candidateInfo = &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs", Value: "git"}, {Key: "vcs.revision", Value: source}, {Key: "vcs.modified", Value: "true"}}}
			case "nonce":
				binding.RunNonce = strings.Repeat("4", 64)
				candidateContext = service.ContextWithPtr(service.ExtendContext(prepared), &binding)
			case "digest":
				binding.ConfigDigest = strings.Repeat("5", 64)
				candidateContext = service.ContextWithPtr(service.ExtendContext(prepared), &binding)
			case "domain":
				other := mustPrepareActivationFixture(t, ctx, options, source, info)
				candidateContext = adapter.ContextWithTailscaleDirectoryDomain(prepared, adapter.TailscaleDirectoryDomainFromContext(other))
			case "mapping":
				domain := adapter.TailscaleDirectoryDomainFromContext(prepared)
				mapping, err := adapter.NewTailscaleDirectoryMapping(domain, []adapter.TailscaleDirectoryMappingInput{{StateDirectory: endpoint.StateDirectory, TaildropDirectory: endpoint.TaildropDirectory}})
				if err != nil {
					t.Fatal(err)
				}
				candidateContext = adapter.ContextWithTailscaleDirectoryMapping(prepared, mapping)
			case "missing-domain":
				candidateContext = adapter.ContextWithTailscaleDirectoryDomain(prepared, nil)
			case "missing-mapping":
				candidateContext = adapter.ContextWithTailscaleDirectoryMapping(prepared, nil)
			case "path":
				endpoint.StateDirectory = filepath.Join(envelope.Root, "tailscale", "other")
				endpoint.TaildropDirectory = filepath.Join(endpoint.StateDirectory, "Taildrop")
			case "taildrop":
				endpoint.TaildropDirectory = filepath.Join(endpoint.StateDirectory, "OtherTaildrop")
			case "ssh-enabled":
				endpoint.SSHServer = &option.TailscaleSSHServerOptions{Enabled: true}
			case "ssh-options":
				endpoint.SSHServer = &option.TailscaleSSHServerOptions{DisablePTY: true}
			case "tag":
				candidate.Endpoints[0].Tag = "different"
			case "endpoint-count":
				additional := endpoint
				additional.StateDirectory = filepath.Join(envelope.Root, "tailscale", "additional")
				additional.TaildropDirectory = filepath.Join(additional.StateDirectory, "Taildrop")
				candidate.Endpoints = append(candidate.Endpoints, option.Endpoint{Type: C.TypeTailscale, Tag: "additional", Options: &additional})
			case "endpoint-type":
				candidate.Endpoints[0].Type = "wireguard"
			case "runtime-options":
				candidate.Log = &option.LogOptions{Level: "debug"}
			}
			// ContextWithPtr updates its registry in place; candidate bindings must
			// use a cloned registry so the original activation remains unchanged.
			if *service.PtrFromContext[adapter.TailscaleStoreRunBinding](prepared) != originalBinding {
				t.Fatal("candidate setup changed original run binding")
			}
			if err := validatePreparedActivation(candidateContext, candidate, candidateSource, candidateInfo, true); err == nil {
				t.Fatal("mismatched prepared activation accepted")
			}
			if err := validatePreparedActivation(prepared, options, source, info, true); err != nil {
				t.Fatal("failed validation consumed or corrupted original token", err)
			}
		})
	}
}

func TestPreparedActivationCopiesCallerOwnedFields(t *testing.T) {
	ctx, options, source, info := preparedActivationFixture(t)
	prepared := mustPrepareActivationFixture(t, ctx, options, source, info)
	activation := prepared.Value(preparedActivationKey{}).(*PreparedActivation)
	originalEnvelope, originalBinding := activation.envelope, activation.binding
	originalEndpoint := activation.projection.endpoints[0]
	options.PolarisWindowsDirectory.Root = `C:\other`
	options.Endpoints[0].Options.(*option.TailscaleEndpointOptions).StateDirectory = `C:\other\tailscale\node`
	options.Endpoints[0].Options.(*option.TailscaleEndpointOptions).SSHServer.DisableSFTP = false
	options.RawMessage[0] = ' '
	service.PtrFromContext[adapter.TailscaleStoreRunBinding](ctx).RunNonce = strings.Repeat("9", 64)
	if activation.envelope != originalEnvelope || activation.binding != originalBinding || activation.projection.endpoints[0] != originalEndpoint {
		t.Fatal("caller mutation changed frozen token authority")
	}
	if err := validatePreparedActivation(prepared, options, source, info, true); err == nil {
		t.Fatal("mutated caller graph accepted")
	}
}

func TestPreparedActivationPreflightRejectsBeforeAuthority(t *testing.T) {
	for _, name := range []string{"missing-binding", "invalid-binding", "missing-envelope", "missing-raw", "stale-raw-path", "stale-raw-envelope", "ssh", "duplicate-tag", "duplicate-path", "case-alias", "outbound-tag", "outside-root", "raw-reserved", "typed-reserved", "nil-poison"} {
		t.Run(name, func(t *testing.T) {
			ctx, options, source, info := preparedActivationFixture(t)
			endpoint := options.Endpoints[0].Options.(*option.TailscaleEndpointOptions)
			poisonCalls := 0
			poison := func(string) error { poisonCalls++; return nil }
			switch name {
			case "missing-binding":
				ctx = context.Background()
			case "invalid-binding":
				ctx = service.ContextWithPtr(ctx, &adapter.TailscaleStoreRunBinding{RunNonce: "bad", ConfigDigest: "bad"})
			case "missing-envelope":
				options.PolarisWindowsDirectory = nil
			case "missing-raw":
				options.RawMessage = nil
			case "stale-raw-path":
				endpoint.StateDirectory = filepath.Join(options.PolarisWindowsDirectory.Root, "tailscale", "other")
				endpoint.TaildropDirectory = filepath.Join(endpoint.StateDirectory, "Taildrop")
			case "stale-raw-envelope":
				options.PolarisWindowsDirectory.RunNonce = strings.Repeat("4", 32)
			case "ssh":
				endpoint.SSHServer.Enabled = true
			case "duplicate-tag":
				options.Endpoints = append(options.Endpoints, option.Endpoint{Type: C.TypeTailscale, Tag: "0", Options: endpoint})
			case "duplicate-path":
				options.Endpoints = append(options.Endpoints, option.Endpoint{Type: C.TypeTailscale, Tag: "other", Options: endpoint})
			case "case-alias":
				alias := *endpoint
				alias.StateDirectory = filepath.Join(options.PolarisWindowsDirectory.Root, "tailscale", "NODE")
				alias.TaildropDirectory = filepath.Join(alias.StateDirectory, "Taildrop")
				options.Endpoints = append(options.Endpoints, option.Endpoint{Type: C.TypeTailscale, Tag: "other", Options: &alias})
			case "outbound-tag":
				options.Outbounds = []option.Outbound{{Type: "direct", Tag: "0", Options: &option.StubOptions{}}}
			case "outside-root":
				endpoint.StateDirectory = `C:\other\tailscale\node`
				endpoint.TaildropDirectory = filepath.Join(endpoint.StateDirectory, "Taildrop")
			case "raw-reserved":
				options.Log = &option.LogOptions{Output: `C:\polaris\tailscale-windows-v1\log`}
				setActivationFixtureRaw(t, ctx, &options)
			case "typed-reserved":
				options.Log = &option.LogOptions{Output: `C:\polaris\tailscale-windows-v1\log`}
			case "nil-poison":
				poison = nil
			}
			if _, err := prepareActivationWithSource(ctx, options, poison, source, info); err == nil {
				t.Fatal("invalid preflight accepted")
			}
			if poisonCalls != 0 || adapter.TailscaleDirectoryDomainFromContext(ctx) != nil || adapter.TailscaleDirectoryMappingFromContext(ctx) != nil || HasPreparedActivation(ctx) {
				t.Fatal("failed pure validation changed authority")
			}
		})
	}
}

func TestPreparedActivationRejectsSuppliedAuthorityWithoutRevocation(t *testing.T) {
	ctx, options, source, info := preparedActivationFixture(t)
	poisonCalls := 0
	prepared, err := prepareActivationWithSource(ctx, options, func(string) error { poisonCalls++; return nil }, source, info)
	if err != nil {
		t.Fatal(err)
	}
	domain := adapter.TailscaleDirectoryDomainFromContext(prepared)
	mapping := adapter.TailscaleDirectoryMappingFromContext(prepared)
	for _, inherited := range []context.Context{
		adapter.ContextWithTailscaleDirectoryDomain(ctx, domain),
		adapter.ContextWithTailscaleDirectoryMapping(ctx, mapping),
		prepared,
	} {
		if _, err := prepareActivationWithSource(inherited, options, func(string) error { poisonCalls++; return nil }, source, info); err == nil {
			t.Fatal("supplied domain, mapping or token accepted as a new activation")
		}
	}
	inherited := adapter.ContextWithTailscaleDirectoryDomain(ctx, domain)
	inherited = adapter.ContextWithTailscaleDirectoryMapping(inherited, mapping)
	if _, err := Prepare(inherited, options, nil); err == nil {
		t.Fatal("ordinary envelope path accepted supplied authority without token")
	}
	if !domain.Active() || poisonCalls != 0 {
		t.Fatal("preparation speculatively revoked an inherited domain")
	}
	if err := validatePreparedActivation(adapter.ContextWithTailscaleDirectoryMapping(ctx, mapping), options, source, info, true); err == nil {
		t.Fatal("supplied mapping fabricated private prepared authority")
	}
	if err := validatePreparedActivation(context.WithValue(ctx, preparedActivationKey{}, new(PreparedActivation)), options, source, info, true); err == nil {
		t.Fatal("zero token accepted")
	}
}

func TestPreparedActivationRejectsRevokedOriginalDomain(t *testing.T) {
	ctx, options, source, info := preparedActivationFixture(t)
	poisonCalls := 0
	prepared, err := prepareActivationWithSource(ctx, options, func(string) error { poisonCalls++; return nil }, source, info)
	if err != nil {
		t.Fatal(err)
	}
	domain := adapter.TailscaleDirectoryDomainFromContext(prepared)
	if err := domain.Fail(errors.New("fixture revocation")); err != nil {
		t.Fatal(err)
	}
	if err := validatePreparedActivation(prepared, options, source, info, true); err == nil || poisonCalls != 1 {
		t.Fatal("revoked authority consumed or revocation repeated")
	}
}

func TestPreparedActivationAllowsAlreadyAppliedOverrides(t *testing.T) {
	ctx, options, source, info := preparedActivationFixture(t)
	// The original bytes intentionally do not include these runtime-only fields.
	options.Services = append(options.Services, option.Service{Type: C.TypeOOMKiller, Options: &option.OOMKillerServiceOptions{MemoryLimitOverride: 1024}})
	options.Inbounds = append(options.Inbounds, option.Inbound{Type: "tun", Tag: "tun", Options: &option.TunInboundOptions{AutoRedirect: true, IncludePackage: []string{"fixture.package"}}})
	prepared := mustPrepareActivationFixture(t, ctx, options, source, info)
	if err := validatePreparedActivation(prepared, options, source, info, true); err != nil {
		t.Fatal("already-accounted override invalidated directory projection", err)
	}
}

func TestPreparedActivationEnvironmentAndTypedValueProjection(t *testing.T) {
	ctx, options, source, info := preparedActivationFixture(t)
	t.Setenv("POLARIS_F05_NODE", "node")
	endpoint := options.Endpoints[0].Options.(*option.TailscaleEndpointOptions)
	endpoint.StateDirectory = options.PolarisWindowsDirectory.Root + `\tailscale\${POLARIS_F05_NODE}`
	endpoint.TaildropDirectory = endpoint.StateDirectory + `\Taildrop`
	// A typed value and a typed pointer project identically; neither is retained.
	options.Endpoints[0].Options = *endpoint
	setActivationFixtureRaw(t, ctx, &options)
	prepared := mustPrepareActivationFixture(t, ctx, options, source, info)
	if err := validatePreparedActivation(prepared, options, source, info, false); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POLARIS_F05_NODE", "other")
	if err := validatePreparedActivation(prepared, options, source, info, true); err == nil {
		t.Fatal("changed expanded path consumed original token")
	}
	t.Setenv("POLARIS_F05_NODE", "node")
	if err := validatePreparedActivation(prepared, options, source, info, true); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareOrdinaryNoTokenBehaviorAndNoConfigCapability(t *testing.T) {
	ctx := context.Background()
	options := option.Options{RawMessage: []byte(`{"already_prepared":true,"prepared_activation":true}`)}
	result, err := Prepare(ctx, options, nil)
	if err != nil || result != ctx || HasPreparedActivation(result) || adapter.TailscaleDirectoryDomainFromContext(result) != nil || adapter.TailscaleDirectoryMappingFromContext(result) != nil {
		t.Fatal("no-envelope ordinary path changed or config fabricated authority", err)
	}
	if _, err := Prepare(ctx, option.Options{RawMessage: []byte(`{"log":{"output":"tailscale-windows-v1"}}`)}, nil); err == nil {
		t.Fatal("ordinary reserved namespace scan bypassed")
	}
	if _, err := Prepare(ctx, option.Options{PolarisWindowsDirectory: &option.WindowsDirectoryOptions{Version: 1}}, nil); err == nil {
		t.Fatal("ordinary invalid envelope accepted")
	}
	if HasPreparedActivation(ctx) {
		t.Fatal("ordinary context acquired a token")
	}
}
