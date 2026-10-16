package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestDirectoryMappingLeavesSubmittedOptionsUnchanged(t *testing.T) {
	base := filepath.Join(t.TempDir(), "polaris")
	d, err := adapter.NewTailscaleDirectoryDomain(base, "native-owner")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetFailureHandler(func(error) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := d.Activate(); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(base, "tailscale", "node")
	ts := &option.TailscaleEndpointOptions{StateDirectory: state, TaildropDirectory: filepath.Join(state, "Taildrop")}
	opts := option.Options{Endpoints: []option.Endpoint{{Type: C.TypeTailscale, Tag: "node", Options: ts}}}
	ctx, err := prepareTailscaleDirectoryMapping(adapter.ContextWithTailscaleDirectoryDomain(context.Background(), d), opts)
	if err != nil {
		t.Fatal(err)
	}
	m := adapter.TailscaleDirectoryMappingFromContext(ctx)
	if m == nil {
		t.Fatal("valid whole-config census has no plan")
	}
	if ts.StateDirectory != state || ts.TaildropDirectory != filepath.Join(state, "Taildrop") {
		t.Fatal("submitted options mutated")
	}
	if _, _, ok := m.Resolve(ts.StateDirectory, ts.TaildropDirectory); !ok {
		t.Fatal("validated endpoint missing")
	}
}

func TestDirectoryMappingRejectsSSHAndClearsInheritedPlan(t *testing.T) {
	for _, bad := range []any{nil, &option.TailscaleEndpointOptions{SSHServer: &option.TailscaleSSHServerOptions{Enabled: true}}} {
		base := filepath.Join(t.TempDir(), "polaris")
		d, err := adapter.NewTailscaleDirectoryDomain(base, "native-owner")
		if err != nil {
			t.Fatal(err)
		}
		if err := d.SetFailureHandler(func(error) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if err := d.Activate(); err != nil {
			t.Fatal(err)
		}
		state := filepath.Join(base, "tailscale", "node")
		in := adapter.TailscaleDirectoryMappingInput{StateDirectory: state, TaildropDirectory: filepath.Join(state, "Taildrop")}
		old, err := adapter.NewTailscaleDirectoryMapping(d, []adapter.TailscaleDirectoryMappingInput{in})
		if err != nil {
			t.Fatal(err)
		}
		ctx := adapter.ContextWithTailscaleDirectoryDomain(context.Background(), d)
		ctx = adapter.ContextWithTailscaleDirectoryMapping(ctx, old)
		opts := option.Options{Endpoints: []option.Endpoint{
			{Type: C.TypeTailscale, Options: &option.TailscaleEndpointOptions{StateDirectory: in.StateDirectory, TaildropDirectory: in.TaildropDirectory}},
			{Type: C.TypeTailscale, Options: bad},
		}}
		ctx, err = prepareTailscaleDirectoryMapping(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		if adapter.TailscaleDirectoryMappingFromContext(ctx) != nil || d.Active() {
			t.Fatal("partial or inherited plan survived bad endpoint")
		}
		if _, _, ok := old.Resolve(in.StateDirectory, in.TaildropDirectory); ok {
			t.Fatal("old plan survived sticky failure")
		}
	}
}

func TestLegacyDirectoryConfigHasNoPlan(t *testing.T) {
	ctx, err := prepareTailscaleDirectoryMapping(context.Background(), option.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if adapter.TailscaleDirectoryMappingFromContext(ctx) != nil {
		t.Fatal("legacy configuration gained managed capability")
	}
}

func TestMappingPersistenceFailureBlocksLegacyStart(t *testing.T) {
	d, err := adapter.NewTailscaleDirectoryDomain(filepath.Join(t.TempDir(), "polaris"), "owner")
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("unsafe marker could not close")
	if err := d.SetFailureHandler(func(error) error { return failure }); err != nil {
		t.Fatal(err)
	}
	ctx := adapter.ContextWithTailscaleDirectoryDomain(context.Background(), d)
	if _, err := prepareTailscaleDirectoryMapping(ctx, option.Options{}); err == nil {
		t.Fatal("prepared domain admitted Start")
	}
	if err := d.Activate(); err != nil {
		t.Fatal(err)
	}
	opts := option.Options{Endpoints: []option.Endpoint{{Type: C.TypeTailscale, Options: &option.TailscaleEndpointOptions{}}}}
	ctx, err = prepareTailscaleDirectoryMapping(ctx, opts)
	if err != failure || adapter.TailscaleDirectoryMappingFromContext(ctx) != nil {
		t.Fatal("failed persistence admitted legacy writer")
	}
	if _, err = prepareTailscaleDirectoryMapping(ctx, option.Options{}); err != failure {
		t.Fatal("subsequent Start erased sticky persistence error")
	}
}

func TestRawPhysicalNamespaceRevokesBeforeTypedConstruction(t *testing.T) {
	cases := []string{
		`{"log":{"output":"../TAILSCALE-G4-V1/node/log"}}`,
		`{"log":{"output":"/group/polaris/tailscale-g4-v1/node/log"}}`,
		`{"experimental":{"cache_file":{"path":"../tailscale-g4-v1/node/cache"}}}`,
		`{"unknown":[{"nested":"../tailscale-\u00674-v1/node"}]}`,
		`{"path":"tailscale-g4-v1/node","path":"harmless"}`,
		`{"path":"/group\/polaris\/tailscale-g4-v1\/node"}`,
	}
	for _, content := range cases {
		d, err := adapter.NewTailscaleDirectoryDomain(filepath.Join(t.TempDir(), "polaris"), "owner")
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		if err := d.SetFailureHandler(func(error) error { calls++; return nil }); err != nil {
			t.Fatal(err)
		}
		if err := d.Activate(); err != nil {
			t.Fatal(err)
		}
		ctx := adapter.ContextWithTailscaleDirectoryDomain(context.Background(), d)
		if err := guardRawDirectoryNamespace(ctx, content); err != nil {
			t.Fatal(err)
		}
		if d.Active() || calls != 1 {
			t.Fatal("raw physical path retained positive proof")
		}
	}
}

func TestRawNamespacePoisonFailurePreventsLegacyAndNormalProfileStaysActive(t *testing.T) {
	d, err := adapter.NewTailscaleDirectoryDomain(filepath.Join(t.TempDir(), "polaris"), "owner")
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("unsafe marker close failed")
	if err := d.SetFailureHandler(func(error) error { return failure }); err != nil {
		t.Fatal(err)
	}
	if err := d.Activate(); err != nil {
		t.Fatal(err)
	}
	ctx := adapter.ContextWithTailscaleDirectoryDomain(context.Background(), d)
	if err := guardRawDirectoryNamespace(ctx, `{"endpoints":[{"state_directory":"/group/polaris/tailscale/id"}]}`); err != nil || !d.Active() {
		t.Fatal("ordinary logical profile changed domain")
	}
	if err := guardRawDirectoryNamespace(ctx, `{"log":{"output":"tailscale-g4-v1/id/log"}}`); err != failure {
		t.Fatal("poison persistence failure permitted writer")
	}
	if err := guardRawDirectoryNamespace(context.Background(), `{"log":{"output":"tailscale-g4-v1/id/log"}}`); err != nil {
		t.Fatal("ordinary legacy fork behavior changed")
	}
}

func TestExpandedRawNamespaceAlsoRevokes(t *testing.T) {
	t.Setenv("POLARIS_TEST_UI_ROOT", "../tailscale-g4-v1/node")
	d, err := adapter.NewTailscaleDirectoryDomain(filepath.Join(t.TempDir(), "polaris"), "owner")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetFailureHandler(func(error) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := d.Activate(); err != nil {
		t.Fatal(err)
	}
	ctx := adapter.ContextWithTailscaleDirectoryDomain(context.Background(), d)
	if err := guardRawDirectoryNamespace(ctx, `{"experimental":{"clash_api":{"external_ui":"$POLARIS_TEST_UI_ROOT"}}}`); err != nil {
		t.Fatal(err)
	}
	if d.Active() {
		t.Fatal("expanded external_ui retained managed proof")
	}
}

func TestUnknownJSONDialectPoisonsBeforeLegacyParser(t *testing.T) {
	for _, persistFails := range []bool{false, true} {
		d, err := adapter.NewTailscaleDirectoryDomain(filepath.Join(t.TempDir(), "polaris"), "owner")
		if err != nil {
			t.Fatal(err)
		}
		failure := errors.New("poison close failed")
		if err := d.SetFailureHandler(func(error) error {
			if persistFails {
				return failure
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := d.Activate(); err != nil {
			t.Fatal(err)
		}
		ctx := adapter.ContextWithTailscaleDirectoryDomain(context.Background(), d)
		err = guardRawDirectoryNamespace(ctx, `{/* JSONC retained for the original parser */ "log":{}}`)
		if d.Active() || (persistFails && err != failure) || (!persistFails && err != nil) {
			t.Fatal("unknown dialect bypassed poison or changed legacy admission")
		}
	}
}
