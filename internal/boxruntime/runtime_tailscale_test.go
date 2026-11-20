//go:build with_tailscale

package boxruntime

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	protocolTS "github.com/sagernet/sing-box/protocol/tailscale"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

func TestRuntimeTailscaleDirectoryOverlapIsComponentBounded(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "state", "node")
	for _, test := range []struct {
		a, b    string
		overlap bool
	}{
		{root, root, true},
		{root, filepath.Join(root, "Taildrop"), true},
		{filepath.Join(root, "Taildrop"), root, true},
		{root, root + "-other", false},
		{filepath.Join(root, "a"), filepath.Join(root, "b"), false},
	} {
		if got := runtimeTailscaleDirectoriesOverlap(test.a, test.b); got != test.overlap {
			t.Fatalf("overlap(%q,%q)=%v", test.a, test.b, got)
		}
	}
}

type runtimeTailscaleAdvisoryFixture struct {
	runtimeTestPlatform
	allowed    bool
	validation []adapter.RuntimeTailscaleDirectories
}

func (*runtimeTailscaleAdvisoryFixture) RequiresRuntimeTailscaleWriter() bool { return true }
func (p *runtimeTailscaleAdvisoryFixture) ValidateRuntimeTailscaleWriter(_ string, directories adapter.RuntimeTailscaleDirectories) bool {
	p.validation = append(p.validation, directories)
	return p.allowed
}

func (*runtimeTailscaleAdvisoryFixture) ClaimRuntimeTailscaleWriter(adapter.RuntimeTailscaleWriterScope) (bool, error) {
	panic("Box reached native acquisition without the original registrar")
}

func (*runtimeTailscaleAdvisoryFixture) ReleaseRuntimeTailscaleWriter(adapter.RuntimeTailscaleWriterScope, bool) error {
	panic("Box reached native release without the original registrar")
}

func TestRuntimeTailscaleAndroidPlanRequiresCapacityAndApplyUsesOriginalRegistration(t *testing.T) {
	root := t.TempDir()
	rulePath := filepath.Join(root, "rules.json")
	if err := os.WriteFile(rulePath, runtimeTestSourceBytes("native-tailscale.test"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, options := newRuntimeTestConstruction(t, runtimeTestLocalConfig(rulePath), nil)
	options.Route.Final = "" // Constructor materializes a default that isn't in the accepted Plan bytes.
	native := &runtimeTailscaleAdvisoryFixture{}
	ctx := service.ContextWith[adapter.PlatformInterface](f.ctx, native)
	protocolTS.RegisterEndpoint(service.FromContext[adapter.EndpointRegistry](ctx).(*endpoint.Registry))
	capacity := false
	ctx = adapter.ContextWithRuntimeTailscaleChildCapacity(ctx, func() bool { return capacity })
	var reservations []adapter.RuntimeTailscaleChildRequest
	var observedPlanDigest string
	var frozenConstruction []byte
	ctx = adapter.ContextWithRuntimeTailscaleChildRegistrar(ctx, func(ctx context.Context, child adapter.RuntimeTailscaleChildRequest) (adapter.RuntimeTailscaleChildRegistration, error) {
		if adapter.RuntimeTailscaleStartupChild(ctx) {
			t.Error("warm Apply marked its child as part of the original startup")
		}
		reservations = append(reservations, child)
		observedPlanDigest, _ = adapter.RuntimeTailscalePlanDigest(ctx)
		frozenConstruction, _ = adapter.RuntimeTailscaleConfiguration(ctx)
		return nil, errors.New("controlled stop before the writer may acquire")
	})
	f.ctx, options.Context = ctx, ctx
	var err error
	f.box, err = New(options)
	if err != nil {
		t.Fatal(err)
	}
	clientShapeFinish(t, f)
	f.start(t)
	runtimeTestProducer(t, f).stop()
	before := f.identity()

	logOnly := options.Options
	log := *logOnly.Log
	log.Level = "debug"
	logOnly.Log = &log
	logContent, err := json.MarshalContext(ctx, logOnly)
	if err != nil {
		t.Fatal(err)
	}
	if _, plan := f.plan(t, logContent); plan.Expected != before || len(native.validation) != 0 || len(reservations) != 0 {
		t.Fatal("ordinary log-level Plan entered the Android Tailscale admission path")
	}

	directories := adapter.RuntimeTailscaleDirectories{State: filepath.Join(root, "state"), Taildrop: filepath.Join(root, "drop")}
	candidate := options.Options
	candidate.Endpoints = []option.Endpoint{{Type: C.TypeTailscale, Tag: "new-child", Options: &option.TailscaleEndpointOptions{
		OnDemand: true, StateDirectory: directories.State, TaildropDirectory: directories.Taildrop,
	}}}
	content, err := json.MarshalContext(ctx, candidate)
	if err != nil {
		t.Fatal(err)
	}
	reject := func() {
		t.Helper()
		plan, err := f.box.planRuntimeConfig(ctx, "actor-a", before, content)
		if err != nil || plan.Applicable || len(plan.Errors) != 1 || plan.Errors[0].Code != "RESTART_REQUIRED" || len(reservations) != 0 {
			t.Fatalf("ineligible writer had an applicable Plan: %+v, %v", plan.Errors, err)
		}
	}
	reject()
	if len(native.validation) != 0 {
		t.Fatal("full original census entered native advisory validation")
	}
	capacity = true
	reject()
	native.allowed = true
	plan, apply := f.plan(t, content)
	if len(reservations) != 0 || f.identity() != before {
		t.Fatal("Plan began a native reservation or changed R")
	}
	if err := os.WriteFile(rulePath, runtimeTestSourceBytes("changed-after-plan.test"), 0o600); err != nil {
		t.Fatal(err)
	}
	operation, _ := f.box.applyRuntimeConfig(ctx, "actor-a", apply)
	if len(reservations) != 1 || reservations[0].NativeWriter == nil || *reservations[0].NativeWriter != directories ||
		reservations[0].ResourceID.Incarnation != before.Incarnation || reservations[0].Generation == 0 {
		t.Fatal("Apply did not enter the original physical registration with its exact directories")
	}
	var frozen option.Options
	if err := json.UnmarshalContext(ctx, frozenConstruction, &frozen); err != nil {
		t.Fatal(err)
	}
	if observedPlanDigest != plan.CandidateDigest || runtimeDigest(frozenConstruction) == observedPlanDigest ||
		frozen.Route.RuleSet[0].Type != C.RuleSetTypeInline || frozen.Route.Final == "" ||
		!bytes.Contains(frozenConstruction, []byte("native-tailscale.test")) ||
		bytes.Contains(frozenConstruction, []byte("changed-after-plan.test")) {
		t.Fatal("native binding did not preserve the accepted digest independently of frozen constructor inputs")
	}
	if f.identity() != before || operation.Active != before {
		t.Fatal("writer failure changed the active incarnation/revision")
	}
}

func TestRuntimeTailscaleAndroidEmptyCandidateChecksOnlyActiveEndpointInventory(t *testing.T) {
	ctx := service.ContextWith[adapter.PlatformInterface](context.Background(), &runtimeTailscaleAdvisoryFixture{})
	old := &protocolTS.Endpoint{Adapter: endpoint.NewAdapter(C.TypeTailscale, "existing", nil, nil)}
	box := &Box{runtime: &runtimeCoordinator{ctx: ctx, resources: []*runtimeResource{{
		components: map[string]*runtimeComponent{"endpoint:existing": {endpoint: old}},
	}}}}
	err := box.preflightRuntimeTailscaleEndpoints(ctx, option.Options{}, nil, [32]byte{})
	var restart *runtimeEndpointRestartRequiredError
	if !errors.As(err, &restart) || restart.detail.Path != "endpoints.existing" {
		t.Fatalf("removing the active native writer did not produce a typed restart: %v", err)
	}
}
