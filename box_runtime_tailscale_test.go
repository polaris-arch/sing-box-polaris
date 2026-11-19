//go:build with_tailscale

package box

import (
	"context"
	"errors"
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
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "native-tailscale.test"), nil)
	native := &runtimeTailscaleAdvisoryFixture{}
	ctx := service.ContextWith[adapter.PlatformInterface](f.ctx, native)
	protocolTS.RegisterEndpoint(service.FromContext[adapter.EndpointRegistry](ctx).(*endpoint.Registry))
	capacity := false
	ctx = adapter.ContextWithRuntimeTailscaleChildCapacity(ctx, func() bool { return capacity })
	var reservations []adapter.RuntimeTailscaleChildRequest
	ctx = adapter.ContextWithRuntimeTailscaleChildRegistrar(ctx, func(_ context.Context, child adapter.RuntimeTailscaleChildRequest) (adapter.RuntimeTailscaleChildRegistration, error) {
		reservations = append(reservations, child)
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
	before := f.identity()

	root := t.TempDir()
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
	_, apply := f.plan(t, content)
	if len(reservations) != 0 || f.identity() != before {
		t.Fatal("Plan began a native reservation or changed R")
	}
	operation, _ := f.box.applyRuntimeConfig(ctx, "actor-a", apply)
	if len(reservations) != 1 || reservations[0].NativeWriter == nil || *reservations[0].NativeWriter != directories ||
		reservations[0].ResourceID.Incarnation != before.Incarnation || reservations[0].Generation == 0 {
		t.Fatal("Apply did not enter the original physical registration with its exact directories")
	}
	if f.identity() != before || operation.Active != before {
		t.Fatal("writer failure changed the active incarnation/revision")
	}
}
