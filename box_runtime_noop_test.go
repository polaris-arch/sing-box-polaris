package box

import (
	"context"
	"testing"
)

func TestRuntimeNoOpPreservesIdentityAndConsumesTicket(t *testing.T) {
	config := runtimeTestConfig(1080, "example.org")
	f := newRuntimeTestFixture(t, config, nil)
	f.start(t)
	before := f.identity()
	plan, request := f.plan(t, config)
	if !plan.NoOp {
		t.Fatal("unchanged effective configuration was not recognized")
	}
	operation, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil {
		t.Fatal(err)
	}
	if operation.Active != before || operation.Before != before || f.identity() != before {
		t.Fatal("no-op changed graph or control identity")
	}
	if f.count("a") != 1 || f.count("b") != 1 {
		t.Fatal("no-op constructed protocol resources")
	}
	repeated, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || repeated.Active != before || repeated.State != operation.State {
		t.Fatal("no-op ticket replay lost exact receipt")
	}
}

func TestRuntimeNoOpDoesNotCureUnacknowledgedControlDurability(t *testing.T) {
	config := runtimeTestConfig(1080, "example.org")
	f := newRuntimeTestFixture(t, config, nil)
	f.start(t)
	f.box.runtime.access.Lock()
	f.box.runtime.durableDigest = f.box.runtime.active.EffectiveDigest
	f.box.runtime.durableIdentity = f.box.runtime.active
	f.box.runtime.active.ControlRevision++
	f.box.runtime.access.Unlock()
	plan, request := f.plan(t, config)
	if !plan.NoOp {
		t.Fatal("config-only equality must preserve newer controls")
	}
	operation, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil {
		t.Fatal(err)
	}
	if operation.Durable || operation.State != "COMMITTED_DURABILITY_PENDING" {
		t.Fatal("matching config digest hid unacknowledged control state")
	}
}
