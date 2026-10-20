package box

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestRuntimeBoxReferenceEffectSurvivesCanceledCandidate(t *testing.T) {
	effect := newRuntimeTestBarrier()
	candidate := newRuntimeTestBarrier()
	count := 0
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), func(outbound *runtimeTestSocks) error {
		if outbound.Tag() == "a" {
			count++
			outbound.idleHook = func(bool) { effect.block() }
			if count == 2 {
				outbound.startHook = func(stage adapter.StartStage) error {
					if stage == adapter.StartStateStarted {
						candidate.block()
					}
					return nil
				}
			}
		}
		return nil
	})
	t.Cleanup(effect.open)
	t.Cleanup(candidate.open)
	f.start(t)
	runtimeTestWait(t, effect.entered, "current graph reference effect")
	old, view := f.acquire(t)
	resource := runtimeTestResource(t, f, view.componentIDs["outbound:a"])
	_, request := f.plan(t, runtimeTestConfig(1081, "example.org"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := runtimeTestApplyAsync(f, ctx, request)
	runtimeTestWait(t, candidate.entered, "actual candidate startup")
	candidate.open()
	cancel()
	operation := runtimeTestReceiveApply(t, result)
	if operation.State != "ABORTING_UNAPPLIED" || f.identity() != request.Expected {
		t.Fatalf("canceled publication replaced active reference census: %+v", operation)
	}
	select {
	case <-resource.owner.Closed():
		t.Fatal("reference effect lost its original resource")
	default:
	}
	// Failed preparation resumes the current observer. Once its actual effect
	// exits, a fresh transaction can publish and reconcile the new census.
	effect.open()
	_, retry := f.plan(t, runtimeTestConfig(1082, "example.org"))
	committed, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", retry)
	if err != nil || committed.Active.Revision != 2 {
		t.Fatalf("reference observer did not resume: %+v %v", committed, err)
	}
	old.Release()
	if err := resource.owner.WaitClosed(runtimeTestContext(t)); err != nil {
		t.Fatal(err)
	}
	if err := f.box.runtime.reference.CloseIdleConnections(runtimeTestContext(t)); err != nil {
		t.Fatal(err)
	}
}
