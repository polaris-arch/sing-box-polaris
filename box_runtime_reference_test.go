package box

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestRuntimeBoxReferenceEffectSurvivesCanceledCandidate(t *testing.T) {
	for _, blockedCleanup := range []bool{false, true} {
		t.Run(map[bool]string{false: "immediate-cleanup", true: "blocked-cleanup"}[blockedCleanup], func(t *testing.T) {
			effect := newRuntimeTestBarrier()
			candidate := newRuntimeTestBarrier()
			cleanup := newRuntimeTestBarrier()
			count := 0
			f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), func(outbound *runtimeTestSocks) error {
				if outbound.Tag() == "a" {
					count++
					outbound.idleHook = func(bool) { effect.block() }
					if count == 2 {
						if blockedCleanup {
							outbound.closeHook = func() error { cleanup.block(); return nil }
						}
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
			t.Cleanup(cleanup.open)
			f.start(t)
			runtimeTestWait(t, effect.entered, "current graph reference effect")
			old, view := f.acquire(t)
			t.Cleanup(old.Release)
			resource := runtimeTestResource(t, f, view.componentIDs["outbound:a"])
			_, request := f.plan(t, runtimeTestConfig(1081, "example.org"))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := runtimeTestApplyAsync(f, ctx, request)
			runtimeTestWait(t, candidate.entered, "actual candidate startup")
			cancel()
			candidate.open()
			operation := runtimeTestReceiveApply(t, result)
			if (operation.State != "ABORTING_UNAPPLIED" && operation.State != "ABORTED_UNAPPLIED") || operation.Before != request.Expected || operation.Active != request.Expected || f.identity() != request.Expected {
				t.Fatalf("canceled publication replaced active reference census: %+v", operation)
			}
			if blockedCleanup {
				runtimeTestWait(t, cleanup.entered, "actual canceled candidate cleanup")
				if operation.State != "ABORTING_UNAPPLIED" {
					t.Fatalf("blocked candidate already reported terminal: %+v", operation)
				}
			}
			select {
			case <-resource.owner.Closed():
				t.Fatal("reference effect lost its original resource")
			default:
			}
			cleanup.open()
			runtimeTestRequireCleanSourceAbort(t, f, operation, request.Expected)
			// Failed preparation resumes the current observer. Once its actual effect
			// exits, a fresh transaction can publish and reconcile the new census.
			effect.open()
			_, retry := f.plan(t, runtimeTestConfig(1082, "example.org"))
			committed, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", retry)
			if err != nil || committed.Before != request.Expected || committed.Active.Revision != request.Expected.Revision+1 || committed.Active != f.identity() {
				t.Fatalf("reference observer did not resume: %+v %v", committed, err)
			}
			old.Release()
			if err := resource.owner.WaitClosed(runtimeTestContext(t)); err != nil {
				t.Fatal(err)
			}
			if err := f.box.runtime.reference.CloseIdleConnections(runtimeTestContext(t)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
