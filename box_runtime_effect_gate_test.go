package box

import (
	"context"
	"errors"
	"testing"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

func TestRuntimePublicationEffectGateCancellationDoesNotConsumeOwnership(t *testing.T) {
	var gate runtimeEffectGate
	gate.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error,1)
	go func(){ done <- gate.LockContext(ctx) }()
	cancel()
	select {
	case err := <-done: if !errors.Is(err,context.Canceled) { t.Fatalf("canceled publication wait: %v",err) }
	case <-runtimeTestContext(t).Done(): t.Fatal("canceled publication remained behind effect")
	}
	gate.Unlock()
	if err := gate.LockContext(runtimeTestContext(t)); err != nil { t.Fatal(err) }
	gate.Unlock()
}

func TestRuntimeApplyWaitingForControlEffectCancelsWithoutPublication(t *testing.T) {
	barrier := newRuntimeTestBarrier()
	count := 0
	f := newRuntimeTestFixture(t,runtimeTestConfig(1080,"example.org"),func(outbound *runtimeTestSocks) error {
		if outbound.Tag() == "a" {
			count++
			if count == 2 { outbound.startHook = func(stage adapter.StartStage) error { if stage == adapter.StartStateStarted { barrier.block() }; return nil } }
		}
		return nil
	})
	f.start(t)
	_, request := f.plan(t,runtimeTestConfig(1081,"example.org"))
	f.box.runtime.controlEffects.Lock()
	var release sync.Once
	unlock := func(){ release.Do(f.box.runtime.controlEffects.Unlock) }
	t.Cleanup(unlock)
	t.Cleanup(barrier.open)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan RuntimeConfigOperation,1)
	go func(){ operation, _ := f.box.applyRuntimeConfig(ctx,"actor-a",request); done <- operation }()
	runtimeTestWait(t,barrier.entered,"candidate reached final lifecycle stage")
	lease, err := f.box.runtime.store.Acquire()
	if err != nil { t.Fatal("control effect blocked current graph admission:",err) }
	lease.Release()
	barrier.open()
	cancel()
	select {
	case operation := <-done:
		if operation.State != "ABORTING_UNAPPLIED" || f.identity() != request.Expected { t.Fatalf("canceled candidate published: %+v",operation) }
	case <-runtimeTestContext(t).Done(): t.Fatal("Apply could not cancel while prior effect remained admitted")
	}
	unlock()
}

type runtimeBlockingModeCache struct {
	adapter.CacheFile
	barrier *runtimeTestBarrier
}
func (c *runtimeBlockingModeCache) StoreMode(string) error { c.barrier.block(); return nil }

func TestRuntimeModeEffectRetainsGraphUntilActualCacheWrite(t *testing.T) {
	f := newRuntimeTestFixture(t,runtimeTestConfig(1080,"example.org"),nil)
	f.start(t)
	barrier := newRuntimeTestBarrier()
	t.Cleanup(barrier.open)
	service.MustRegister[adapter.CacheFile](f.box.runtime.ctx,&runtimeBlockingModeCache{barrier:barrier})
	f.box.runtime.clashMode.RuntimeReplaceModes([]string{"Rule","Global"})
	done := make(chan bool,1)
	go func(){ done <- f.box.runtime.SetRuntimeClashMode("Global") }()
	runtimeTestWait(t,barrier.entered,"actual detached StoreMode effect")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.box.closeRuntimeResourcesContext(ctx); !errors.Is(err,context.Canceled) { t.Fatalf("bounded shutdown observation: %v",err) }
	select { case <-f.box.runtime.stable.owner.Closed(): t.Fatal("stable dependencies closed during admitted cache effect"); default: }
	barrier.open()
	select { case accepted := <-done: if !accepted { t.Fatal("admitted mode change was rejected") }; case <-runtimeTestContext(t).Done(): t.Fatal("mode effect did not complete") }
	if err := f.box.closeRuntimeResourcesContext(runtimeTestContext(t)); err != nil { t.Fatal(err) }
}
