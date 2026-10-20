package lifecycle

import (
	"context"
	"errors"
	"testing"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
)

func await(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select { case <-signal: case <-time.After(5 * time.Second): t.Fatal("barrier was not reached") }
}

func TestAfterFuncFalseStopIsNotCompletion(t *testing.T) {
	var work Work
	ctx, cancel := context.WithCancel(context.Background())
	entered, leave, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
	stop, ok := work.AfterFunc(ctx, func() { close(entered); <-leave })
	if !ok { t.Fatal("callback admission failed") }
	cancel(); await(t, entered)
	if stop() { t.Fatal("running callback was reported stopped") }
	work.Seal()
	go func() { work.Wait(); close(joined) }()
	select { case <-joined: t.Fatal("cancelled callback was falsely joined"); default: }
	close(leave); await(t, joined)
	if _, ok := work.Reserve(); ok { t.Fatal("work admitted after seal") }
}

func TestOperationContinuesReceivingResourceAfterSeal(t *testing.T) {
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "dns-work", Sequence: 1}, nil, func() error { return nil })
	if err != nil { t.Fatal(err) }
	lease, err := owner.Acquire(); if err != nil { t.Fatal(err) }
	ctx := adapter.ContextWithRuntimeResourceLease(context.Background(), lease)
	owner.Seal()
	var work Work
	ctx, done, err := work.Operation(ctx, owner)
	if err != nil { t.Fatal("live inherited receiver was rejected:", err) }
	lease.Release()
	if _, ok := adapter.RuntimeResourceLeaseFromContext(ctx, owner.ID()); !ok { t.Fatal("receiver context was lost") }
	select { case <-owner.Closed(): t.Fatal("resource closed during operation"); default: }
	done()
	await(t, owner.Closed())
	if _, _, err := work.Operation(context.Background(), owner); err == nil { t.Fatal("sealed receiver admitted a fresh root") }
}

func TestConstructionCleanupRejectsAlreadyClosedScope(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	scope := adapter.NewScope(context.Background(), logger)
	if err := scope.Close(); err != nil { t.Fatal(err) }
	closed := 0
	owned, err := ConstructionCleanup(adapter.ContextWithConstructionScope(context.Background(), scope), func() error { closed++; return nil })
	if !owned || err == nil || closed != 1 { t.Fatalf("already-cleaned constructor accepted: owned=%v err=%v closed=%d", owned, err, closed) }
	standaloneClosed := false
	owned, err = ConstructionCleanup(context.Background(), func() error { standaloneClosed = true; return nil })
	if owned || err != nil || standaloneClosed { t.Fatal("standalone construction was cleaned immediately") }
}

func TestUncertaintySurvivesScopeCancellationFiltering(t *testing.T) {
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	scope.Add(func() error { return Uncertain("native callback", context.Canceled) })
	err := scope.Close()
	if err == nil || errors.Is(err, context.Canceled) { t.Fatal("completion uncertainty was discarded or unwrapped") }
}

func TestSocketCohortRetirementDoesNotBlockUpdateStack(t *testing.T) {
	var scopes Scopes
	scope, err := scopes.New(context.Background(), log.NewNOPFactory().Logger())
	if err != nil { t.Fatal(err) }
	entered, leave := make(chan struct{}), make(chan struct{})
	scope.Add(func() error { close(entered); <-leave; return nil })
	scopes.Retire(scope)
	await(t, entered)
	closed := make(chan struct{})
	go func() { _ = scopes.Close(); close(closed) }()
	select { case <-closed: t.Fatal("cohort close returned before its callback"); default: }
	close(leave); await(t, closed)
}

func TestStructuralCohortBackpressureRetriesLatestAfterActualClose(t *testing.T) {
	var scopes Scopes
	logger := log.NewNOPFactory().Logger()
	old, err := scopes.New(context.Background(), logger); if err != nil { t.Fatal(err) }
	current, err := scopes.New(context.Background(), logger); if err != nil { t.Fatal(err) }
	if _, err := scopes.New(context.Background(), logger); !errors.Is(err, ErrSocketCohortBusy) { t.Fatal("unbounded third cohort admitted") }
	closeEntered, closeMayFinish := make(chan struct{}), make(chan struct{})
	old.Add(func() error { close(closeEntered); <-closeMayFinish; return nil })
	scopes.Retire(old); await(t, closeEntered)
	var work Work
	var refresh CoalescedRefresh
	ctx, cancel := context.WithCancel(context.Background()); defer cancel()
	var desired atomic.Int64
	updated := make(chan int64, 1)
	update := func(context.Context) bool { updated <- desired.Load(); return false }
	for value := int64(1); value <= 100; value++ {
		desired.Store(value)
		if !refresh.Request(&work, ctx, 0, scopes.WaitReady, update) { t.Fatal("refresh rejected") }
	}
	select { case <-updated: t.Fatal("retirement request was mistaken for capacity completion"); default: }
	close(closeMayFinish)
	select { case value := <-updated: if value != 100 { t.Fatal("refresh installed stale desired state", value) }; case <-time.After(5*time.Second): t.Fatal("latest pending refresh was lost") }
	work.Seal(); cancel(); work.Wait()
	scopes.Retire(current)
	if err := scopes.Close(); err != nil { t.Fatal(err) }
}

func TestCoalescedRefreshCancellationJoinsPendingWorker(t *testing.T) {
	var work Work
	var refresh CoalescedRefresh
	ctx, cancel := context.WithCancel(context.Background())
	waiting := make(chan struct{})
	ready := func(ctx context.Context) error { close(waiting); <-ctx.Done(); return ctx.Err() }
	if !refresh.Request(&work, ctx, 0, ready, func(context.Context) bool { t.Error("cancelled refresh applied"); return false }) { t.Fatal("refresh rejected") }
	await(t, waiting)
	work.Seal(); cancel(); work.Wait()
	if refresh.Request(&work, ctx, 0, ready, nil) { t.Fatal("copied callback restarted stopped refresh") }
}
