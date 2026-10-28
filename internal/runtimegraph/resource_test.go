package runtimegraph

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func mustResourceLease(t *testing.T, r *resourceOwner) *resourceLease {
	t.Helper()
	l, err := r.acquire()
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func waitResource(t *testing.T, r *resourceOwner) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return r.waitClosed(ctx)
}

func assertResourcePending(t *testing.T, r *resourceOwner) {
	t.Helper()
	select {
	case <-r.closed:
		t.Fatal("cleanup unexpectedly complete")
	default:
	}
}

func TestResourceDrainAndBlockingClose(t *testing.T) {
	entered, unblock := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	r := newResourceOwner(context.Background(), func() error {
		calls.Add(1)
		close(entered)
		<-unblock
		return nil
	})
	construction := mustResourceLease(t, r)
	stream := mustResourceLease(t, r)
	r.requestClose()
	r.requestClose()
	if r.context().Err() != nil {
		t.Fatal("retirement canceled live operations")
	}
	if _, err := r.acquire(); !errors.Is(err, errResourceSealed) {
		t.Fatal(err)
	}
	construction.release()
	construction.release()
	if r.context().Err() != nil {
		t.Fatal("construction release canceled retained stream")
	}
	assertResourcePending(t, r)
	select {
	case <-entered:
		t.Fatal("cleanup started before drain")
	default:
	}
	released := make(chan struct{})
	go func() { stream.release(); close(released) }()
	await(t, entered)
	// Cleanup is definitely blocked, yet last release must already be able to
	// return. This would deadlock until the watchdog with synchronous cleanup.
	await(t, released)
	if !errors.Is(r.context().Err(), context.Canceled) {
		t.Fatal("drained context still live")
	}
	assertResourcePending(t, r)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.waitClosed(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	assertResourcePending(t, r)
	r.mu.Lock()
	state, refs := r.state, r.refs
	r.mu.Unlock()
	if state != resourceClosing || refs != 0 {
		t.Fatalf("blocked close state=%v refs=%d", state, refs)
	}
	close(unblock)
	if err := waitResource(t, r); err != nil {
		t.Fatal(err)
	}
	stream.release()
	r.requestClose()
	if calls.Load() != 1 {
		t.Fatalf("cleanup count %d", calls.Load())
	}
}

func TestResourceWaitCancellationPreservesLease(t *testing.T) {
	r := newResourceOwner(context.Background(), nil)
	l := mustResourceLease(t, r)
	r.requestClose()
	ctx, cancel := context.WithDeadline(context.Background(), time.Time{})
	defer cancel()
	if err := r.waitClosed(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if r.context().Err() != nil {
		t.Fatal("wait timeout canceled resource")
	}
	r.mu.Lock()
	refs := r.refs
	state := r.state
	r.mu.Unlock()
	if refs != 1 || state != resourceSealed {
		t.Fatalf("wait mutated ownership: %d %v", refs, state)
	}
	assertResourcePending(t, r)
	l.release()
	if err := waitResource(t, r); err != nil {
		t.Fatal(err)
	}
}

func TestResourceStickyErrorAndPanic(t *testing.T) {
	sentinel := errors.New("cleanup failed")
	for _, test := range []struct {
		name    string
		closeFn func() error
		check   func(error) bool
	}{
		{"error", func() error { return sentinel }, func(err error) bool { return errors.Is(err, sentinel) }},
		{"panic", func() error { panic("cleanup exploded") }, func(err error) bool { return err != nil && strings.Contains(err.Error(), "cleanup exploded") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			r := newResourceOwner(context.Background(), func() error { calls.Add(1); return test.closeFn() })
			start := make(chan struct{})
			results := make(chan error, 16)
			var wg sync.WaitGroup
			for range 16 {
				wg.Go(func() {
					<-start
					r.requestClose()
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					results <- r.waitClosed(ctx)
				})
			}
			close(start)
			wg.Wait()
			close(results)
			var first error
			for err := range results {
				if !test.check(err) {
					t.Fatalf("unexpected result: %v", err)
				}
				if first == nil {
					first = err
				} else if err != first {
					t.Fatal("close result was not sticky")
				}
			}
			if err := waitResource(t, r); err != first {
				t.Fatalf("later result changed: %v", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("cleanup count %d", calls.Load())
			}
		})
	}
}

func TestResourceZeroRefCloseAndReentrantRequest(t *testing.T) {
	entered, unblock := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	var r *resourceOwner
	r = newResourceOwner(context.Background(), func() error {
		calls.Add(1)
		r.requestClose()
		close(entered)
		<-unblock
		return nil
	})
	requested := make(chan struct{})
	go func() { r.requestClose(); close(requested) }()
	await(t, entered)
	await(t, requested)
	assertResourcePending(t, r)
	if _, err := r.acquire(); !errors.Is(err, errResourceSealed) {
		t.Fatal(err)
	}
	close(unblock)
	if err := waitResource(t, r); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("cleanup count %d", calls.Load())
	}
	if _, err := r.acquire(); !errors.Is(err, errResourceSealed) {
		t.Fatal(err)
	}
}

func TestResourceParentShutdownException(t *testing.T) {
	parent, shutdown := context.WithCancel(context.Background())
	r := newResourceOwner(parent, nil)
	l := mustResourceLease(t, r)
	r.requestClose()
	if r.context().Err() != nil {
		t.Fatal("ordinary retirement canceled context")
	}
	shutdown()
	await(t, r.context().Done())
	assertResourcePending(t, r)
	r.mu.Lock()
	refs := r.refs
	r.mu.Unlock()
	if refs != 1 {
		t.Fatal("parent shutdown discarded lease")
	}
	l.release()
	if err := waitResource(t, r); err != nil {
		t.Fatal(err)
	}
}

func TestResourceConcurrentSealAcquireRelease(t *testing.T) {
	var calls atomic.Int32
	r := newResourceOwner(context.Background(), func() error { calls.Add(1); return nil })
	leases := make([]*resourceLease, 32)
	for i := range leases {
		leases[i] = mustResourceLease(t, r)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, l := range leases {
		for range 2 {
			wg.Add(1)
			go func(l *resourceLease) { defer wg.Done(); <-start; l.release(); r.requestClose() }(l)
		}
	}
	wg.Go(func() {
		<-start
		l, err := r.acquire()
		if err == nil {
			l.release()
		} else if !errors.Is(err, errResourceSealed) {
			t.Error(err)
		}
	})
	close(start)
	wg.Wait()
	if err := waitResource(t, r); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("cleanup count %d", calls.Load())
	}
	r.mu.Lock()
	refs := r.refs
	state := r.state
	r.mu.Unlock()
	if refs != 0 || state != resourceClosed {
		t.Fatalf("final state refs=%d state=%v", refs, state)
	}
}

func TestResourceAbortConstruction(t *testing.T) {
	var calls atomic.Int32
	r := newResourceOwner(context.Background(), func() error { calls.Add(1); return nil })
	construction := mustResourceLease(t, r)
	// Failed prepare seals, finishes registration/unwind, releases its lease,
	// then joins outside all commit/daemon locks.
	r.requestClose()
	assertResourcePending(t, r)
	construction.release()
	if err := waitResource(t, r); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("abort did not clean exactly once")
	}
}

func TestResourceOpenZeroReferencesDoesNotClose(t *testing.T) {
	var calls atomic.Int32
	r := newResourceOwner(context.Background(), func() error { calls.Add(1); return nil })
	l := mustResourceLease(t, r)
	l.release()
	assertResourcePending(t, r)
	if r.context().Err() != nil || calls.Load() != 0 {
		t.Fatal("open zero-reference owner was closed")
	}
	late := mustResourceLease(t, r)
	r.requestClose()
	if _, err := r.acquire(); !errors.Is(err, errResourceSealed) {
		t.Fatal(err)
	}
	late.release()
	if err := waitResource(t, r); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("cleanup was not exactly once")
	}
}
