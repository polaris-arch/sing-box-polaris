package runtimegraph

import (
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

// Deadlines are failure watchdogs only, never scheduling/order assumptions.
func await(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("barrier did not complete")
	}
}

func eventually(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for !predicate() {
		select {
		case <-deadline.C:
			t.Fatal("lock barrier did not become observable")
		default:
			runtime.Gosched()
		}
	}
}

func mustAdmission(t *testing.T, g *generation) *admission {
	t.Helper()
	a, err := newAdmission(g)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func mustGenerationLease(t *testing.T, a *admission) *generationLease {
	t.Helper()
	l, err := a.acquire()
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func assertGeneration(t *testing.T, g *generation, refs uint64, claimed, retired bool) {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.refs != refs || g.claimed != claimed || g.retired != retired {
		t.Fatalf("generation got refs=%d claimed=%v retired=%v; want %d %v %v", g.refs, g.claimed, g.retired, refs, claimed, retired)
	}
	select {
	case <-g.zero:
		if refs != 0 {
			t.Fatal("premature zero signal")
		}
	default:
		if refs == 0 {
			t.Fatal("missing zero signal")
		}
	}
}

func TestAcquireRetainExcludesPublish(t *testing.T) {
	old, next := newGeneration(1), newGeneration(2)
	a := mustAdmission(t, old)
	old.mu.Lock()
	leaseCh := make(chan *generationLease, 1)
	errCh := make(chan error, 1)
	go func() { l, err := a.acquire(); leaseCh <- l; errCh <- err }()
	// acquire must hold the read guard while waiting on old.mu to retain.
	eventually(t, func() bool {
		if a.mu.TryLock() {
			a.mu.Unlock()
			return false
		}
		return true
	})
	published := make(chan struct{})
	publishErr := make(chan error, 1)
	go func() { _, err := a.publish(1, next); publishErr <- err; close(published) }()
	// A waiting writer bars new readers, making its arrival observable.
	eventually(t, func() bool {
		if a.mu.TryRLock() {
			a.mu.RUnlock()
			return false
		}
		return true
	})
	select {
	case <-published:
		t.Fatal("publish passed blocked retain")
	default:
	}
	old.mu.Unlock()
	await(t, published)
	if err := <-publishErr; err != nil {
		t.Fatal(err)
	}
	l := <-leaseCh
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if l.generation != old {
		t.Fatal("reader lost original generation")
	}
	assertGeneration(t, old, 1, true, true)
	l.release()
	l.release()
	assertGeneration(t, old, 0, true, true)
	a.seal()
}

func TestRejectedPublishPreservesOwnership(t *testing.T) {
	g := newGeneration(9)
	a := mustAdmission(t, g)
	candidate := newGeneration(10)
	if _, err := a.publish(8, candidate); !errors.Is(err, errRevisionMismatch) {
		t.Fatal(err)
	}
	assertGeneration(t, candidate, 1, false, false)
	assertGeneration(t, g, 1, true, false)
	for _, next := range []*generation{nil, g, newGeneration(9), newGeneration(8)} {
		if _, err := a.publish(9, next); !errors.Is(err, errInvalidGeneration) {
			t.Fatal(err)
		}
		if next != nil && next != g {
			if err := next.discard(); err != nil {
				t.Fatal(err)
			}
		}
	}
	retired := newGeneration(11)
	if err := retired.discard(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.publish(9, retired); !errors.Is(err, errInvalidGeneration) {
		t.Fatal(err)
	}
	if err := candidate.discard(); err != nil {
		t.Fatal(err)
	}
	assertGeneration(t, candidate, 0, false, true)
	if err := candidate.discard(); !errors.Is(err, errInvalidGeneration) {
		t.Fatal(err)
	}
	if err := g.discard(); !errors.Is(err, errInvalidGeneration) {
		t.Fatal(err)
	}
	if _, err := newAdmission(nil); !errors.Is(err, errInvalidGeneration) {
		t.Fatal(err)
	}
	if _, err := newAdmission(g); !errors.Is(err, errInvalidGeneration) {
		t.Fatal(err)
	}
	if _, err := newAdmission(retired); !errors.Is(err, errInvalidGeneration) {
		t.Fatal(err)
	}
	if _, err := newAdmission(&generation{}); !errors.Is(err, errInvalidGeneration) {
		t.Fatal(err)
	}
	a.seal()
}

func TestCrossAdmissionSingleClaim(t *testing.T) {
	a := mustAdmission(t, newGeneration(1))
	b := mustAdmission(t, newGeneration(1))
	next := newGeneration(2)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, owner := range []*admission{a, b} {
		go func(owner *admission) { <-start; _, err := owner.publish(1, next); results <- err }(owner)
	}
	close(start)
	first, second := <-results, <-results
	if !((first == nil && errors.Is(second, errInvalidGeneration)) || (second == nil && errors.Is(first, errInvalidGeneration))) {
		t.Fatalf("claim results: %v, %v", first, second)
	}
	assertGeneration(t, next, 1, true, false)
	a.seal()
	b.seal()
	assertGeneration(t, next, 0, true, true)
}

func TestDiscardVersusClaim(t *testing.T) {
	a := mustAdmission(t, newGeneration(1))
	next := newGeneration(2)
	start := make(chan struct{})
	published, discarded := make(chan error, 1), make(chan error, 1)
	go func() { <-start; _, err := a.publish(1, next); published <- err }()
	go func() { <-start; discarded <- next.discard() }()
	close(start)
	p, d := <-published, <-discarded
	if !((p == nil && errors.Is(d, errInvalidGeneration)) || (d == nil && errors.Is(p, errInvalidGeneration))) {
		t.Fatalf("publish/discard results: %v, %v", p, d)
	}
	a.seal()
	assertGeneration(t, next, 0, p == nil, true)
}

func TestSealRacesAndParallelRelease(t *testing.T) {
	g, next := newGeneration(1), newGeneration(2)
	a := mustAdmission(t, g)
	leases := make([]*generationLease, 32)
	for i := range leases {
		leases[i] = mustGenerationLease(t, a)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); <-start; a.seal() }()
	go func() {
		defer wg.Done()
		<-start
		l, err := a.acquire()
		if err == nil {
			l.release()
		} else if !errors.Is(err, errAdmissionSealed) {
			t.Error(err)
		}
	}()
	published := make(chan error, 1)
	go func() { defer wg.Done(); <-start; _, err := a.publish(1, next); published <- err }()
	close(start)
	wg.Wait()
	err := <-published
	if err != nil {
		if !errors.Is(err, errAdmissionSealed) {
			t.Fatal(err)
		}
		assertGeneration(t, next, 1, false, false)
		if err := next.discard(); err != nil {
			t.Fatal(err)
		}
	}
	if a.seal() != nil {
		t.Fatal("seal released owner twice")
	}
	if _, err := a.acquire(); !errors.Is(err, errAdmissionSealed) {
		t.Fatal(err)
	}
	unused := newGeneration(3)
	if _, err := a.publish(2, unused); !errors.Is(err, errAdmissionSealed) {
		t.Fatal(err)
	}
	assertGeneration(t, unused, 1, false, false)
	unused.discard()
	assertGeneration(t, g, 32, true, true)
	for _, l := range leases {
		wg.Add(2)
		for i := 0; i < 2; i++ {
			go func(l *generationLease) { defer wg.Done(); l.release() }(l)
		}
	}
	wg.Wait()
	assertGeneration(t, g, 0, true, true)
}

func TestRevisionDoesNotWrap(t *testing.T) {
	a := mustAdmission(t, newGeneration(^uint64(0)))
	next := newGeneration(0)
	if _, err := a.publish(^uint64(0), next); !errors.Is(err, errInvalidGeneration) {
		t.Fatal(err)
	}
	next.discard()
	a.seal()
}
