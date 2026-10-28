package runtimegraph

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCleanupSnapshotDoesNotTakeLeaseOrWaitForMutex(t *testing.T) {
	r := newResourceOwner(context.Background(), nil)
	o := &ResourceOwner{owner: r}
	lease, err := r.acquire()
	if err != nil {
		t.Fatal(err)
	}
	before := o.CleanupSnapshot()
	if !before.Available || before.References != 1 || before.State != 0 {
		t.Fatal(before)
	}
	r.mu.Lock()
	blocked := o.CleanupSnapshot()
	r.mu.Unlock()
	if blocked.Available {
		t.Fatal("snapshot waited for ownership lock")
	}
	after := o.CleanupSnapshot()
	if after != before {
		t.Fatal("observation changed owner")
	}
	lease.release()
	r.requestClose()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.waitClosed(ctx); err != nil {
		t.Fatal(err)
	}
	done := o.CleanupSnapshot()
	if !done.Available || done.State != 3 || done.References != 0 || done.Failed {
		t.Fatal(done)
	}
}

func TestCleanupSnapshotDistinguishesLeaseDrainNativeCloseAndFailure(t *testing.T) {
	entered, unblock := make(chan struct{}), make(chan struct{})
	failure := errors.New("private owner failure")
	r := newResourceOwner(context.Background(), func() error { close(entered); <-unblock; return failure })
	o := &ResourceOwner{owner: r}
	lease, err := r.acquire()
	if err != nil {
		t.Fatal(err)
	}
	r.requestClose()
	waiting := o.CleanupSnapshot()
	if waiting.State != 1 || waiting.References != 1 || waiting.Failed {
		t.Fatal(waiting)
	}
	lease.release()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("close not started")
	}
	active := o.CleanupSnapshot()
	if active.State != 2 || active.References != 0 || active.Failed {
		t.Fatal(active)
	}
	close(unblock)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.waitClosed(ctx); err != failure {
		t.Fatal(err)
	}
	done := o.CleanupSnapshot()
	if done.State != 3 || !done.Failed || done.References != 0 {
		t.Fatal(done)
	}
}
