package route

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/runtimegraph"
)

func TestRuntimeTaskRetainsResourceOnlyContinuation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "route-task", Sequence: 1}, nil, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	parent, err := owner.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Release()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	if err := runtimeTask(adapter.ContextWithRuntimeResourceLease(ctx, parent), func(owned context.Context) {
		if _, ok := adapter.RuntimeResourceLeaseFromContext(owned, owner.ID()); !ok {
			panic("missing inherited resource")
		}
		close(entered)
		<-release
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	parent.Release()
	owner.Seal()
	select {
	case <-owner.Closed():
		t.Fatal("resource freed while copy tail is live")
	default:
	}
	unblock()
	if err := owner.WaitClosed(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeTaskReleasedContinuationCannotReadmit(t *testing.T) {
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "route-task", Sequence: 2}, nil, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Seal()
	parent, err := owner.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	ctx := adapter.ContextWithRuntimeResourceLease(context.Background(), parent)
	parent.Release()
	called := make(chan struct{}, 1)
	if err := runtimeTask(ctx, func(context.Context) { called <- struct{}{} }); err == nil {
		t.Fatal("released continuation accepted")
	}
	select {
	case <-called:
		t.Fatal("rejected worker dispatched")
	default:
	}
}
