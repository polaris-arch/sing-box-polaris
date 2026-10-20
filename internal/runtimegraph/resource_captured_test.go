package runtimegraph

import (
 "context"
 "errors"
 "testing"

 "github.com/sagernet/sing-box/adapter"
)

func TestCapturedResourceRejectsSelfAndUnrelated(t *testing.T) {
 leaf, leafLease := testOwner(t, 301, nil, nil)
 middle, middleLease := testOwner(t, 302, []adapter.RuntimeResourceLease{leafLease}, nil)
 owner, ownerLease := testOwner(t, 303, []adapter.RuntimeResourceLease{middleLease}, nil)
 _ = middle
 for _, id := range []adapter.RuntimeResourceID{owner.ID(), {Incarnation:"test-run", Sequence:304}, {Incarnation:"other", Sequence:301}} {
  if lease, err := owner.RetainCapturedResource(id); !errors.Is(err, ErrResourceNotMember) || lease != nil { t.Fatalf("invalid target admitted: %v %v", lease, err) }
 }
 owner.owner.mu.Lock(); before := owner.owner.refs; owner.owner.mu.Unlock()
 lease, err := owner.RetainCapturedResource(leaf.ID())
 if err != nil { t.Fatal(err) }
 defer lease.Release()
 owner.owner.mu.Lock(); after := owner.owner.refs; owner.owner.mu.Unlock()
 if before != after { t.Fatal("internal dependency reservation pinned its own owner") }
 ownerLease.Release()
}

func TestCapturedResourceInsideClosingFence(t *testing.T) {
 leaf, leafLease := testOwner(t, 311, nil, nil)
 entered, release := make(chan struct{}), make(chan struct{})
 owner, ownerLease := testOwner(t, 312, []adapter.RuntimeResourceLease{leafLease}, func() error { close(entered); <-release; return nil })
 defer close(release)
 owner.Seal(); ownerLease.Release()
 await(t, entered)
 // This represents a callback admitted by the concrete fence before cleanup
 // sealed it. Cleanup is deliberately still joining that same fence.
 lease, err := owner.RetainCapturedResource(leaf.ID())
 if err != nil { t.Fatal(err) }
 lease.Release()
 if _, err = owner.Acquire(); err == nil { t.Fatal("external root admission reopened") }
}

func TestCapturedResourceAfterTerminalCleanup(t *testing.T) {
 leaf, leafLease := testOwner(t, 321, nil, nil)
 owner, ownerLease := testOwner(t, 322, []adapter.RuntimeResourceLease{leafLease}, nil)
 owner.Seal(); ownerLease.Release()
 await(t, owner.Closed())
 if err := owner.WaitClosed(context.Background()); err != nil { t.Fatal(err) }
 if lease, err := owner.RetainCapturedResource(leaf.ID()); err == nil || lease != nil { t.Fatal("terminal source admitted dependency") }
}
