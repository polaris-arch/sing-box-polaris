package adapter

import "context"

// RuntimeResourceSource is constructor-bound admission for one actual receiving
// resource. The source is an owner, never a permanent baseline reservation.
type RuntimeResourceSource interface {
	ID() RuntimeResourceID
	Acquire() (RuntimeResourceLease, error)
}

// RuntimeCapturedResourceSource is for a concrete resource's registered internal
// callback fence, not external request admission. The caller must hold that
// fence until the returned reservation has been transferred or released, and
// owner cleanup must join the fence before releasing its captured dependencies.
// Self retention is deliberately unavailable: the concrete fence owns that
// lifetime, so an internal worker cannot prevent its own shutdown from starting.
type RuntimeCapturedResourceSource interface {
	RuntimeResourceSource
	RetainCapturedResource(RuntimeResourceID) (RuntimeResourceLease, error)
}

// RuntimeResourceContinuation exposes only the immutable captured dependency
// closure of a retained resource. It cannot admit unrelated or tag-derived IDs.
type RuntimeResourceContinuation interface {
	RuntimeResourceLease
	RetainResource(RuntimeResourceID) (RuntimeResourceLease, error)
}

type runtimeResourceSourceKey struct{}
type runtimeResourceSourceValue struct { source RuntimeResourceSource }
type runtimeResourceLeasesKey struct{}
type runtimeResourceLeases struct {
	lease RuntimeResourceLease
	previous *runtimeResourceLeases
}

func ContextWithRuntimeResourceSource(ctx context.Context, source RuntimeResourceSource) context.Context {
	return context.WithValue(ctx, runtimeResourceSourceKey{}, runtimeResourceSourceValue{source: source})
}
func RuntimeResourceSourceFromContext(ctx context.Context) (RuntimeResourceSource, bool) {
	value, ok := ctx.Value(runtimeResourceSourceKey{}).(runtimeResourceSourceValue)
	return value.source, ok && value.source != nil
}

// ContextWithRuntimeResourceLease borrows a handle. It does not create ownership.
func ContextWithRuntimeResourceLease(ctx context.Context, lease RuntimeResourceLease) context.Context {
	if lease == nil { return ctx }
	previous, _ := ctx.Value(runtimeResourceLeasesKey{}).(*runtimeResourceLeases)
	return context.WithValue(ctx, runtimeResourceLeasesKey{}, &runtimeResourceLeases{lease: lease, previous: previous})
}
func RuntimeResourceLeaseFromContext(ctx context.Context, id RuntimeResourceID) (RuntimeResourceLease, bool) {
	entry, _ := ctx.Value(runtimeResourceLeasesKey{}).(*runtimeResourceLeases)
	for ; entry != nil; entry = entry.previous {
		if entry.lease.ID() == id { return entry.lease, true }
	}
	return nil, false
}

// ContextWithRuntimeOwnership copies only borrowed lifetime capabilities. It
// preserves the receiver's registry, stores, cancellation and ordinary values.
func ContextWithRuntimeOwnership(receiver, caller context.Context) context.Context {
	graph, _ := RuntimeLeaseFromContext(caller)
	receiver = ContextWithRuntimeLease(receiver, graph)
	entries, _ := caller.Value(runtimeResourceLeasesKey{}).(*runtimeResourceLeases)
	return context.WithValue(receiver, runtimeResourceLeasesKey{}, entries)
}

// AcquireRuntimeOperation reserves before invocation or asynchronous publication.
// It retains inherited receivers too, because a checker/callback may capture a
// previous receiver outside the incoming graph's closure. Release is idempotent.
// A matching continuation that is already released cannot fall back to new root
// admission. Receivers outside both the graph and retained dependency closures
// may admit only through their own still-open constructor-bound source.
func AcquireRuntimeOperation(ctx context.Context, source RuntimeResourceSource) (context.Context, func(), error) {
	var graph RuntimeLease
	if borrowed, ok := RuntimeLeaseFromContext(ctx); ok {
		var err error
		graph, err = borrowed.Fork()
		if err != nil { return nil, nil, err }
	}
	var retained *runtimeResourceLeases
	seen := make(map[RuntimeResourceID]bool)
	release := func() {
		for entry := retained; entry != nil; entry = entry.previous { entry.lease.Release() }
		if graph != nil { graph.Release() }
	}
	inherited, _ := ctx.Value(runtimeResourceLeasesKey{}).(*runtimeResourceLeases)
	for entry := inherited; entry != nil; entry = entry.previous {
		id := entry.lease.ID()
		if seen[id] { continue }
		lease, err := entry.lease.Fork()
		if err != nil { release(); return nil, nil, err }
		seen[id] = true
		retained = &runtimeResourceLeases{lease: lease, previous: retained}
	}
	if source != nil && !seen[source.ID()] {
		var lease RuntimeResourceLease
		var err error
		if graph != nil { lease, err = graph.RetainResource(source.ID()) }
		if lease == nil {
			for entry := retained; entry != nil; entry = entry.previous {
				if closure, ok := entry.lease.(RuntimeResourceContinuation); ok {
					lease, err = closure.RetainResource(source.ID())
					if lease != nil { break }
				}
			}
		}
		if lease == nil { lease, err = source.Acquire() }
		if err != nil { release(); return nil, nil, err }
		retained = &runtimeResourceLeases{lease: lease, previous: retained}
	}
	ctx = ContextWithRuntimeLease(ctx, graph)
	ctx = context.WithValue(ctx, runtimeResourceLeasesKey{}, retained)
	return ctx, release, nil
}
