package adapter

import (
	"context"

	"github.com/sagernet/sing-tun"
)

// RuntimeRevision identifies one immutable effective graph, within one Box run.
type RuntimeRevision struct {
	Incarnation string
	Revision uint64
}

// RuntimeResourceID identifies an allocation, never a user-configured tag.
type RuntimeResourceID struct {
	Incarnation string
	Sequence uint64
}

// RuntimeView contains leaf dependencies. Ingress gateways are never leaves.
// Implementations must seal their lookup inventories before publication.
type RuntimeView interface {
	Identity() RuntimeRevision
	Router() Router
	DNSRouter() DNSRouter
	OutboundManager() OutboundManager
	EndpointManager() EndpointManager
	DNSTransportManager() DNSTransportManager
	NetworkManager() NetworkManager
}

// RuntimePortView binds the exact port object to its graph resource closure.
type RuntimePortView interface {
	RuntimePortResource(tun.Port) (RuntimeResourceID, bool)
}

// RuntimeLease is an admitted graph reservation. Fork is continuation admission,
// including after retirement, and fails after this source handle is released.
type RuntimeLease interface {
	View() RuntimeView
	Fork() (RuntimeLease, error)
	RetainResource(RuntimeResourceID) (RuntimeResourceLease, error)
	Release()
}

type RuntimeResourceLease interface {
	ID() RuntimeResourceID
	Fork() (RuntimeResourceLease, error)
	Retiring() <-chan struct{}
	Release()
}

type RuntimeAdmission interface {
	Acquire() (RuntimeLease, error)
}

type runtimeLeaseContextKey struct{}
type runtimeLeaseContextValue struct { lease RuntimeLease }

// ContextWithRuntimeLease borrows lease. Copying the context does not retain it;
// an escaping callback or goroutine must Fork before it is published.
func ContextWithRuntimeLease(ctx context.Context, lease RuntimeLease) context.Context {
	return context.WithValue(ctx, runtimeLeaseContextKey{}, runtimeLeaseContextValue{lease: lease})
}

func RuntimeLeaseFromContext(ctx context.Context) (RuntimeLease, bool) {
	value, loaded := ctx.Value(runtimeLeaseContextKey{}).(runtimeLeaseContextValue)
	return value.lease, loaded && value.lease != nil
}
