package adapter

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/sagernet/sing-tun"
)

// RuntimeRevision identifies one immutable effective graph, within one Box run.
type RuntimeRevision struct {
	Incarnation string
	Revision    uint64
}

// ErrProbeGraphChanged reports that the graph condition failed before selector mutation.
var ErrProbeGraphChanged = errors.New("probe graph changed before selection")

// ParseRuntimeRevisionToken reads the canonical runtime graph identifier used by probes.
func ParseRuntimeRevisionToken(token string) (RuntimeRevision, bool) {
	incarnation, revision, found := strings.Cut(token, "/")
	var nonce [32]byte
	if !found || len(incarnation) != hex.EncodedLen(len(nonce)) || incarnation != strings.ToLower(incarnation) {
		return RuntimeRevision{}, false
	}
	if _, err := hex.Decode(nonce[:], []byte(incarnation)); err != nil || revision == "" || revision[0] < '1' || revision[0] > '9' {
		return RuntimeRevision{}, false
	}
	value, err := strconv.ParseUint(revision, 10, 64)
	return RuntimeRevision{Incarnation: incarnation, Revision: value}, err == nil
}

// RuntimeResourceID identifies an allocation, never a user-configured tag.
type RuntimeResourceID struct {
	Incarnation string
	Sequence    uint64
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

type (
	runtimeLeaseContextKey   struct{}
	runtimeLeaseContextValue struct{ lease RuntimeLease }
)

// ContextWithRuntimeLease borrows lease. Copying the context does not retain it;
// an escaping callback or goroutine must Fork before it is published.
func ContextWithRuntimeLease(ctx context.Context, lease RuntimeLease) context.Context {
	return context.WithValue(ctx, runtimeLeaseContextKey{}, runtimeLeaseContextValue{lease: lease})
}

func RuntimeLeaseFromContext(ctx context.Context) (RuntimeLease, bool) {
	value, loaded := ctx.Value(runtimeLeaseContextKey{}).(runtimeLeaseContextValue)
	return value.lease, loaded && value.lease != nil
}
