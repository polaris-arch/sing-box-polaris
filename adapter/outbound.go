package adapter

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"
)

// ErrOutboundCapacity means an outbound could not allocate local resources to start a dial.
var ErrOutboundCapacity = errors.New("outbound engine capacity exhausted")

// ErrOutboundForegroundSlot is a local capacity refusal caused by reserving the last slot for foreground work.
var ErrOutboundForegroundSlot = fmt.Errorf("outbound engine slot reserved for foreground: %w", ErrOutboundCapacity)

// ErrProbeBindingMismatch means the route did not match the probe's member or graph.
var ErrProbeBindingMismatch = errors.New("probe route binding mismatch")

// ProbeMemberDigest identifies the intended member of a loopback probe selector.
type ProbeMemberDigest [sha256.Size]byte

// ProbeBinding pins a loopback probe to a member and optionally to one runtime graph.
type ProbeBinding struct {
	Member       ProbeMemberDigest
	Graph        RuntimeRevision
	OnVerified   func()
	TicketMember string
	TicketSlot   uint32
}

type probeBindingKey struct{}

func ContextWithProbeBinding(ctx context.Context, binding ProbeBinding) context.Context {
	return context.WithValue(ctx, probeBindingKey{}, binding)
}

// TakeProbeBinding consumes the binding at route admission so nested dials do not inherit it.
func TakeProbeBinding(ctx context.Context) (context.Context, ProbeBinding, bool) {
	binding, loaded := ctx.Value(probeBindingKey{}).(ProbeBinding)
	if loaded {
		ctx = context.WithValue(ctx, probeBindingKey{}, nil)
	}
	return ctx, binding, loaded
}

// IsOutboundForegroundSlot recognizes a refusal with no accompanying failure.
func IsOutboundForegroundSlot(err error) bool {
	return isOnlyOutboundError(err, ErrOutboundForegroundSlot)
}

// IsOutboundCapacity recognizes a capacity refusal with no accompanying failure.
func IsOutboundCapacity(err error) bool {
	return isOnlyOutboundError(err, ErrOutboundCapacity)
}

// IsOutboundClosed recognizes a closed outbound with no accompanying failure.
func IsOutboundClosed(err error) bool {
	return isOnlyOutboundError(err, net.ErrClosed)
}

func isOnlyOutboundError(err, target error) bool {
	if err == target {
		return true
	}
	switch cause := err.(type) {
	case interface{ Unwrap() []error }:
		causes := cause.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, child := range causes {
			if !isOnlyOutboundError(child, target) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return isOnlyOutboundError(cause.Unwrap(), target)
	default:
		return false
	}
}

// Note: for proxy protocols, outbound creates early connections by default.

type Outbound interface {
	Type() string
	Tag() string
	Network() []string
	Dependencies() []string
	N.Dialer
}

type OutboundWithPreferredRoutes interface {
	Outbound
	PreferredDomain(metadata *InboundContext, domain string) bool
	PreferredAddress(metadata *InboundContext, address netip.Addr) bool
}

type OutboundWithMultiplex interface {
	Outbound
	MultiplexEnabled() bool
}

type FlowOutbound interface {
	Outbound
	tun.Port
	PreMatchFlow(network string, destination netip.Addr) PreMatchAction
}

type OutboundRegistry interface {
	option.OutboundOptionsRegistry
	CreateOutbound(ctx context.Context, router Router, logger log.ContextLogger, tag string, outboundType string, options any) (Outbound, error)
}

type OutboundManager interface {
	Lifecycle
	Outbounds() []Outbound
	Outbound(tag string) (Outbound, bool)
	Default() Outbound
	Create(ctx context.Context, router Router, logger log.ContextLogger, tag string, outboundType string, options any) error
}

type IdleConnectionKeeper interface {
	SetKeepIdleConnections(keep bool)
	CloseIdleConnections()
}

// RuntimeSharedConnectionOwner identifies the physical connections behind
// distinct logical outbounds. The owner belongs to the admitted runtime graph.
type RuntimeSharedConnectionOwner interface {
	RuntimeSharedConnectionOwner() (RuntimeResourceID, bool)
}

type Referrer interface {
	References() []string
}
