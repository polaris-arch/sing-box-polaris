package adapter

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
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

// ErrProbeBindingMismatch means a probe's requested selector member did not carry its route.
var ErrProbeBindingMismatch = errors.New("probe selected a different outbound member")

// ProbeMemberDigest identifies the intended member of a loopback probe selector.
type ProbeMemberDigest [sha256.Size]byte

type probeMemberKey struct{}

func ContextWithProbeMember(ctx context.Context, member ProbeMemberDigest) context.Context {
	return context.WithValue(ctx, probeMemberKey{}, member)
}

// TakeProbeMember consumes the binding at route admission so nested dials do not inherit it.
func TakeProbeMember(ctx context.Context) (context.Context, ProbeMemberDigest, bool) {
	member, loaded := ctx.Value(probeMemberKey{}).(ProbeMemberDigest)
	if loaded {
		ctx = context.WithValue(ctx, probeMemberKey{}, nil)
	}
	return ctx, member, loaded
}

// IsOutboundForegroundSlot recognizes a refusal with no accompanying failure.
func IsOutboundForegroundSlot(err error) bool {
	return isOnlyOutboundError(err, ErrOutboundForegroundSlot)
}

// IsOutboundCapacity recognizes a capacity refusal with no accompanying failure.
func IsOutboundCapacity(err error) bool {
	return isOnlyOutboundError(err, ErrOutboundCapacity)
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
