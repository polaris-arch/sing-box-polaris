package tun

import (
	"context"
	"net/netip"
	"time"
)

type FlowVerdict struct {
	Ownership   FlowOwnership
	Action      FlowAction
	Port        Port
	Destination netip.AddrPort
	UDPTimeout  time.Duration
	NewTracker  func() FlowTracker
}

type FlowAction uint8

const (
	ActionAccept FlowAction = iota
	ActionFlow
	ActionReject
	ActionDrop
	ActionBypass
	ActionHijackDNS
)

type FlowTracker interface {
	AttachFlow(handle FlowHandle)
	CountForward(n int)
	CountReverse(n int)
	FlowEstablished()
	CloseFlow(reason FlowCloseReason)
}

type FlowHandle interface {
	CloseFlow()
}

type FlowCloseReason uint8

const (
	FlowCloseReset FlowCloseReason = iota
	FlowCloseFinished
	FlowCloseTimeout
)

func (r FlowCloseReason) String() string {
	switch r {
	case FlowCloseFinished:
		return "finished"
	case FlowCloseTimeout:
		return "idle timeout"
	default:
		return "connection reset"
	}
}

type Port interface {
	PortAddresses() (v4 netip.Addr, v6 netip.Addr)
	PortMTU() uint32
	AttachReturn(returnPath Return) error
	DetachReturn(returnPath Return) error
	WritePackets(packets [][]byte) error
}

// PortWithNATIdentity shares the existing NAT selector namespace between logical
// ports backed by one physical network identity. The returned Port must be stable,
// comparable and alive for every logical attachment; it supplies physical selector
// capabilities only. Attachment callbacks and ownership still use the logical Port.
// A nil identity retains the ordinary logical-port namespace. Identity is sampled
// once per attachment and must not change during that attachment's lifetime.
type PortWithNATIdentity interface {
 NATIdentity() Port
}

type SelectorRange struct {
	Start uint16
	Count uint16
}

type PortWithSelectorRange interface {
	PortSelectorRanges(protocol uint8) []SelectorRange
	ExpandSelectorRanges(protocol uint8) bool
}

type PortWithSelectorReservation interface {
	ReserveSelector(protocol uint8, address netip.AddrPort) bool
	ReleaseSelector(protocol uint8, address netip.AddrPort)
}

type PortWithUpstream interface {
	UpstreamPort() any
}

func portCapability[T any](port any) (T, bool) {
	for port != nil {
		capability, matched := port.(T)
		if matched {
			return capability, true
		}
		wrapper, isWrapper := port.(PortWithUpstream)
		if !isWrapper {
			break
		}
		port = wrapper.UpstreamPort()
	}
	var zero T
	return zero, false
}

type Return interface {
	ReturnHeadroom() int
	ReturnPackets(packets [][]byte) [][]byte
}

// FlowOwnership is implemented by the runtime adapter. Retain is a continuation
// of an existing admission, including after retirement; it never admits current.
// BindContext borrows this handle. A context copy does not retain ownership.
type FlowOwnership interface {
	Retain() (FlowOwnership, error)
	BindContext(context.Context) context.Context
	RetainPort(Port) (PortOwnership, error)
	Release()
}

type PortOwnership interface {
	Retain() (PortOwnership, error)
	Retiring() <-chan struct{}
	Release()
}

// Take transfers the complete verdict. Ordinary value copies do not transfer or
// retain a handle. The source must not be used after this call.
func (v *FlowVerdict) Take() FlowVerdict {
	result := *v
	*v = FlowVerdict{}
	return result
}

func (v *FlowVerdict) Release() {
	ownership := v.Ownership
	*v = FlowVerdict{}
	if ownership != nil {
		ownership.Release()
	}
}

func (v FlowVerdict) CloneForDelivery() (FlowVerdict, error) {
	if v.Ownership != nil {
		ownership, err := v.Ownership.Retain()
		if err != nil {
			return FlowVerdict{}, err
		}
		v.Ownership = ownership
	}
	return v, nil
}

func (v FlowVerdict) BindContext(ctx context.Context) context.Context {
	if v.Ownership != nil {
		return v.Ownership.BindContext(ctx)
	}
	return ctx
}

// ClassifyAndRelease is only for scalar prefilters which do not establish a
// core flow. In particular it must not be used for a fallback-routing cache.
func (v *FlowVerdict) ClassifyAndRelease() FlowAction {
	action := v.Action
	v.Release()
	return action
}
