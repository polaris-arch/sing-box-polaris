package bridge

import (
	"context"
	"errors"
	"net/netip"
	"slices"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
)

func (o *Outbound) initRuntime(ctx context.Context, cancel context.CancelFunc, logger log.ContextLogger) {
	o.runtimeSource, _ = adapter.RuntimeResourceSourceFromContext(ctx)
	o.runtimeCalls = outbound.NewRuntimeIOFence(nil)
	o.runtimeStarts = outbound.NewRuntimeIOFence(func() error { cancel(); return nil })
	o.backendScope = adapter.NewScope(ctx, logger)
	o.runtimeCapabilities = bridgeCapabilities(o)
	o.runtimeCleanup = outbound.OnceRuntimeCleanup(func() error {
		// Cancellation precedes the real Start join. In-flight Start may still
		// append rollback callbacks; its private Scope is closed only afterward.
		if err := o.runtimeStarts.RuntimeCloseAndWait(); err != nil {
			return err
		}
		if err := o.runtimeCalls.RuntimeCloseAndWait(); err != nil {
			return err
		}
		var returnErr error
		if owner, ok := o.backend.(interface{ closeRuntimeReturns() error }); ok {
			returnErr = owner.closeRuntimeReturns()
		}
		return errors.Join(returnErr, o.backendScope.Close())
	})
}

// Capability adapters preserve only implemented, guarded operations. They do
// not expose the raw backend through UpstreamPort, even during selector cleanup.
type runtimeRanges struct {
	owner  *Outbound
	ranges tun.PortWithSelectorRange
}

func (p *runtimeRanges) PortSelectorRanges(protocol uint8) []tun.SelectorRange {
	release, err := p.owner.runtimeCalls.Acquire()
	if err != nil {
		return nil
	}
	ranges := slices.Clone(p.ranges.PortSelectorRanges(protocol))
	release()
	return ranges
}

func (p *runtimeRanges) ExpandSelectorRanges(protocol uint8) bool {
	release, err := p.owner.runtimeCalls.Acquire()
	if err != nil {
		return false
	}
	expanded := p.ranges.ExpandSelectorRanges(protocol)
	release()
	return expanded
}

type runtimeReservation struct {
	owner       *Outbound
	reservation tun.PortWithSelectorReservation
}

func (p *runtimeReservation) ReserveSelector(protocol uint8, address netip.AddrPort) bool {
	release, err := p.owner.runtimeCalls.Acquire()
	if err != nil {
		return false
	}
	reserved := p.reservation.ReserveSelector(protocol, address)
	release()
	return reserved
}

func (p *runtimeReservation) ReleaseSelector(protocol uint8, address netip.AddrPort) {
	release, err := p.owner.runtimeCalls.Acquire()
	if err != nil {
		return
	}
	p.reservation.ReleaseSelector(protocol, address)
	release()
}

type runtimeRangesReservation struct {
	*runtimeRanges
	*runtimeReservation
}

func bridgeCapabilities(o *Outbound) any {
	ranges, hasRanges := o.backend.(tun.PortWithSelectorRange)
	reservation, hasReservation := o.backend.(tun.PortWithSelectorReservation)
	if hasRanges && hasReservation {
		return &runtimeRangesReservation{&runtimeRanges{o, ranges}, &runtimeReservation{o, reservation}}
	}
	if hasRanges {
		return &runtimeRanges{o, ranges}
	}
	if hasReservation {
		return &runtimeReservation{o, reservation}
	}
	return nil
}
