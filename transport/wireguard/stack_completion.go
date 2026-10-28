package wireguard

import (
	"context"
	"errors"
	"net/netip"

	"github.com/sagernet/sing-tun"
)

// Only observes the existing shutdown operation and embedded stack. It adds no
// lifetime count and makes no native callback-detachment capability assertion.
func waitStackDetached(ctx context.Context, done <-chan struct{}, closeErr *error, stack tun.StackWithDetachWaiter) error {
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return errors.Join(*closeErr, stack.WaitDetached(ctx))
}

func (e *Endpoint) WaitDetached(ctx context.Context) error {
	// Endpoint.Close already waits for the exact Device after native Close.
	select {
	case <-e.closeDone:
		return e.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// deviceIPStack is the exact stack stored by the existing device constructor.
// Keeping this typed boundary permits deterministic completion barriers without
// replacing the real production stack with a port-capability lookup.
type deviceIPStack interface {
	tun.Stack
	tun.StackWithDetachWaiter
	DialTCP(context.Context, netip.Addr, netip.AddrPort) (*tun.GoConn, error)
	DialUDP(netip.AddrPort, netip.AddrPort) (*tun.GoUDPConn, error)
	ListenUDP(netip.AddrPort) (*tun.GoUDPConn, error)
}

var _ deviceIPStack = (*tun.Go)(nil)
