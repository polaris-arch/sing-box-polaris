package device

import (
	"context"
	"errors"
	"net/netip"

	"github.com/sagernet/sing-tun"
)

// CloseAndWait is a lifecycle-owner operation, never a packet/return callback.
// The caller must hold no storage/admission guard. Canceling an observer cannot
// abandon cleanup: production lifecycle cleanup always uses Background.
func CloseAndWait(device Device) error {
	closeErr := device.Close()
	return errors.Join(closeErr, device.WaitDetached(context.Background()))
}

// done publishes closeErr after the existing Close operation has returned.
// There is no new lifetime count and no inference from UpstreamPort identity.
func waitStackDetached(ctx context.Context, done <-chan struct{}, closeErr *error, stack tun.StackWithDetachWaiter) error {
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return errors.Join(*closeErr, stack.WaitDetached(ctx))
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
