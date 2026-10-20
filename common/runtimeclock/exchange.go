package runtimeclock

import (
	"context"
	"errors"
	"net"
	"os"

	"github.com/sagernet/sing-box/adapter/outbound"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Each public Exchange uses one of these synchronous, non-escaping dialers.
// Its owner joins closeAndWait before releasing its admitted update or starting
// another sample. A context cancellation interrupts the actual UDP carrier,
// rather than merely canceling an unused context beside a deadline-only read.
type exchangeDialer struct {
	upstream   N.Dialer
	connection *exchangeConnection
}
type exchangeConnection struct {
	net.Conn
	fence      *outbound.RuntimeIOFence
	stopCancel func() bool
	cancelDone chan struct{}
}

func (d *exchangeDialer) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.connection != nil {
		return nil, errors.New("NTP exchange attempted more than one connection")
	}
	conn, err := d.upstream.DialContext(ctx, network, address)
	if conn != nil {
		wrapped, fence := outbound.WrapRuntimeOwnedConn(conn)
		owned := &exchangeConnection{Conn: wrapped, fence: fence, cancelDone: make(chan struct{})}
		owned.stopCancel = context.AfterFunc(ctx, func() { defer close(owned.cancelDone); _ = fence.Close() })
		d.connection = owned
	}
	// Retain even a conn+error or late-after-cancel result for the same sole
	// terminal close. The public Exchange would otherwise discard that carrier.
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if d.connection == nil {
		return nil, errors.New("NTP dial returned no connection")
	}
	return d.connection, nil
}

func (*exchangeDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (d *exchangeDialer) closeAndWait() error {
	c := d.connection
	if c == nil {
		return nil
	}
	if !c.stopCancel() {
		<-c.cancelDone
	}
	return c.fence.RuntimeCloseAndWait()
}
