package listener

import (
	"context"
	"errors"
	"net"
	"sync"
)

// SOCKSPacketListener owns the single new UDP carrier during one SOCKS
// handshake. The pinned SOCKS helper does not close it when writing the
// association response fails. Finish must be called with that helper's result;
// nil transfers ownership, an error rolls back only this allocation.
type SOCKSPacketListener struct {
	listen    func(net.ListenConfig, context.Context, string, string) (net.PacketConn, error)
	packet    *socksPacketConn
	attempted bool
	finished  bool
}

func NewSOCKSPacketListener(listen func(net.ListenConfig, context.Context, string, string) (net.PacketConn, error)) *SOCKSPacketListener {
	return &SOCKSPacketListener{listen: listen}
}

// ListenPacket is called synchronously by HandleConnectionEx, at most once.
// The returned carrier may subsequently be closed from its control goroutine.
func (l *SOCKSPacketListener) ListenPacket(config net.ListenConfig, ctx context.Context, network string, address string) (net.PacketConn, error) {
	if l.attempted || l.finished {
		return nil, errors.New("SOCKS handshake cannot allocate another UDP carrier")
	}
	l.attempted = true
	conn, err := l.listen(config, ctx, network, address)
	if err != nil {
		if conn != nil {
			err = errors.Join(err, conn.Close())
		}
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("SOCKS UDP listener returned no carrier")
	}
	l.packet = &socksPacketConn{PacketConn: conn}
	return l.packet, nil
}

func (l *SOCKSPacketListener) Finish(err error) error {
	if l.finished {
		return err
	}
	l.finished = true
	if err != nil && l.packet != nil {
		return errors.Join(err, l.packet.Close())
	}
	return err
}

type socksPacketConn struct {
	net.PacketConn
	closeOnce sync.Once
	closeErr  error
}

// Do not expose Upstream: all protocol and rollback closes must pass through
// the same exact-once boundary, including the concurrent TCP-control closer.
func (c *socksPacketConn) Close() error {
	c.closeOnce.Do(func() { c.closeErr = c.PacketConn.Close() })
	return c.closeErr
}
