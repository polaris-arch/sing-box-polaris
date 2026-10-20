package naive

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	N "github.com/sagernet/sing/common/network"
)

func (r *inboundRuntime) wrapConnection(ctx context.Context, conn net.Conn, onClose N.CloseHandlerFunc) (net.Conn, N.CloseHandlerFunc, error) {
	owned, release, err := adapter.AcquireRuntimeOperation(ctx, nil)
	if err != nil {
		return conn, onClose, err
	}
	physical, fence := outbound.WrapRuntimeOwnedConn(conn)
	wrapped := outbound.WrapRuntimeConn(owned, release, physical)
	result := &inboundHandshakeConn{Conn: wrapped, physical: conn, ctx: owned, fence: fence, runtime: r}
	return result, N.OnceClose(func(err error) {
		_ = result.Close()
		if onClose != nil {
			onClose(err)
		}
	}), nil
}

// Only protocol handshake methods are bridged. Raw Upstream and syscall access
// are deliberately absent; all methods share the terminal physical I/O fence.
type inboundHandshakeConn struct {
	net.Conn
	physical net.Conn
	ctx      context.Context
	fence    *outbound.RuntimeIOFence
	runtime  *inboundRuntime
}

func (c *inboundHandshakeConn) handshake(call func() error) error {
	_, release, err := c.runtime.enter(c.ctx)
	if err != nil {
		return err
	}
	defer release()
	leave, err := c.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	return call()
}

func (c *inboundHandshakeConn) HandshakeSuccess() error {
	return c.handshake(func() error {
		if h, ok := c.physical.(interface{ HandshakeSuccess() error }); ok {
			return h.HandshakeSuccess()
		}
		return nil
	})
}

func (c *inboundHandshakeConn) HandshakeFailure(err error) error {
	return c.handshake(func() error {
		if h, ok := c.physical.(interface{ HandshakeFailure(error) error }); ok {
			return h.HandshakeFailure(err)
		}
		return nil
	})
}
