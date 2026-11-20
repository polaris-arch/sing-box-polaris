package runtimeingress

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

type carrierGate interface {
	EnterRuntimeIngress(context.Context) (context.Context, func(), error)
}

// WrapConnection gives the physical stream a continuation of the admitted graph.
// Its handshake callbacks also need the protocol's callback admission gate.
func WrapConnection[G carrierGate](ctx context.Context, conn net.Conn, onClose N.CloseHandlerFunc, gate G) (net.Conn, N.CloseHandlerFunc, error) {
	owned, release, err := adapter.AcquireRuntimeOperation(ctx, nil)
	if err != nil {
		return conn, onClose, err
	}
	physical, fence := outbound.WrapRuntimeOwnedConn(conn)
	wrapped := outbound.WrapRuntimeConn(owned, release, physical)
	result := &inboundHandshakeConn[G]{carrierConn: carrierConn{Conn: wrapped}, physical: conn, ctx: owned, fence: fence, gate: gate}
	return result, result.carrierConn.closeHandler(onClose), nil
}

type carrierConn struct{ net.Conn }

// The non-generic receiver keeps the close callback from capturing the gate's type dictionary.
func (c *carrierConn) closeHandler(onClose N.CloseHandlerFunc) N.CloseHandlerFunc {
	return N.OnceClose(func(err error) {
		_ = c.Close()
		if onClose != nil {
			onClose(err)
		}
	})
}

// The concrete gate pointer avoids binding a method value on every stream.
// Only handshake methods reach the physical connection, under its I/O fence.
type inboundHandshakeConn[G carrierGate] struct {
	carrierConn
	physical net.Conn
	ctx      context.Context
	fence    *outbound.RuntimeIOFence
	gate     G
}

func (c *inboundHandshakeConn[G]) handshake(call func() error) error {
	_, release, err := c.gate.EnterRuntimeIngress(c.ctx)
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

func (c *inboundHandshakeConn[G]) HandshakeSuccess() error {
	return c.handshake(func() error {
		if h, ok := c.physical.(interface{ HandshakeSuccess() error }); ok {
			return h.HandshakeSuccess()
		}
		return nil
	})
}

func (c *inboundHandshakeConn[G]) HandshakeFailure(err error) error {
	return c.handshake(func() error {
		if h, ok := c.physical.(interface{ HandshakeFailure(error) error }); ok {
			return h.HandshakeFailure(err)
		}
		return nil
	})
}

// WrapPacketConnection preserves the admitted graph for the lifetime of a packet carrier.
func WrapPacketConnection(ctx context.Context, conn N.PacketConn, onClose N.CloseHandlerFunc) (N.PacketConn, N.CloseHandlerFunc, error) {
	owned, release, err := adapter.AcquireRuntimeOperation(ctx, nil)
	if err != nil {
		return conn, onClose, err
	}
	physical, _ := outbound.WrapRuntimeOwnedPacketConn(bufio.NewNetPacketConn(conn))
	wrapped := bufio.NewPacketConn(outbound.WrapRuntimePacketConn(owned, release, physical))
	return wrapped, N.OnceClose(func(err error) {
		_ = wrapped.Close()
		if onClose != nil {
			onClose(err)
		}
	}), nil
}
