package masque

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

type runtimeInboundHandshake struct {
	physical       any
	ctx            context.Context
	fence          *outbound.RuntimeIOFence
	readHandshake  bool
	writeHandshake bool
}

func (h *runtimeInboundHandshake) call(callback func() error) error {
	_, release, err := adapter.AcquireRuntimeOperation(h.ctx, nil)
	if err != nil {
		return err
	}
	defer release()
	leave, err := h.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	return callback()
}

func (h *runtimeInboundHandshake) HandshakeSuccess() error {
	return h.call(func() error {
		if value, ok := h.physical.(interface{ HandshakeSuccess() error }); ok {
			return value.HandshakeSuccess()
		}
		return nil
	})
}

func (h *runtimeInboundHandshake) HandshakeFailure(err error) error {
	return h.call(func() error {
		if value, ok := h.physical.(interface{ HandshakeFailure(error) error }); ok {
			return value.HandshakeFailure(err)
		}
		return nil
	})
}
func (h *runtimeInboundHandshake) NeedHandshakeForRead() bool  { return h.readHandshake }
func (h *runtimeInboundHandshake) NeedHandshakeForWrite() bool { return h.writeHandshake }
func runtimeHandshake(physical any, ctx context.Context, fence *outbound.RuntimeIOFence) *runtimeInboundHandshake {
	h := &runtimeInboundHandshake{physical: physical, ctx: ctx, fence: fence}
	if value, ok := physical.(interface{ NeedHandshakeForRead() bool }); ok {
		h.readHandshake = value.NeedHandshakeForRead()
	}
	if value, ok := physical.(interface{ NeedHandshakeForWrite() bool }); ok {
		h.writeHandshake = value.NeedHandshakeForWrite()
	}
	return h
}

type (
	runtimeInboundConn struct {
		net.Conn
		*runtimeInboundHandshake
	}
	runtimeInboundPacket struct {
		N.PacketConn
		*runtimeInboundHandshake
	}
)

func (p *runtimeClientState) wrapInboundConn(ctx context.Context, conn net.Conn, onClose N.CloseHandlerFunc) (context.Context, net.Conn, N.CloseHandlerFunc, error) {
	owned, release, err := adapter.AcquireRuntimeOperation(ctx, p.source)
	if err != nil {
		return ctx, conn, onClose, err
	}
	physical, fence := outbound.WrapRuntimeOwnedConn(conn)
	wrapped := &runtimeInboundConn{Conn: outbound.WrapRuntimeConn(owned, release, physical), runtimeInboundHandshake: runtimeHandshake(conn, owned, fence)}
	return owned, wrapped, N.OnceClose(func(err error) {
		_ = wrapped.Close()
		if onClose != nil {
			onClose(err)
		}
	}), nil
}

func (p *runtimeClientState) wrapInboundPacket(ctx context.Context, conn N.PacketConn, onClose N.CloseHandlerFunc) (context.Context, N.PacketConn, N.CloseHandlerFunc, error) {
	owned, release, err := adapter.AcquireRuntimeOperation(ctx, p.source)
	if err != nil {
		return ctx, conn, onClose, err
	}
	physical, fence := outbound.WrapRuntimeOwnedPacketConn(bufio.NewNetPacketConn(conn))
	wrapped := &runtimeInboundPacket{PacketConn: bufio.NewPacketConn(outbound.WrapRuntimePacketConn(owned, release, physical)), runtimeInboundHandshake: runtimeHandshake(conn, owned, fence)}
	return owned, wrapped, N.OnceClose(func(err error) {
		_ = wrapped.Close()
		if onClose != nil {
			onClose(err)
		}
	}), nil
}
