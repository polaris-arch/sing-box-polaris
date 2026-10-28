package direct

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var (
	_ listener.RuntimePacketHandler      = (*Inbound)(nil)
	_ listener.RuntimePacketBatchHandler = (*Inbound)(nil)
)

type (
	runtimePacketKey        struct{}
	runtimePacketInvocation struct {
		ctx               context.Context
		releaseInvocation func()
		releaseCarrier    func()
	}
)

func (p *runtimePacketInvocation) wrap(conn N.PacketConn) N.PacketConn {
	return bufio.NewPacketConn(outbound.WrapRuntimePacketConn(p.ctx, p.releaseCarrier, bufio.NewNetPacketConn(conn)))
}

func (i *Inbound) NewPacketContext(ctx context.Context, buffer *buf.Buffer, source M.Socksaddr) {
	// udpnat2 copies these bytes synchronously. Listener retains its read buffer.
	i.udpNat.NewPacket([][]byte{buffer.Bytes()}, source, i.listener.UDPAddr(), ctx)
}

func (i *Inbound) NewPacketBatchContext(ctx context.Context, buffers []*buf.Buffer, sources []M.Socksaddr) {
	// The actual helper consumes batch buffers, as its legacy caller does.
	i.udpNat.NewPacketBatch(buffers, sources, i.listener.UDPAddr(), ctx)
}

func (i *Inbound) prepareRuntimePacketConnection(source M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	ctx, ok := userData.(context.Context)
	if !ok {
		return false, nil, nil, nil
	}
	// prepare runs inside the new-session branch before udpnat2 launches its
	// goroutine. Both invocation and carrier are owned before publication.
	invocation, releaseInvocation, err := i.runtime.enter(ctx)
	if err != nil {
		return false, nil, nil, nil
	}
	carrier, releaseCarrier, err := adapter.AcquireRuntimeOperation(invocation, nil)
	if err != nil {
		releaseInvocation()
		return false, nil, nil, nil
	}
	prepared := &runtimePacketInvocation{ctx: carrier, releaseInvocation: releaseInvocation, releaseCarrier: releaseCarrier}
	carrier = context.WithValue(log.ContextWithNewID(carrier), runtimePacketKey{}, prepared)
	return true, carrier, &directPacketWriter{i.listener.PacketWriter(), source}, nil
}
