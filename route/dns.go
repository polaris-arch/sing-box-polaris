package route

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	dnsOutbound "github.com/sagernet/sing-box/protocol/dns"
	R "github.com/sagernet/sing-box/route/rule"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

func (r *Router) hijackDNSStream(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	conn = dnsOutbound.NewDNSStreamConn(conn)
	r.searchProcessInfo(ctx, &metadata)
	metadata.Destination = M.Socksaddr{}
	err := N.ReportConnHandshakeSuccess(conn, conn)
	if err != nil {
		return E.Cause(err, "report handshake success")
	}
	ctx, queryRouter := adapter.RuntimeDNSCarrierContext(ctx, r.dns)
	for {
		conn.SetReadDeadline(time.Now().Add(C.DNSTimeout))
		err = dnsOutbound.HandleStreamDNSRequest(ctx, queryRouter, conn, metadata)
		if err != nil {
			if !E.IsClosedOrCanceled(err) {
				return err
			} else {
				return nil
			}
		}
	}
}

func (r *Router) hijackDNSPacket(ctx context.Context, conn N.PacketConn, packetBuffers []*N.PacketBuffer, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	r.searchProcessInfo(ctx, &metadata)
	err := N.ReportPacketConnHandshakeSuccess(conn, nil)
	if err != nil {
		N.ReleaseMultiPacketBuffer(packetBuffers)
		err = E.Cause(err, "report handshake success")
	} else {
		ctx, queryRouter := adapter.RuntimeDNSCarrierContext(ctx, r.dns)
		err = dnsOutbound.NewDNSPacketConnection(ctx, queryRouter, conn, packetBuffers, metadata)
	}
	N.CloseOnHandshakeFailure(conn, onClose, err)
	if err != nil && !E.IsClosedOrCanceled(err) {
		return E.Cause(err, "process DNS packet")
	}
	return nil
}

func (r *Router) HijackDNSPacket(ctx context.Context, payload []byte, writer N.PacketWriter, metadata adapter.InboundContext) {
	var message mDNS.Msg
	err := message.Unpack(payload)
	if err != nil {
		r.logger.ErrorContext(ctx, E.Cause(err, "process DNS packet: unpack request"))
		return
	}
	r.searchProcessInfo(ctx, &metadata)
	destination := metadata.Destination
	metadata.Destination = M.Socksaddr{}
	var operation adapter.RuntimeLease
	if borrowed, ok := adapter.RuntimeLeaseFromContext(ctx); ok {
		operation, err = borrowed.Fork()
		if err != nil { return }
		ctx = adapter.ContextWithRuntimeLease(ctx, operation)
	}
	// A core-owned packet carrier admits current DNS policy for every query,
	// even if its writer/port still belongs to a retained older flow. The old
	// operation reservation above remains through the actual response write.
	queryRouter := r.dns
	if ingress, ok := adapter.RuntimeDNSIngressFromContext(ctx); ok { queryRouter = ingress }
	answers:=&adapter.FakeIPAnswerBatch{}
	ctx=adapter.ContextWithFakeIPAnswerSink(ctx,answers)
	var completed sync.Once
	releaseOperation := func() { if operation != nil { completed.Do(operation.Release) } }
	defer func() { if recovered := recover(); recovered != nil { answers.Abort(); releaseOperation(); panic(recovered) } }()
	queryRouter.ExchangeAsync(adapter.WithContext(ctx, &metadata), &message, adapter.DNSQueryOptions{}, func(response *mDNS.Msg, exchangeErr error) {
		defer releaseOperation()
  defer answers.Abort()
		if exchangeErr == nil {
			exchangeErr = r.writeDNSPacketResponse(&message, response, writer, destination, answers)
		}
		if exchangeErr != nil && !R.IsRejected(exchangeErr) && !E.IsClosedOrCanceled(exchangeErr) {
			r.logger.ErrorContext(ctx, E.Cause(exchangeErr, "process DNS packet"))
		}
	})
}

func (r *Router) writeDNSPacketResponse(message *mDNS.Msg, response *mDNS.Msg, writer N.PacketWriter, destination M.Socksaddr, answers *adapter.FakeIPAnswerBatch) error {
	responseBuffer, err := dns.TruncateDNSMessage(message, response, N.CalculateFrontHeadroom(writer), N.CalculateRearHeadroom(writer))
	if err != nil {
		return err
	}
	defer func(){answers.Delivered(time.Now())}()
	return writer.WritePacket(responseBuffer, destination)
}
