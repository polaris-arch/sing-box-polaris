package dns

import (
	"context"
	"encoding/binary"
	"net"
	"io"
	"sync"
 "time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/task"

	mDNS "github.com/miekg/dns"
)

// NewDNSStreamConn serializes complete framed responses, including pipelined
// asynchronous replies. Query ownership is retained by the callback until the
// entire Write returns. Close unblocks writers through the underlying socket.
func NewDNSStreamConn(conn net.Conn) net.Conn {
	if _, ok := conn.(*dnsStreamConn); ok { return conn }
	return &dnsStreamConn{Conn: conn}
}
type dnsStreamConn struct { net.Conn; writeAccess sync.Mutex }
func (c *dnsStreamConn) Write(p []byte) (int, error) {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	total := 0
	for len(p) > 0 {
		n, err := c.Conn.Write(p)
		total += n
		p = p[n:]
		if err != nil { return total, err }
		if n == 0 { return total, io.ErrNoProgress }
	}
	return total, nil
}

func queryRouter(ctx context.Context, fallback adapter.DNSRouter) adapter.DNSRouter {
	if ingress, ok := adapter.RuntimeDNSIngressFromContext(ctx); ok { return ingress }
	return fallback
}

func HandleStreamDNSRequest(ctx context.Context, router adapter.DNSRouter, conn net.Conn, metadata adapter.InboundContext) error {
	var queryLength uint16
	err := binary.Read(conn, binary.BigEndian, &queryLength)
	if err != nil {
		return err
	}
	if queryLength == 0 {
		return dns.RcodeFormatError
	}
	buffer := buf.NewSize(int(queryLength))
	defer buffer.Release()
	_, err = buffer.ReadFullFrom(conn, int(queryLength))
	if err != nil {
		return err
	}
	var message mDNS.Msg
	err = message.Unpack(buffer.Bytes())
	if err != nil {
		return err
	}
	metadataInQuery := metadata
 answers:=&adapter.FakeIPAnswerBatch{}
 queryContext:=adapter.ContextWithFakeIPAnswerSink(ctx,answers)
	exchangeDNSAnswer(adapter.WithContext(queryContext, &metadataInQuery), router, &message, adapter.DNSQueryOptions{}, answers, func(response *mDNS.Msg, err error) {
  defer answers.Abort()
		if err != nil {
			conn.Close()
			return
		}
		writeStreamResponse(conn, response, answers)
	})
	return nil
}

func writeStreamResponse(conn net.Conn, response *mDNS.Msg, answers *adapter.FakeIPAnswerBatch) {
	responseLength := response.Len()
	responseBuffer := buf.NewSize(3 + responseLength)
	defer responseBuffer.Release()
	responseBuffer.Resize(2, 0)
	n, err := response.PackBuffer(responseBuffer.FreeBytes())
	if err != nil {
		return
	}
	responseBuffer.Truncate(len(n))
	binary.BigEndian.PutUint16(responseBuffer.ExtendHeader(2), uint16(len(n)))
	// Once Write is entered, a partial error or panic may have issued bytes.
 defer func(){answers.Delivered(time.Now())}()
	conn.Write(responseBuffer.Bytes())
}

func NewDNSPacketConnection(ctx context.Context, router adapter.DNSRouter, conn N.PacketConn, cachedPackets []*N.PacketBuffer, metadata adapter.InboundContext) error {
	metadata.Destination = M.Socksaddr{}
	frontHeadroom := N.CalculateFrontHeadroom(conn)
	rearHeadroom := N.CalculateRearHeadroom(conn)
	var reader N.PacketReader = conn
	var counters []N.CountFunc
	cachedPackets = common.Reverse(cachedPackets)
	for {
		reader, counters = N.UnwrapCountPacketReader(reader, counters)
		if cachedReader, isCached := reader.(N.CachedPacketReader); isCached {
			packet := cachedReader.ReadCachedPacket()
			if packet != nil {
				cachedPackets = append(cachedPackets, packet)
				continue
			}
		}
		if readWaiter, created := bufio.CreatePacketReadWaiter(reader); created {
			readWaiter.InitializeReadWaiter(N.ReadWaitOptions{})
			return newDNSPacketConnection(ctx, router, conn, readWaiter, counters, cachedPackets, metadata)
		}
		break
	}
	fastClose, cancel := context.WithCancelCause(ctx)
	timeout := canceler.New(fastClose, cancel, C.DNSTimeout)
	var group task.Group
	group.Append0(func(_ context.Context) error {
		for {
			var message mDNS.Msg
			var destination M.Socksaddr
			var err error
			if len(cachedPackets) > 0 {
				packet := cachedPackets[0]
				cachedPackets = cachedPackets[1:]
				for _, counter := range counters {
					counter(int64(packet.Buffer.Len()))
				}
				err = message.Unpack(packet.Buffer.Bytes())
				packet.Buffer.Release()
				if err != nil {
					cancel(err)
					return err
				}
				destination = packet.Destination
			} else {
				buffer := buf.NewPacket()
				destination, err = conn.ReadPacket(buffer)
				if err != nil {
					buffer.Release()
					cancel(err)
					return err
				}
				for _, counter := range counters {
					counter(int64(buffer.Len()))
				}
				err = message.Unpack(buffer.Bytes())
				buffer.Release()
				if err != nil {
					cancel(err)
					return err
				}
				timeout.Update()
			}
			metadataInQuery := metadata
   answers:=&adapter.FakeIPAnswerBatch{}
   queryContext:=adapter.ContextWithFakeIPAnswerSink(ctx,answers)
			exchangeDNSAnswer(adapter.WithContext(queryContext, &metadataInQuery), router, &message, adapter.DNSQueryOptions{}, answers, func(response *mDNS.Msg, err error) {
    defer answers.Abort()
				if err != nil {
					cancel(err)
					return
				}
				timeout.Update()
				responseBuffer, truncateErr := dns.TruncateDNSMessage(&message, response, frontHeadroom, rearHeadroom)
				if truncateErr != nil {
					cancel(truncateErr)
					return
				}
    defer func(){answers.Delivered(time.Now())}()
				writeErr := conn.WritePacket(responseBuffer, destination)
				if writeErr != nil {
					cancel(writeErr)
				}
			})
		}
	})
	group.Cleanup(func() {
		conn.Close()
	})
	return group.Run(fastClose)
}

func newDNSPacketConnection(ctx context.Context, router adapter.DNSRouter, conn N.PacketConn, readWaiter N.PacketReadWaiter, readCounters []N.CountFunc, cached []*N.PacketBuffer, metadata adapter.InboundContext) error {
	frontHeadroom := N.CalculateFrontHeadroom(conn)
	rearHeadroom := N.CalculateRearHeadroom(conn)
	fastClose, cancel := context.WithCancelCause(ctx)
	timeout := canceler.New(fastClose, cancel, C.DNSTimeout)
	var group task.Group
	group.Append0(func(_ context.Context) error {
		for {
			var (
				message     mDNS.Msg
				destination M.Socksaddr
				err         error
				buffer      *buf.Buffer
			)
			if len(cached) > 0 {
				packet := cached[0]
				cached = cached[1:]
				for _, counter := range readCounters {
					counter(int64(packet.Buffer.Len()))
				}
				err = message.Unpack(packet.Buffer.Bytes())
				packet.Buffer.Release()
				destination = packet.Destination
				N.PutPacketBuffer(packet)
				if err != nil {
					cancel(err)
					return err
				}
			} else {
				buffer, destination, err = readWaiter.WaitReadPacket()
				if err != nil {
					cancel(err)
					return err
				}
				for _, counter := range readCounters {
					counter(int64(buffer.Len()))
				}
				err = message.Unpack(buffer.Bytes())
				buffer.Release()
				if err != nil {
					cancel(err)
					return err
				}
				timeout.Update()
			}
			metadataInQuery := metadata
   answers:=&adapter.FakeIPAnswerBatch{}
   queryContext:=adapter.ContextWithFakeIPAnswerSink(ctx,answers)
			exchangeDNSAnswer(adapter.WithContext(queryContext, &metadataInQuery), router, &message, adapter.DNSQueryOptions{}, answers, func(response *mDNS.Msg, err error) {
    defer answers.Abort()
				if err != nil {
					cancel(err)
					return
				}
				timeout.Update()
				responseBuffer, truncateErr := dns.TruncateDNSMessage(&message, response, frontHeadroom, rearHeadroom)
				if truncateErr != nil {
					cancel(truncateErr)
					return
				}
    defer func(){answers.Delivered(time.Now())}()
				writeErr := conn.WritePacket(responseBuffer, destination)
				if writeErr != nil {
					cancel(writeErr)
				}
			})
		}
	})
	group.Cleanup(func() {
		conn.Close()
	})
	return group.Run(fastClose)
}

// A dispatch panic is a definitely-undelivered exit unless the callback already
// entered its writer (whose terminal Delivered call wins over Abort).
func exchangeDNSAnswer(ctx context.Context,router adapter.DNSRouter,message *mDNS.Msg,options adapter.DNSQueryOptions,answers *adapter.FakeIPAnswerBatch,callback func(*mDNS.Msg,error)){
 defer func(){if recovered:=recover();recovered!=nil{answers.Abort();panic(recovered)}}()
 queryRouter(ctx,router).ExchangeAsync(ctx,message,options,callback)
}
