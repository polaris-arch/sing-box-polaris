package transport

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

var (
	_ adapter.DNSTransport         = (*TCPTransport)(nil)
	_ adapter.IdleConnectionKeeper = (*TCPTransport)(nil)
)

func RegisterTCP(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.RemoteDNSServerOptions](registry, C.DNSTypeTCP, NewTCP)
}

type TCPTransport struct {
	dns.TransportAdapter
	dialer            N.Dialer
	serverAddr        M.Socksaddr
	multiplexer       *queryMultiplexer
	runtimeResource   adapter.RuntimeResourceSource
	constructionOwned bool
}

func NewTCP(ctx context.Context, logger log.ContextLogger, tag string, options option.RemoteDNSServerOptions) (adapter.DNSTransport, error) {
	transportDialer, err := dns.NewRemoteDialer(ctx, options)
	if err != nil {
		return nil, err
	}
	serverAddr := options.DNSServerAddressOptions.Build()
	if serverAddr.Port == 0 {
		serverAddr.Port = 53
	}
	if !serverAddr.IsValid() {
		return nil, E.New("invalid server address: ", serverAddr)
	}
	transport := newTCPRaw(ctx, dns.NewTransportAdapterWithRemoteOptions(C.DNSTypeTCP, tag, options), transportDialer, serverAddr)
	if transport.runtimeResource != nil {
		if err := adapter.DeferConstructionCleanup(ctx, transport.multiplexer.Close); err != nil {
			return nil, err
		}
		transport.constructionOwned = true
		transport.multiplexer.queryAccess.Lock()
		stopped := transport.multiplexer.workSealed
		transport.multiplexer.queryAccess.Unlock()
		if stopped {
			return nil, net.ErrClosed
		}
	}
	return transport, nil
}

func NewTCPRaw(transportAdapter dns.TransportAdapter, dialer N.Dialer, serverAddr M.Socksaddr) *TCPTransport {
	return newTCPRaw(context.Background(), transportAdapter, dialer, serverAddr)
}

func newTCPRaw(ctx context.Context, transportAdapter dns.TransportAdapter, dialer N.Dialer, serverAddr M.Socksaddr) *TCPTransport {
	runtimeResource, _ := adapter.RuntimeResourceSourceFromContext(ctx)
	t := &TCPTransport{
		runtimeResource:  runtimeResource,
		TransportAdapter: transportAdapter,
		dialer:           dialer,
		serverAddr:       serverAddr,
	}
	t.multiplexer = newQueryMultiplexer(queryMultiplexerOptions{
		context: ctx,
		dial: func(ctx context.Context) (net.Conn, error) {
			conn, err := t.dialer.DialContext(ctx, N.NetworkTCP, t.serverAddr)
			if err != nil {
				return nil, E.Cause(err, "dial TCP connection")
			}
			return conn, nil
		},
		write: func(conn net.Conn, message *mDNS.Msg, queryId uint16) error {
			return WriteMessage(conn, queryId, message)
		},
		readNext: func(conn net.Conn) (*mDNS.Msg, error) {
			return ReadMessage(conn)
		},
		retryReadError: true,
		probeReuse:     true,
	})
	return t
}

func (t *TCPTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if !t.constructionOwned {
		scope.Add(t.multiplexer.Close)
	}
	return dialer.InitializeDetour(t.dialer)
}

func (t *TCPTransport) Reset() {
	t.multiplexer.Reset()
}

func (t *TCPTransport) SetKeepIdleConnections(keep bool) {
	t.multiplexer.SetKeepIdleConnections(keep)
}

func (t *TCPTransport) CloseIdleConnections() {
	t.multiplexer.CloseIdleConnections()
}

func (t *TCPTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	ctx, releaseRuntime, runtimeErr := adapter.AcquireRuntimeOperation(ctx, t.runtimeResource)
	if runtimeErr != nil {
		return nil, runtimeErr
	}
	defer releaseRuntime()
	return t.multiplexer.Exchange(ctx, message)
}

func (t *TCPTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	ctx, releaseCall, runtimeErr := adapter.AcquireRuntimeOperation(ctx, t.runtimeResource)
	if runtimeErr != nil {
		callback(nil, runtimeErr)
		return
	}
	defer releaseCall()
	ctx, releaseCallback, runtimeErr := adapter.AcquireRuntimeOperation(ctx, t.runtimeResource)
	if runtimeErr != nil {
		callback(nil, runtimeErr)
		return
	}
	originalCallback := callback
	callback = func(response *mDNS.Msg, err error) { defer releaseCallback(); originalCallback(response, err) }

	t.multiplexer.ExchangeAsync(ctx, message, callback)
}

func setConnDeadline(ctx context.Context, conn net.Conn, needClose bool) func() {
	if needClose {
		stop := afterFuncJoined(ctx, func() {
			conn.Close()
		})
		return func() { stop() }
	}
	if d, ok := ctx.Deadline(); ok {
		conn.SetDeadline(d)
		return func() { conn.SetDeadline(time.Time{}) }
	}
	return func() {}
}

func ReadMessage(reader io.Reader) (*mDNS.Msg, error) {
	var responseLen uint16
	err := binary.Read(reader, binary.BigEndian, &responseLen)
	if err != nil {
		return nil, err
	}
	if responseLen < 10 {
		return nil, mDNS.ErrShortRead
	}
	buffer := buf.NewSize(int(responseLen))
	defer buffer.Release()
	_, err = buffer.ReadFullFrom(reader, int(responseLen))
	if err != nil {
		return nil, err
	}
	var message mDNS.Msg
	err = message.Unpack(buffer.Bytes())
	return &message, err
}

func WriteMessage(writer io.Writer, messageId uint16, message *mDNS.Msg) error {
	requestLen := message.Len()
	buffer := buf.NewSize(3 + requestLen)
	defer buffer.Release()
	common.Must(binary.Write(buffer, binary.BigEndian, uint16(requestLen)))
	exMessage := *message
	exMessage.Id = messageId
	exMessage.Compress = true
	rawMessage, err := exMessage.PackBuffer(buffer.FreeBytes())
	if err != nil {
		return err
	}
	buffer.Truncate(2 + len(rawMessage))
	return common.Error(writer.Write(buffer.Bytes()))
}

// Ordinary retirement stops optional producers while admitted exchanges remain.
func (t *TCPTransport) StopRuntimeProducers() { t.multiplexer.StopProbes() }

// Final stop may cancel sockets before external users drain. This never joins
// the calling callback; the resource cleanup's Close performs the actual join.
func (t *TCPTransport) StopRuntimeOperations() { t.multiplexer.Stop() }
