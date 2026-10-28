package transport

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

var (
	_ adapter.DNSTransport         = (*TLSTransport)(nil)
	_ adapter.IdleConnectionKeeper = (*TLSTransport)(nil)
)

func RegisterTLS(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.RemoteTLSDNSServerOptions](registry, C.DNSTypeTLS, NewTLS)
}

type TLSTransport struct {
	dns.TransportAdapter
	logger            logger.ContextLogger
	dialer            tls.Dialer
	serverAddr        M.Socksaddr
	multiplexer       *queryMultiplexer
	runtimeResource   adapter.RuntimeResourceSource
	constructionOwned bool
	closeAccess       sync.Mutex
	closeErr          error
}

func NewTLS(ctx context.Context, logger log.ContextLogger, tag string, options option.RemoteTLSDNSServerOptions) (adapter.DNSTransport, error) {
	transportDialer, err := dns.NewRemoteDialer(ctx, options.RemoteDNSServerOptions)
	if err != nil {
		return nil, err
	}
	tlsOptions := common.PtrValueOrDefault(options.TLS)
	tlsOptions.Enabled = true
	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, tlsOptions)
	if err != nil {
		return nil, err
	}
	serverAddr := options.DNSServerAddressOptions.Build()
	if serverAddr.Port == 0 {
		serverAddr.Port = 853
	}
	if !serverAddr.IsValid() {
		return nil, E.New("invalid server address: ", serverAddr)
	}
	t := newTLSRaw(ctx, logger, dns.NewTransportAdapterWithRemoteOptions(C.DNSTypeTLS, tag, options.RemoteDNSServerOptions), transportDialer, serverAddr, tlsConfig)
	if adapter.HasConstructionScope(ctx) {
		t.constructionOwned = true
		if err := adapter.DeferConstructionCleanup(ctx, t.RuntimeCloseAndWait); err != nil {
			return nil, err
		}
		if err := adapter.ConstructionScopeErr(ctx); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return t, nil
}

func NewTLSRaw(logger logger.ContextLogger, transportAdapter dns.TransportAdapter, dialer N.Dialer, serverAddr M.Socksaddr, tlsConfig tls.Config) *TLSTransport {
	return newTLSRaw(context.Background(), logger, transportAdapter, dialer, serverAddr, tlsConfig)
}

func newTLSRaw(ctx context.Context, logger logger.ContextLogger, transportAdapter dns.TransportAdapter, dialer N.Dialer, serverAddr M.Socksaddr, tlsConfig tls.Config) *TLSTransport {
	source, _ := adapter.RuntimeResourceSourceFromContext(ctx)
	t := &TLSTransport{
		TransportAdapter: transportAdapter,
		runtimeResource:  source,
		logger:           logger,
		dialer:           tls.NewDialer(dialer, tlsConfig),
		serverAddr:       serverAddr,
	}
	t.multiplexer = newQueryMultiplexer(queryMultiplexerOptions{
		context: ctx,
		dial: func(ctx context.Context) (net.Conn, error) {
			if t.runtimeResource != nil {
				var err error
				ctx, err = outbound.ContextForRuntimeOwnedSession(ctx, t.runtimeResource)
				if err != nil {
					return nil, err
				}
			}
			conn, err := t.dialer.DialTLSContext(ctx, t.serverAddr)
			if err != nil {
				if tls.IsRuntimeCleanupIncomplete(err) {
					t.closeAccess.Lock()
					t.closeErr = errors.Join(t.closeErr, err)
					t.closeAccess.Unlock()
				}
				return nil, E.Cause(err, "dial TLS connection")
			}
			return &tlsRuntimeCloseRecorder{Conn: conn, owner: t}, nil
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

func (t *TLSTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if !t.constructionOwned {
		scope.Add(t.RuntimeCloseAndWait)
	}
	return dialer.InitializeDetour(t.dialer)
}

func (t *TLSTransport) Reset() {
	t.multiplexer.Reset()
}

func (t *TLSTransport) SetKeepIdleConnections(keep bool) {
	t.multiplexer.SetKeepIdleConnections(keep)
}

func (t *TLSTransport) CloseIdleConnections() {
	t.multiplexer.CloseIdleConnections()
}

func (t *TLSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	ctx, release, err := adapter.AcquireRuntimeOperation(ctx, t.runtimeResource)
	if err != nil {
		return nil, err
	}
	defer release()
	return t.multiplexer.Exchange(ctx, message)
}

func (t *TLSTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	ctx, release, err := adapter.AcquireRuntimeOperation(ctx, t.runtimeResource)
	if err != nil {
		callback(nil, err)
		return
	}
	defer release()
	ctx, releaseCallback, err := adapter.AcquireRuntimeOperation(ctx, t.runtimeResource)
	if err != nil {
		callback(nil, err)
		return
	}
	t.multiplexer.ExchangeAsync(ctx, message, func(response *mDNS.Msg, err error) { defer releaseCallback(); callback(response, err) })
}

func (t *TLSTransport) StopRuntimeProducers()  { t.multiplexer.StopProbes() }
func (t *TLSTransport) StopRuntimeOperations() { t.multiplexer.Stop() }
func (t *TLSTransport) RuntimeCloseAndWait() error {
	err := t.multiplexer.Close()
	t.closeAccess.Lock()
	defer t.closeAccess.Unlock()
	if t.closeErr != nil {
		return E.New("DNS TLS cleanup incomplete: ", errors.Join(err, t.closeErr))
	}
	return err
}

// ConnPool's historical close callback is void. Record the real socket/TLS
// result on this receiving transport before the multiplexer discards it.
type tlsRuntimeCloseRecorder struct {
	net.Conn
	owner *TLSTransport
}

func (c *tlsRuntimeCloseRecorder) Close() (err error) {
	defer func() {
		if value := recover(); value != nil {
			err = E.New("DNS TLS close panic: ", value)
		}
		if err != nil {
			c.owner.closeAccess.Lock()
			c.owner.closeErr = errors.Join(c.owner.closeErr, err)
			c.owner.closeAccess.Unlock()
		}
	}()
	return c.Conn.Close()
}
