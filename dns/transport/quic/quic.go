package quic

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

var _ adapter.DNSTransport = (*Transport)(nil)

func RegisterTransport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.RemoteTLSDNSServerOptions](registry, C.DNSTypeQUIC, NewQUIC)
}

type Transport struct {
	dns.TransportAdapter

	dialer     N.Dialer
	serverAddr M.Socksaddr
	tlsConfig  tls.Config

	connection        *transport.ConnPool[*httpclient.RuntimeQUICSession]
	runtimeResource   adapter.RuntimeResourceSource
	fence             *outbound.RuntimeIOFence
	constructionOwned bool
	stopOnce          sync.Once
	closeAccess       sync.Mutex
	closeErr          error
}

func NewQUIC(ctx context.Context, logger log.ContextLogger, tag string, options option.RemoteTLSDNSServerOptions) (adapter.DNSTransport, error) {
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
	if len(tlsConfig.NextProtos()) == 0 {
		tlsConfig.SetNextProtos([]string{"doq"})
	}
	serverAddr := options.DNSServerAddressOptions.Build()
	if serverAddr.Port == 0 {
		serverAddr.Port = 853
	}
	if !serverAddr.IsValid() {
		return nil, E.New("invalid server address: ", serverAddr)
	}

	t := &Transport{
		TransportAdapter: dns.NewTransportAdapterWithRemoteOptions(C.DNSTypeQUIC, tag, options.RemoteDNSServerOptions),
		dialer:           transportDialer, serverAddr: serverAddr, tlsConfig: tlsConfig,
	}
	t.runtimeResource, _ = adapter.RuntimeResourceSourceFromContext(ctx)
	t.connection = transport.NewConnPool(transport.ConnPoolOptions[*httpclient.RuntimeQUICSession]{
		Mode: transport.ConnPoolSingle,
		IsAlive: func(session *httpclient.RuntimeQUICSession) bool {
			return session != nil && !common.Done(session.Conn.Context())
		},
		Close: func(session *httpclient.RuntimeQUICSession, _ error) { t.recordClose(session.RuntimeCloseAndWait()) },
	})
	t.fence = outbound.NewRuntimeIOFence(t.connection.Close)
	if adapter.HasConstructionScope(ctx) {
		t.constructionOwned = true
		if err = adapter.DeferConstructionCleanup(ctx, t.RuntimeCloseAndWait); err != nil {
			return nil, err
		}
	}
	if err = adapter.ConstructionScopeErr(ctx); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Transport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if !t.constructionOwned {
		scope.Add(t.RuntimeCloseAndWait)
	}
	return dialer.InitializeDetour(t.dialer)
}

func (t *Transport) Reset() {
	leave, err := t.fence.Acquire()
	if err != nil {
		return
	}
	defer leave()
	t.connection.Reset()
}

func (t *Transport) begin(ctx context.Context) (context.Context, func(), error) {
	ctx, release, err := adapter.AcquireRuntimeOperation(ctx, t.runtimeResource)
	if err != nil {
		return nil, nil, err
	}
	leave, err := t.fence.Acquire()
	if err != nil {
		release()
		return nil, nil, err
	}
	return ctx, func() { leave(); release() }, nil
}

func (t *Transport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	ctx, release, err := t.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return t.exchangeOwned(ctx, message)
}

func (t *Transport) exchangeOwned(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	var (
		conn     *httpclient.RuntimeQUICSession
		err      error
		response *mDNS.Msg
	)
	for range 2 {
		conn, _, err = t.connection.Acquire(ctx, func(ctx context.Context) (*httpclient.RuntimeQUICSession, error) {
			// ConnPool retains its creation reservation until installation or
			// late-result close. Only this interval borrows the exact owner.
			if t.runtimeResource != nil {
				var err error
				ctx, err = outbound.ContextForRuntimeOwnedSession(ctx, t.runtimeResource)
				if err != nil {
					return nil, err
				}
			}
			config, err := t.tlsConfig.STDConfig()
			if err != nil {
				return nil, err
			}
			raw, err := t.dialer.DialContext(ctx, N.NetworkUDP, t.serverAddr)
			if err != nil {
				return nil, E.Cause(err, "dial UDP connection")
			}
			return httpclient.DialRuntimeQUIC(ctx, raw, config, nil, t.recordClose)
		})
		if err != nil {
			return nil, err
		}
		response, err = t.exchange(ctx, message, conn.Conn)
		if err == nil {
			t.connection.Release(conn, true)
			return response, nil
		} else if !isQUICRetryError(err) {
			t.connection.Release(conn, true)
			return nil, err
		} else {
			t.connection.Release(conn, true)
			t.Reset()
			continue
		}
	}
	return nil, err
}

func (t *Transport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	ctx, release, err := t.begin(ctx)
	if err != nil {
		callback(nil, err)
		return
	}
	go func() { defer release(); callback(t.exchangeOwned(ctx, message)) }()
}

func (t *Transport) recordClose(err error) {
	if err != nil {
		t.closeAccess.Lock()
		t.closeErr = errors.Join(t.closeErr, err)
		t.closeAccess.Unlock()
	}
}

func (t *Transport) RuntimeCloseAndWait() error {
	err := t.fence.RuntimeCloseAndWait()
	t.closeAccess.Lock()
	defer t.closeAccess.Unlock()
	if t.closeErr != nil {
		return E.New("DNS QUIC cleanup incomplete: ", errors.Join(err, t.closeErr))
	}
	return err
}

func (t *Transport) exchange(ctx context.Context, message *mDNS.Msg, conn *quic.Conn) (*mDNS.Msg, error) {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, E.Cause(err, "open stream")
	}
	defer stream.CancelRead(0)
	watchDone := make(chan struct{})
	stopWatch := context.AfterFunc(ctx, func() {
		defer close(watchDone)
		stream.CancelRead(0)
		_ = stream.SetWriteDeadline(time.Now())
	})
	defer func() {
		if !stopWatch() {
			<-watchDone
		}
	}()
	err = transport.WriteMessage(stream, 0, message)
	if err != nil {
		stream.Close()
		return nil, E.Cause(err, "write request")
	}
	stream.Close()
	response, err := transport.ReadMessage(stream)
	if err != nil {
		return nil, E.Cause(err, "read response")
	}
	return response, nil
}

// https://github.com/AdguardTeam/dnsproxy/blob/fd1868577652c639cce3da00e12ca548f421baf1/upstream/upstream_quic.go#L394
func isQUICRetryError(err error) (ok bool) {
	if errors.Is(err, os.ErrClosed) {
		return true
	}

	var qAppErr *quic.ApplicationError
	if errors.As(err, &qAppErr) && qAppErr.ErrorCode == 0 {
		return true
	}

	if _, ok := errors.AsType[*quic.IdleTimeoutError](err); ok {
		return true
	}

	if _, ok := errors.AsType[*quic.StatelessResetError](err); ok {
		return true
	}

	var qTransportError *quic.TransportError
	if errors.As(err, &qTransportError) && qTransportError.ErrorCode == quic.NoError {
		return true
	}

	if errors.Is(err, quic.Err0RTTRejected) {
		return true
	}

	return false
}

func (t *Transport) StopRuntimeOperations() {
	t.stopOnce.Do(func() { go func() { _ = t.fence.Close() }() })
}
