package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/badhttp"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
	"golang.org/x/net/http2"
)

const MimeType = "application/dns-message"

var (
	_ adapter.DNSTransport         = (*HTTPSTransport)(nil)
	_ adapter.IdleConnectionKeeper = (*HTTPSTransport)(nil)
)

func RegisterHTTPS(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.RemoteHTTPSDNSServerOptions](registry, C.DNSTypeHTTPS, NewHTTPS)
}

type HTTPSTransport struct {
	dns.TransportAdapter
	logger            logger.ContextLogger
	dialer            N.Dialer
	destination       *url.URL
	headers           http.Header
	serverAddr        M.Socksaddr
	fallback          *atomic.Bool
	keepIdle          atomic.Bool
	transportAccess   sync.Mutex
	transport         *HTTPSTransportWrapper
	transportResetAt  time.Time
	runtimeResource   adapter.RuntimeResourceSource
	fence             *outbound.RuntimeIOFence
	closed            bool
	constructionOwned bool
	stopOnce          sync.Once
	transports        []*HTTPSTransportWrapper
	closeErr          error
}

func NewHTTPS(ctx context.Context, logger log.ContextLogger, tag string, options option.RemoteHTTPSDNSServerOptions) (adapter.DNSTransport, error) {
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
		tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
	}
	headers := options.Headers.Build()
	host := headers.Get("Host")
	if host != "" {
		headers.Del("Host")
	} else {
		if tlsConfig.ServerName() != "" {
			host = tlsConfig.ServerName()
		} else {
			host = options.Server
		}
	}
	destinationURL := url.URL{
		Scheme: "https",
		Host:   host,
	}
	if destinationURL.Host == "" {
		destinationURL.Host = options.Server
	}
	if options.ServerPort != 0 && options.ServerPort != 443 {
		destinationURL.Host = net.JoinHostPort(destinationURL.Host, strconv.Itoa(int(options.ServerPort)))
	}
	path := options.Path
	if path == "" {
		path = "/dns-query"
	}
	err = badhttp.URLSetPath(&destinationURL, path)
	if err != nil {
		return nil, err
	}
	serverAddr := options.DNSServerAddressOptions.Build()
	if serverAddr.Port == 0 {
		serverAddr.Port = 443
	}
	if !serverAddr.IsValid() {
		return nil, E.New("invalid server address: ", serverAddr)
	}
	result := newHTTPSRaw(ctx,
		dns.NewTransportAdapterWithRemoteOptions(C.DNSTypeHTTPS, tag, options.RemoteDNSServerOptions),
		logger,
		transportDialer,
		&destinationURL,
		headers,
		serverAddr,
		tlsConfig,
	)
	if adapter.HasConstructionScope(ctx) {
		result.constructionOwned = true
		if err = adapter.DeferConstructionCleanup(ctx, result.RuntimeCloseAndWait); err != nil {
			return nil, err
		}
	}
	if err = adapter.ConstructionScopeErr(ctx); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func NewHTTPSRaw(
	transportAdapter dns.TransportAdapter,
	logger log.ContextLogger,
	dialer N.Dialer,
	destination *url.URL,
	headers http.Header,
	serverAddr M.Socksaddr,
	tlsConfig tls.Config,
) *HTTPSTransport {
	return newHTTPSRaw(context.Background(), transportAdapter, logger, dialer, destination, headers, serverAddr, tlsConfig)
}

func newHTTPSRaw(ctx context.Context, transportAdapter dns.TransportAdapter, logger log.ContextLogger, dialer N.Dialer, destination *url.URL, headers http.Header, serverAddr M.Socksaddr, tlsConfig tls.Config) *HTTPSTransport {
	if tlsConfig != nil {
		dialer = tls.NewDialer(dialer, tlsConfig)
	}
	fallback := new(atomic.Bool)
	if destination.Scheme == "http" {
		// plain HTTP DoH used by Tailscale
		fallback.Store(true)
	}
	transport := &HTTPSTransport{
		TransportAdapter: transportAdapter,
		logger:           logger,
		dialer:           dialer,
		destination:      new(*destination),
		headers:          headers.Clone(),
		serverAddr:       serverAddr,
		fallback:         fallback,
		transport:        NewHTTPSTransportWrapper(dialer, serverAddr, fallback),
	}
	transport.runtimeResource, _ = adapter.RuntimeResourceSourceFromContext(ctx)
	transport.fence = outbound.NewRuntimeIOFence(transport.closeOwned)
	transport.transports = append(transport.transports, transport.transport)
	transport.keepIdle.Store(true)
	return transport
}

func (t *HTTPSTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if !t.constructionOwned {
		scope.Add(t.RuntimeCloseAndWait)
	}
	return dialer.InitializeDetour(t.dialer)
}

func (t *HTTPSTransport) Reset() { t.resetAfter(time.Time{}) }
func (t *HTTPSTransport) resetAfter(start time.Time) {
	leave, err := t.fence.Acquire()
	if err != nil {
		return
	}
	defer leave()
	t.transportAccess.Lock()
	if t.closed || (!start.IsZero() && t.transportResetAt.After(start)) {
		t.transportAccess.Unlock()
		return
	}
	old := t.transport
	t.transport = NewHTTPSTransportWrapper(t.dialer, t.serverAddr, t.fallback)
	t.transports = append(t.transports, t.transport)
	t.transportResetAt = time.Now()
	t.transportAccess.Unlock()
	t.recordClose(old.RuntimeCloseAndWait())
}

func (t *HTTPSTransport) SetKeepIdleConnections(keep bool) {
	t.keepIdle.Store(keep)
	if !keep {
		t.CloseIdleConnections()
	}
}

func (t *HTTPSTransport) CloseIdleConnections() {
	leave, err := t.fence.Acquire()
	if err != nil {
		return
	}
	defer leave()
	t.transportAccess.Lock()
	current := t.transport
	t.transportAccess.Unlock()
	current.CloseIdleConnections()
}

func (t *HTTPSTransport) begin(ctx context.Context) (context.Context, func(), error) {
	ctx, release, err := adapter.AcquireRuntimeOperation(ctx, t.runtimeResource)
	if err != nil {
		return nil, nil, err
	}
	leave, err := t.fence.Acquire()
	if err != nil {
		release()
		return nil, nil, err
	}
	if t.runtimeResource != nil {
		ctx, err = outbound.ContextForRuntimeOwnedSession(ctx, t.runtimeResource)
		if err != nil {
			leave()
			release()
			return nil, nil, err
		}
	}
	return ctx, func() { leave(); release() }, nil
}

func (t *HTTPSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	ctx, release, err := t.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return t.exchangeOwned(ctx, message)
}

func (t *HTTPSTransport) exchangeOwned(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	start := time.Now()
	response, err := t.exchange(ctx, message)
	if !t.keepIdle.Load() {
		t.CloseIdleConnections()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.resetAfter(start)
	}
	return response, err
}

func (t *HTTPSTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	ctx, release, err := t.begin(ctx)
	if err != nil {
		callback(nil, err)
		return
	}
	// Admission and inherited continuations are retained before dispatch, and
	// released only after the callback tail, including a losing DNS race.
	go func() { defer release(); callback(t.exchangeOwned(ctx, message)) }()
}

func (t *HTTPSTransport) recordClose(err error) {
	if err != nil {
		t.transportAccess.Lock()
		t.closeErr = errors.Join(t.closeErr, err)
		t.transportAccess.Unlock()
	}
}

func (t *HTTPSTransport) closeOwned() error {
	t.transportAccess.Lock()
	t.closed = true
	all := append([]*HTTPSTransportWrapper(nil), t.transports...)
	t.transportAccess.Unlock()
	for _, current := range all {
		current.boundary.StopRuntimeOperations()
	}
	for _, current := range all {
		t.recordClose(current.RuntimeCloseAndWait())
	}
	return nil
}

func (t *HTTPSTransport) RuntimeCloseAndWait() error {
	err := t.fence.RuntimeCloseAndWait()
	t.transportAccess.Lock()
	defer t.transportAccess.Unlock()
	if t.closeErr != nil {
		return E.New("DNS HTTPS cleanup incomplete: ", errors.Join(err, t.closeErr))
	}
	return err
}

func (t *HTTPSTransport) exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	exMessage := *message
	exMessage.Id = 0
	exMessage.Compress = true
	// Request bytes may be consumed by a transport worker after RoundTrip
	// returns. Keep them Go-owned until the request boundary joins its body.
	rawMessage, err := exMessage.Pack()
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, t.destination.String(), bytes.NewReader(rawMessage))
	if err != nil {
		return nil, err
	}
	request.Header = t.headers.Clone()
	request.Header.Set("Content-Type", MimeType)
	request.Header.Set("Accept", MimeType)
	t.transportAccess.Lock()
	currentTransport := t.transport
	t.transportAccess.Unlock()
	response, err := currentTransport.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, E.New("unexpected status: ", response.Status)
	}
	var responseMessage mDNS.Msg
	if response.ContentLength > 0 {
		responseBuffer := buf.NewSize(int(response.ContentLength))
		defer responseBuffer.Release()
		_, err = responseBuffer.ReadFullFrom(response.Body, int(response.ContentLength))
		if err != nil {
			return nil, err
		}
		err = responseMessage.Unpack(responseBuffer.Bytes())
	} else {
		rawMessage, err = io.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
		err = responseMessage.Unpack(rawMessage)
	}
	if err != nil {
		return nil, err
	}
	return &responseMessage, nil
}

func (t *HTTPSTransport) StopRuntimeOperations() {
	t.stopOnce.Do(func() { go func() { _ = t.fence.Close() }() })
}
