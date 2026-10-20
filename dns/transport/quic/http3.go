package quic

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

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/badhttp"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

var _ adapter.DNSTransport = (*HTTP3Transport)(nil)

func RegisterHTTP3Transport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.RemoteHTTPSDNSServerOptions](registry, C.DNSTypeHTTP3, NewHTTP3)
}

type HTTP3Transport struct {
	dns.TransportAdapter
	logger          logger.ContextLogger
	dialer          N.Dialer
	destination     *url.URL
	headers         http.Header
	serverAddr      M.Socksaddr
	tlsConfig       *tls.STDConfig
	transportAccess sync.Mutex
	transport       *dnsHTTP3Epoch
	transports []*dnsHTTP3Epoch
	runtimeResource adapter.RuntimeResourceSource
	fence *outbound.RuntimeIOFence
	constructionOwned bool
	stopOnce sync.Once
	closed bool
	keepIdle bool // guarded by transportAccess; defaults to true in NewHTTP3
	closeErr error
}

func NewHTTP3(ctx context.Context, logger log.ContextLogger, tag string, options option.RemoteHTTPSDNSServerOptions) (adapter.DNSTransport, error) {
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
	stdConfig, err := tlsConfig.STDConfig()
	if err != nil {
		return nil, err
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
	t := &HTTP3Transport{
		TransportAdapter: dns.NewTransportAdapterWithRemoteOptions(C.DNSTypeHTTP3, tag, options.RemoteDNSServerOptions),
		logger:           logger,
		dialer:           transportDialer,
		destination:      &destinationURL,
		headers:          headers,
		serverAddr:       serverAddr,
		tlsConfig:        stdConfig,
		keepIdle:         true,
	}
	t.runtimeResource,_=adapter.RuntimeResourceSourceFromContext(ctx)
	t.fence=outbound.NewRuntimeIOFence(t.closeOwned)
	t.transport = t.newTransport()
	t.transports=append(t.transports,t.transport)
	if adapter.HasConstructionScope(ctx){t.constructionOwned=true;if err=adapter.DeferConstructionCleanup(ctx,t.RuntimeCloseAndWait);err!=nil{return nil,err}}
	if err=adapter.ConstructionScopeErr(ctx);err!=nil{return nil,err};if err=ctx.Err();err!=nil{return nil,err}
	return t,nil
}

type dnsHTTP3RoundTripper interface {
	http.RoundTripper
	Close() error
}

type dnsHTTP3Epoch struct {
	transport dnsHTTP3RoundTripper
	boundary  *httpclient.RuntimeTransportBoundary
	// Count a complete DNS exchange, including response-body reads and close.
	// Both fields are guarded by the enclosing transportAccess mutex.
	active  int
	retired bool
}
func(e *dnsHTTP3Epoch)RoundTrip(r *http.Request)(*http.Response,error){return e.boundary.RoundTrip(r,e.transport.RoundTrip)}
func(e *dnsHTTP3Epoch)RuntimeCloseAndWait()error{return e.boundary.RuntimeCloseAndWait()}
func(t *HTTP3Transport)newTransport()*dnsHTTP3Epoch{
	inner:=&http3.Transport{TLSClientConfig:t.tlsConfig.Clone()}
	e:=&dnsHTTP3Epoch{transport:inner}
	e.boundary=httpclient.NewRuntimeTransportBoundary(inner.Close)
	inner.Dial=func(ctx context.Context,_ string,config *tls.STDConfig,quicConfig *quic.Config)(*quic.Conn,error){
		ctx,leave,err:=e.boundary.BeginDial(ctx);if err!=nil{return nil,err};defer leave()
		if t.runtimeResource!=nil{ctx,err=outbound.ContextForRuntimeOwnedSession(ctx,t.runtimeResource);if err!=nil{return nil,err}}
		raw,err:=t.dialer.DialContext(ctx,N.NetworkUDP,t.serverAddr);if err!=nil{return nil,err}
		session,err:=httpclient.DialRuntimeQUIC(ctx,raw,config,quicConfig,e.boundary.RecordClose);if err!=nil{return nil,err}
		if err=e.boundary.RegisterResource(session);err!=nil{return nil,err};return session.Conn,nil
	}
	return e
}
func(t *HTTP3Transport)Start(stage adapter.StartStage,scope *adapter.Scope)error{
	if stage!=adapter.StartStateStart{return nil};if !t.constructionOwned{scope.Add(t.RuntimeCloseAndWait)};return dialer.InitializeDetour(t.dialer)
}
func (t *HTTP3Transport) Reset() {
	leave, err := t.fence.Acquire()
	if err != nil {
		return
	}
	defer leave()
	t.transportAccess.Lock()
	if t.closed {
		t.transportAccess.Unlock()
		return
	}
	old := t.transport
	if old != nil {
		old.retired = true
	}
	t.transport = t.newTransport()
	t.transports = append(t.transports, t.transport)
	t.transportAccess.Unlock()
	if old != nil {
		t.recordClose(old.RuntimeCloseAndWait())
	}
}
func(t *HTTP3Transport)begin(ctx context.Context)(context.Context,func(),error){
	ctx,release,err:=adapter.AcquireRuntimeOperation(ctx,t.runtimeResource);if err!=nil{return nil,nil,err}
	leave,err:=t.fence.Acquire();if err!=nil{release();return nil,nil,err};return ctx,func(){leave();release()},nil
}
func(t *HTTP3Transport)recordClose(err error){if err!=nil{t.transportAccess.Lock();t.closeErr=errors.Join(t.closeErr,err);t.transportAccess.Unlock()}}
func(t *HTTP3Transport)closeOwned()error{
	t.transportAccess.Lock();t.closed=true;all:=append([]*dnsHTTP3Epoch(nil),t.transports...);t.transportAccess.Unlock()
	for _,epoch:=range all{epoch.boundary.StopRuntimeOperations()}
	for _,epoch:=range all{t.recordClose(epoch.RuntimeCloseAndWait())};return nil
}
func(t *HTTP3Transport)RuntimeCloseAndWait()error{
	err:=t.fence.RuntimeCloseAndWait();t.transportAccess.Lock();defer t.transportAccess.Unlock();if t.closeErr!=nil{return E.New("DNS HTTP3 cleanup incomplete: ",errors.Join(err,t.closeErr))};return err
}
func(t *HTTP3Transport)Exchange(ctx context.Context,message *mDNS.Msg)(*mDNS.Msg,error){
	ctx,release,err:=t.begin(ctx);if err!=nil{return nil,err};defer release();return t.exchangeOwned(ctx,message)
}

func (t *HTTP3Transport) exchangeOwned(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	exMessage := *message
	exMessage.Id = 0
	exMessage.Compress = true
	rawMessage, err := exMessage.Pack()
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, t.destination.String(), bytes.NewReader(rawMessage))
	if err != nil {
		return nil, err
	}
	request.Header = t.headers.Clone()
	request.Header.Set("Content-Type", transport.MimeType)
	request.Header.Set("Accept", transport.MimeType)
	currentTransport, err := t.acquireTransport()
	if err != nil {
		return nil, err
	}
	defer t.releaseTransport(currentTransport)
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

func(t *HTTP3Transport)ExchangeAsync(ctx context.Context,message *mDNS.Msg,callback func(*mDNS.Msg,error)){
	ctx,release,err:=t.begin(ctx);if err!=nil{callback(nil,err);return}
	go func(){defer release();callback(t.exchangeOwned(ctx,message))}()
}

func(t *HTTP3Transport)StopRuntimeOperations(){t.stopOnce.Do(func(){go func(){_ = t.fence.Close()}()})}
