package v2rayhttp

import (
	"context"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/badhttp"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

var _ adapter.V2RayMultiplexClientTransport = (*Client)(nil)

type Client struct {
	boundary *httpclient.RuntimeTransportBoundary
	source adapter.RuntimeResourceSource
	ctx        context.Context
	dialer     N.Dialer
	serverAddr M.Socksaddr
	transport  common.TypedValue[http.RoundTripper]
	http2      bool
	requestURL url.URL
	host       []string
	method     string
	headers    http.Header
	closeIdle  atomic.Bool
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayHTTPOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	var transport http.RoundTripper
	if tlsConfig == nil {
		transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
		}
	} else {
		if len(tlsConfig.NextProtos()) == 0 {
			tlsConfig.SetNextProtos([]string{http2.NextProtoTLS})
		}
		tlsDialer := tls.NewDialer(dialer, tlsConfig)
		transport = &http2.Transport{
			ReadIdleTimeout: time.Duration(options.IdleTimeout),
			PingTimeout:     time.Duration(options.PingTimeout),
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.STDConfig) (net.Conn, error) {
				return tlsDialer.DialTLSContext(ctx, M.ParseSocksaddr(addr))
			},
		}
	}
	if options.Method == "" {
		options.Method = http.MethodPut
	}
	var requestURL url.URL
	if tlsConfig == nil {
		requestURL.Scheme = "http"
	} else {
		requestURL.Scheme = "https"
	}
	requestURL.Host = serverAddr.String()
	requestURL.Path = options.Path
	err := badhttp.URLSetPath(&requestURL, options.Path)
	if err != nil {
		return nil, E.Cause(err, "parse path")
	}
	if !strings.HasPrefix(requestURL.Path, "/") {
		requestURL.Path = "/" + requestURL.Path
	}
	client := &Client{
		ctx:        ctx,
		dialer:     dialer,
		serverAddr: serverAddr,
		requestURL: requestURL,
		host:       append([]string(nil),options.Host...),
		method:     options.Method,
		headers:    options.Headers.Build(),
		http2:      tlsConfig != nil,
	}
	client.source,_=adapter.RuntimeResourceSourceFromContext(ctx)
	client.boundary=httpclient.NewRuntimeTransportBoundary(func()error{CloseIdleConnections(transport);return nil})
	switch t:=transport.(type){case *http.Transport:client.boundary.BindHTTP1(t);case *http2.Transport:client.boundary.BindHTTP2(t)}
	client.transport.Store(transport)
	return client, nil
}

func(c *Client)DialContext(ctx context.Context)(net.Conn,error){
	ctx,release,err:=adapter.AcquireRuntimeOperation(ctx,c.source);if err!=nil{return nil,err}
	leave,err:=c.boundary.Acquire();if err!=nil{release();return nil,err};defer leave()
	if c.source!=nil{ctx,err=outbound.ContextForRuntimeOwnedSession(ctx,c.source);if err!=nil{release();return nil,err}}
	conn,err:=c.dialContextOwned(ctx);if err!=nil{release();return nil,err}
	return outbound.WrapRuntimeConn(ctx,release,conn),nil
}
func (c *Client) dialContextOwned(ctx context.Context) (net.Conn, error) {
	if !c.http2 {
		return c.dialHTTP(ctx)
	} else {
		return c.dialHTTP2(ctx)
	}
}

func (c *Client) dialHTTP(ctx context.Context) (net.Conn, error) {
	conn, err := c.boundary.Dial(ctx,func(ctx context.Context)(net.Conn,error){return c.dialer.DialContext(ctx,N.NetworkTCP,c.serverAddr)})
	if err != nil {
		return nil, err
	}

	request := &http.Request{
		Method: c.method,
		URL:    &c.requestURL,
		Header: c.headers.Clone(),
	}
	switch hostLen := len(c.host); hostLen {
	case 0:
		request.Host = c.serverAddr.AddrString()
	case 1:
		request.Host = c.host[0]
	default:
		request.Host = c.host[rand.Intn(hostLen)]
	}

	return NewHTTP1Conn(conn, request), nil
}

func (c *Client) dialHTTP2(ctx context.Context) (net.Conn, error) {
	pipeInReader, pipeInWriter := io.Pipe()
	requestCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	request := &http.Request{
		Method: c.method,
		Body:   pipeInReader,
		URL:    &c.requestURL,
		Header: c.headers.Clone(),
	}
	request = request.WithContext(requestCtx)
	switch hostLen := len(c.host); hostLen {
	case 0:
		// https://github.com/v2fly/v2ray-core/blob/master/transport/internet/http/config.go#L13
		request.Host = "www.example.com"
	case 1:
		request.Host = c.host[0]
	default:
		request.Host = c.host[rand.Intn(hostLen)]
	}
	conn := NewLateHTTPConn(pipeInWriter, cancel)
	keepSession := adapter.KeepSessionFromContext(ctx)
	conn.onClose = func() {
		if c.closeIdle.Load() && !keepSession {
			CloseIdleConnections(c.transport.Load())
		}
	}
	handshakeTimeout := C.TCPTimeout
	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		handshakeTimeout = time.Until(deadline)
	}
	var handshakeTimedOut atomic.Bool
	timerDone:=make(chan struct{})
	var timerOnce sync.Once
	handshakeTimer := time.AfterFunc(handshakeTimeout, func() {
		defer timerOnce.Do(func(){close(timerDone)})
		handshakeTimedOut.Store(true)
		cancel()
	})
	workerCtx,releaseWorker,workerErr:=adapter.AcquireRuntimeOperation(ctx,nil)
	if workerErr!=nil{if handshakeTimer.Stop(){timerOnce.Do(func(){close(timerDone)})};<-timerDone;cancel();_ = pipeInWriter.Close();_ = pipeInReader.Close();return nil,workerErr}
	leaveWorker,workerErr:=c.boundary.Acquire()
	if workerErr!=nil{if handshakeTimer.Stop(){timerOnce.Do(func(){close(timerDone)})};<-timerDone;releaseWorker();cancel();_ = pipeInWriter.Close();_ = pipeInReader.Close();return nil,workerErr}
	_ = workerCtx // The retained capability owns the existing request context.
	go func() {
		defer leaveWorker();defer releaseWorker()
		response, err := c.boundary.RoundTrip(request,c.transport.Load().RoundTrip)
		if handshakeTimer.Stop(){timerOnce.Do(func(){close(timerDone)})}
		<-timerDone
		if err != nil {
			if handshakeTimedOut.Load() {
				err = os.ErrDeadlineExceeded
			}
			conn.Setup(nil, err)
		} else if response.StatusCode != 200 {
			response.Body.Close()
			conn.Setup(nil, E.New("v2ray-http: unexpected status: ", response.Status))
		} else {
			conn.Setup(response.Body, nil)
		}
	}()
	return conn, nil
}

func (c *Client) MultiplexEnabled() bool {
	return c.http2
}

func (c *Client) SetKeepIdleConnections(keep bool) {
	c.closeIdle.Store(!keep)
	if !keep {
		c.CloseIdleConnections()
	}
}

func (c *Client) CloseIdleConnections() {
	CloseIdleConnections(c.transport.Load())
}

func(c *Client)Close()error{return c.boundary.RuntimeCloseAndWait()}
func(c *Client)RuntimeCloseAndWait()error{return c.Close()}

func(c *Client)StopRuntimeOperations(){c.boundary.StopRuntimeOperations()}
