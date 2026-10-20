package v2raywebsocket

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/badhttp"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/bufio/deadline"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/ws"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

type Client struct {
	boundary *httpclient.RuntimeTransportBoundary
	source adapter.RuntimeResourceSource
	dialer              N.Dialer
	serverAddr          M.Socksaddr
	requestURL          url.URL
	headers             http.Header
	maxEarlyData        uint32
	earlyDataHeaderName string
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayWebsocketOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	if tlsConfig != nil {
		if len(tlsConfig.NextProtos()) == 0 {
			tlsConfig.SetNextProtos([]string{"http/1.1"})
		}
		dialer = tls.NewDialer(dialer, tlsConfig)
	}
	var requestURL url.URL
	if tlsConfig == nil {
		requestURL.Scheme = "ws"
	} else {
		requestURL.Scheme = "wss"
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
	headers := options.Headers.Build()
	if host := headers.Get("Host"); host != "" {
		headers.Del("Host")
		requestURL.Host = host
	}
	if headers.Get("User-Agent") == "" {
		headers.Set("User-Agent", "Go-http-client/1.1")
	}
	client:=&Client{dialer:dialer,serverAddr:serverAddr,requestURL:requestURL,headers:headers,maxEarlyData:options.MaxEarlyData,earlyDataHeaderName:options.EarlyDataHeaderName}
	client.source,_=adapter.RuntimeResourceSourceFromContext(ctx)
	client.boundary=httpclient.NewRuntimeTransportBoundary(nil)
	return client,nil
}

func(c *Client)DialContext(ctx context.Context)(net.Conn,error){
	ctx,release,err:=adapter.AcquireRuntimeOperation(ctx,c.source);if err!=nil{return nil,err}
	leave,err:=c.boundary.Acquire();if err!=nil{release();return nil,err};defer leave()
	conn,err:=c.dialContextOwned(ctx);if err!=nil{release();return nil,err};return outbound.WrapRuntimeConn(ctx,release,conn),nil
}
func (c *Client) dialContextOwned(ctx context.Context) (net.Conn, error) {
	conn, err := c.boundary.Dial(ctx,func(ctx context.Context)(net.Conn,error){return c.dialer.DialContext(ctx,N.NetworkTCP,c.serverAddr)})
	if err != nil {
		return nil, err
	}
	if c.maxEarlyData > 0 {
		return &EarlyWebsocketConn{Client: c, rawConn: conn, create: make(chan struct{})}, nil
	}
	websocketConn, err := c.upgrade(conn, &c.requestURL, c.headers)
	if err != nil {
		return nil, err
	}
	return websocketConn, nil
}

func (c *Client) upgrade(conn net.Conn, requestURL *url.URL, headers http.Header) (*WebsocketConn, error) {
	var deadlineConn net.Conn
	if deadline.NeedAdditionalReadDeadline(conn) {
		deadlineConn = deadline.NewConn(conn)
	} else {
		deadlineConn = conn
	}
	deadlineConn.SetDeadline(time.Now().Add(C.TCPTimeout))
	var protocols []string
	protocolHeader := headers.Get("Sec-WebSocket-Protocol")
	if protocolHeader != "" {
		protocols = []string{protocolHeader}
		headers = headers.Clone()
		headers.Del("Sec-WebSocket-Protocol")
	}
	reader, _, err := ws.Dialer{Header: ws.HandshakeHeaderHTTP(headers), Protocols: protocols}.Upgrade(deadlineConn, requestURL)
	deadlineConn.SetDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return nil, err
	}
	if reader != nil {
		buffer := buf.NewSize(reader.Buffered())
		_, err = buffer.ReadFullFrom(reader, buffer.FreeLen())
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn = bufio.NewCachedConn(conn, buffer)
	}
	return NewConn(conn, nil, ws.StateClientSide), nil
}

func(c *Client)Close()error{return c.boundary.RuntimeCloseAndWait()}
func(c *Client)RuntimeCloseAndWait()error{return c.Close()}

func(c *Client)StopRuntimeOperations(){c.boundary.StopRuntimeOperations()}
