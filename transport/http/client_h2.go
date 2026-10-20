package http

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/pipe"
	"github.com/sagernet/sing-box/common/tls"

	"golang.org/x/net/http2"
)

func (c *Client) acquireHTTP2(ctx context.Context) (*http2ClientConn, net.Conn, error) {
	c.http2Access.Lock()
	for _, clientConn := range c.http2Conns {
		if !clientConn.isClosed() && clientConn.reserveNewRequest() {
			c.http2Access.Unlock()
			return clientConn, nil, nil
		}
	}
	epoch := c.http2Epoch
	c.http2Access.Unlock()
	// TLS/network creation is deliberately outside the pool's short lock.
	dialCtx,err:=c.ownedDialContext(ctx)
	if err!=nil{return nil,nil,err}
	conn, err := c.tlsDialer.DialTLSContext(dialCtx, c.server)
	if err != nil {if tls.IsRuntimeCleanupIncomplete(err){c.recordCloseError(err)};return nil, nil, err }
	if c.isClosed() || ctx.Err() != nil {
		c.recordCloseError(closeHTTPResource(conn.Close))
		return nil, nil, errors.Join(net.ErrClosed, ctx.Err())
	}
	if conn.ConnectionState().NegotiatedProtocol != http2.NextProtoTLS {
		if !c.disableVersionFallback { c.http2Unsupported.Store(true) }
		return nil, conn, nil
	}
	stop := c.closeOnCancel(ctx, conn)
	clientConn, err := newHTTP2ClientConn(c.http2Transport, conn)
	stopped := stop()
	if err != nil {
		c.recordCloseError(closeHTTPResource(conn.Close))
		return nil, nil, E.Cause(err, "create HTTP/2 connection")
	}
	c.http2Access.Lock()
	if !stopped || c.http2Epoch != epoch || c.isClosed() || ctx.Err() != nil {
		c.http2Access.Unlock()
		c.recordCloseError(closeHTTPResource(clientConn.Close))
		return nil, nil, errors.Join(net.ErrClosed, ctx.Err())
	}
	clientConn.reserveNewRequest()
	c.http2Conns = append(c.http2Conns, clientConn)
	c.http2Access.Unlock()
	return clientConn, nil, nil
}

func (c *Client) connectHTTP2(ctx context.Context, clientConn *http2ClientConn, destination M.Socksaddr) (net.Conn, error) {
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: destination.String()},
		Host:   destination.String(),
		Header: buildRequestHeader(c.headers, c.authorization, false),
	}
	streamConn, err := c.roundTripHTTP2(ctx, clientConn, request, destination)
	if err != nil {
		return nil, err
	}
	return c.ownConnection(ctx, newClientTunnelConn(streamConn))
}

func (c *Client) roundTripHTTP2(ctx context.Context, clientConn *http2ClientConn, request *http.Request, destination M.Socksaddr) (*clientStreamConn, error) {
	pipeReader, pipeWriter := pipe.Pipe()
	streamCtx, cancel := context.WithCancel(context.Background())
	request.Body = pipeReader
	request = request.WithContext(streamCtx)
	stop := joinedAfterFunc(ctx, cancel)
	response, err := clientConn.roundTrip(request)
	stopped := stop()
	if err == nil && !stopped {
		response.Body.Close()
		err = ctx.Err()
	}
	if err != nil {
		cancel()
		pipeWriter.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// golang.org/x/net/http2 has no exported sentinel for a peer that lacks
		// SETTINGS_ENABLE_CONNECT_PROTOCOL; it returns errExtendedConnectNotSupported
		// ("net/http: extended connect not supported by peer") from RoundTrip.
		if strings.Contains(err.Error(), "extended connect not supported") {
			return nil, E.Cause1(errExtendedConnectUnsupported, err)
		}
		return nil, E.Cause(err, "HTTP/2 CONNECT")
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		cancel()
		pipeWriter.Close()
		return nil, statusError(response)
	}
	return &clientStreamConn{
		reader:     response.Body,
		writer:     pipeWriter,
		cancel:     cancel,
		localAddr:  M.Socksaddr{},
		remoteAddr: destination,
	}, nil
}

func (c *Client) connectAndClose(ctx context.Context, conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	result, err := c.connect(ctx, conn, destination)
	if err != nil {
		c.recordCloseError(closeHTTPResource(conn.Close))
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return c.ownConnection(ctx, result)
}
