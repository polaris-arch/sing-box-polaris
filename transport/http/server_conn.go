package http

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/badhttp"
	"github.com/sagernet/sing-box/common/urltest"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type requestResult uint8

const (
	requestContinue requestResult = iota
	requestClose
	requestHandedOff
)

type serverConn struct {
	server   *Server
	ctx      context.Context
	conn     net.Conn
	reader   *Reader
	handler  Handler
	source   M.Socksaddr
	onClose  N.CloseHandlerFunc
	upstream *upstreamConn
}

func (c *serverConn) serve() {
	for {
		result, err := c.serveRequest()
		switch result {
		case requestContinue:
			continue
		case requestHandedOff:
			c.closeUpstream()
			return
		case requestClose:
			c.closeUpstream()
			c.server.finishConnection(c.ctx, c.conn, c.source, c.onClose, err)
			return
		}
	}
}

func (c *serverConn) serveRequest() (requestResult, error) {
	c.conn.SetReadDeadline(time.Now().Add(idleTimeout))
	c.reader.setLimit(maxHeaderBytes)
	request, err := badhttp.ReadRequest(c.reader.Reader)
	c.reader.setLimit(-1)
	c.conn.SetReadDeadline(time.Time{})
	if err != nil {
		switch {
		case errors.Is(err, io.EOF), E.IsTimeout(err), E.IsClosed(err):
			return requestClose, err
		case errors.Is(err, errHeaderTooLarge):
			return c.rejectAndClose(nil, http.StatusRequestHeaderFieldsTooLarge, err)
		default:
			return c.rejectAndClose(nil, http.StatusBadRequest, E.Cause(err, "read request"))
		}
	}
	tunnelProtocol, tunnelHandler := c.server.upgradeTunnelHandler(request)
	if tunnelHandler != nil {
		tunnelCtx, tunnelAuthErr := c.server.authenticate(c.ctx, request, "Authorization")
		if tunnelAuthErr != nil {
			c.server.logger.ErrorContext(c.ctx, E.Cause(tunnelAuthErr, "process connection from ", c.source))
			return c.reject(request, requestKeepAlive(request), http.StatusUnauthorized, nil, tunnelAuthErr)
		}
		return c.serveTunnel(tunnelCtx, request, badhttp.ForwardedSource(request, c.source), tunnelProtocol, tunnelHandler)
	}
	if c.handler == nil {
		return c.reject(request, requestKeepAlive(request), http.StatusNotFound, nil, E.New("unexpected request: ", request.Method, " ", request.URL))
	}
	ctx, authErr := c.server.authenticate(c.ctx, request, "Proxy-Authorization")
	if authErr != nil {
		c.server.logger.ErrorContext(c.ctx, E.Cause(authErr, "process connection from ", c.source))
		return c.reject(request, requestKeepAlive(request), http.StatusProxyAuthRequired, nil, authErr)
	}
	source := badhttp.ForwardedSource(request, c.source)
	switch {
	case request.Method == http.MethodConnect:
		return c.serveConnect(ctx, request, source)
	case c.server.udp && requestIsConnectUDP(request):
		return c.serveConnectUDP(ctx, request, source)
	case requestIsUpgrade(request):
		return c.serveForward(ctx, request, source, true)
	default:
		return c.serveForward(ctx, request, source, false)
	}
}

func (c *serverConn) serveConnect(ctx context.Context, request *http.Request, source M.Socksaddr) (requestResult, error) {
	destination := connectDestination(request)
	if !destination.IsValid() {
		return c.reject(request, requestKeepAlive(request), http.StatusBadRequest, nil, E.New("invalid CONNECT target: ", request.URL.Host))
	}
	version := F.ToString("HTTP/", request.ProtoMajor, ".", request.ProtoMinor)
	probeMode := request.Header.Get("X-Polaris-Probe")
	probe := c.server.probeConnect && (probeMode == "1" || probeMode == "background") &&
		M.SocksaddrFromNet(c.conn.RemoteAddr()).Addr.Unmap().IsLoopback()
	if !probe {
		if _, err := io.WriteString(c.conn, version+connectSuccess); err != nil {
			return requestClose, E.Cause(err, "write response")
		}
	}
	conn := c.reader.cachedConn(c.conn)
	if probe {
		conn = &probeConnectConn{Conn: conn, version: version}
		if probeMode == "background" {
			ctx = urltest.ContextWithBackgroundProbe(ctx)
		}
	}
	c.handler.NewConnectionEx(ctx, conn, source, destination, c.onClose)
	return requestHandedOff, nil
}

const connectSuccess = " 200 Connection established\r\n\r\n"

type probeConnectConn struct {
	net.Conn
	version   string
	responded atomic.Bool
}

func (c *probeConnectConn) HandshakeSuccess() error {
	return c.writeResponse(connectSuccess)
}

func (c *probeConnectConn) HandshakeFailure(err error) error {
	capacity := errors.Is(err, adapter.ErrOutboundCapacity)
	if errors.Is(err, adapter.ErrOutboundForegroundSlot) {
		capacity = adapter.IsOutboundCapacity(err)
	}
	if capacity {
		return c.writeResponse(" 503 Service Unavailable\r\nX-Polaris-Probe-Outcome: budget-busy\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
	}
	return c.writeResponse(" 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
}

func (c *probeConnectConn) writeResponse(response string) error {
	if !c.responded.CompareAndSwap(false, true) {
		return nil
	}
	_, err := io.WriteString(c.Conn, c.version+response)
	return err
}

func (c *serverConn) reject(request *http.Request, keepAlive bool, statusCode int, header http.Header, cause error) (requestResult, error) {
	if keepAlive && request.Body != nil && request.Body != http.NoBody {
		keepAlive = c.discardBody(request.Body)
	}
	err := c.writeReject(request, statusCode, header, keepAlive)
	if err != nil {
		return requestClose, E.Errors(cause, err)
	}
	if keepAlive {
		return requestContinue, nil
	}
	return requestClose, cause
}

func (c *serverConn) rejectAndClose(request *http.Request, statusCode int, cause error) (requestResult, error) {
	err := c.writeReject(request, statusCode, nil, false)
	if err != nil {
		return requestClose, E.Errors(cause, err)
	}
	return requestClose, cause
}

func (c *serverConn) writeReject(request *http.Request, statusCode int, header http.Header, keepAlive bool) error {
	response := &http.Response{
		StatusCode: statusCode,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     header.Clone(),
		Request:    request,
		Close:      !keepAlive,
	}
	if response.Header == nil {
		response.Header = make(http.Header)
	}
	if request != nil {
		response.ProtoMajor = request.ProtoMajor
		response.ProtoMinor = request.ProtoMinor
	}
	switch statusCode {
	case http.StatusProxyAuthRequired:
		response.Header.Set("Proxy-Authenticate", `Basic realm="`+realm+`", charset="UTF-8"`)
	case http.StatusUnauthorized:
		response.Header.Set("WWW-Authenticate", `Basic realm="`+realm+`", charset="UTF-8"`)
	}
	if keepAlive && request.ProtoMajor == 1 && request.ProtoMinor == 0 {
		response.Header.Set("Connection", "keep-alive")
		response.Header.Set("Proxy-Connection", "keep-alive")
	}
	err := response.Write(c.conn)
	if err != nil {
		return E.Cause(err, "write response")
	}
	return nil
}

func (c *serverConn) discardBody(body io.Reader) bool {
	c.conn.SetReadDeadline(time.Now().Add(discardBodyTimeout))
	_, err := io.CopyN(io.Discard, body, maxDiscardBodyBytes)
	c.conn.SetReadDeadline(time.Time{})
	return errors.Is(err, io.EOF)
}

func (c *serverConn) closeUpstream() {
	if c.upstream != nil {
		c.upstream.Close()
		c.upstream = nil
	}
}
