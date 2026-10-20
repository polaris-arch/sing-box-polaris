//go:build with_quic

package http

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-quic"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

func init() {
	NewHTTP3Client = newHTTP3Client
}

type http3ClientImpl struct {
	dialer        N.Dialer
	tlsConfig     aTLS.Config
	server        M.Socksaddr
	authority     string
	headers       http.Header
	authorization string
	quicConfig    *quic.Config
	transport     *http3.Transport
	access        sync.Mutex
	conn          *http3.ClientConn
	rawConn       *httpclient.RuntimeQUICSession
	closed        bool
	epoch         uint64
	closeErr      error
}

func newHTTP3Client(options ClientOptions, authorization string) (http3Client, error) {
	if options.TLSConfig == nil {
		return nil, E.New("HTTP/3 requires TLS")
	}
	dialer := options.RawDialer
	if dialer == nil {
		dialer = N.SystemDialer
	}
	quicConfig := httpclient.NewQUICConfig(options.HTTP3Options)
	quicConfig.EnableDatagrams = true
	headers := options.Headers.Clone()
	authority := options.Server.String()
	if options.Authority != "" {
		authority = options.Authority
	}
	if headers != nil {
		if host := headers.Get("Host"); host != "" {
			authority = host
		}
		headers.Del("Host")
	}
	return &http3ClientImpl{
		dialer:        dialer,
		tlsConfig:     options.TLSConfig,
		server:        options.Server,
		authority:     authority,
		headers:       headers,
		authorization: authorization,
		quicConfig:    quicConfig,
		transport:     &http3.Transport{EnableDatagrams: true, DisableCompression: true},
	}, nil
}

func (c *http3ClientImpl) acquire(ctx context.Context) (*http3.ClientConn, error) {
	c.access.Lock()
	if c.closed { c.access.Unlock(); return nil, net.ErrClosed }
	if c.conn != nil && c.conn.Context().Err() == nil {
		connection := c.conn
		c.access.Unlock()
		return connection, nil
	}
	previous, previousRaw, epoch := c.conn, c.rawConn, c.epoch
	c.conn, c.rawConn = nil, nil
	c.access.Unlock()
	c.recordClose(closeHTTP3Connection(previous, previousRaw))
	// Pending creation is owned by the enclosing Client operation. Close seals
	// publication and cancels/joins that operation without holding this lock.
	rawConn, err := c.dialer.DialContext(ctx, N.NetworkUDP, c.server)
	if err != nil {
		if ctx.Err() != nil { return nil, ctx.Err() }
		return nil, E.Cause1(ErrHTTP3Unavailable, err)
	}
	stdConfig,err:=c.tlsConfig.STDConfig()
	if err!=nil{c.recordClose(closeHTTPResource(rawConn.Close));return nil,err}
	quicSession, err := httpclient.DialRuntimeQUIC(ctx, rawConn, stdConfig, c.quicConfig,c.recordClose)
	if err != nil {
		return nil, E.Cause1(ErrHTTP3Unavailable, err)
	}
	connection := c.transport.NewClientConn(quicSession.Conn)
	c.access.Lock()
	if c.closed || c.epoch != epoch || ctx.Err() != nil {
		c.access.Unlock()
		c.recordClose(closeHTTP3Connection(connection, quicSession))
		return nil, errors.Join(net.ErrClosed, ctx.Err())
	}
	if c.conn != nil {
		existing := c.conn
		c.access.Unlock()
		c.recordClose(closeHTTP3Connection(connection, quicSession))
		return existing, nil
	}
	c.conn, c.rawConn = connection, quicSession
	c.access.Unlock()
	return connection, nil
}

func (c *http3ClientImpl) openStream(ctx context.Context, request *http.Request) (*http3.RequestStream, *http3.ClientConn, error) {
	clientConn, err := c.acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	stream, err := clientConn.OpenRequestStream(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, E.Cause1(ErrHTTP3Unavailable, err)
	}
	stop := joinedAfterFunc(ctx, func() {
		stream.CancelRead(0)
		stream.CancelWrite(0)
	})
	var response *http.Response
	err = stream.SendRequestHeader(request)
	if err == nil {
		response, err = stream.ReadResponse()
	}
	if err == nil {
		select {
		case <-clientConn.ReceivedSettings():
		case <-clientConn.Context().Done():
			err = context.Cause(clientConn.Context())
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	if !stop() {
		err = ctx.Err()
	}
	if err != nil {
		stream.CancelRead(0)
		stream.Close()
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, E.Cause(err, "HTTP/3 CONNECT")
	}
	if response.StatusCode != http.StatusOK {
		stream.CancelRead(0)
		stream.Close()
		return nil, nil, statusError(response)
	}
	return stream, clientConn, nil
}

func (c *http3ClientImpl) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	stream, _, err := c.openStream(ctx, &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: destination.String()},
		Host:   destination.String(),
		Header: buildRequestHeader(c.headers, c.authorization, false),
	})
	if err != nil {
		return nil, err
	}
	return &http3StreamConn{stream: stream, remoteAddr: destination}, nil
}

func (c *http3ClientImpl) OpenTunnel(ctx context.Context, request tunnelRequest) (DatagramStream, error) {
	requestURL := *request.url
	requestURL.Scheme = "https"
	requestURL.Host = c.authority
	header := buildRequestHeader(c.headers, c.authorization, request.originAuthorization)
	header.Set("Capsule-Protocol", "?1")
	stream, clientConn, err := c.openStream(ctx, &http.Request{
		Method: http.MethodConnect,
		Proto:  request.protocol,
		URL:    &requestURL,
		Host:   c.authority,
		Header: header,
	})
	if err != nil {
		return nil, err
	}
	return &http3RequestDatagramStream{stream: stream, datagramsEnabled: clientConn.Settings().EnableDatagrams}, nil
}

func closeHTTP3Connection(connection *http3.ClientConn, raw *httpclient.RuntimeQUICSession) error {
	var closeErrors []error
	if raw != nil { closeErrors = append(closeErrors, closeHTTPResource(raw.Close)) }
	if connection != nil { closeErrors = append(closeErrors, closeHTTPResource(func() error { return connection.CloseWithError(0, "") })) }
	return errors.Join(closeErrors...)
}

func (c *http3ClientImpl) recordClose(err error) {
	if err == nil || httpAlreadyClosed(err) { return }
	c.access.Lock()
	c.closeErr = errors.Join(c.closeErr, err)
	c.access.Unlock()
}

func (c *http3ClientImpl) ResetConnection() {
	c.access.Lock()
	if c.closed { c.access.Unlock(); return }
	connection, raw := c.conn, c.rawConn
	c.conn, c.rawConn = nil, nil
	c.epoch++
	c.access.Unlock()
	c.recordClose(closeHTTP3Connection(connection, raw))
}

func (c *http3ClientImpl) Close() error {
	c.access.Lock()
	c.closed = true
	connection, raw := c.conn, c.rawConn
	c.conn, c.rawConn = nil, nil
	c.epoch++
	c.access.Unlock()
	c.recordClose(closeHTTP3Connection(connection, raw))
	c.recordClose(closeHTTPResource(c.transport.Close))
	c.access.Lock()
	defer c.access.Unlock()
	return c.closeErr
}

type http3StreamConn struct {
	stream      *http3.RequestStream
	remoteAddr  net.Addr
	writeAccess sync.Mutex
	closed      atomic.Bool
}

func (c *http3StreamConn) Read(p []byte) (int, error) {
	n, err := c.stream.Read(p)
	return n, c.wrapError(err)
}

func (c *http3StreamConn) Write(p []byte) (int, error) {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	n, err := c.stream.Write(p)
	return n, c.wrapError(err)
}

func (c *http3StreamConn) wrapError(err error) error {
	if err == nil {
		return nil
	}
	if c.closed.Load() {
		return net.ErrClosed
	}
	return qtls.WrapError(err)
}

func (c *http3StreamConn) CloseWrite() error {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	return c.stream.Close()
}

func (c *http3StreamConn) Close() error {
	c.closed.Store(true)
	c.stream.SetWriteDeadline(time.Now())
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	c.stream.CancelRead(0)
	return c.stream.Close()
}

func (c *http3StreamConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *http3StreamConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *http3StreamConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *http3StreamConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *http3StreamConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

func (c *http3StreamConn) NeedAdditionalReadDeadline() bool {
	return true
}

type http3RequestDatagramStream struct {
	stream           *http3.RequestStream
	datagramsEnabled bool
}

func (s *http3RequestDatagramStream) Read(p []byte) (int, error) {
	return s.stream.Read(p)
}

func (s *http3RequestDatagramStream) Write(p []byte) (int, error) {
	return s.stream.Write(p)
}

func (s *http3RequestDatagramStream) Close() error {
	s.stream.SetWriteDeadline(time.Now())
	s.stream.CancelRead(0)
	return s.stream.Close()
}

func (s *http3RequestDatagramStream) SendDatagram(payload []byte) error {
	if !s.datagramsEnabled {
		return ErrDatagramUnsupported
	}
	err := s.stream.SendDatagram(payload)
	if err == nil {
		return nil
	}
	if tooLarge, ok := errors.AsType[*quic.DatagramTooLargeError](err); ok {
		return &DatagramTooLargeError{MaxPayloadSize: int(tooLarge.MaxDatagramPayloadSize) - VarintLen(uint64(s.stream.StreamID()/4))}
	}
	return err
}

func (s *http3RequestDatagramStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return s.stream.ReceiveDatagram(ctx)
}

var (
	_ net.Conn       = (*http3StreamConn)(nil)
	_ N.WriteCloser  = (*http3StreamConn)(nil)
	_ DatagramStream = (*http3RequestDatagramStream)(nil)
)

func(c *http3ClientImpl)RuntimeCloseAndWait()error{return c.Close()}
