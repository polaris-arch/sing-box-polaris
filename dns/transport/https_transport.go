package transport

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"

	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/tls"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

var errFallback = E.New("fallback to HTTP/1.1")

type HTTPSTransportWrapper struct {
	http2Transport *http2.Transport
	httpTransport  *http.Transport
	fallback       *atomic.Bool
	boundary       *httpclient.RuntimeTransportBoundary
}

func NewHTTPSTransportWrapper(dialer N.Dialer, serverAddr M.Socksaddr, fallback *atomic.Bool) *HTTPSTransportWrapper {
	wrapper := &HTTPSTransportWrapper{fallback: fallback}
	wrapper.boundary = httpclient.NewRuntimeTransportBoundary(func() error { wrapper.CloseIdleConnections(); return nil })
	wrapper.http2Transport = &http2.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.STDConfig) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, N.NetworkTCP, serverAddr)
			if err != nil {
				return nil, err
			}
			if tlsConn, ok := conn.(tls.Conn); ok && tlsConn.ConnectionState().NegotiatedProtocol != http2.NextProtoTLS {
				closeErr := tlsConn.Close()
				if closeErr != nil {
					return nil, tls.NewRuntimeCleanupError(closeErr)
				}
				fallback.Store(true)
				return nil, errFallback
			}
			return conn, nil
		},
	}
	wrapper.httpTransport = &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, N.NetworkTCP, serverAddr)
		},
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, N.NetworkTCP, serverAddr)
		},
	}
	wrapper.boundary.BindHTTP1(wrapper.httpTransport)
	wrapper.boundary.BindHTTP2(wrapper.http2Transport)
	return wrapper
}

func (h *HTTPSTransportWrapper) RoundTrip(request *http.Request) (*http.Response, error) {
	return h.boundary.RoundTrip(request, func(request *http.Request) (*http.Response, error) {
		if h.fallback.Load() {
			return h.httpTransport.RoundTrip(request)
		}
		response, err := h.http2Transport.RoundTrip(request)
		if errors.Is(err, errFallback) {
			retry := request.Clone(request.Context())
			if request.GetBody != nil {
				body, getErr := request.GetBody()
				if getErr != nil {
					return nil, getErr
				}
				retry.Body = body
			}
			return h.httpTransport.RoundTrip(retry)
		}
		return response, err
	})
}

// Close retains the historical void signature. Runtime owners use the typed
// terminal method so a failed physical close cannot be mistaken for completion.
func (h *HTTPSTransportWrapper) Close()                     { _ = h.RuntimeCloseAndWait() }
func (h *HTTPSTransportWrapper) RuntimeCloseAndWait() error { return h.boundary.RuntimeCloseAndWait() }
func (h *HTTPSTransportWrapper) CloseIdleConnections() {
	h.http2Transport.CloseIdleConnections()
	h.httpTransport.CloseIdleConnections()
}
