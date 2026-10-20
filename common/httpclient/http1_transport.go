package httpclient

import (
	"context"
	"net"
	"net/http"

	"github.com/sagernet/sing-box/common/tls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type http1Transport struct {
	transport *http.Transport
	boundary  *RuntimeTransportBoundary
}

func newHTTP1Transport(rawDialer N.Dialer, baseTLSConfig tls.Config) *http1Transport {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return rawDialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
		},
	}
	if baseTLSConfig != nil {
		transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialTLS(ctx, rawDialer, baseTLSConfig, M.ParseSocksaddr(addr), []string{"http/1.1"}, "")
		}
	}
	boundary := NewRuntimeTransportBoundary(func() error { transport.CloseIdleConnections(); return nil })
	boundary.BindHTTP1(transport)
	return &http1Transport{transport: transport, boundary: boundary}
}

func (t *http1Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	return t.boundary.RoundTrip(request, t.transport.RoundTrip)
}

func (t *http1Transport) CloseIdleConnections() {
	t.transport.CloseIdleConnections()
}

func (t *http1Transport) Close() error {
	return t.boundary.Close()
}

func (t *http1Transport) StopRuntimeOperations() { t.boundary.StopRuntimeOperations() }
