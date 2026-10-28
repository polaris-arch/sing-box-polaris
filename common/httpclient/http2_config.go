package httpclient

import (
	"context"
	stdTLS "crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/net/http2"
)

func CloneHTTP2Transport(transport *http2.Transport) *http2.Transport {
	return &http2.Transport{
		ReadIdleTimeout: transport.ReadIdleTimeout,
		PingTimeout:     transport.PingTimeout,
		DialTLSContext:  transport.DialTLSContext,
	}
}

func ConfigureHTTP2Transport(options option.HTTP2Options) (*http2.Transport, error) {
	stdTransport := &http.Transport{
		TLSClientConfig: &stdTLS.Config{},
		HTTP2: &http.HTTP2Config{
			MaxReceiveBufferPerStream:     int(options.StreamReceiveWindow.Value()),
			MaxReceiveBufferPerConnection: int(options.ConnectionReceiveWindow.Value()),
			MaxConcurrentStreams:          options.MaxConcurrentStreams,
			SendPingTimeout:               time.Duration(options.KeepAlivePeriod),
			PingTimeout:                   time.Duration(options.IdleTimeout),
		},
	}
	h2Transport, err := http2.ConfigureTransports(stdTransport)
	if err != nil {
		return nil, E.Cause(err, "configure HTTP/2 transport")
	}
	// ConfigureTransports binds ConnPool to the throwaway http.Transport; sever it so DialTLSContext is used directly.
	h2Transport.ConnPool = nil
	h2Transport.ReadIdleTimeout = time.Duration(options.KeepAlivePeriod)
	h2Transport.PingTimeout = time.Duration(options.IdleTimeout)
	return h2Transport, nil
}

// BindHTTP2 completes the same pinned x/net configuration contract as
// ConfigureHTTP2Transport. It must run before publication or the first invocation.
// Keep x/net-specific dialing and pooling here; RuntimeTransportBoundary owns
// the dependency-neutral fences and physical-connection cleanup. In particular,
// do not replace the caller's pool or change the dependency's engine selection.
func (b *RuntimeTransportBoundary) BindHTTP2(t *http2.Transport) {
	if dial := t.DialTLSContext; dial != nil {
		t.DialTLSContext = func(ctx context.Context, network, addr string, config *stdTLS.Config) (net.Conn, error) {
			return b.Dial(ctx, func(ctx context.Context) (net.Conn, error) { return dial(ctx, network, addr, config) })
		}
	}
	if dial := t.DialTLS; dial != nil {
		t.DialTLS = func(network, addr string, config *stdTLS.Config) (net.Conn, error) {
			return b.Dial(context.Background(), func(context.Context) (net.Conn, error) { return dial(network, addr, config) })
		}
	}
	if count := t.CountError; count != nil {
		t.CountError = func(name string) {
			release, err := b.fence.Acquire()
			if err != nil {
				return
			}
			defer release()
			count(name)
		}
	}
	if t.ConnPool != nil {
		t.ConnPool = &runtimeHTTP2Pool{pool: t.ConnPool, boundary: b}
	}
}

type runtimeHTTP2Pool struct {
	pool     http2.ClientConnPool
	boundary *RuntimeTransportBoundary
}

func (p *runtimeHTTP2Pool) GetClientConn(r *http.Request, addr string) (*http2.ClientConn, error) {
	release, err := p.boundary.fence.Acquire()
	if err != nil {
		return nil, err
	}
	defer release()
	return p.pool.GetClientConn(r, addr)
}

func (p *runtimeHTTP2Pool) MarkDead(c *http2.ClientConn) {
	release, err := p.boundary.fence.Acquire()
	if err != nil {
		return
	}
	defer release()
	p.pool.MarkDead(c)
}
