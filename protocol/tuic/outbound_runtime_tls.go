//go:build with_quic

package tuic

import (
	"context"
	stdTLS "crypto/tls"
	"errors"
	"net"
	"net/http"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/tls"
	qtls "github.com/sagernet/sing-quic"
)

// The native client reaches the exact existing QUIC provider/socket fences.
// STDConfig preserves configured TLS/auth values; unsupported alternate QUIC
// engines are rejected rather than silently replaced by standard TLS.
type outboundRuntimeTLS struct {
	tls.Config
	owner *outboundRuntime
}

var _ qtls.Config = (*outboundRuntimeTLS)(nil)

func newOutboundRuntimeTLS(config tls.Config, owner *outboundRuntime) (tls.Config, error) {
	if _, custom := config.(qtls.Config); custom {
		return nil, errors.New("custom QUIC TLS engine requires its own runtime completion adapter")
	}
	if _, err := config.STDConfig(); err != nil {
		return nil, err
	}
	return &outboundRuntimeTLS{Config: config, owner: owner}, nil
}

func (c *outboundRuntimeTLS) Dial(ctx context.Context, raw net.Conn, config *quic.Config) (*quic.Conn, error) {
	return c.dial(ctx, raw, config, false)
}

func (c *outboundRuntimeTLS) DialEarly(ctx context.Context, raw net.Conn, config *quic.Config) (*quic.Conn, error) {
	return c.dial(ctx, raw, config, true)
}

func (c *outboundRuntimeTLS) dial(ctx context.Context, raw net.Conn, config *quic.Config, early bool) (*quic.Conn, error) {
	standard, err := c.Config.STDConfig()
	if err != nil {
		c.owner.boundary.RecordClose(raw.Close())
		return nil, err
	}
	return c.dialNative(ctx, raw, config, early, standard)
}

func (c *outboundRuntimeTLS) dialNative(ctx context.Context, raw net.Conn, config *quic.Config, early bool, standard *stdTLS.Config) (*quic.Conn, error) {
	ctx, leave, err := c.owner.boundary.BeginDial(ctx)
	if err != nil {
		c.owner.boundary.RecordClose(raw.Close())
		return nil, err
	}
	defer leave()
	session, err := httpclient.DialRuntimeQUIC(ctx, c.owner.nativeCarrier(raw), standard, config, c.owner.boundary.RecordClose)
	if err != nil {
		return nil, err
	}
	if err = c.owner.boundary.RegisterResource(session); err != nil {
		return nil, err
	}
	if !early {
		select {
		case <-session.Conn.HandshakeComplete():
		case <-session.Conn.Context().Done():
			return nil, context.Cause(session.Conn.Context())
		case <-ctx.Done():
			c.owner.boundary.RecordClose(session.RuntimeCloseAndWait())
			return nil, ctx.Err()
		}
	}
	return session.Conn, nil
}

func (c *outboundRuntimeTLS) CreateTransport(raw net.Conn, connection **quic.Conn, config *quic.Config) http.RoundTripper {
	standard, err := c.Config.STDConfig()
	if err != nil {
		return outboundFailedRoundTripper{err}
	}
	transport := &http3.Transport{TLSClientConfig: standard, QUICConfig: config, Dial: func(ctx context.Context, _ string, negotiated *stdTLS.Config, config *quic.Config) (*quic.Conn, error) {
		// Preserve http3.Transport's ALPN/SNI adjustments to its private clone.
		conn, err := c.dialNative(ctx, raw, config, true, negotiated)
		if err == nil {
			*connection = conn
		}
		return conn, err
	}}
	// This transport is private to the authentication offer and remains owned
	// even after auth fails or the foreground request abandons the shared offer.
	if err := c.owner.boundary.RegisterResource(outboundHTTP3Closer{transport}); err != nil {
		return outboundFailedRoundTripper{err}
	}
	return transport
}

func (c *outboundRuntimeTLS) CreatePacketTransport(net.PacketConn, net.Addr, **quic.Conn, *quic.Config) http.RoundTripper {
	return outboundFailedRoundTripper{errors.New("Realm packet transport has no ordinary-node runtime contract")}
}

type outboundHTTP3Closer struct{ transport *http3.Transport }

func (c outboundHTTP3Closer) RuntimeCloseAndWait() error { return c.transport.Close() }

type outboundFailedRoundTripper struct{ err error }

func (t outboundFailedRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, t.err
}
