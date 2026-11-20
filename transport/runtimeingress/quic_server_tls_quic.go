//go:build with_quic

package runtimeingress

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	qtls "github.com/sagernet/sing-quic"
)

var (
	_ qtls.ServerConfig  = (*QUICServerTLS)(nil)
	_ qtls.ServerRuntime = (*QUICServerTLS)(nil)
)

func (c *QUICServerTLS) RuntimeValidate() error { return tls.ValidateRuntimeServer(c.ServerConfig) }

func (c *QUICServerTLS) Listen(packet net.PacketConn, config *quic.Config) (qtls.Listener, error) {
	return c.listen(packet, config, false)
}

func (c *QUICServerTLS) ListenEarly(packet net.PacketConn, config *quic.Config) (qtls.EarlyListener, error) {
	return c.listen(packet, config, true)
}

func (c *QUICServerTLS) listen(packet net.PacketConn, config *quic.Config, early bool) (qtls.Listener, error) {
	// Packet is precisely the XPlus/Salamander/Gecko wrapper supplied by Start.
	transportOptions := QUICTransportOptions{
		DisableVersionNegotiationPackets: c.options.DisableVersionNegotiationPackets,
		StatelessReset:                   c.options.StatelessReset,
	}
	endpoint, err := ListenQUICPacket(c.options.Context, c.options.Listener, packet, c.ServerConfig, config, early, transportOptions)
	if err != nil {
		return nil, err
	}
	c.ready = make(chan struct{})
	return &quicServerAcceptor{QUICEndpoint: endpoint, owner: c}, nil
}

func (c *QUICServerTLS) ConfigureHTTP3() {
	// Match qtls.ConfigureHTTP3's standard-config branch, without discarding the
	// optional server lifecycle hook used by ListenWithOptions.
	standard, err := c.ServerConfig.STDConfig()
	if err != nil {
		c.options.RecordFailure(err)
		return
	}
	http3.ConfigureTLSConfig(standard)
}

func (c *QUICServerTLS) WaitReady() error {
	if c.ready == nil {
		return errors.New("QUIC service returned without installing its private endpoint")
	}
	select {
	case <-c.ready:
		select {
		case <-c.options.Failed:
			return errors.New("QUIC accept worker failed")
		default:
			return nil
		}
	case <-c.options.Context.Done():
		return c.options.Context.Err()
	case <-c.options.Failed:
		return errors.New("QUIC accept worker failed before readiness")
	}
}

type quicServerAcceptor struct {
	*QUICEndpoint
	owner *QUICServerTLS
}

func (l *quicServerAcceptor) Accept(ctx context.Context) (*quic.Conn, error) {
	l.owner.readyOnce.Do(func() { close(l.owner.ready) })
	return l.QUICEndpoint.Accept(ctx)
}

// Preserve constructor services and exact physical cancellation separately.
// This borrows the endpoint's session lease, never a worker's temporary fork.
type quicSessionContext struct {
	context.Context
	physical context.Context
}

func (c quicSessionContext) Deadline() (time.Time, bool) { return c.physical.Deadline() }
func (c quicSessionContext) Done() <-chan struct{}       { return c.physical.Done() }
func (c quicSessionContext) Err() error                  { return c.physical.Err() }
func (c *QUICServerTLS) RuntimeServerContext(fallback context.Context, connection *quic.Conn) (context.Context, error) {
	if connection == nil {
		return nil, errors.New("missing accepted physical QUIC connection")
	}
	return quicServerSessionContext(fallback, connection.Context())
}

func quicServerSessionContext(fallback, physical context.Context) (context.Context, error) {
	if _, ok := adapter.RuntimeLeaseFromContext(physical); !ok {
		return nil, errors.New("QUIC connection lacks admitted graph")
	}
	if err := physical.Err(); err != nil {
		return nil, err
	}
	return quicSessionContext{Context: adapter.ContextWithRuntimeOwnership(fallback, physical), physical: physical}, nil
}

func (c *QUICServerTLS) RuntimeServerTask(ctx context.Context, task func(context.Context)) bool {
	return c.options.RunTask(ctx, task)
}
