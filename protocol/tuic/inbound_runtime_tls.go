//go:build with_quic

package tuic

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/transport/runtimeingress"
	qtls "github.com/sagernet/sing-quic"
)

type inboundRuntimeTLS struct {
	tls.ServerConfig
	runtime          *inboundRuntime
	listener         *listener.Listener
	transportOptions inboundQUICTransportOptions
	ready            chan struct{}
	readyOnce        sync.Once
}

var (
	_ qtls.ServerConfig  = (*inboundRuntimeTLS)(nil)
	_ qtls.ServerRuntime = (*inboundRuntimeTLS)(nil)
)

func (c *inboundRuntimeTLS) RuntimeValidate() error { return tls.ValidateRuntimeServer(c.ServerConfig) }
func (c *inboundRuntimeTLS) Listen(packet net.PacketConn, config *quic.Config) (qtls.Listener, error) {
	return c.listen(packet, config, false)
}

func (c *inboundRuntimeTLS) ListenEarly(packet net.PacketConn, config *quic.Config) (qtls.EarlyListener, error) {
	return c.listen(packet, config, true)
}

func (c *inboundRuntimeTLS) listen(packet net.PacketConn, config *quic.Config, early bool) (qtls.Listener, error) {
	// Packet is precisely the XPlus/Salamander/Gecko wrapper supplied by Start.
	endpoint, err := runtimeingress.ListenQUICPacket(c.runtime.ctx, c.listener, packet, c.ServerConfig, config, early, runtimeingress.QUICTransportOptions{DisableVersionNegotiationPackets: c.transportOptions.DisableVersionNegotiationPackets, StatelessReset: c.transportOptions.StatelessReset})
	if err != nil {
		return nil, err
	}
	c.ready = make(chan struct{})
	return &inboundRuntimeAcceptor{QUICEndpoint: endpoint, owner: c}, nil
}

func (c *inboundRuntimeTLS) ConfigureHTTP3() {
	// Match qtls.ConfigureHTTP3's standard-config branch, without discarding the
	// optional server lifecycle hook used by ListenWithOptions.
	standard, err := c.ServerConfig.STDConfig()
	if err != nil {
		c.runtime.record(err)
		return
	}
	http3.ConfigureTLSConfig(standard)
}

func (c *inboundRuntimeTLS) waitReady() error {
	if c.ready == nil {
		return errors.New("QUIC service returned without installing its private endpoint")
	}
	select {
	case <-c.ready:
		select {
		case <-c.runtime.failed:
			return errors.New("QUIC accept worker failed")
		default:
			return nil
		}
	case <-c.runtime.ctx.Done():
		return c.runtime.ctx.Err()
	case <-c.runtime.failed:
		return errors.New("QUIC accept worker failed before readiness")
	}
}

type inboundRuntimeAcceptor struct {
	*runtimeingress.QUICEndpoint
	owner *inboundRuntimeTLS
}

func (l *inboundRuntimeAcceptor) Accept(ctx context.Context) (*quic.Conn, error) {
	l.owner.readyOnce.Do(func() { close(l.owner.ready) })
	return l.QUICEndpoint.Accept(ctx)
}

// Preserve constructor services and exact physical cancellation separately.
// This borrows the endpoint's session lease, never a worker's temporary fork.
type inboundSessionContext struct {
	context.Context
	physical context.Context
}

func (c inboundSessionContext) Deadline() (time.Time, bool) { return c.physical.Deadline() }
func (c inboundSessionContext) Done() <-chan struct{}       { return c.physical.Done() }
func (c inboundSessionContext) Err() error                  { return c.physical.Err() }
func (c *inboundRuntimeTLS) RuntimeServerContext(fallback context.Context, connection *quic.Conn) (context.Context, error) {
	if connection == nil {
		return nil, errors.New("missing accepted physical QUIC connection")
	}
	return c.sessionContext(fallback, connection.Context())
}

func (c *inboundRuntimeTLS) sessionContext(fallback, physical context.Context) (context.Context, error) {
	if _, ok := adapter.RuntimeLeaseFromContext(physical); !ok {
		return nil, errors.New("QUIC connection lacks admitted graph")
	}
	if err := physical.Err(); err != nil {
		return nil, err
	}
	return inboundSessionContext{Context: adapter.ContextWithRuntimeOwnership(fallback, physical), physical: physical}, nil
}

func (c *inboundRuntimeTLS) RuntimeServerTask(ctx context.Context, task func(context.Context)) bool {
	return c.runtime.runTask(ctx, task)
}
