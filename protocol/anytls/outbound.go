package anytls

import (
	"context"
	"net"
	"os"

	"github.com/sagernet/sing-anytls"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.AnyTLSOutboundOptions](registry, C.TypeAnyTLS, NewOutbound)
}

var (
	_ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	runtimeSource       adapter.RuntimeResourceSource
	runtimeContext      context.Context
	runtimeCleanup      func() error
	constructionCleanup bool
	runtimeFences       *outbound.RuntimeIOFenceSet
	runtimeCallbacks    *outbound.RuntimeIOFence
	runtimeStop         context.Context
	runtimeCancel       context.CancelFunc
	dialer              tls.Dialer
	server              M.Socksaddr
	tlsConfig           tls.Config
	clientOptions       anytls.ClientOptions
	client              *anytls.Client
	uotClient           *uot.Client
	logger              log.ContextLogger
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AnyTLSOutboundOptions) (adapter.Outbound, error) {
	outbound := &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeAnyTLS, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		server:  options.ServerOptions.Build(),
		logger:  logger,
	}
	if err := outbound.initRuntimeCleanup(ctx); err != nil {
		return nil, err
	}
	constructed := false
	defer func() {
		if !constructed && !outbound.constructionCleanup {
			_ = outbound.runtimeCleanup()
		}
	}()
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	if options.DialerOptions.TCPFastOpen {
		return nil, E.New("tcp_fast_open is not supported with anytls outbound")
	}

	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	outbound.tlsConfig = tlsConfig

	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		RemoteIsDomain: options.ServerIsDomain(),
	})
	if err != nil {
		return nil, err
	}

	outbound.dialer = tls.NewDialer(outboundDialer, tlsConfig)

	outbound.initRuntimePool()
	outbound.clientOptions = anytls.ClientOptions{
		Password:                 options.Password,
		ClientMetadata:           options.ClientMetadata,
		DialOut:                  outbound.dialOut,
		IdleSessionCheckInterval: options.IdleSessionCheckInterval.Build(),
		IdleSessionTimeout:       options.IdleSessionTimeout.Build(),
		MinIdleSession:           options.MinIdleSession,
		Logger:                   outbound.runtimeLogger(logger),
	}
	outbound.client, err = anytls.NewClient(outbound.clientOptions)
	if err != nil {
		return nil, err
	}
	outbound.uotClient = &uot.Client{Dialer: anytlsDialer(outbound.client.DialContext), Version: uot.Version}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := adapter.ConstructionScopeErr(ctx); err != nil {
		return nil, err
	}
	if err := outbound.finishRuntimeConstruction(ctx); err != nil {
		return nil, err
	}
	constructed = true
	return outbound, nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	return h.registerRuntimeStart(scope)
}

type anytlsDialer func(ctx context.Context, destination M.Socksaddr) (net.Conn, error)

func (d anytlsDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d(ctx, destination)
}

func (d anytlsDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (h *Outbound) dialOut(ctx context.Context) (net.Conn, error) {
	return h.dialRuntimeSession(ctx)
}

func (h *Outbound) MultiplexEnabled() bool {
	return true
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	_, release, err := adapter.AcquireRuntimeOperation(ctx, h.runtimeSource)
	if err != nil {
		return
	}
	defer release()
	h.client.Reset()
}

func (h *Outbound) SetKeepIdleConnections(keep bool) {
	_, release, err := adapter.AcquireRuntimeOperation(context.Background(), h.runtimeSource)
	if err != nil {
		return
	}
	defer release()
	h.client.SetKeepIdleConnections(keep)
}

func (h *Outbound) CloseIdleConnections() {
	_, release, err := adapter.AcquireRuntimeOperation(context.Background(), h.runtimeSource)
	if err != nil {
		return
	}
	defer release()
	h.client.CloseIdleConnections()
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return outbound.DialRuntimeConn(ctx, h.runtimeSource, func(ctx context.Context) (net.Conn, error) {
		return h.dialContext(ctx, network, destination)
	})
}

func (h *Outbound) dialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.client.DialContext(ctx, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		return h.uotClient.DialContext(ctx, network, destination)
	}
	return nil, os.ErrInvalid
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return outbound.ListenRuntimePacket(ctx, h.runtimeSource, func(ctx context.Context) (net.PacketConn, error) {
		return h.listenPacket(ctx, destination)
	})
}

func (h *Outbound) listenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
	return h.uotClient.ListenPacket(ctx, destination)
}
