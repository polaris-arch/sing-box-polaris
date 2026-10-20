package hysteria

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.HysteriaOutboundOptions](registry, C.TypeHysteria, NewOutbound)
}

var (
	_ adapter.Outbound                = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
	_ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
)

type Outbound struct {
	runtime *outboundRuntime

	outbound.Adapter
	logger logger.ContextLogger
	client *hysteria.Client
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HysteriaOutboundOptions) (adapter.Outbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	runtime := newOutboundRuntime(ctx)
	runtime.allowNativeDescriptor = options.Obfs == "" && len(options.ServerPorts) == 0
	constructed := false
	defer func() {
		if !constructed {
			_ = runtime.close()
		}
	}()
	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	networkList := options.Network.Build()
	var password string
	if options.AuthString != "" {
		password = options.AuthString
	} else {
		password = string(options.Auth)
	}
	var sendBps, receiveBps uint64
	if options.Up.Value() > 0 {
		sendBps = options.Up.Value()
	} else {
		sendBps = uint64(options.UpMbps) * hysteria.MbpsToBps
	}
	if options.Down.Value() > 0 {
		receiveBps = options.Down.Value()
	} else {
		receiveBps = uint64(options.DownMbps) * hysteria.MbpsToBps
	}
	tlsConfig, err = runtime.guardTLS(tlsConfig)
	if err != nil {
		return nil, err
	}
	client, err := hysteria.NewClient(hysteria.ClientOptions{
		Context:       runtime.ctx,
		Dialer:        runtime.guardDialer(outboundDialer),
		Logger:        outbound.WrapRuntimeLogger(logger, runtime.fence),
		ServerAddress: options.ServerOptions.Build(),
		ServerPorts:   options.ServerPorts,
		HopInterval:   time.Duration(options.HopInterval),
		SendBPS:       sendBps,
		ReceiveBPS:    receiveBps,
		XPlusPassword: options.Obfs,
		Password:      password,
		TLSConfig:     tlsConfig,
		QUICOptions:   buildOutboundQUICOptions(options),
		UDPDisabled:   !common.Contains(networkList, N.NetworkUDP),
	})
	if err != nil {
		return nil, err
	}
	if err = runtime.install(ctx, client); err != nil {
		return nil, err
	}
	constructed = true
	return &Outbound{
		runtime: runtime,
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeHysteria, tag, networkList, options.DialerOptions),
		logger:  logger,
		client:  client,
	}, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return outbound.DialRuntimeConn(ctx, h.runtime.source, func(ctx context.Context) (net.Conn, error) { return h.dialContextOwned(ctx, network, destination) })
}

func (h *Outbound) dialContextOwned(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.client.DialConn(ctx, destination)
	case N.NetworkUDP:
		conn, err := h.listenPacketOwned(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(conn, destination), nil
	default:
		return nil, E.New("unsupported network: ", network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return outbound.ListenRuntimePacket(ctx, h.runtime.source, func(ctx context.Context) (net.PacketConn, error) { return h.listenPacketOwned(ctx, destination) })
}

func (h *Outbound) listenPacketOwned(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return h.client.ListenPacket(ctx, destination)
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	leave, err := h.runtime.fence.Acquire()
	if err != nil {
		return
	}
	defer leave()
	h.client.CloseWithError(E.New("network changed"))
}

func (h *Outbound) MultiplexEnabled() bool {
	return true
}

func (h *Outbound) SetKeepIdleConnections(keep bool) {
	leave, err := h.runtime.fence.Acquire()
	if err != nil {
		return
	}
	defer leave()
	h.client.SetKeepIdleConnections(keep)
}

func (h *Outbound) CloseIdleConnections() {
	leave, err := h.runtime.fence.Acquire()
	if err != nil {
		return
	}
	defer leave()
	h.client.CloseIdleConnections()
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	if !h.runtime.registered {
		scope.Add(h.runtime.close)
	}
	return nil
}
