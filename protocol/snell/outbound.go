package snell

import (
	"context"
	"errors"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	snellprotocol "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.SnellOutboundOptions](registry, C.TypeSnell, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	runtimeSource       adapter.RuntimeResourceSource
	runtimeContext      context.Context
	runtimeCleanup      func() error
	constructionCleanup bool
	runtimeDialer       *runtimeDialer
	logger              logger.ContextLogger
	dialer              N.Dialer
	client              snellClient
	serverAddr          M.Socksaddr
	reuse               bool
}

var (
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
	_ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
)

type snellClient interface {
	snellprotocol.Method
	DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	Reset()
	SetKeepIdleConnections(keep bool)
	CloseIdleConnections()
	Close() error
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SnellOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	ownedDialer := newRuntimeDialer(ctx, outboundDialer)
	serverAddr := options.ServerOptions.Build()
	var client snellClient
	switch options.Version {
	case 4:
		var obfsMode snellprotocol.ObfsMode
		obfsMode, err = snellprotocol.ParseObfsMode(options.ObfsOptions.ObfsMode)
		if err != nil {
			return nil, err
		}
		client, err = snellv4.NewClient(snellv4.ClientOptions{
			PSK:      []byte(options.PSK),
			UserKey:  []byte(options.UserKey),
			Reuse:    options.Reuse,
			ObfsMode: obfsMode,
			ObfsHost: options.ObfsOptions.ObfsHost,
			Dialer:   ownedDialer,
			Server:   serverAddr,
		})
	case 6:
		var mode snellv6.Mode
		mode, err = snellv6.ParseMode(options.V6Options.Mode)
		if err != nil {
			return nil, err
		}
		client, err = snellv6.NewClient(snellv6.ClientOptions{
			PSK:     []byte(options.PSK),
			UserKey: []byte(options.UserKey),
			Mode:    mode,
			Reuse:   options.Reuse,
			Dialer:  ownedDialer,
			Server:  serverAddr,
		})
	case 0:
		return nil, E.New("snell: missing version")
	default:
		return nil, E.New("snell: unsupported version: ", options.Version)
	}
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter:       outbound.NewAdapterWithDialerOptions(C.TypeSnell, tag, options.Network.Build(), options.DialerOptions),
		logger:        logger,
		dialer:        outboundDialer,
		runtimeDialer: ownedDialer,
		client:        client,
		serverAddr:    serverAddr,
		reuse:         options.Reuse,
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

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return outbound.DialRuntimeConn(ctx, h.runtimeSource, func(ctx context.Context) (net.Conn, error) {
		return h.dialContext(ctx, network, destination)
	})
}

func (h *Outbound) dialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	networkName := N.NetworkName(network)
	switch networkName {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.client.DialContext(ctx, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		conn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
		if err != nil {
			return nil, err
		}
		packetConn, err := h.client.DialPacketConn(conn)
		if err != nil {
			return nil, errors.Join(err, outbound.CloseRuntimeCreation(ctx, h.runtimeSource, conn.Close))
		}
		return bufio.NewBindPacketConn(packetConn, destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
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
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	conn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	if err != nil {
		return nil, err
	}
	packetConn, err := h.client.DialPacketConn(conn)
	if err != nil {
		return nil, errors.Join(err, outbound.CloseRuntimeCreation(ctx, h.runtimeSource, conn.Close))
	}
	return packetConn, nil
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	_, release, err := adapter.AcquireRuntimeOperation(ctx, h.runtimeSource)
	if err != nil {
		return
	}
	defer release()
	h.client.Reset()
}

func (h *Outbound) MultiplexEnabled() bool {
	return h.reuse
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

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	return h.registerRuntimeStart(scope)
}
