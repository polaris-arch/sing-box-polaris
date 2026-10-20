package bridge

import (
	"context"
	"net"
	"net/netip"
	"slices"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.BridgeOutboundOptions](registry, C.TypeBridge, NewOutbound)
}

var (
	_ adapter.Outbound                    = (*Outbound)(nil)
	_ adapter.FlowOutbound                = (*Outbound)(nil)
	_ adapter.OutboundWithPreferredRoutes = (*Outbound)(nil)
	_ adapter.Lifecycle                   = (*Outbound)(nil)
)

type Backend interface {
	adapter.Lifecycle
	tun.Port
}

type Outbound struct {
	outbound.Adapter
	runtimeSource       adapter.RuntimeResourceSource
	runtimeCalls        *outbound.RuntimeIOFence
	runtimeStarts       *outbound.RuntimeIOFence
	runtimeCleanup      func() error
	runtimeCapabilities any
	backendScope        *adapter.Scope
	constructionCleanup bool
	logger              log.ContextLogger
	networkManager      adapter.NetworkManager
	platformInterface   adapter.PlatformInterface
	backend             Backend
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.BridgeOutboundOptions) (adapter.Outbound, error) {
	ctx, cancel := context.WithCancel(ctx)
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	outboundBackend, err := newBackend(ctx, logger, networkManager, tag, options)
	if err != nil {
		cancel()
		return nil, err
	}
	instance := &Outbound{
		Adapter:           outbound.NewAdapter(C.TypeBridge, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, nil),
		logger:            logger,
		networkManager:    networkManager,
		platformInterface: service.FromContext[adapter.PlatformInterface](ctx),
		backend:           outboundBackend,
	}
	instance.initRuntime(ctx, cancel, logger)
	registered, err := outbound.RegisterRuntimeCleanup(ctx, instance.runtimeCleanup)
	instance.constructionCleanup = registered
	if err != nil {
		return nil, err
	}
	return instance, nil
}

func (o *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if err := scope.Context().Err(); err != nil {
		_ = o.runtimeCleanup()
		return err
	}
	if !o.constructionCleanup {
		registered, err := outbound.RegisterRuntimeCleanup(adapter.ContextWithConstructionScope(scope.Context(), scope), o.runtimeCleanup)
		o.constructionCleanup = registered
		if err != nil {
			return err
		}
	}
	release, err := o.runtimeStarts.Acquire()
	if err != nil {
		return err
	}
	err = o.backend.Start(stage, o.backendScope)
	release()
	return err
}

func (o *Outbound) PreferredDomain(metadata *adapter.InboundContext, domain string) bool {
	return false
}

func (o *Outbound) PreferredAddress(metadata *adapter.InboundContext, address netip.Addr) bool {
	release, err := o.runtimeCalls.Acquire()
	if err != nil {
		return false
	}
	defer release()
	return metadata.PreMatch && !o.isLocalDestination(address)
}

func (o *Outbound) PreMatchFlow(network string, destination netip.Addr) adapter.PreMatchAction {
	release, err := o.runtimeCalls.Acquire()
	if err != nil {
		return adapter.PreMatchReject
	}
	defer release()
	if o.isLocalDestination(destination) {
		o.logger.Warn("rejected connection to local destination ", destination, ": traffic to local addresses is not supported by bridge, exclude them in route rules")
		return adapter.PreMatchReject
	}
	return adapter.PreMatchFlow
}

func (o *Outbound) isLocalDestination(destination netip.Addr) bool {
	if !destination.IsValid() {
		return false
	}
	destination = destination.Unmap()
	if destination.IsLoopback() || destination.IsUnspecified() {
		return true
	}
	if o.platformInterface != nil && slices.Contains(o.platformInterface.MyInterfaceAddress(), destination) {
		return true
	}
	for _, netInterface := range o.networkManager.InterfaceFinder().Interfaces() {
		for _, prefix := range netInterface.Addresses {
			if prefix.Addr() == destination {
				return true
			}
		}
	}
	return false
}

func (o *Outbound) PortAddresses() (netip.Addr, netip.Addr) {
	release, err := o.runtimeCalls.Acquire()
	if err != nil {
		return netip.Addr{}, netip.Addr{}
	}
	defer release()
	return o.backend.PortAddresses()
}

func (o *Outbound) PortMTU() uint32 {
	release, err := o.runtimeCalls.Acquire()
	if err != nil {
		return 0
	}
	defer release()
	return o.backend.PortMTU()
}

func (o *Outbound) UpstreamPort() any {
	return o.runtimeCapabilities
}

func (o *Outbound) AttachReturn(returnPath tun.Return) error {
	release, err := o.runtimeCalls.Acquire()
	if err != nil {
		return err
	}
	defer release()
	return o.backend.AttachReturn(returnPath)
}

func (o *Outbound) DetachReturn(returnPath tun.Return) error {
	release, err := o.runtimeCalls.Acquire()
	if err != nil {
		return err
	}
	defer release()
	return o.backend.DetachReturn(returnPath)
}

func (o *Outbound) WritePackets(packets [][]byte) error {
	release, err := o.runtimeCalls.Acquire()
	if err != nil {
		return err
	}
	defer release()
	return o.backend.WritePackets(packets)
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return outbound.DialRuntimeConn(ctx, o.runtimeSource, func(ctx context.Context) (net.Conn, error) {
		return o.dialContext(ctx, network, destination)
	})
}

func (o *Outbound) dialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, E.New("only L3 traffic is supported by bridge")
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return outbound.ListenRuntimePacket(ctx, o.runtimeSource, func(ctx context.Context) (net.PacketConn, error) {
		return o.listenPacket(ctx, destination)
	})
}

func (o *Outbound) listenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("only L3 traffic is supported by bridge")
}
