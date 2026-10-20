package masque

import (
	"context"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/iponly"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/service/oomkiller"
	"github.com/sagernet/sing-box/transport/device"
	"github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const defaultKeepAlivePeriod = 10 * time.Second

var (
	_ adapter.OutboundWithPreferredRoutes = (*ClientEndpoint)(nil)
	_ adapter.FlowOutbound                = (*ClientEndpoint)(nil)
	_ adapter.InterfaceUpdateListener     = (*ClientEndpoint)(nil)
	_ adapter.OnDemandEndpoint            = (*ClientEndpoint)(nil)
	_ dialer.PacketDialerWithDestination  = (*ClientEndpoint)(nil)
	_ masque.ClientHandler                = (*ClientEndpoint)(nil)
)

type ClientEndpoint struct {
	endpointBase
	ctx           context.Context
	dnsRouter     adapter.DNSRouter
	client        *masque.Client
	deviceOptions *device.Options
	device        device.Device
	mtu           uint32
	onDemand      bool
	stateAccess   sync.Mutex
	deviceStarted bool
	state         atomic.Pointer[clientState]
}

type clientState struct {
	configured     bool
	localAddresses []netip.Prefix
	routes         []masque.AddressRange
}

func NewClientEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MASQUEClientEndpointOptions) (adapter.Endpoint, error) {
	if options.MTU == 0 {
		options.MTU = masque.DefaultMTU
	}
	version := options.ResolvedVersion()
	http2Options := options.HTTP2Options
	if version == 3 {
		http2Options = options.HTTP3Options.HTTP2Options
		if options.Version == 0 && http.NewHTTP3Client == nil {
			version = 2
		}
	}
	if http2Options.KeepAlivePeriod == 0 {
		http2Options.KeepAlivePeriod = badoption.Duration(defaultKeepAlivePeriod)
	}
	options.HTTP3Options.HTTP2Options = http2Options
	if options.HTTP3Options.InitialPacketSize == 0 {
		options.HTTP3Options.InitialPacketSize = min(int(options.MTU)+masque.QUICPacketOverhead, math.MaxUint16)
	}
	clientEndpoint := &ClientEndpoint{
		endpointBase: endpointBase{
			Adapter: endpoint.NewAdapterWithDialerOptions(C.TypeMASQUEClient, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, options.DialerOptions),
			router:  router,
			logger:  logger,
		},
		ctx:       ctx,
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
		mtu:       options.MTU,
		onDemand:  options.OnDemand,
	}
	clientEndpoint.state.Store(&clientState{})
	if err := clientEndpoint.initializeRuntime(ctx, options.System); err != nil {
		return nil, err
	}
	logger = clientEndpoint.logger
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:          ctx,
		Options:          options.DialerOptions,
		RemoteIsDomain:   options.ServerIsDomain(),
		ResolverOnDetour: true,
		NewDialer:        true,
	})
	if err != nil {
		return nil, err
	}
	if clientEndpoint.runtime != nil {
		outboundDialer = clientEndpoint.runtime.wrapDialer(outboundDialer)
	}
	headers := options.Headers.Build()
	authority := headers.Get("Host")
	headers.Del("Host")
	if authority == "" {
		server := options.ServerOptions.Build()
		authority = server.String()
		if server.Port == 443 {
			authority = server.AddrString()
			if server.IsIPv6() {
				authority = "[" + authority + "]"
			}
		}
	}
	httpClient, err := http.NewClientWithTLS(ctx, logger, outboundDialer, options.ServerOptions, common.PtrValueOrDefault(options.TLS), http.ClientOptions{
		Authority:              authority,
		Username:               options.Username,
		Password:               options.Password,
		Headers:                headers,
		Version:                version,
		DisableVersionFallback: options.DisableVersionFallback,
		HTTP2Options:           http2Options,
		HTTP3Options:           options.HTTP3Options,
	})
	if err != nil {
		return nil, err
	}

	clientEndpoint.deviceOptions = newDeviceOptions(ctx, logger, clientEndpoint, options.MASQUEEndpointOptions, time.Duration(options.UDPTimeout), nil)
	nativeContext := ctx
	if clientEndpoint.runtime != nil {
		var release func()
		nativeContext, release, err = clientEndpoint.runtime.begin(ctx)
		if err != nil {
			return nil, E.Errors(err, httpClient.Close())
		}
		clientEndpoint.runtime.nativeRelease = release
		nativeContext, err = outbound.ContextForRuntimeOwnedSession(nativeContext, clientEndpoint.runtime.source)
		if err != nil {
			release()
			return nil, E.Errors(err, httpClient.Close())
		}
	}
	clientEndpoint.client, err = masque.NewClient(masque.ClientOptions{
		Context:         nativeContext,
		Logger:          logger,
		HTTPClient:      httpClient,
		Path:            options.Path,
		AdvertiseRoutes: options.AdvertiseRoutes,
		Handler:         clientEndpoint,
	})
	if err != nil {
		return nil, E.Errors(err, httpClient.Close())
	}
	if clientEndpoint.runtime != nil {
		if err := clientEndpoint.runtime.installNative(clientEndpoint.client.Close); err != nil {
			return nil, err
		}
		clientEndpoint.runtime.scope.Add(clientEndpoint.closeNativeClient)
	}
	return clientEndpoint, nil
}

func (c *ClientEndpoint) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		c.deviceOptions.MemoryPressure = oomkiller.MemoryPressure(c.ctx)
		tunnelDevice, err := device.New(*c.deviceOptions)
		if err != nil {
			return err
		}
		scope.Add(func() error { return device.CloseAndWait(tunnelDevice) })
		tunnelDevice.SetPacketWriter(c.writePacketBuffers)
		c.device = tunnelDevice
		c.deviceOptions = nil
		scope.Add(c.closeNativeClient)
	case adapter.StartStatePostStart:
		c.client.Start()
	}
	return nil
}

func (c *ClientEndpoint) UpdateConfiguration(configuration masque.Configuration) error {
	if c.runtime != nil {
		leave, err := c.runtime.callbacks.Acquire()
		if err != nil {
			return err
		}
		defer leave()
	}
	c.stateAccess.Lock()
	defer c.stateAccess.Unlock()
	err := c.device.UpdateConfiguration(device.Configuration{
		MTU:     c.mtu,
		Address: configuration.Address,
	})
	if err != nil {
		return E.Cause(err, "update device configuration")
	}
	if !c.deviceStarted {
		err = c.device.Start()
		if err != nil {
			return E.Cause(err, "start device")
		}
		c.deviceStarted = true
	}
	if !slices.Equal(c.state.Load().localAddresses, configuration.Address) {
		c.logger.Info("assigned ", strings.Join(common.Map(configuration.Address, netip.Prefix.String), " "))
	}
	c.state.Store(&clientState{
		configured:     true,
		localAddresses: configuration.Address,
		routes:         configuration.Routes,
	})
	return nil
}

func (c *ClientEndpoint) WriteInboundBuffers(packetBuffers []*buf.Buffer) error {
	if c.runtime != nil {
		leave, err := c.runtime.callbacks.Acquire()
		if err != nil {
			buf.ReleaseMulti(packetBuffers)
			return err
		}
		defer leave()
	}
	if !c.state.Load().configured {
		buf.ReleaseMulti(packetBuffers)
		return nil
	}
	err := c.device.WriteInboundBuffers(packetBuffers)
	buf.ReleaseMulti(packetBuffers)
	return err
}

func (c *ClientEndpoint) FrontHeadroom() int {
	if c.runtime != nil {
		leave, err := c.runtime.callbacks.Acquire()
		if err != nil {
			return 0
		}
		defer leave()
	}
	return c.device.FrontHeadroom()
}

func (c *ClientEndpoint) InterfaceUpdated(ctx context.Context) {
	if c.runtime != nil {
		leave, err := c.runtime.acquire()
		if err != nil {
			return
		}
		defer leave()
	}
	c.client.RestartSession()
}

func (c *ClientEndpoint) OnDemand() bool {
	return c.onDemand
}

func (c *ClientEndpoint) SetKeepIdleConnections(keep bool) {
	if c.runtime != nil {
		leave, err := c.runtime.acquire()
		if err != nil {
			return
		}
		defer leave()
	}
	if keep {
		c.client.Resume()
	} else {
		c.client.Suspend()
	}
}

func (c *ClientEndpoint) waitReady(ctx context.Context) error {
	if !c.onDemand {
		if !c.client.Ready() {
			return E.New("endpoint is not ready yet")
		}
		return nil
	}
	c.client.Resume()
	waitCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()
	return c.client.WaitReady(waitCtx)
}

func (c *ClientEndpoint) PreMatchFlow(network string, destination netip.Addr) adapter.PreMatchAction {
	return adapter.PreMatchFlow
}

func (c *ClientEndpoint) PortAddresses() (netip.Addr, netip.Addr) {
	if c.runtime != nil {
		leave, err := c.runtime.acquire()
		if err != nil {
			return netip.Addr{}, netip.Addr{}
		}
		defer leave()
	}
	return c.device.PortAddresses()
}

func (c *ClientEndpoint) PortMTU() uint32 {
	if c.runtime != nil {
		leave, err := c.runtime.acquire()
		if err != nil {
			return 0
		}
		defer leave()
	}
	return c.device.PortMTU()
}

func (c *ClientEndpoint) UpstreamPort() any {
	if c.runtime != nil {
		return c
	}
	return c.device
}

func (c *ClientEndpoint) AttachReturn(returnPath tun.Return) error {
	if c.runtime != nil {
		leave, err := c.runtime.acquire()
		if err != nil {
			return err
		}
		defer leave()
	}
	return c.device.AttachReturn(returnPath)
}

func (c *ClientEndpoint) DetachReturn(returnPath tun.Return) error {
	if c.runtime != nil {
		leave, err := c.runtime.acquire()
		if err != nil {
			return err
		}
		defer leave()
	}
	return c.device.DetachReturn(returnPath)
}

func (c *ClientEndpoint) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	if c.runtime != nil && !c.runtime.ingress.Load() {
		return tun.FlowVerdict{Action: tun.ActionDrop}
	}
	if c.runtime != nil {
		leave, err := c.runtime.callbacks.Acquire()
		if err != nil {
			return tun.FlowVerdict{Action: tun.ActionDrop}
		}
		defer leave()
	}
	return c.judgeFlow(c, c.state.Load().localAddresses, network, source, destination, firstPacket)
}

func (c *ClientEndpoint) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
	c.NewDNSPacketEx(c.ctx, payload, source, destination, writer)
}

// NewDNSPacketEx forwards the borrowed packet admission synchronously.
// HijackDNSPacket owns the fork before asynchronous DNS work is published.
func (c *ClientEndpoint) NewDNSPacketEx(ctx context.Context, payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
	if c.runtime != nil && !c.runtime.ingress.Load() {
		return
	}
	if c.runtime != nil {
		leave, err := c.runtime.callbacks.Acquire()
		if err != nil {
			return
		}
		defer leave()
	}
	if c.runtime != nil {
		owned, release, err := adapter.AcquireRuntimeOperation(ctx, c.runtime.source)
		if err != nil {
			return
		}
		defer release()
		ctx = owned
	}
	c.newDNSPacket(log.ContextWithNewID(ctx), c, payload, source, destination, writer)
}

func (c *ClientEndpoint) WritePackets(packets [][]byte) error {
	if c.runtime != nil {
		leave, err := c.runtime.acquire()
		if err != nil {
			return err
		}
		defer leave()
	}
	if c.onDemand {
		c.client.Resume()
	}
	if !c.client.Ready() {
		return E.New("endpoint is not ready yet")
	}
	return c.client.WritePacketBuffers(common.Map(packets, func(packet []byte) *buf.Buffer {
		packetBuffer := buf.NewSize(masque.PacketHeadroom + len(packet))
		packetBuffer.Resize(masque.PacketHeadroom, 0)
		common.Must1(packetBuffer.Write(packet))
		return packetBuffer
	}), true)
}

func (c *ClientEndpoint) writePacketBuffers(packetBuffers []*buf.Buffer) error {
	if c.runtime != nil {
		leave, err := c.runtime.callbacks.Acquire()
		if err != nil {
			buf.ReleaseMulti(packetBuffers)
			return err
		}
		defer leave()
	}
	if c.onDemand {
		c.client.Resume()
	}
	return c.client.WritePacketBuffers(packetBuffers, false)
}

func (c *ClientEndpoint) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if c.runtime != nil && !c.runtime.ingress.Load() {
		N.CloseOnHandshakeFailure(conn, onClose, net.ErrClosed)
		return
	}
	if c.runtime != nil {
		leave, err := c.runtime.callbacks.Acquire()
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			return
		}
		defer leave()
	}
	if c.runtime != nil {
		var err error
		ctx, conn, onClose, err = c.runtime.wrapInboundConn(ctx, conn, onClose)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			return
		}
	}
	c.newConnection(ctx, c, c.state.Load().localAddresses, conn, source, destination, onClose)
}

func (c *ClientEndpoint) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if c.runtime != nil && !c.runtime.ingress.Load() {
		N.CloseOnHandshakeFailure(conn, onClose, net.ErrClosed)
		return
	}
	if c.runtime != nil {
		leave, err := c.runtime.callbacks.Acquire()
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			return
		}
		defer leave()
	}
	if c.runtime != nil {
		var err error
		ctx, conn, onClose, err = c.runtime.wrapInboundPacket(ctx, conn, onClose)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			return
		}
	}
	c.newPacketConnection(ctx, c, c.state.Load().localAddresses, conn, source, destination, onClose)
}

func (c *ClientEndpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if c.runtime == nil {
		return c.dialContext(ctx, network, destination)
	}
	return outbound.DialRuntimeConn(ctx, c.runtime.source, func(ctx context.Context) (net.Conn, error) {
		leave, err := c.runtime.acquire()
		if err != nil {
			return nil, err
		}
		defer leave()
		return c.dialContext(ctx, network, destination)
	})
}

func (c *ClientEndpoint) dialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch network {
	case N.NetworkTCP:
		c.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		c.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	err := c.waitReady(ctx)
	if err != nil {
		return nil, err
	}
	if destination.IsDomain() {
		destinationAddresses, lookupErr := c.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if lookupErr != nil {
			return nil, lookupErr
		}
		return N.DialSerial(ctx, c.device, network, destination, destinationAddresses)
	}
	if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return c.device.DialContext(ctx, network, destination)
}

func (c *ClientEndpoint) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	if c.runtime == nil {
		return c.listenPacketWithDestination(ctx, destination)
	}
	var address netip.Addr
	packet, err := outbound.ListenRuntimePacket(ctx, c.runtime.source, func(ctx context.Context) (net.PacketConn, error) {
		leave, err := c.runtime.acquire()
		if err != nil {
			return nil, err
		}
		defer leave()
		var packet net.PacketConn
		packet, address, err = c.listenPacketWithDestination(ctx, destination)
		return packet, err
	})
	return packet, address, err
}

func (c *ClientEndpoint) listenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	c.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	err := c.waitReady(ctx)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if destination.IsDomain() {
		destinationAddresses, lookupErr := c.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if lookupErr != nil {
			return nil, netip.Addr{}, lookupErr
		}
		packetConn, destinationAddress, listenErr := N.ListenSerial(ctx, c.device, destination, destinationAddresses)
		if listenErr != nil {
			return nil, netip.Addr{}, listenErr
		}
		return iponly.NewPacketConn(c.logger, packetConn), destinationAddress, nil
	}
	packetConn, err := c.device.ListenPacket(ctx, destination)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if destination.IsIP() {
		return iponly.NewPacketConn(c.logger, packetConn), destination.Addr, nil
	}
	return iponly.NewPacketConn(c.logger, packetConn), netip.Addr{}, nil
}

func (c *ClientEndpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	packetConn, destinationAddress, err := c.ListenPacketWithDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	if destinationAddress.IsValid() && destination != M.SocksaddrFrom(destinationAddress, destination.Port) {
		return bufio.NewNATPacketConn(bufio.NewPacketConn(packetConn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
	}
	return packetConn, nil
}

func (c *ClientEndpoint) PreferredDomain(metadata *adapter.InboundContext, domain string) bool {
	if c.runtime != nil {
		leave, err := c.runtime.acquire()
		if err != nil {
			return false
		}
		defer leave()
	}
	return false
}

func (c *ClientEndpoint) PreferredAddress(metadata *adapter.InboundContext, address netip.Addr) bool {
	if c.runtime != nil {
		leave, err := c.runtime.acquire()
		if err != nil {
			return false
		}
		defer leave()
	}
	state := c.state.Load()
	if !state.configured || !c.client.Ready() {
		return false
	}
	var protocol uint8
	switch metadata.Network {
	case N.NetworkTCP:
		protocol = uint8(header.TCPProtocolNumber)
	case N.NetworkUDP:
		protocol = uint8(header.UDPProtocolNumber)
	case N.NetworkICMP:
		protocol = uint8(header.ICMPv4ProtocolNumber)
	}
	return masque.RoutesContain(state.routes, address, protocol)
}

var _ tun.DNSPacketHandlerEx = (*ClientEndpoint)(nil)
