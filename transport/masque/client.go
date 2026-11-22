package masque

import (
	"context"
	"io"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	transportHTTP "github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

const (
	reconnectBackoffInitial = time.Second
	reconnectBackoffMax     = time.Minute
)

type Configuration struct {
	Address          []netip.Prefix
	Routes           []AddressRange
	RoutesAdvertised bool
}

type ClientHandler interface {
	UpdateConfiguration(configuration Configuration) error
	WriteInboundBuffers(packetBuffers []*buf.Buffer) error
	FrontHeadroom() int
}

type ClientOptions struct {
	Context         context.Context
	Logger          logger.ContextLogger
	HTTPClient      *transportHTTP.Client
	Path            string
	AdvertiseRoutes []netip.Prefix
	Handler         ClientHandler
	StartSuspended  bool
	ScopedProbes    bool
}

type Client struct {
	ctx             context.Context
	cancel          context.CancelFunc
	logger          logger.ContextLogger
	httpClient      *transportHTTP.Client
	template        *Template
	advertiseRoutes []AddressRange
	handler         ClientHandler
	access          sync.Mutex
	current         *clientSession
	probe           *probeActivation
	dialCancel      context.CancelFunc
	probePause      pause.Manager
	stopProbePause  func()
	suspended       bool
	reset           *sessionReset
	lastError       error
	stateUpdated    chan struct{}
	loopDone        chan struct{}
}

type sessionReset struct {
	done  chan struct{}
	apply func()
}

type probeActivation struct {
	ctx        context.Context
	cancel     context.CancelCauseFunc
	users      sync.Map
	persistent atomic.Bool
	count      int
	err        error
}

func (p *probeActivation) allBackground(classify func(context.Context) bool) bool {
	foreground := false
	p.users.Range(func(_, value any) bool {
		ctx := value.(context.Context)
		foreground = ctx.Err() == nil && !classify(ctx) && ctx.Err() == nil
		return !foreground
	})
	return !foreground && !p.persistent.Load()
}

type clientSession struct {
	*session
	client        *Client
	probe         *probeActivation
	access        sync.Mutex
	configuration Configuration
	ready         bool
}

func NewClient(options ClientOptions) (*Client, error) {
	template, err := ParseTemplate(options.Path)
	if err != nil {
		return nil, err
	}
	advertiseRoutes, err := RangesFromPrefixes(options.AdvertiseRoutes, 0)
	if err != nil {
		return nil, E.Cause(err, "build advertised routes")
	}
	ctx, cancel := context.WithCancel(options.Context)
	var probePause pause.Manager
	if options.ScopedProbes {
		probePause = service.FromContext[pause.Manager](ctx)
	}
	return &Client{
		ctx:             ctx,
		cancel:          cancel,
		logger:          options.Logger,
		httpClient:      options.HTTPClient,
		template:        template,
		advertiseRoutes: advertiseRoutes,
		handler:         options.Handler,
		probePause:      probePause,
		suspended:       options.StartSuspended,
		stateUpdated:    make(chan struct{}),
	}, nil
}

func (c *Client) Start() {
	if c.probePause != nil {
		callback := c.probePause.RegisterCallback(func(event int) {
			if event != pause.EventDevicePaused && event != pause.EventNetworkPause {
				return
			}
			c.access.Lock()
			if c.suspended && c.probe != nil {
				c.endProbeLocked(c.probe, urltest.ErrProbeNotRun)
			}
			c.access.Unlock()
		})
		c.stopProbePause = sync.OnceFunc(func() { c.probePause.UnregisterCallback(callback) })
	}
	c.loopDone = make(chan struct{})
	go c.loop()
}

func (c *Client) Close() error {
	c.cancel()
	if c.stopProbePause != nil {
		c.stopProbePause()
	}
	if c.loopDone != nil {
		<-c.loopDone
	}
	return c.httpClient.Close()
}

func (c *Client) notifyStateLocked() {
	close(c.stateUpdated)
	c.stateUpdated = make(chan struct{})
}

func (c *Client) loop() {
	defer close(c.loopDone)
	backoff := reconnectBackoffInitial
	var latestReset *sessionReset
	for {
		c.access.Lock()
		probe := c.probe
		idle := c.suspended && probe == nil
		reset := c.reset
		stateUpdated := c.stateUpdated
		if !idle {
			c.lastError = nil
		}
		c.access.Unlock()
		if c.ctx.Err() != nil {
			return
		}
		if reset != latestReset {
			// Join the exact old pool reset before opening its successor.
			reset.apply()
			latestReset = reset
			backoff = reconnectBackoffInitial
			continue
		}
		if idle {
			select {
			case <-stateUpdated:
				continue
			case <-c.ctx.Done():
				return
			}
		}
		established, err := c.connect(probe, reset)
		if c.ctx.Err() != nil {
			return
		}
		c.access.Lock()
		interrupted := c.reset != reset || (probe != nil && probe.ctx.Err() != nil) || (c.suspended && probe == nil)
		if !interrupted {
			c.lastError = err
		}
		c.notifyStateLocked()
		stateUpdated = c.stateUpdated
		c.access.Unlock()
		if interrupted {
			backoff = reconnectBackoffInitial
			continue
		}
		if err != nil {
			c.logger.Error(E.Cause(err, "connection closed"))
		}
		if established {
			backoff = reconnectBackoffInitial
		}
		timer := time.NewTimer(backoff)
		select {
		case <-timer.C:
		case <-stateUpdated:
			timer.Stop()
		case <-c.ctx.Done():
			timer.Stop()
			return
		}
		backoff = min(backoff*2, reconnectBackoffMax)
	}
}

func (c *Client) connect(probe *probeActivation, reset *sessionReset) (bool, error) {
	ownerCtx := c.ctx
	if probe != nil {
		ownerCtx = probe.ctx
	}
	c.access.Lock()
	if c.reset != reset || (c.suspended && probe == nil) || ownerCtx.Err() != nil {
		c.access.Unlock()
		return false, context.Canceled
	}
	attemptCtx, cancelAttempt := context.WithCancel(ownerCtx)
	c.dialCancel = cancelAttempt
	c.access.Unlock()
	dialCtx := attemptCtx
	if probe != nil {
		dialCtx = urltest.ContextWithSharedBackgroundProbe(attemptCtx, probe.allBackground)
	}
	stream, err := c.openTunnel(dialCtx)
	c.access.Lock()
	if probe != nil && adapter.IsOutboundForegroundSlot(err) {
		if c.probe == probe && c.reset == reset && attemptCtx.Err() == nil {
			if probe.allBackground(urltest.IsBackgroundProbe) {
				c.endProbeLocked(probe, err)
			} else {
				c.access.Unlock()
				stream, err = c.openTunnel(urltest.ContextWithSharedBackgroundProbe(attemptCtx, nil))
				c.access.Lock()
			}
		}
	}
	c.dialCancel = nil
	cancelAttempt()
	if err != nil {
		c.access.Unlock()
		return false, err
	}
	current := &clientSession{client: c, probe: probe}
	if (c.suspended && probe == nil) || c.reset != reset || ownerCtx.Err() != nil {
		c.access.Unlock()
		stream.Close()
		return false, nil
	}
	current.session = newSession(ownerCtx, stream, current, c.handler.FrontHeadroom)
	c.current = current
	c.access.Unlock()
	err = current.run(func() error {
		setupErr := current.writeCapsule(newAddressCapsule(capsuleTypeAddressRequest, []AssignedAddress{
			{RequestID: 1, Prefix: netip.PrefixFrom(netip.IPv4Unspecified(), 32)},
			{RequestID: 2, Prefix: netip.PrefixFrom(netip.IPv6Unspecified(), 128)},
		}))
		if setupErr == nil && len(c.advertiseRoutes) > 0 {
			setupErr = current.writeCapsule(newRouteCapsule(c.advertiseRoutes))
		}
		return setupErr
	})
	c.access.Lock()
	c.current = nil
	c.access.Unlock()
	current.access.Lock()
	established := current.ready
	current.ready = false
	current.access.Unlock()
	return established, err
}

func (c *Client) openTunnel(ctx context.Context) (io.ReadWriteCloser, error) {
	dialCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()
	return c.httpClient.OpenTunnel(dialCtx, upgradeToken, c.template.Expand())
}

func (c *Client) activeSession() *clientSession {
	c.access.Lock()
	defer c.access.Unlock()
	return c.activeSessionLocked()
}

func (c *Client) activeSessionLocked() *clientSession {
	current := c.current
	if current != nil && current.ctx.Err() != nil {
		return nil
	}
	return current
}

func (c *Client) Ready() bool {
	current := c.activeSession()
	if current == nil {
		return false
	}
	current.access.Lock()
	defer current.access.Unlock()
	return current.ready
}

func (c *Client) WaitReady(ctx context.Context) error {
	return c.waitReady(ctx, nil)
}

// WaitReadyForProbe holds a scoped on-demand activation until the caller is
// finished with the connection or packet carrier that uses the tunnel.
func (c *Client) WaitReadyForProbe(ctx context.Context) (func(), error) {
	c.access.Lock()
	if err := ctx.Err(); err != nil {
		c.access.Unlock()
		return nil, err
	}
	if err := c.ctx.Err(); err != nil {
		c.access.Unlock()
		return nil, err
	}
	if c.probePause != nil && (c.probePause.IsDevicePaused() || c.probePause.IsNetworkPaused()) {
		c.access.Unlock()
		return nil, urltest.ErrProbeNotRun
	}
	var release func()
	probe := c.probe
	if c.suspended || probe != nil {
		if probe == nil {
			ownerCtx, cancel := context.WithCancelCause(c.ctx)
			probe = &probeActivation{ctx: ownerCtx, cancel: cancel}
			c.probe = probe
			c.lastError = nil
			c.notifyStateLocked()
		}
		key := &ctx
		probe.users.Store(key, ctx)
		probe.count++
		release = sync.OnceFunc(func() {
			c.access.Lock()
			probe.users.Delete(key)
			probe.count--
			if c.probe == probe && c.suspended && probe.count == 0 {
				c.endProbeLocked(probe, context.Canceled)
			}
			c.access.Unlock()
		})
	}
	c.access.Unlock()
	waitCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()
	if err := c.waitReady(waitCtx, probe); err != nil {
		if release != nil {
			release()
		}
		return nil, err
	}
	return release, nil
}

func (c *Client) endProbeLocked(probe *probeActivation, err error) {
	probe.err = err
	probe.cancel(err)
	c.probe = nil
	c.requestResetLocked()
	c.notifyStateLocked()
}

func (c *Client) requestResetLocked() *sessionReset {
	if c.reset != nil {
		select {
		case <-c.reset.done:
		default:
			return c.reset
		}
	}
	reset := &sessionReset{done: make(chan struct{})}
	reset.apply = sync.OnceFunc(func() {
		defer close(reset.done)
		c.httpClient.ResetConnections()
	})
	c.reset = reset
	return reset
}

func (c *Client) waitReady(ctx context.Context, probe *probeActivation) error {
	for {
		c.access.Lock()
		if probe != nil && probe.err != nil {
			err := probe.err
			c.access.Unlock()
			return err
		}
		current := c.activeSessionLocked()
		lastError := c.lastError
		stateUpdated := c.stateUpdated
		if current != nil && (probe == nil || probe == current.probe) {
			current.access.Lock()
			ready := current.ready
			current.access.Unlock()
			if ready {
				c.access.Unlock()
				return nil
			}
		} else if lastError != nil {
			c.access.Unlock()
			return lastError
		}
		c.access.Unlock()
		select {
		case <-stateUpdated:
		case <-ctx.Done():
			return ctx.Err()
		case <-c.ctx.Done():
			return c.ctx.Err()
		}
	}
}

func (c *Client) Suspend() {
	c.access.Lock()
	probe := c.probe
	if c.suspended && probe == nil {
		c.access.Unlock()
		return
	}
	c.suspended = true
	if c.dialCancel != nil {
		c.dialCancel()
	}
	if c.current != nil {
		c.current.cancel(E.New("suspended"))
	}
	if probe != nil {
		c.endProbeLocked(probe, context.Canceled)
	} else {
		c.requestResetLocked()
		c.notifyStateLocked()
	}
	reset := c.reset
	c.access.Unlock()
	reset.apply()
}

func (c *Client) Resume() {
	c.access.Lock()
	defer c.access.Unlock()
	if !c.suspended {
		return
	}
	c.suspended = false
	if c.probe != nil {
		c.probe.persistent.Store(true)
	}
	c.lastError = nil
	c.notifyStateLocked()
}

func (c *Client) RestartSession() {
	c.access.Lock()
	reset := c.requestResetLocked()
	if c.dialCancel != nil {
		c.dialCancel()
	}
	if c.current != nil {
		c.current.cancel(E.New("network changed"))
	}
	c.lastError = nil
	c.notifyStateLocked()
	c.access.Unlock()
	reset.apply()
}

func (c *Client) WritePacketBuffers(packetBuffers []*buf.Buffer, forwarded bool) error {
	current := c.activeSession()
	if current == nil {
		buf.ReleaseMulti(packetBuffers)
		return nil
	}
	current.access.Lock()
	configuration := current.configuration
	ready := current.ready
	current.access.Unlock()
	if !ready {
		buf.ReleaseMulti(packetBuffers)
		return nil
	}
	inet4Address, inet6Address := firstAddresses(configuration.Address)
	var replies []*buf.Buffer
	routedBuffers := packetBuffers[:0]
	for _, packetBuffer := range packetBuffers {
		_, destination, protocol, valid := packetAddresses(packetBuffer.Bytes())
		if !valid {
			packetBuffer.Release()
			continue
		}
		errorType := tun.ICMPErrorNoRoute
		routed := !configuration.RoutesAdvertised || RoutesContain(configuration.Routes, destination, protocol)
		if routed && forwarded && !decrementHopLimit(packetBuffer.Bytes()) {
			routed = false
			errorType = tun.ICMPErrorHopLimitExceeded
		}
		if !routed {
			reply, built := buildICMPError(packetBuffer.Bytes(), errorType, inet4Address, inet6Address, 0, c.handler.FrontHeadroom())
			if built {
				replies = append(replies, reply)
			}
			packetBuffer.Release()
			continue
		}
		routedBuffers = append(routedBuffers, packetBuffer)
	}
	err := current.writePackets(routedBuffers)
	if err != nil {
		current.cancel(err)
	}
	if len(replies) > 0 {
		return c.handler.WriteInboundBuffers(replies)
	}
	return nil
}

func (s *clientSession) handleAddressAssign(addresses []AssignedAddress) error {
	var assigned []netip.Prefix
	for _, address := range addresses {
		if address.RequestID != 0 && address.Prefix.Addr().IsUnspecified() && address.Prefix.IsSingleIP() {
			continue
		}
		localAddress := address.Prefix.Addr()
		if !address.Prefix.IsSingleIP() {
			localAddress = localAddress.Next()
		}
		assigned = append(assigned, netip.PrefixFrom(localAddress, address.Prefix.Bits()))
	}
	s.access.Lock()
	if slices.Equal(s.configuration.Address, assigned) {
		s.access.Unlock()
		return nil
	}
	s.configuration.Address = assigned
	configuration := s.configuration
	s.access.Unlock()
	return s.updateConfiguration(configuration)
}

func (s *clientSession) handleRouteAdvertisement(routes []AddressRange) error {
	s.access.Lock()
	if s.configuration.RoutesAdvertised && slices.Equal(s.configuration.Routes, routes) {
		s.access.Unlock()
		return nil
	}
	s.configuration.Routes = routes
	s.configuration.RoutesAdvertised = true
	configuration := s.configuration
	s.access.Unlock()
	if len(configuration.Address) == 0 {
		return nil
	}
	return s.updateConfiguration(configuration)
}

func (s *clientSession) updateConfiguration(configuration Configuration) error {
	if len(configuration.Address) == 0 {
		s.access.Lock()
		s.ready = false
		s.access.Unlock()
		s.client.access.Lock()
		s.client.notifyStateLocked()
		s.client.access.Unlock()
		return nil
	}
	err := s.client.handler.UpdateConfiguration(configuration)
	if err != nil {
		return E.Cause(err, "update configuration")
	}
	s.access.Lock()
	s.ready = true
	s.access.Unlock()
	s.client.access.Lock()
	s.client.lastError = nil
	s.client.notifyStateLocked()
	s.client.access.Unlock()
	return nil
}

func (s *clientSession) handleAddressRequest(addresses []AssignedAddress) error {
	rejections := make([]AssignedAddress, 0, len(addresses))
	for _, address := range addresses {
		unspecified := netip.IPv4Unspecified()
		if address.Prefix.Addr().Is6() {
			unspecified = netip.IPv6Unspecified()
		}
		rejections = append(rejections, AssignedAddress{RequestID: address.RequestID, Prefix: netip.PrefixFrom(unspecified, unspecified.BitLen())})
	}
	return s.writeCapsule(newAddressCapsule(capsuleTypeAddressAssign, rejections))
}

func (s *clientSession) handlePacket(buffer *buf.Buffer) {
	_, destination, _, valid := packetAddresses(buffer.Bytes())
	if !valid {
		buffer.Release()
		return
	}
	s.access.Lock()
	configuration := s.configuration
	s.access.Unlock()
	if !prefixesContain(configuration.Address, destination) && !rangesContain(s.client.advertiseRoutes, destination) {
		inet4Address, inet6Address := firstAddresses(configuration.Address)
		reply, built := buildICMPError(buffer.Bytes(), tun.ICMPErrorNoRoute, inet4Address, inet6Address, 0, transportHTTP.CapsuleHeadroom)
		buffer.Release()
		if built {
			_ = s.writePackets([]*buf.Buffer{reply})
		}
		return
	}
	err := s.client.handler.WriteInboundBuffers([]*buf.Buffer{buffer})
	if err != nil {
		s.client.logger.Debug(E.Cause(err, "write packet to device"))
	}
}

func (s *clientSession) handlePacketTooBig(buffer *buf.Buffer, mtu int) {
	s.access.Lock()
	inet4Address, inet6Address := firstAddresses(s.configuration.Address)
	s.access.Unlock()
	reply, built := buildICMPError(buffer.Bytes(), tun.ICMPErrorPacketTooBig, inet4Address, inet6Address, mtu, s.client.handler.FrontHeadroom())
	buffer.Release()
	if !built {
		return
	}
	err := s.client.handler.WriteInboundBuffers([]*buf.Buffer{reply})
	if err != nil {
		s.client.logger.Debug(E.Cause(err, "write packet to device"))
	}
}

func firstAddresses(addresses []netip.Prefix) (netip.Addr, netip.Addr) {
	var inet4Address netip.Addr
	var inet6Address netip.Addr
	for _, prefix := range addresses {
		if prefix.Addr().Is4() && !inet4Address.IsValid() {
			inet4Address = prefix.Addr()
		} else if prefix.Addr().Is6() && !inet6Address.IsValid() {
			inet6Address = prefix.Addr()
		}
	}
	return inet4Address, inet6Address
}

func prefixesContain(prefixes []netip.Prefix, address netip.Addr) bool {
	return slices.ContainsFunc(prefixes, func(prefix netip.Prefix) bool {
		return prefix.Contains(address)
	})
}

func RoutesContain(routes []AddressRange, address netip.Addr, protocol uint8) bool {
	return slices.ContainsFunc(routes, func(route AddressRange) bool {
		return route.Contains(address) && (route.Protocol == 0 || route.Protocol == protocol || isControlProtocol(protocol))
	})
}

func rangesContain(routes []AddressRange, address netip.Addr) bool {
	return slices.ContainsFunc(routes, func(route AddressRange) bool {
		return route.Contains(address)
	})
}
