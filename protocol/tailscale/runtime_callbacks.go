//go:build with_tailscale

package tailscale

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	runtimeTLS "github.com/sagernet/sing-box/common/tls"
	M "github.com/sagernet/sing/common/metadata"
	tsDNS "github.com/sagernet/tailscale/net/dns"
	"github.com/sagernet/tailscale/net/netmon"
	"github.com/sagernet/tailscale/types/nettype"
	"github.com/sagernet/tailscale/wgengine/router"
	"github.com/sagernet/tailscale/wgengine/wgcfg"
)

func (p *runtimeEndpointPhysical) joinContext(ctx context.Context) (context.Context, func()) {
	combined, cancel := context.WithCancel(ctx)
	finished := make(chan struct{})
	stop := context.AfterFunc(p.ctx, func() { defer close(finished); cancel() })
	return combined, func() {
		cancel()
		if !stop() {
			<-finished
		}
	}
}

func (p *runtimeEndpointPhysical) ownedContext(ctx context.Context) (context.Context, func(), error) {
	_, owned, release, err := p.bindingContext(ctx, false)
	if err != nil {
		return nil, nil, err
	}
	owned, cancel := p.joinContext(owned)
	return owned, func() { cancel(); release() }, nil
}

// Admission occurs before the goroutine becomes visible. Canceling a caller
// never releases this fence; only the actual worker's return does so.
func (p *runtimeEndpointPhysical) launch(worker func()) error {
	leave, err := p.callbacks.Acquire()
	if err != nil {
		return err
	}
	go func() { defer leave(); worker() }()
	return nil
}

func (t *Endpoint) runtimeOperation(ctx context.Context) (*Endpoint, context.Context, func(), error) {
	owned, release, err := adapter.AcquireRuntimeOperation(ctx, t.runtime.source)
	if err != nil {
		return nil, nil, nil, err
	}
	child, owned, leave, err := t.runtimeBoundChild(owned)
	if err != nil {
		release()
		return nil, nil, nil, err
	}
	return child, owned, func() { leave(); release() }, nil
}

type runtimeEndpointDialer struct{ physical *runtimeEndpointPhysical }

func (d *runtimeEndpointDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	b, owned, release, err := d.physical.bindingContext(ctx, false)
	if err != nil {
		return nil, err
	}
	defer release()
	return b.dial(owned, network, destination)
}

func (d *runtimeEndpointDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	b, owned, release, err := d.physical.bindingContext(ctx, false)
	if err != nil {
		return nil, err
	}
	defer release()
	return b.listenPacket(owned, destination)
}

func (p *runtimeEndpointPhysical) wrapSystemBinding(binding systemBinding) systemBinding {
	result := binding
	if callback := binding.interfaces; callback != nil {
		result.interfaces = func() ([]netmon.Interface, error) {
			leave, err := p.callbacks.Acquire()
			if err != nil {
				return nil, err
			}
			defer leave()
			return callback()
		}
	}
	if callback := binding.control; callback != nil {
		result.control = func(network, address string, raw syscall.RawConn) error {
			leave, err := p.callbacks.Acquire()
			if err != nil {
				return err
			}
			defer leave()
			return callback(network, address, raw)
		}
	}

	return result
}

// This exact nettype.PacketConn adapter retains the optimized AddrPort API and
// descriptor callbacks without exposing the raw retired carrier via Upstream.
type runtimeNetIPPacketConn struct {
	raw   nettype.PacketConn
	fence *outbound.RuntimeIOFence
	local net.Addr
}

func (c *runtimeNetIPPacketConn) ReadFromUDPAddrPort(bytes []byte) (int, netip.AddrPort, error) {
	leave, err := c.fence.Acquire()
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	defer leave()
	return c.raw.ReadFromUDPAddrPort(bytes)
}

func (c *runtimeNetIPPacketConn) WriteToUDPAddrPort(bytes []byte, address netip.AddrPort) (int, error) {
	leave, err := c.fence.Acquire()
	if err != nil {
		return 0, err
	}
	defer leave()
	return c.raw.WriteToUDPAddrPort(bytes, address)
}
func (c *runtimeNetIPPacketConn) Close() error               { return c.fence.Close() }
func (c *runtimeNetIPPacketConn) RuntimeCloseAndWait() error { return c.fence.RuntimeCloseAndWait() }
func (c *runtimeNetIPPacketConn) LocalAddr() net.Addr        { return c.local }
func (c *runtimeNetIPPacketConn) SetDeadline(deadline time.Time) error {
	leave, err := c.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	return c.raw.SetDeadline(deadline)
}

func (c *runtimeNetIPPacketConn) SetReadDeadline(deadline time.Time) error {
	leave, err := c.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	return c.raw.SetReadDeadline(deadline)
}

func (c *runtimeNetIPPacketConn) SetWriteDeadline(deadline time.Time) error {
	leave, err := c.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	return c.raw.SetWriteDeadline(deadline)
}

func (c *runtimeNetIPPacketConn) SyscallConn() (syscall.RawConn, error) {
	leave, err := c.fence.Acquire()
	if err != nil {
		return nil, err
	}
	defer leave()
	raw, err := outbound.RuntimeSyscallConn(c.raw)
	if err != nil {
		return nil, err
	}
	return &runtimePacketRawConn{raw: raw, fence: c.fence}, nil
}

type runtimePacketRawConn struct {
	raw   syscall.RawConn
	fence *outbound.RuntimeIOFence
}

func (c *runtimePacketRawConn) Control(callback func(uintptr)) error {
	leave, err := c.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	return c.raw.Control(callback)
}

func (c *runtimePacketRawConn) Read(callback func(uintptr) bool) error {
	leave, err := c.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	return c.raw.Read(callback)
}

func (c *runtimePacketRawConn) Write(callback func(uintptr) bool) error {
	leave, err := c.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	return c.raw.Write(callback)
}

// packetListener encloses the actual native/custom factory call. A post-return
// decorator alone could miss a socket allocated after the owner's final wait.
func (p *runtimeEndpointPhysical) packetListener(ctx context.Context, network, address string, next netmon.PacketListenerFunc) (result nettype.PacketConn, resultErr error) {
	creation, err := p.carriers.Begin()
	if err != nil {
		return nil, err
	}
	defer creation.Done()
	var fence *outbound.RuntimeIOFence
	defer func() {
		if failure := recover(); failure != nil {
			uncertainty := runtimeTLS.NewRuntimeCleanupError(errors.New("Tailscale native packet creation panicked; original allocation retained as unknown"))
			p.carriers.Record(uncertainty)
			if fence != nil {
				resultErr = errors.Join(uncertainty, fence.RuntimeCloseAndWait())
			} else {
				resultErr = uncertainty
			}
			result = nil
		}
	}()
	b, owned, release, err := p.bindingContext(ctx, false)
	if err != nil {
		return nil, err
	}
	owned, cancel := p.joinContext(owned)
	complete := func() { cancel(); release() }
	raw, err := next(owned, network, address)
	if raw == nil {
		complete()
		return nil, err
	}
	// Register the actual carrier before calling optional metadata/capability
	// methods. A panic there still leaves a closeable original owned object.
	fence = outbound.NewRuntimeIOFence(raw.Close)
	registerErr := creation.Register(fence)
	b.holdCarrier(fence, complete)
	if err != nil || registerErr != nil || p.ctx.Err() != nil {
		return nil, errors.Join(err, registerErr, p.ctx.Err(), fence.RuntimeCloseAndWait())
	}
	return &runtimeNetIPPacketConn{raw: raw, fence: fence, local: raw.LocalAddr()}, nil
}

func (p *runtimeEndpointPhysical) timeFunction(base func() time.Time) func() time.Time {
	if base == nil {
		return nil
	}
	return func() time.Time {
		leave, err := p.callbacks.Acquire()
		if err != nil {
			return time.Now()
		}
		defer leave()
		return base()
	}
}

// A logical subscription survives a compensating physical reconstruction, but
// each delivery names the exact original child. Unregistration seals the
// consumer's fence; no callback is run under the endpoint state mutex.
type runtimeReconfigRegistration struct {
	fence    *outbound.RuntimeIOFence
	callback func(*Endpoint, *wgcfg.Config, *router.Config, *tsDNS.Config)
}

func (t *Endpoint) registerRuntimeReconfig(fence *outbound.RuntimeIOFence, callback func(*Endpoint, *wgcfg.Config, *router.Config, *tsDNS.Config)) (func(), error) {
	if t.runtime == nil {
		return nil, errors.New("Tailscale DNS requires a prepared logical endpoint")
	}
	registration := &runtimeReconfigRegistration{fence: fence, callback: callback}
	r := t.runtime
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return nil, net.ErrClosed
	}
	if r.reconfig == nil {
		r.reconfig = make(map[*runtimeReconfigRegistration]struct{})
	}
	r.reconfig[registration] = struct{}{}
	r.mu.Unlock()
	return func() { r.mu.Lock(); delete(r.reconfig, registration); r.mu.Unlock(); _ = fence.Close() }, nil
}

func (p *runtimeEndpointPhysical) reconfigured(child *Endpoint, cfg *wgcfg.Config, route *router.Config, dns *tsDNS.Config) {
	p.mu.Lock()
	logicals := make([]*Endpoint, 0, len(p.attachments))
	for b := range p.attachments {
		logicals = append(logicals, b.logical)
	}
	p.mu.Unlock()
	var registrations []*runtimeReconfigRegistration
	for _, logical := range logicals {
		r := logical.runtime
		r.mu.Lock()
		for registration := range r.reconfig {
			registrations = append(registrations, registration)
		}
		r.mu.Unlock()
	}
	for _, registration := range registrations {
		func() {
			leave, err := registration.fence.Acquire()
			if err != nil {
				return
			}
			defer leave()
			registration.callback(child, cfg, route, dns)
		}()
	}
}

func (t *Endpoint) runtimeLookup(ctx context.Context, host string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	if t.runtimePhysical == nil {
		return t.dnsRouter.Lookup(ctx, host, options)
	}
	b, owned, release, err := t.runtimePhysical.bindingContext(ctx, false)
	if err != nil {
		return nil, err
	}
	defer release()
	return b.dns.Lookup(owned, host, options)
}
