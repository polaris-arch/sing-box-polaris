//go:build with_tailscale

package tailscale

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	runtimeTLS "github.com/sagernet/sing-box/common/tls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/tailscale/net/netmon"
	"github.com/sagernet/tailscale/types/nettype"
)

// A lazy native node has its own exact callback/carrier census. It uses the
// outbound's captured dependency authority without retaining its own resource.
// Public flow ownership keeps the logical outbound alive; lazy native work is
// joined here before that outbound's captured edges may be released.
type runtimeTailcatSession struct {
	ctx       context.Context
	cancel    context.CancelFunc
	source    adapter.RuntimeResourceSource
	scope     *adapter.Scope
	callbacks *outbound.RuntimeIOFence
	carriers  *outbound.RuntimeIOFenceSet
	begin     func(context.Context) (context.Context, func(), error)
	node      *tailcatNode
	closeOnce sync.Once
	closeErr  error
}

func (o *TailcatOutbound) newRuntimeSession() (*runtimeTailcatSession, error) {
	source, ok := adapter.RuntimeResourceSourceFromContext(o.ctx)
	if !ok {
		return nil, nil
	}
	ctx, cancel := context.WithCancel(o.nodeContext)
	s := &runtimeTailcatSession{ctx: ctx, cancel: cancel, source: source, callbacks: outbound.NewRuntimeIOFence(nil), carriers: outbound.NewRuntimeIOFenceSet()}
	s.scope = adapter.NewScope(ctx, o.logger)
	s.ctx = adapter.ContextWithConstructionScope(s.scope.Context(), s.scope)
	var err error
	s.begin, err = outbound.RegisterRuntimeOwnedFence(s.ctx, s.callbacks)
	if err != nil {
		cancel()
		return nil, errors.Join(err, s.scope.Close())
	}
	return s, nil
}

func (s *runtimeTailcatSession) owned(ctx context.Context) (context.Context, func(), error) {
	owned, release, err := s.begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	owned, err = outbound.ContextForRuntimeOwnedSession(owned, s.source)
	if err != nil {
		release()
		return nil, nil, err
	}
	combined, cancel := context.WithCancel(owned)
	done := make(chan struct{})
	stop := context.AfterFunc(s.ctx, func() { defer close(done); cancel() })
	return combined, func() {
		cancel()
		if !stop() {
			<-done
		}
		release()
	}, nil
}

func (s *runtimeTailcatSession) close() error {
	s.closeOnce.Do(func() {
		s.closeErr = runtimeTLS.NewRuntimeCleanupError(errors.New("tailcat native session cleanup did not return"))
		s.cancel()
		_ = s.callbacks.Close()
		s.carriers.Stop()
		// No joined callback acquires TailcatOutbound.access. All potentially
		// blocking native joins are outside node callback admission locks.
		if s.node != nil {
			s.node.close()
		}
		s.closeErr = errors.Join(s.carriers.Wait(), s.callbacks.Wait(), s.scope.Close())
		if s.closeErr != nil {
			s.closeErr = runtimeTLS.NewRuntimeCleanupError(s.closeErr)
		}
	})
	return s.closeErr
}

func (s *runtimeTailcatSession) wrapOptions(o tailcatNodeOptions) tailcatNodeOptions {
	o.Context = s.ctx
	o.Logger = outbound.WrapRuntimeLogger(o.Logger, s.callbacks)
	o.OnConstruct = func(node *tailcatNode) { s.node = node }
	raw := o.Hooks
	o.Hooks.Dialer = &runtimeTailcatDialer{session: s, base: raw.Dialer}
	if raw.Interfaces != nil {
		o.Hooks.Interfaces = func() ([]netmon.Interface, error) {
			leave, err := s.callbacks.Acquire()
			if err != nil {
				return nil, err
			}
			defer leave()
			return raw.Interfaces()
		}
	}
	if raw.Control != nil {
		o.Hooks.Control = func(network, address string, conn syscall.RawConn) error {
			leave, err := s.callbacks.Acquire()
			if err != nil {
				return err
			}
			defer leave()
			return raw.Control(network, address, conn)
		}
	}
	o.Hooks.PacketListener = s.packetListener
	if lookup := o.LookupHook; lookup != nil {
		o.LookupHook = func(ctx context.Context, host string) ([]netip.Addr, error) {
			owned, leave, err := s.owned(ctx)
			if err != nil {
				return nil, err
			}
			defer leave()
			return lookup(owned, host)
		}
	}
	// Selected MemoryPressure only reads its private atomic pressure value; it
	// has no captured graph callback or external handle. Preserve that pure read.
	return o
}

type runtimeTailcatDialer struct {
	session *runtimeTailcatSession
	base    N.Dialer
}

func (d *runtimeTailcatDialer) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	s := d.session
	creation, err := s.carriers.Begin()
	if err != nil {
		return nil, err
	}
	defer creation.Done()
	owned, leave, err := s.owned(ctx)
	if err != nil {
		return nil, err
	}
	defer leave()
	raw, err := d.base.DialContext(owned, network, address)
	if raw == nil {
		return nil, err
	}
	wrapped, fence := outbound.WrapRuntimeOwnedConn(raw)
	registerErr := creation.Register(fence)
	if err != nil || registerErr != nil || s.ctx.Err() != nil {
		return nil, errors.Join(err, registerErr, s.ctx.Err(), fence.RuntimeCloseAndWait())
	}
	return wrapped, nil
}

func (d *runtimeTailcatDialer) ListenPacket(ctx context.Context, address M.Socksaddr) (net.PacketConn, error) {
	s := d.session
	creation, err := s.carriers.Begin()
	if err != nil {
		return nil, err
	}
	defer creation.Done()
	owned, leave, err := s.owned(ctx)
	if err != nil {
		return nil, err
	}
	defer leave()
	raw, err := d.base.ListenPacket(owned, address)
	if raw == nil {
		return nil, err
	}
	wrapped, fence := outbound.WrapRuntimeOwnedPacketConn(raw)
	registerErr := creation.Register(fence)
	if err != nil || registerErr != nil || s.ctx.Err() != nil {
		return nil, errors.Join(err, registerErr, s.ctx.Err(), fence.RuntimeCloseAndWait())
	}
	return wrapped, nil
}

func (s *runtimeTailcatSession) packetListener(ctx context.Context, network, address string, next netmon.PacketListenerFunc) (result nettype.PacketConn, resultErr error) {
	creation, err := s.carriers.Begin()
	if err != nil {
		return nil, err
	}
	defer creation.Done()
	var fence *outbound.RuntimeIOFence
	defer func() {
		if recover() != nil {
			uncertain := runtimeTLS.NewRuntimeCleanupError(errors.New("tailcat original packet allocation panicked"))
			s.carriers.Record(uncertain)
			if fence != nil {
				uncertain = runtimeTLS.NewRuntimeCleanupError(errors.Join(uncertain, fence.RuntimeCloseAndWait()))
			}
			result = nil
			resultErr = uncertain
		}
	}()
	owned, leave, err := s.owned(ctx)
	if err != nil {
		return nil, err
	}
	defer leave()
	raw, err := next(owned, network, address)
	if raw == nil {
		return nil, err
	}
	fence = outbound.NewRuntimeIOFence(raw.Close)
	registerErr := creation.Register(fence)
	if err != nil || registerErr != nil || s.ctx.Err() != nil {
		return nil, errors.Join(err, registerErr, s.ctx.Err(), fence.RuntimeCloseAndWait())
	}
	return &runtimeNetIPPacketConn{raw: raw, fence: fence, local: raw.LocalAddr()}, nil
}

// The active-node slot follows the original public carrier's Close AND every
// admitted method return. Closing while Read is still unwinding cannot tear
// down the lazy engine early. The wrapper exposes no upstream escape hatch.
func (o *TailcatOutbound) ownRuntimeConn(raw net.Conn, release func()) net.Conn {
	if _, bound := adapter.RuntimeResourceSourceFromContext(o.ctx); !bound {
		switch c := raw.(type) {
		case *tailcatConn:
			c.release = release
		case *tailcatPacketConn:
			c.release = release
		}
		return raw
	}
	wrapped, fence := outbound.WrapRuntimeOwnedConn(raw)
	go func() {
		if err := fence.Wait(); err == nil {
			release()
		}
	}()
	if packet, ok := wrapped.(net.PacketConn); ok {
		return &runtimeTailcatJoinedConnPacket{runtimeTailcatJoinedConn: &runtimeTailcatJoinedConn{Conn: wrapped, fence: fence}, packet: packet}
	}
	return &runtimeTailcatJoinedConn{Conn: wrapped, fence: fence}
}

func (o *TailcatOutbound) ownRuntimePacket(raw *tailcatPacketConn, release func()) net.PacketConn {
	if _, bound := adapter.RuntimeResourceSourceFromContext(o.ctx); !bound {
		raw.release = release
		return raw
	}
	wrapped, fence := outbound.WrapRuntimeOwnedPacketConn(raw)
	go func() {
		if err := fence.Wait(); err == nil {
			release()
		}
	}()
	return &runtimeTailcatJoinedPacket{PacketConn: wrapped, fence: fence}
}

// Existing IP-only/NAT wrappers forward Close but do not expose the concrete
// runtime fence. Join here so an outer public resource wrapper cannot mistake
// the owned carrier's asynchronous Close request for its actual completion.
// These client-side netstack carriers invoke no caller callback from Close.
type runtimeTailcatJoinedConn struct {
	net.Conn
	fence *outbound.RuntimeIOFence
}

func (c *runtimeTailcatJoinedConn) Close() error { return c.fence.RuntimeCloseAndWait() }

type runtimeTailcatJoinedConnPacket struct {
	*runtimeTailcatJoinedConn
	packet net.PacketConn
}

func (c *runtimeTailcatJoinedConnPacket) ReadFrom(p []byte) (int, net.Addr, error) {
	return c.packet.ReadFrom(p)
}

func (c *runtimeTailcatJoinedConnPacket) WriteTo(p []byte, a net.Addr) (int, error) {
	return c.packet.WriteTo(p, a)
}

type runtimeTailcatJoinedPacket struct {
	net.PacketConn
	fence *outbound.RuntimeIOFence
}

func (c *runtimeTailcatJoinedPacket) Close() error { return c.fence.RuntimeCloseAndWait() }
