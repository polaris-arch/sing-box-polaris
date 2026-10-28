package hysteria

import (
	"context"
	"errors"
	"net"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/tls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// One private runtime belongs to one immutable outbound resource generation.
// Active returned carriers retain that generation. Retirement never resets its
// client; only the resource's terminal cleanup closes it after those carriers.
type outboundRuntime struct {
	ctx                   context.Context
	cancel                context.CancelFunc
	source                adapter.RuntimeResourceSource
	fence                 *outbound.RuntimeIOFence
	boundary              *httpclient.RuntimeTransportBoundary
	begin                 func(context.Context) (context.Context, func(), error)
	client                outbound.RuntimeCloseWaiter
	cleanup               func() error
	registered            bool
	allowNativeDescriptor bool
}

func newOutboundRuntime(ctx context.Context) *outboundRuntime {
	r := &outboundRuntime{}
	r.source, _ = adapter.RuntimeResourceSourceFromContext(ctx)
	r.ctx, r.cancel = context.WithCancel(adapter.ContextWithRuntimeOwnership(ctx, context.Background()))
	r.boundary = httpclient.NewRuntimeTransportBoundary(func() error {
		if r.client != nil {
			return r.client.RuntimeCloseAndWait()
		}
		return nil
	})
	r.fence = outbound.NewRuntimeIOFence(func() error { r.cancel(); return r.boundary.RuntimeCloseAndWait() })
	r.cleanup = outbound.OnceRuntimeCleanup(r.fence.RuntimeCloseAndWait)
	return r
}

func (r *outboundRuntime) install(ctx context.Context, client any) error {
	waiter, ok := client.(outbound.RuntimeCloseWaiter)
	if !ok {
		return errors.New("ordinary QUIC outbound requires pinned sing-quic client worker-join delta")
	}
	r.client = waiter
	var err error
	r.begin, err = outbound.RegisterRuntimeOwnedFence(ctx, r.fence)
	if err != nil {
		return err
	}
	r.registered, err = outbound.RegisterRuntimeCleanup(ctx, r.cleanup)
	return err
}
func (r *outboundRuntime) close() error { return r.cleanup() }
func (r *outboundRuntime) guardTLS(config tls.Config) (tls.Config, error) {
	return newOutboundRuntimeTLS(config, r)
}

func (r *outboundRuntime) guardDialer(dialer N.Dialer) N.Dialer {
	return &outboundOwnedDialer{dialer: dialer, owner: r}
}

// Every port hop and shared-offer socket open reserves the constructor's actual
// owner fence before calling its captured dialer. There is no borrowed active
// request or synthetic session lease and no external idle self-reference.
type outboundOwnedDialer struct {
	dialer N.Dialer
	owner  *outboundRuntime
}

func (d *outboundOwnedDialer) enter(ctx context.Context) (context.Context, func(), error) {
	r := d.owner
	if r.begin == nil {
		return nil, nil, errors.New("QUIC client used before ownership installation")
	}
	ctx, leave, err := r.begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	if r.source != nil {
		ctx, err = outbound.ContextForRuntimeOwnedSession(ctx, r.source)
		if err != nil {
			leave()
			return nil, nil, err
		}
	}
	return ctx, leave, nil
}

func (d *outboundOwnedDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, leave, err := d.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer leave()
	ctx, finish, err := d.owner.boundary.BeginDial(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	raw, err := d.dialer.DialContext(ctx, network, destination)
	if err != nil {
		if raw != nil {
			_, fence := outbound.WrapRuntimeOwnedConn(raw)
			closeErr := fence.RuntimeCloseAndWait()
			d.owner.boundary.RecordClose(closeErr)
			if closeErr != nil {
				return nil, tls.NewRuntimeCleanupError(errors.Join(err, closeErr))
			}
		}
		if tls.IsRuntimeCleanupIncomplete(err) {
			d.owner.boundary.RecordClose(err)
		}
		return nil, err
	}
	if raw == nil {
		return nil, errors.New("QUIC physical dial returned no carrier")
	}
	guarded, fence := outbound.WrapRuntimeOwnedConn(raw)
	if err = d.owner.boundary.RegisterResource(fence); err != nil {
		return nil, err
	}
	return &outboundJoinedConn{Conn: guarded, fence: fence}, nil
}

func (d *outboundOwnedDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	// Ordinary clients use connected UDP. Optional Realm's unconnected/remote
	// registration branch needs a separately reviewed ownership contract.
	return nil, errors.New("QUIC outbound unconnected Realm carrier is outside ordinary node runtime scope")
}

// Obfuscation and port-hopping wrappers embed net.Conn.Close. Give them a
// terminal close, not an owned carrier's asynchronous "pending" observation.
// The exact underlying fence still owns every method and descriptor callback.
type outboundJoinedConn struct {
	net.Conn
	fence *outbound.RuntimeIOFence
}

func (c *outboundJoinedConn) Close() error { return c.fence.RuntimeCloseAndWait() }
func (c *outboundJoinedConn) SyscallConn() (syscall.RawConn, error) {
	return outbound.RuntimeSyscallConn(c.Conn)
}

func (c *outboundJoinedConn) IOActivityFuncs() (func(int), func(int)) {
	return outbound.RuntimeIOActivityFuncs(c.Conn)
}

// An obfuscation/hopping carrier must not be unwrapped to its socket by the
// native descriptor fast path: doing so would bypass its wire transformation.
type outboundOpaqueConn struct{ net.Conn }

func (r *outboundRuntime) nativeCarrier(raw net.Conn) net.Conn {
	if r.allowNativeDescriptor {
		return raw
	}
	return &outboundOpaqueConn{raw}
}
