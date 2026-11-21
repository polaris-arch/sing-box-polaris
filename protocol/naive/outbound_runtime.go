//go:build with_naive_outbound

package naive

import (
	"context"
	"errors"
	"net"
	"os"

	"github.com/sagernet/cronet-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/service/oomkiller"
	"github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
	"golang.org/x/sync/semaphore"
)

// Independent URLTest groups and management requests share the native startup
// budget even when each group limits its own workers.
var probeClients = semaphore.NewWeighted(10)

func deferColdProbe(ctx context.Context, pressure func() tun.MemoryPressure) bool {
	return urltest.IsBackgroundProbe(ctx) && pressure != nil && pressure() != tun.MemoryPressureNone
}

func acquireColdProbe(ctx context.Context) error {
	queueCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()
	if err := probeClients.Acquire(queueCtx, 1); err != nil {
		return errors.Join(urltest.ErrProbeNotRun, err)
	}
	return nil
}

// Each immutable outbound owns its native client, callbacks and physical
// carriers. The composed Cronet Close is the actual operation/callback/proxy/
// active-stream join followed by checked engine Shutdown and Destroy.
type outboundRuntime struct {
	ctx        context.Context
	cancel     context.CancelFunc
	source     adapter.RuntimeResourceSource
	fence      *outbound.RuntimeIOFence
	boundary   *httpclient.RuntimeTransportBoundary
	begin      func(context.Context) (context.Context, func(), error)
	client     interface{ Close() error }
	cleanup    func() error
	registered bool
}

func newOutboundRuntime(ctx context.Context) *outboundRuntime {
	r := &outboundRuntime{}
	r.source, _ = adapter.RuntimeResourceSourceFromContext(ctx)
	r.ctx, r.cancel = context.WithCancel(adapter.ContextWithRuntimeOwnership(ctx, context.Background()))
	r.boundary = httpclient.NewRuntimeTransportBoundary(func() error {
		if r.client != nil {
			return r.client.Close()
		}
		return nil
	})
	// Stop physical sockets in parallel with native Close, so a proxy worker
	// cannot prevent the native join from receiving its I/O interruption.
	r.fence = outbound.NewRuntimeIOFence(func() error { r.cancel(); return r.boundary.RuntimeCloseAndWait() })
	r.cleanup = outbound.OnceRuntimeCleanup(r.fence.RuntimeCloseAndWait)
	return r
}

func (r *outboundRuntime) install(ctx context.Context) error {
	var err error
	r.begin, err = outbound.RegisterRuntimeOwnedFence(ctx, r.fence)
	if err != nil {
		return err
	}
	r.registered, err = outbound.RegisterRuntimeCleanup(ctx, r.cleanup)
	return err
}
func (r *outboundRuntime) close() error { return r.cleanup() }

// WithURLTestDialer lets a probe borrow an active client or own a client for
// the duration of the request. Keep the owner's dependency edges until native
// shutdown and any physical dial callbacks have completed.
func (h *Outbound) WithURLTestDialer(ctx context.Context, test func(context.Context, N.Dialer) (uint16, error)) (delay uint16, resultErr error) {
	if !h.client.IsDormant() {
		return test(ctx, h)
	}
	pressure := oomkiller.MemoryPressure(h.ctx)
	if deferColdProbe(ctx, pressure) {
		return 0, urltest.ErrProbeNotRun
	}
	if err := acquireColdProbe(ctx); err != nil {
		return 0, err
	}
	defer probeClients.Release(1)
	if !h.client.IsDormant() {
		return test(ctx, h)
	}
	owner := h.runtime
	if _, err := outbound.ValidateRuntimeOwnedSession(ctx, owner.source); err != nil {
		return 0, err
	}
	ctx, release, err := adapter.AcquireRuntimeOperation(ctx, owner.source)
	if err != nil {
		return 0, err
	}
	defer release()
	leave, err := owner.boundary.Acquire()
	if err != nil {
		return 0, err
	}
	defer leave()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(owner.ctx, cancel)
	defer stop()
	if owner.ctx.Err() != nil {
		cancel()
	}
	if err = ctx.Err(); err != nil {
		return 0, errors.Join(urltest.ErrProbeNotRun, err)
	}
	if deferColdProbe(ctx, pressure) {
		return 0, urltest.ErrProbeNotRun
	}

	probe := newOutboundRuntime(h.ctx)
	probe.begin = owner.begin
	defer func() {
		if closeErr := probe.close(); closeErr != nil {
			owner.boundary.RecordClose(closeErr)
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	options := h.clientOptions
	options.InsecureConcurrency = 1
	client, err := cronet.NewNaiveClient(probe.guardClientOptions(options))
	if err != nil {
		return 0, err
	}
	probe.client = client
	if err = client.StartOnDemand(); err != nil {
		return 0, err
	}
	return test(ctx, &naiveDialer{client})
}

func (r *outboundRuntime) enter(ctx context.Context) (context.Context, func(), error) {
	if r.begin == nil {
		return nil, nil, errors.New("Naive callback before ownership installation")
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

func (r *outboundRuntime) guardDNS(resolve func(context.Context, *mDNS.Msg) *mDNS.Msg) func(context.Context, *mDNS.Msg) *mDNS.Msg {
	return func(ctx context.Context, request *mDNS.Msg) *mDNS.Msg {
		ctx, leave, err := r.enter(ctx)
		if err != nil {
			return dns.FixedResponseStatus(request, mDNS.RcodeServerFailure)
		}
		defer leave()
		return resolve(ctx, request)
	}
}

func (r *outboundRuntime) guardDialer(dialer N.Dialer) N.Dialer {
	return &outboundOwnedDialer{dialer: dialer, owner: r}
}

type outboundOwnedDialer struct {
	dialer N.Dialer
	owner  *outboundRuntime
}

func (d *outboundOwnedDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, leave, err := d.owner.enter(ctx)
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
		return nil, errors.New("Naive physical dial returned no carrier")
	}
	guarded, fence := outbound.WrapRuntimeOwnedConn(raw)
	if err = d.owner.boundary.RegisterResource(fence); err != nil {
		return nil, err
	}
	// No Upstream/ReaderReplaceable/raw descriptor escape: Cronet deliberately
	// takes its socket-pair fallback. Both TCP and UDP relays are joined by Close.
	return &outboundJoinedConn{Conn: guarded, fence: fence}, nil
}

func (d *outboundOwnedDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("Naive native dialer requires connected TCP or UDP")
}

type outboundJoinedConn struct {
	net.Conn
	fence *outbound.RuntimeIOFence
}

func (c *outboundJoinedConn) Close() error { return c.fence.RuntimeCloseAndWait() }

func (c *outboundJoinedConn) CloseRead() error {
	if closer, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return closer.CloseRead()
	}
	return os.ErrInvalid
}

func (c *outboundJoinedConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return os.ErrInvalid
}

// Keep standalone native descriptor transfer and callbacks exactly as supplied.
// Runtime-owned clients require opaque relay carriers and captured continuations.
func (r *outboundRuntime) guardClientOptions(options cronet.NaiveClientOptions) cronet.NaiveClientOptions {
	if r.source == nil {
		return options
	}
	options.Context = r.ctx
	options.Logger = outbound.WrapRuntimeLogger(options.Logger, r.fence)
	options.Dialer = r.guardDialer(options.Dialer)
	if options.DNSResolver != nil {
		options.DNSResolver = r.guardDNS(options.DNSResolver)
	}
	return options
}
