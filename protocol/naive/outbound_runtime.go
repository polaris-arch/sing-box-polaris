//go:build with_naive_outbound

package naive

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"

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

// Probe concurrency is separate from the lifetime budget of physical engines.
const probeClientLimit = 10

var probeClients = semaphore.NewWeighted(probeClientLimit)

// Runtime generations and probes coexist in the same process.
var nativeEngines = nativeEngineBudget{limit: nativeEngineLimit()}

var errNativeEngineCapacity = adapter.ErrOutboundCapacity

type nativeEngineBudget struct {
	mu    sync.Mutex
	limit int64
	used  int64
}

func nativeEngineLimit() int64 {
	if C.IsIos {
		// Leave room for an active engine and one handoff or cold probe.
		return 2
	}
	return probeClientLimit
}

func reserveNativeEngines(ctx context.Context, count int) (func(int), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nativeEngines.reserve(count, urltest.IsBackgroundProbe(ctx))
}

func (b *nativeEngineBudget) reserve(count int, keepHandoffSlot bool) (func(int), error) {
	// A Cronet socket callback may dial through another Naive outbound. Waiting
	// for capacity there can deadlock the engine that is already holding it.
	b.mu.Lock()
	available := b.limit - b.used
	if int64(count) > available {
		b.mu.Unlock()
		return nil, errNativeEngineCapacity
	}
	if keepHandoffSlot && int64(count) == available {
		b.mu.Unlock()
		return nil, adapter.ErrOutboundForegroundSlot
	}
	b.used += int64(count)
	b.mu.Unlock()
	return func(released int) {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.used -= int64(released)
		if b.used < 0 {
			panic("released more native engines than reserved")
		}
	}, nil
}

type nativeCallbackKey struct{}

func deferColdProbe(ctx context.Context, pressure func() tun.MemoryPressure) bool {
	return urltest.IsBackgroundProbe(ctx) && pressure != nil && pressure() != tun.MemoryPressureNone
}

func acquireColdProbe(ctx context.Context, slots int64) error {
	queueCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()
	if err := probeClients.Acquire(queueCtx, slots); err != nil {
		return errors.Join(urltest.ErrProbeNotRun, err)
	}
	return nil
}

// The physical slot and its callbacks belong to one runtime. A logical alias
// has a separate runtime for its operation fence and cold probes.
// Cronet Close joins its operations, callbacks, proxies and active streams
// before checked engine Shutdown and Destroy.
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
	warm, err := h.clients.acquire(ctx, false)
	if err != nil {
		return 0, err
	}
	if warm != nil {
		defer h.clients.release()
		return test(ctx, h)
	}
	pressure := oomkiller.MemoryPressure(h.ctx)
	if deferColdProbe(ctx, pressure) {
		return 0, urltest.ErrProbeNotRun
	}
	slots := int64(1)
	if oomkiller.InAppleNetworkExtension(h.ctx) {
		// Serialize transient engines before the extension's next memory sample.
		slots = probeClientLimit
	}
	if err := acquireColdProbe(ctx, slots); err != nil {
		return 0, err
	}
	defer probeClients.Release(slots)
	warm, err = h.clients.acquire(ctx, false)
	if err != nil {
		return 0, err
	}
	if warm != nil {
		defer h.clients.release()
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
	ctx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
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
	options := h.clients.options
	if h.server != nil {
		options = h.server.options
		options.Context = h.ctx
		options.Logger = h.logger
		if h.clients.resolverForLogger != nil {
			options.DNSResolver = h.clients.resolverForLogger(h.logger)
		}
	}
	options = probe.guardClientOptions(options)
	options.InsecureConcurrency = 1
	options.ReserveEngines = func(_ context.Context, count int) (func(int), error) {
		release, err := reserveNativeEngines(ctx, count)
		if err != nil {
			return nil, errors.Join(urltest.ErrProbeNotRun, err)
		}
		return release, nil
	}
	client, err := cronet.NewNaiveClient(options)
	if err != nil {
		return 0, err
	}
	probe.client = client
	if err = client.StartOnDemand(ctx); err != nil {
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
	return context.WithValue(ctx, nativeCallbackKey{}, true), leave, nil
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
	if err = d.owner.boundary.RegisterCarrier(fence); err != nil {
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
	options.ReserveEngines = reserveNativeEngines
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
