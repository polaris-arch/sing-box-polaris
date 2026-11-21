//go:build with_naive_outbound

package naive

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/cronet-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"

	mDNS "github.com/miekg/dns"
)

type naiveOutboundTestCloser struct{ close func() error }

func (c naiveOutboundTestCloser) Close() error {
	if c.close != nil {
		return c.close()
	}
	return nil
}

func (c naiveOutboundTestCloser) RuntimeCloseAndWait() error { return c.Close() }

type naiveOutboundTestDialer struct {
	dial func(context.Context) (net.Conn, error)
}

func (d naiveOutboundTestDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	return d.dial(ctx)
}

func (d naiveOutboundTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unexpected unconnected dial")
}

type naiveOutboundTestConn struct {
	close      func() error
	once       sync.Once
	err        error
	halfClosed atomic.Bool
}

func (c *naiveOutboundTestConn) Close() error {
	c.once.Do(func() {
		if c.close != nil {
			c.err = c.close()
		}
	})
	return c.err
}
func (*naiveOutboundTestConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (*naiveOutboundTestConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*naiveOutboundTestConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*naiveOutboundTestConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*naiveOutboundTestConn) SetDeadline(time.Time) error      { return nil }
func (*naiveOutboundTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*naiveOutboundTestConn) SetWriteDeadline(time.Time) error { return nil }
func (*naiveOutboundTestConn) Upstream() any                    { return &net.TCPConn{} }
func (c *naiveOutboundTestConn) CloseWrite() error              { c.halfClosed.Store(true); return nil }

func naiveOutboundWait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("completion barrier did not finish")
	}
}

func TestNaiveColdProbePressureAndQueueDeadline(t *testing.T) {
	background := urltest.ContextWithBackgroundProbe(t.Context())
	for _, level := range []tun.MemoryPressure{tun.MemoryPressureNone, tun.MemoryPressureWarning, tun.MemoryPressureCritical} {
		pressure := func() tun.MemoryPressure { return level }
		if deferColdProbe(t.Context(), pressure) || deferColdProbe(background, pressure) != (level != tun.MemoryPressureNone) {
			t.Fatalf("unexpected cold probe admission at pressure %d", level)
		}
	}
	if deferColdProbe(background, nil) {
		t.Fatal("missing pressure monitor blocked a cold probe")
	}
	if err := acquireColdProbe(t.Context(), probeClientLimit); err != nil {
		t.Fatalf("could not reserve the cold probe queue: %v", err)
	}
	defer probeClients.Release(probeClientLimit)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	err := acquireColdProbe(ctx, 1)
	if !errors.Is(err, urltest.ErrProbeNotRun) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queue expiry was not reported as an unattempted probe: %v", err)
	}
}

func TestNaiveOutboundSealedReceiverAndClientAccessor(t *testing.T) {
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "naive", Sequence: 1}, nil, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	owner.Seal()
	client := &cronet.NaiveClient{}
	clients := &naiveClientSlot{
		options: cronet.NaiveClientOptions{Context: t.Context()},
		current: &naiveClientIncarnation{client: client},
	}
	h := &Outbound{runtime: &outboundRuntime{source: owner}, clients: clients}
	if _, err := h.DialContext(context.Background(), "tcp", M.Socksaddr{}); err == nil {
		t.Fatal("sealed receiver dispatched")
	}
	if _, err := h.ListenPacket(context.Background(), M.Socksaddr{}); err == nil {
		t.Fatal("sealed receiver dispatched")
	}
	if h.Client() != nil {
		t.Fatal("native client escaped runtime owner")
	}
	if (&Outbound{clients: clients}).Client() != client || !clients.pinned {
		t.Fatal("standalone accessor changed")
	}
}

func testWarmNaiveOutbound(t *testing.T) (*Outbound, *naiveClientIncarnation) {
	t.Helper()
	ctx := t.Context()
	owner := newOutboundRuntime(ctx)
	clients := &naiveClientSlot{
		owner: owner,
		options: cronet.NaiveClientOptions{
			Context:       ctx,
			ServerAddress: M.ParseSocksaddrHostPort("127.0.0.1", 443),
			DNSResolver:   func(context.Context, *mDNS.Msg) *mDNS.Msg { return nil },
		},
		keep: true,
	}
	owner.client = clients
	first, err := clients.newIncarnation()
	if err != nil {
		t.Skipf("Cronet library unavailable: %v", err)
	}
	clients.current = first
	t.Cleanup(func() { _ = owner.close() })
	if err = first.client.Start(); err != nil {
		t.Fatal(err)
	}
	return &Outbound{
		runtime:   owner,
		logger:    log.NewNOPFactory().Logger(),
		clients:   clients,
		uotClient: &uot.Client{Dialer: clients},
	}, first
}

func TestNaiveOutboundIdleClientRetiresAndReopens(t *testing.T) {
	h, first := testWarmNaiveOutbound(t)
	ctx, clients := t.Context(), h.clients
	var err error
	if _, err = h.WithURLTestDialer(ctx, func(_ context.Context, probeDialer N.Dialer) (uint16, error) {
		if probeDialer != h {
			t.Fatal("warm probe did not borrow the persistent client")
		}
		h.SetKeepIdleConnections(false)
		h.CloseIdleConnections()
		if first.client.Version() == "" {
			t.Fatal("reclamation overtook the warm probe")
		}
		return 1, nil
	}); err != nil {
		t.Fatal(err)
	}
	h.CloseIdleConnections()
	if first.client.Version() != "" {
		t.Fatal("unreferenced engine remained warm after the probe")
	}
	h.InterfaceUpdated(ctx)
	if warm, err := clients.acquire(ctx, false); err != nil || warm != nil {
		t.Fatalf("idle controls warmed the outbound: %v, %v", warm, err)
	}
	h.SetKeepIdleConnections(true)
	next, err := clients.acquire(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if next == first || !next.client.IsDormant() {
		t.Fatal("ordinary acquisition did not create a fresh dormant client")
	}
	if err = next.client.Start(); err != nil {
		t.Fatal(err)
	}
	clients.release()
	if next.client.Version() == "" {
		t.Fatal("a referenced client did not remain warm after release")
	}
	h.CloseIdleConnections()
	if next.client.Version() != "" {
		t.Fatal("explicit idle cleanup retained a referenced idle client")
	}
	final, err := clients.acquire(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if final == next {
		t.Fatal("ordinary acquisition reused a closed client")
	}
	if err = final.client.Start(); err != nil {
		t.Fatal(err)
	}
	clients.release()
	if err = h.runtime.close(); err != nil || final.client.Version() != "" {
		t.Fatalf("final stop did not join the replacement: %v", err)
	}
	if _, err = clients.acquire(ctx, true); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("final stop allowed a replacement: %v", err)
	}
}

func TestNaiveOutboundIdleRetirementKeepsUncertainOwner(t *testing.T) {
	h, first := testWarmNaiveOutbound(t)
	entered, release, stopped := make(chan struct{}), make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	want := errors.New("physical cleanup uncertain")
	if err := first.runtime.boundary.RegisterResource(naiveOutboundTestCloser{close: func() error {
		close(entered)
		<-release
		return want
	}}); err != nil {
		t.Fatal(err)
	}
	go func() {
		h.SetKeepIdleConnections(false)
		close(stopped)
	}()
	naiveOutboundWait(t, entered)
	ctx, cancel := context.WithCancel(t.Context())
	waiting := make(chan error, 1)
	go func() {
		_, err := h.clients.acquire(ctx, true)
		waiting <- err
	}()
	cancel()
	if err := <-waiting; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter acquired a replacement: %v", err)
	}
	unblock()
	naiveOutboundWait(t, stopped)
	dest := M.ParseSocksaddrHostPort("127.0.0.1", 443)
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		if _, err := h.DialContext(t.Context(), network, dest); !errors.Is(err, want) {
			t.Fatalf("%s dial bypassed an unproven shutdown: %v", network, err)
		}
	}
	if _, err := h.ListenPacket(t.Context(), dest); !errors.Is(err, want) {
		t.Fatalf("UoT packet dial bypassed an unproven shutdown: %v", err)
	}
	if h.clients.current != first || !errors.Is(h.runtime.close(), want) {
		t.Fatal("uncertain owner was discarded or final stop lost the failure")
	}
}

func TestNaiveOutboundLateDialCompensatesBeforeClose(t *testing.T) {
	r := newOutboundRuntime(context.Background())
	r.client = naiveOutboundTestCloser{}
	if err := r.install(context.Background()); err != nil {
		t.Fatal(err)
	}
	entered, returned, closeEntered, closeRelease := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var returnOnce, releaseOnce sync.Once
	releaseDial := func() { returnOnce.Do(func() { close(returned) }) }
	releaseClose := func() { releaseOnce.Do(func() { close(closeRelease) }) }
	t.Cleanup(releaseDial)
	t.Cleanup(releaseClose)
	raw := &naiveOutboundTestConn{close: func() error { close(closeEntered); <-closeRelease; return nil }}
	d := r.guardDialer(naiveOutboundTestDialer{dial: func(context.Context) (net.Conn, error) { close(entered); <-returned; return raw, nil }})
	dialDone := make(chan struct{})
	go func() { _, _ = d.DialContext(context.Background(), "tcp", M.Socksaddr{}); close(dialDone) }()
	naiveOutboundWait(t, entered)
	closed := make(chan struct{})
	go func() { _ = r.close(); close(closed) }()
	naiveOutboundWait(t, r.ctx.Done())
	releaseDial()
	naiveOutboundWait(t, closeEntered)
	select {
	case <-closed:
		t.Fatal("late socket cleanup lost")
	default:
	}
	releaseClose()
	naiveOutboundWait(t, dialDone)
	naiveOutboundWait(t, closed)
}

func TestNaiveOutboundPhysicalCarrierUsesRelayAndHalfClose(t *testing.T) {
	r := newOutboundRuntime(context.Background())
	defer r.close()
	r.client = naiveOutboundTestCloser{}
	if err := r.install(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw := &naiveOutboundTestConn{}
	d := r.guardDialer(naiveOutboundTestDialer{dial: func(context.Context) (net.Conn, error) { return raw, nil }})
	conn, err := d.DialContext(context.Background(), "tcp", M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := N.CastReader[*net.TCPConn](conn); ok {
		t.Fatal("raw TCP socket escaped and bypassed relay")
	}
	if _, ok := N.CastReader[*net.UDPConn](conn); ok {
		t.Fatal("raw UDP socket escaped and bypassed relay")
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if !raw.halfClosed.Load() {
		t.Fatal("relay half close not preserved")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNaiveOutboundNativeFailureRemainsSticky(t *testing.T) {
	r := newOutboundRuntime(context.Background())
	var calls atomic.Int32
	r.client = naiveOutboundTestCloser{close: func() error { calls.Add(1); return errors.New("native shutdown incomplete") }}
	if err := r.install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.close() == nil || r.close() == nil {
		t.Fatal("native close uncertainty disappeared")
	}
	if calls.Load() != 1 {
		t.Fatal("native terminal close repeated")
	}
}

func TestNaiveOutboundDNSCallbackRejectedAfterClose(t *testing.T) {
	r := newOutboundRuntime(context.Background())
	// Bind callback admission to a real fence even without a native engine.
	r.begin = func(ctx context.Context) (context.Context, func(), error) {
		leave, err := r.fence.Acquire()
		return ctx, leave, err
	}
	var calls atomic.Int32
	resolve := r.guardDNS(func(_ context.Context, request *mDNS.Msg) *mDNS.Msg { calls.Add(1); return request })
	if err := r.close(); err != nil {
		t.Fatal(err)
	}
	response := resolve(context.Background(), new(mDNS.Msg))
	if calls.Load() != 0 || response.Rcode != mDNS.RcodeServerFailure {
		t.Fatal("sealed DNS callback dispatched")
	}
}

func TestNaiveOutboundCloseJoinsNativeCompletion(t *testing.T) {
	r := newOutboundRuntime(context.Background())
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	releaseNative := func() { once.Do(func() { close(release) }) }
	t.Cleanup(releaseNative)
	r.client = naiveOutboundTestCloser{close: func() error { close(entered); <-release; return nil }}
	if err := r.install(context.Background()); err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { _ = r.close(); close(closed) }()
	naiveOutboundWait(t, entered)
	select {
	case <-closed:
		t.Fatal("native completion was not joined")
	default:
	}
	releaseNative()
	naiveOutboundWait(t, closed)
}

func TestNaiveStandaloneClientOptionsKeepNativePaths(t *testing.T) {
	ctx := context.WithValue(context.Background(), struct{}{}, "standalone")
	r := newOutboundRuntime(ctx)
	dialer := &naiveOutboundTestDialer{}
	request := new(mDNS.Msg)
	var calls atomic.Int32
	options := cronet.NaiveClientOptions{
		Context:     ctx,
		Dialer:      dialer,
		DNSResolver: func(_ context.Context, got *mDNS.Msg) *mDNS.Msg { calls.Add(1); return got },
	}
	guarded := r.guardClientOptions(options)
	if guarded.Context != ctx || guarded.Dialer != dialer || guarded.Logger != options.Logger {
		t.Fatal("standalone native inputs changed")
	}
	if err := r.close(); err != nil {
		t.Fatal(err)
	}
	if guarded.DNSResolver(ctx, request) != request || calls.Load() != 1 {
		t.Fatal("standalone DNS callback was wrapped")
	}
}
