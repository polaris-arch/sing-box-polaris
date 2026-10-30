package hysteria2

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
	nativeHysteria2 "github.com/sagernet/sing-quic/hysteria2"
	M "github.com/sagernet/sing/common/metadata"
)

type outboundTestClient struct{ close func() error }

func (c outboundTestClient) RuntimeCloseAndWait() error {
	if c.close != nil {
		return c.close()
	}
	return nil
}

type outboundTestDialer struct {
	dial func(context.Context) (net.Conn, error)
}

func (d outboundTestDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	return d.dial(ctx)
}

func (d outboundTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unexpected packet listener")
}

type outboundTestConn struct {
	close func() error
	once  sync.Once
	err   error
}

func (c *outboundTestConn) Close() error {
	c.once.Do(func() {
		if c.close != nil {
			c.err = c.close()
		}
	})
	return c.err
}
func (*outboundTestConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (*outboundTestConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*outboundTestConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*outboundTestConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (*outboundTestConn) SetDeadline(time.Time) error      { return nil }
func (*outboundTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*outboundTestConn) SetWriteDeadline(time.Time) error { return nil }
func outboundTestWait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("ownership barrier did not complete")
	}
}

func TestOutboundRejectsSealedReceiverBeforeClientAccess(t *testing.T) {
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "quic-node", Sequence: 1}, nil, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	owner.Seal()
	h := &Outbound{runtime: &outboundRuntime{source: owner}}
	// A dispatched call would touch the deliberately absent logger/client.
	if _, err = h.DialContext(context.Background(), "tcp", M.Socksaddr{}); err == nil {
		t.Fatal("sealed receiver dispatched")
	}
	if _, err = h.ListenPacket(context.Background(), M.Socksaddr{}); err == nil {
		t.Fatal("sealed UDP receiver dispatched")
	}
}

func TestOutboundRuntimeRejectsUnjoinedLegacyClient(t *testing.T) {
	r := newOutboundRuntime(context.Background())
	defer r.close()
	if err := r.install(context.Background(), struct{}{}); err == nil {
		t.Fatal("missing native worker join accepted")
	}
}

func TestOutboundLateSocketIsJoinedBeforeTerminalCleanup(t *testing.T) {
	r := newOutboundRuntime(context.Background())
	if err := r.install(context.Background(), outboundTestClient{}); err != nil {
		t.Fatal(err)
	}
	entered, returnSocket, closeEntered, closeRelease := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var returnOnce, releaseOnce sync.Once
	returnNow := func() { returnOnce.Do(func() { close(returnSocket) }) }
	releaseNow := func() { releaseOnce.Do(func() { close(closeRelease) }) }
	t.Cleanup(returnNow)
	t.Cleanup(releaseNow)
	raw := &outboundTestConn{close: func() error { close(closeEntered); <-closeRelease; return nil }}
	dialer := r.guardDialer(outboundTestDialer{dial: func(context.Context) (net.Conn, error) { close(entered); <-returnSocket; return raw, nil }})
	dialDone := make(chan struct{})
	go func() { _, _ = dialer.DialContext(context.Background(), "udp", M.Socksaddr{}); close(dialDone) }()
	outboundTestWait(t, entered)
	closed := make(chan struct{})
	go func() { _ = r.close(); close(closed) }()
	outboundTestWait(t, r.ctx.Done())
	returnNow()
	outboundTestWait(t, closeEntered)
	select {
	case <-closed:
		t.Fatal("late socket close tail lost")
	default:
	}
	releaseNow()
	outboundTestWait(t, dialDone)
	outboundTestWait(t, closed)
}

func TestOutboundJoinedSocketPreservesTerminalCloseFailure(t *testing.T) {
	failure := errors.New("socket close incomplete")
	raw := &outboundTestConn{close: func() error { return failure }}
	guarded, fence := outbound.WrapRuntimeOwnedConn(raw)
	conn := &outboundJoinedConn{Conn: guarded, fence: fence}
	if err := conn.Close(); err == nil {
		t.Fatal("close uncertainty lost")
	}
	if err := conn.Close(); err == nil {
		t.Fatal("close uncertainty not sticky")
	}
}

func TestOldOutboundCarrierSurvivesEditAndNewOwnerIsIndependent(t *testing.T) {
	var oldClosed, newClosed atomic.Bool
	old, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "quic-node", Sequence: 1}, nil, func() error { oldClosed.Store(true); return nil })
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "quic-node", Sequence: 2}, nil, func() error { newClosed.Store(true); return nil })
	if err != nil {
		t.Fatal(err)
	}
	conn, err := outbound.DialRuntimeConn(context.Background(), old, func(context.Context) (net.Conn, error) { return &outboundTestConn{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	old.Seal() // node edit/remove retires only old root admission
	if oldClosed.Load() {
		t.Fatal("editing node destroyed admitted old carrier")
	}
	if _, err = conn.Write([]byte("old TLS/auth generation")); err != nil {
		t.Fatal(err)
	}
	next, err := outbound.DialRuntimeConn(context.Background(), fresh, func(context.Context) (net.Conn, error) { return &outboundTestConn{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	fresh.Seal()
	if newClosed.Load() {
		t.Fatal("new generation lost its carrier")
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = old.WaitClosed(ctx); err != nil {
		t.Fatal(err)
	}
	if newClosed.Load() {
		t.Fatal("old close affected new generation")
	}
	if err = next.Close(); err != nil {
		t.Fatal(err)
	}
	if err = fresh.WaitClosed(ctx); err != nil {
		t.Fatal(err)
	}
}

type outboundDescriptorConn struct {
	outboundTestConn
	calls atomic.Int32
}

func (c *outboundDescriptorConn) SyscallConn() (syscall.RawConn, error) {
	c.calls.Add(1)
	return nil, errors.New("descriptor probe")
}

func TestObfuscationCarrierCannotExposeUnderlyingDescriptor(t *testing.T) {
	raw := &outboundDescriptorConn{}
	r := newOutboundRuntime(context.Background())
	defer r.close()
	opaque := r.nativeCarrier(raw)
	guarded, fence := outbound.WrapRuntimeOwnedConn(opaque)
	defer fence.RuntimeCloseAndWait()
	_, _ = outbound.RuntimeSyscallConn(guarded)
	if raw.calls.Load() != 0 {
		t.Fatal("native fast path bypassed obfuscation/hopping")
	}
	r.allowNativeDescriptor = true
	plain := r.nativeCarrier(raw)
	guardedPlain, plainFence := outbound.WrapRuntimeOwnedConn(plain)
	defer plainFence.RuntimeCloseAndWait()
	_, _ = outbound.RuntimeSyscallConn(guardedPlain)
	if raw.calls.Load() != 1 {
		t.Fatal("plain UDP lost guarded descriptor path")
	}
}

// Packet listeners use the same owner boundary as ordinary connected sockets.
type outboundRealmTestDialer struct {
	listen func(context.Context) (net.PacketConn, error)
}

func (d outboundRealmTestDialer) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	return d.listen(ctx)
}

func (outboundRealmTestDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("unexpected dial")
}

type outboundRealmTestPacket struct{ outboundTestConn }

func (p *outboundRealmTestPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := p.Read(b)
	return n, p.LocalAddr(), err
}
func (p *outboundRealmTestPacket) WriteTo(b []byte, _ net.Addr) (int, error) { return p.Write(b) }

type outboundRealmRoundTrip func(*http.Request) (*http.Response, error)

func (f outboundRealmRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type outboundRealmBody struct {
	io.Reader
	close func() error
}

func (b *outboundRealmBody) Close() error { return b.close() }

func TestRealmLatePacketListenerIsJoinedAndFailureRetained(t *testing.T) {
	r := newOutboundRuntime(context.Background())
	if err := r.install(context.Background(), outboundTestClient{}); err != nil {
		t.Fatal(err)
	}
	entered, release, closeEntered, closeRelease := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once, closeOnce sync.Once
	releaseNow := func() { once.Do(func() { close(release) }) }
	closeNow := func() { closeOnce.Do(func() { close(closeRelease) }) }
	t.Cleanup(releaseNow)
	t.Cleanup(closeNow)
	failure := errors.New("late packet close failed")
	raw := &outboundRealmTestPacket{outboundTestConn: outboundTestConn{close: func() error { close(closeEntered); <-closeRelease; return failure }}}
	d := r.guardDialer(outboundRealmTestDialer{listen: func(context.Context) (net.PacketConn, error) { close(entered); <-release; return raw, nil }})
	done := make(chan struct{})
	go func() { _, _ = d.ListenPacket(context.Background(), M.Socksaddr{}); close(done) }()
	outboundTestWait(t, entered)
	closed := make(chan struct{})
	var closeErr error
	go func() { closeErr = r.close(); close(closed) }()
	outboundTestWait(t, r.ctx.Done())
	releaseNow()
	outboundTestWait(t, closeEntered)
	select {
	case <-closed:
		t.Fatal("late packet cleanup was not joined")
	default:
	}
	closeNow()
	outboundTestWait(t, closed)
	outboundTestWait(t, done)
	if !errors.Is(closeErr, failure) || !errors.Is(r.close(), failure) {
		t.Fatalf("packet cleanup debt lost: %v", closeErr)
	}
}

func TestRealmCapturedLookupJoinsLateResolver(t *testing.T) {
	r := newOutboundRuntime(context.Background())
	if err := r.install(context.Background(), outboundTestClient{}); err != nil {
		t.Fatal(err)
	}
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	releaseNow := func() { once.Do(func() { close(release) }) }
	t.Cleanup(releaseNow)
	done := make(chan struct{})
	go func() {
		_, _ = r.realmLookup(context.Background(), func(ctx context.Context) ([]netip.Addr, error) {
			close(entered)
			<-ctx.Done()
			close(canceled)
			<-release
			return nil, ctx.Err()
		})
		close(done)
	}()
	outboundTestWait(t, entered)
	closed := make(chan struct{})
	go func() { _ = r.close(); close(closed) }()
	outboundTestWait(t, canceled)
	select {
	case <-closed:
		t.Fatal("retire certified a late resolver")
	default:
	}
	releaseNow()
	outboundTestWait(t, done)
	outboundTestWait(t, closed)
	if _, err := r.realmLookup(context.Background(), func(context.Context) ([]netip.Addr, error) { t.Error("sealed lookup dispatched"); return nil, nil }); err == nil {
		t.Fatal("sealed resolver admitted")
	}
}

func TestRealmLateHTTPBodyCloseIsJoinedAndFailureSticky(t *testing.T) {
	dependency, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "realm-late-body", Sequence: 2}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	depLease, err := dependency.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	var r *outboundRuntime
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "realm-late-body", Sequence: 1}, []adapter.RuntimeResourceLease{depLease}, func() error { return r.close() })
	depLease.Release()
	if err != nil {
		t.Fatal(err)
	}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	ctx := adapter.ContextWithRuntimeResourceSource(adapter.ContextWithConstructionScope(scope.Context(), scope), owner)
	r = newOutboundRuntime(ctx)
	workerDone, waiterEntered := make(chan struct{}), make(chan struct{})
	// Model the native client's counted HTTP consumer: its terminal join cannot
	// finish until the actual body Close has returned and recorded its result.
	if err := r.install(ctx, outboundTestClient{close: func() error {
		close(waiterEntered)
		<-workerDone
		return nil // the boundary, not this fake waiter, must retain the cause
	}}); err != nil {
		t.Fatal(err)
	}
	flow, err := owner.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	entered, release, bodyEntered, bodyRelease := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once, bodyOnce sync.Once
	releaseNow := func() { once.Do(func() { close(release) }) }
	bodyNow := func() { bodyOnce.Do(func() { close(bodyRelease) }) }
	t.Cleanup(releaseNow)
	t.Cleanup(bodyNow)
	failure := errors.New("response body close failed")
	var bodyCloses atomic.Int32
	var dispatches atomic.Int32
	transport := &outboundRealmHTTPTransport{owner: r, transport: outboundRealmRoundTrip(func(*http.Request) (*http.Response, error) {
		if dispatches.Add(1) != 1 {
			return nil, errors.New("sealed HTTP request reached transport")
		}
		close(entered)
		<-release
		return &http.Response{StatusCode: 200, Body: &outboundRealmBody{Reader: strings.NewReader("{}"), close: func() error {
			if bodyCloses.Add(1) == 1 {
				close(bodyEntered)
			}
			<-bodyRelease
			return failure
		}}}, nil
	})}
	request, _ := http.NewRequest(http.MethodGet, "https://realm.invalid", nil)
	go func() {
		defer close(workerDone)
		response, _ := transport.RoundTrip(request)
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
	}()
	t.Cleanup(func() {
		releaseNow()
		bodyNow()
		flow.Release()
		owner.Seal()
		dependency.Seal()
		_ = scope.Close()
	})
	outboundTestWait(t, entered)
	owner.Seal()
	dependency.Seal()
	closed := make(chan struct{})
	var closeErr error
	go func() { closeErr = r.close(); close(closed) }()
	outboundTestWait(t, r.ctx.Done())
	outboundTestWait(t, waiterEntered)
	releaseNow()
	outboundTestWait(t, bodyEntered)
	select {
	case <-closed:
		t.Fatal("body close was detached")
	default:
	}
	select {
	case <-workerDone:
		t.Fatal("consumer completed before the body close returned")
	case <-dependency.Closed():
		t.Fatal("old dependency was released while its consumer was unresolved")
	default:
	}
	bodyNow()
	outboundTestWait(t, workerDone)
	outboundTestWait(t, closed)
	if !errors.Is(closeErr, failure) || !errors.Is(r.close(), failure) {
		t.Fatalf("body failure lost: %v", closeErr)
	}
	if bodyCloses.Load() != 1 {
		t.Fatal("raw body closed more than once")
	}
	if _, err := transport.RoundTrip(request); err == nil || dispatches.Load() != 1 {
		t.Fatal("sealed HTTP owner admitted another request", err)
	}
	owner.Seal()
	dependency.Seal()
	flow.Release()
	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := owner.WaitClosed(waitCtx); !errors.Is(err, failure) {
		t.Fatal("resource cleanup lost the body debt", err)
	}
	if err := scope.Close(); err == nil {
		t.Fatal("Scope certified failed body cleanup")
	}
	select {
	case <-dependency.Closed():
		t.Fatal("failed old generation released its dependency reservation")
	default:
	}
}

func TestRealmOldSameTagUsesCapturedHTTPAndDNSClosure(t *testing.T) {
	type boundGeneration struct {
		runtime           *outboundRuntime
		owner, dependency *runtimegraph.ResourceOwner
		flow              adapter.RuntimeResourceLease
		scope             *adapter.Scope
	}
	makeGeneration := func(sequence uint64) *boundGeneration {
		dependency, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "realm-same-tag", Sequence: sequence + 1}, nil, func() error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		depLease, err := dependency.Acquire()
		if err != nil {
			t.Fatal(err)
		}
		var runtime *outboundRuntime
		owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "realm-same-tag", Sequence: sequence}, []adapter.RuntimeResourceLease{depLease}, func() error { return runtime.close() })
		depLease.Release()
		if err != nil {
			t.Fatal(err)
		}
		scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
		ctx := adapter.ContextWithRuntimeResourceSource(adapter.ContextWithConstructionScope(scope.Context(), scope), owner)
		runtime = newOutboundRuntime(ctx)
		if err = runtime.install(ctx, outboundTestClient{}); err != nil {
			t.Fatal(err)
		}
		flow, err := owner.Acquire()
		if err != nil {
			t.Fatal(err)
		}
		g := &boundGeneration{runtime, owner, dependency, flow, scope}
		t.Cleanup(func() { flow.Release(); owner.Seal(); dependency.Seal(); _ = scope.Close() })
		return g
	}
	old, fresh := makeGeneration(1), makeGeneration(3)
	old.owner.Seal()
	old.dependency.Seal()
	for _, pair := range [][2]*boundGeneration{{old, fresh}, {fresh, old}} {
		g, foreign := pair[0], pair[1]
		verify := func(ctx context.Context) {
			if ok, err := outbound.ValidateRuntimeOwnedSession(ctx, g.dependency); err != nil || !ok {
				t.Errorf("captured dependency unavailable: %v", err)
			}
			if _, err := outbound.ValidateRuntimeOwnedSession(ctx, foreign.dependency); err == nil {
				t.Error("same tag borrowed replacement closure")
			}
		}
		transport := &outboundRealmHTTPTransport{owner: g.runtime, transport: outboundRealmRoundTrip(func(request *http.Request) (*http.Response, error) {
			verify(request.Context())
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}"))}, nil
		})}
		request, _ := http.NewRequest(http.MethodGet, "https://realm.invalid", nil)
		response, err := transport.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		if err = response.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err = g.runtime.realmLookup(context.Background(), func(ctx context.Context) ([]netip.Addr, error) {
			verify(ctx)
			return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := old.runtime.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.runtime.realmLookup(context.Background(), func(context.Context) ([]netip.Addr, error) { return nil, nil }); err != nil {
		t.Fatal("old retire canceled new generation", err)
	}
}

type outboundRealmPeerPacket struct {
	outboundRealmTestPacket
	peers       []net.Addr
	wire        []byte
	writtenPeer net.Addr
}

func TestRealmMappingDeletionKeepsCapturedHTTPUntilActualTerminalJoin(t *testing.T) {
	for _, failClose := range []bool{false, true} {
		t.Run(map[bool]string{false: "confirmed", true: "body-close-failed"}[failClose], func(t *testing.T) {
			dependency, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "realm-delete", Sequence: 2}, nil, func() error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			depLease, err := dependency.Acquire()
			if err != nil {
				t.Fatal(err)
			}
			var r *outboundRuntime
			owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "realm-delete", Sequence: 1}, []adapter.RuntimeResourceLease{depLease}, func() error { return r.close() })
			depLease.Release()
			if err != nil {
				t.Fatal(err)
			}
			scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
			ctx := adapter.ContextWithRuntimeResourceSource(adapter.ContextWithConstructionScope(scope.Context(), scope), owner)
			r = newOutboundRuntime(ctx)
			closing, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			finish := func() { once.Do(func() { close(release) }) }
			failure := errors.New("mapping SOAP body close failed")
			var requests atomic.Int32
			httpClient := r.realmMappingHTTP(outboundRealmRoundTrip(func(request *http.Request) (*http.Response, error) {
				requests.Add(1)
				if request.Method != http.MethodPost || request.URL.Path != "/control" {
					t.Error("terminal mapping operation changed")
				}
				if ok, err := outbound.ValidateRuntimeOwnedSession(request.Context(), dependency); !ok || err != nil {
					t.Error("terminal delete lost the sealed generation's captured dependency", err)
				}
				return &http.Response{StatusCode: 200, Body: &outboundRealmBody{Reader: strings.NewReader("deleted"), close: func() error {
					close(closing)
					<-release
					if failClose {
						return failure
					}
					return nil
				}}}, nil
			}))
			if err = r.install(ctx, outboundTestClient{close: func() error {
				request, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:0/control", strings.NewReader("delete"))
				response, err := httpClient.Do(request)
				if err != nil {
					return err
				}
				_, readErr := io.ReadAll(response.Body)
				return errors.Join(readErr, response.Body.Close())
			}}); err != nil {
				t.Fatal(err)
			}
			flow, err := owner.Acquire()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { finish(); flow.Release(); owner.Seal(); dependency.Seal(); _ = scope.Close() })
			owner.Seal()
			dependency.Seal()
			flow.Release()
			outboundTestWait(t, closing)
			if _, leave, err := r.begin(context.Background()); err == nil {
				leave()
				t.Fatal("cleanup reopened ordinary QUIC admission")
			}
			select {
			case <-owner.Closed():
				t.Fatal("mapping HTTP body was not joined")
			default:
			}
			finish()
			waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = owner.WaitClosed(waitCtx)
			if (err != nil) != failClose || (failClose && !errors.Is(err, failure)) {
				t.Fatal("mapping cleanup result lost", err)
			}
			if _, err = httpClient.Get("http://127.0.0.1:0/control"); err == nil || requests.Load() != 1 {
				t.Fatal("terminal mapping fence admitted new HTTP", err)
			}
		})
	}
}

func (p *outboundRealmPeerPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	if len(p.peers) == 0 {
		return 0, nil, io.EOF
	}
	peer := p.peers[0]
	p.peers = p.peers[1:]
	return copy(b, []byte("peer")), peer, nil
}

func (p *outboundRealmPeerPacket) WriteTo(b []byte, peer net.Addr) (int, error) {
	p.wire = append([]byte(nil), b...)
	p.writtenPeer = peer
	return len(b), nil
}

func TestRealmPacketQUICCarrierKeepsSelectedPeerAndObfuscation(t *testing.T) {
	for _, obfs := range []string{"plain", "salamander", "gecko"} {
		t.Run(obfs, func(t *testing.T) {
			peer := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.2:443"))
			raw := &outboundRealmPeerPacket{peers: []net.Addr{net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.3:443")), peer}}
			var packet net.PacketConn = raw
			switch obfs {
			case "salamander":
				packet = nativeHysteria2.NewSalamanderConn(raw, []byte("test"))
			case "gecko":
				packet = nativeHysteria2.NewGeckoConn(raw, []byte("test"), 64, 128)
			}
			carrier, err := newOutboundRealmPacketCarrier(packet, peer)
			if err != nil {
				t.Fatal(err)
			}
			peer.IP[0] = 203 // caller-owned mutable address must not rebind this session
			if carrier.RemoteAddr().String() != "192.0.2.2:443" {
				t.Fatal("selected peer aliased")
			}
			payload := []byte("QUIC payload")
			if n, err := carrier.Write(payload); err != nil || n != len(payload) {
				t.Fatal(n, err)
			}
			if raw.writtenPeer.String() != "192.0.2.2:443" {
				t.Fatal("write selected a different peer")
			}
			if obfs != "plain" && string(raw.wire) == string(payload) {
				t.Fatal("native path bypassed obfuscation")
			}
			if _, ok := carrier.(interface{ Upstream() any }); ok {
				t.Fatal("raw upstream escaped")
			}
			if _, ok := carrier.(syscall.Conn); ok {
				t.Fatal("raw descriptor escaped")
			}
			if obfs == "plain" {
				// Restore the immutable receive fixture after mutating the caller.
				raw.peers[1] = carrier.RemoteAddr()
				buf := make([]byte, 16)
				if n, err := carrier.Read(buf); err != nil || string(buf[:n]) != "peer" || len(raw.peers) != 0 {
					t.Fatal("foreign peer was accepted or selected peer dropped", err)
				}
			}
		})
	}
	if _, err := newOutboundRealmPacketCarrier(&outboundRealmTestPacket{}, &net.TCPAddr{}); err == nil {
		t.Fatal("non-UDP peer accepted")
	}
}
