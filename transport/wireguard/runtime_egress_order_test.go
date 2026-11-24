package wireguard

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/wireguard-go/conn"
)

type wireguardIdleTestDialer struct {
	N.Dialer
	control control.Func
}

func (d wireguardIdleTestDialer) UDPListenerControl() (control.Func, bool) {
	return d.control, false
}

func newIdleTestEndpoint(t *testing.T, dialer N.Dialer, resolve func(context.Context, string) ([]netip.Addr, error)) (*Endpoint, *net.UDPConn) {
	t.Helper()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerAddress := M.SocksaddrFromNet(peer.LocalAddr())
	if resolve != nil {
		address := peerAddress.Addr
		peerAddress = M.Socksaddr{Fqdn: "peer.test", Port: peerAddress.Port}
		originalResolve := resolve
		resolve = func(ctx context.Context, name string) ([]netip.Addr, error) {
			addrs, err := originalResolve(ctx, name)
			if addrs == nil && err == nil {
				addrs = []netip.Addr{address}
			}
			return addrs, err
		}
	}
	if dialer == nil {
		dialer = wireguardIdleTestDialer{}
	}
	endpoint, err := NewEndpoint(EndpointOptions{
		Context:        t.Context(),
		Logger:         log.NewNOPFactory().Logger(),
		StartSuspended: true,
		Address:        []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")},
		PrivateKey:     base64.StdEncoding.EncodeToString(privateKey.Bytes()),
		ResolvePeer:    resolve,
		Peers: []PeerOptions{{
			Endpoint:                    peerAddress,
			PublicKey:                   base64.StdEncoding.EncodeToString(peerKey.PublicKey().Bytes()),
			AllowedIPs:                  []netip.Prefix{netip.MustParsePrefix("192.0.2.2/32")},
			PersistentKeepaliveInterval: 25,
		}},
		Dialer:  dialer,
		Workers: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := endpoint.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := endpoint.Initialize(nil); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.Start(resolve != nil); err != nil {
		t.Fatal(err)
	}
	return endpoint, peer
}

func TestEndpointStartsSuspendedAndRetriesActivation(t *testing.T) {
	attempted := make(chan struct{}, 1)
	bindFailure := errors.New("test bind failure")
	var failBind atomic.Bool
	endpoint, peer := newIdleTestEndpoint(t, wireguardIdleTestDialer{control: func(_, _ string, _ syscall.RawConn) error {
		select {
		case attempted <- struct{}{}:
		default:
		}
		if failBind.Load() {
			return bindFailure
		}
		return nil
	}}, nil)
	destination := M.ParseSocksaddr("192.0.2.2:443")
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if packet, err := endpoint.ListenPacket(canceled, destination); !errors.Is(err, context.Canceled) {
		if packet != nil {
			_ = packet.Close()
		}
		t.Fatalf("canceled flow did not report cancellation: %v", err)
	}
	select {
	case <-attempted:
		t.Fatal("unreferenced endpoint opened its bind before any flow")
	case <-time.After(100 * time.Millisecond):
	}

	failBind.Store(true)
	if packet, err := endpoint.ListenPacket(t.Context(), destination); !errors.Is(err, bindFailure) {
		if packet != nil {
			_ = packet.Close()
		}
		t.Fatalf("first flow did not report activation failure: %v", err)
	}
	if release, err := endpoint.HoldProbe(urltest.ContextWithScopedProbe(t.Context())); release != nil || !errors.Is(err, bindFailure) || endpoint.probe.Load() != nil {
		if release != nil {
			release()
		}
		t.Fatalf("failed scoped activation retained its hold: %v", err)
	}
	failBind.Store(false)
	endpoint.SetIdle(false)
	readIdleHandshake(t, peer)
}

func readIdleHandshake(t *testing.T, peer *net.UDPConn) {
	t.Helper()
	if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var packet [256]byte
	size, _, err := peer.ReadFromUDP(packet[:])
	if err != nil {
		t.Fatal(err)
	}
	if size != 148 || binary.LittleEndian.Uint32(packet[:4]) != 1 {
		t.Fatalf("activation did not send a WireGuard handshake initiation: size %d, type %d", size, binary.LittleEndian.Uint32(packet[:4]))
	}
}

func TestWireGuardProbeHoldsOneActivationAcrossDestinationLookup(t *testing.T) {
	for _, scenario := range []struct {
		name string
		hold bool
	}{
		{"legacy background waits for physical dialing", false},
		{"scoped foreground bridges lookup and destination", true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			endpoint, peer := newIdleTestEndpoint(t, nil, nil)
			ctx := urltest.ContextWithBackgroundProbe(t.Context())
			if scenario.hold {
				ctx = urltest.ContextWithLegacyPoolProbeDNS(urltest.ContextWithScopedProbe(t.Context()), "dns-probe-exit-1")
			}
			release, err := endpoint.HoldProbe(ctx)
			if err != nil || (release != nil) != scenario.hold {
				t.Fatalf("unexpected lookup hold: %v", err)
			}
			if release != nil {
				defer release()
				const resolver = "dns-probe-exit-1"
				if !urltest.IsLegacyPoolProbeDNS(ctx, resolver) ||
					urltest.IsLegacyPoolProbeDNS(endpoint.activationContext(), resolver) ||
					urltest.IsBackgroundProbe(endpoint.activationContext()) {
					t.Fatal("lookup hold changed foreground priority or let its App resolver into a native context")
				}
			} else if !endpoint.suspended.Load() || endpoint.probe.Load() != nil {
				t.Fatal("unverified legacy background opened the endpoint before its first physical dial")
			}
			// A resolver that closes its carrier before returning used to leave
			// nothing to hold the device for the next destination dial.
			lookup, err := endpoint.DialContext(ctx, N.NetworkUDP, M.ParseSocksaddr("192.0.2.2:53"))
			if err != nil {
				t.Fatal(err)
			}
			defer lookup.Close()
			readIdleHandshake(t, peer)
			if err := lookup.Close(); err != nil {
				t.Fatal(err)
			}
			if endpoint.suspended.Load() == scenario.hold {
				t.Fatal("endpoint lifetime did not follow the lookup hold")
			}

			destination, err := N.DialSerial(ctx, endpoint, N.NetworkUDP, M.ParseSocksaddr("origin.test:443"), []netip.Addr{netip.MustParseAddr("192.0.2.2")})
			if err != nil {
				t.Fatal(err)
			}
			defer destination.Close()
			if !scenario.hold {
				readIdleHandshake(t, peer)
			} else {
				release()
				if endpoint.suspended.Load() {
					t.Fatal("destination carrier did not take over the lookup hold")
				}
				if err := peer.SetReadDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				if _, _, err := peer.ReadFromUDP(make([]byte, 256)); !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("lookup and destination sent more than one initial handshake: %v", err)
				}
			}
			if err := destination.Close(); err != nil || !endpoint.suspended.Load() {
				t.Fatalf("last scoped carrier did not suspend: %v", err)
			}
		})
	}
}

func TestWireGuardScopedForegroundBorrowsWhileBackgroundIsOpening(t *testing.T) {
	for _, cancelOpener := range []bool{false, true} {
		name := "cancel manual waiter"
		if cancelOpener {
			name = "cancel original background opener"
		}
		t.Run(name, func(t *testing.T) {
			entered := make(chan context.Context, 1)
			unwind := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(unwind) })
			endpoint, peer := newIdleTestEndpoint(t, nil, func(ctx context.Context, _ string) ([]netip.Addr, error) {
				select {
				case entered <- ctx:
				default:
				}
				select {
				case <-unwind:
					return nil, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			})
			defer unblock()
			background, cancelBackground := context.WithCancel(urltest.ContextWithBackgroundProbe(t.Context()))
			defer cancelBackground()
			manual, cancelManual := context.WithCancel(urltest.ContextWithScopedProbe(t.Context()))
			defer cancelManual()
			type result struct {
				carrier net.PacketConn
				err     error
			}
			listen := func(ctx context.Context) <-chan result {
				done := make(chan result, 1)
				go func() {
					carrier, err := endpoint.ListenPacket(ctx, M.ParseSocksaddr("192.0.2.2:443"))
					done <- result{carrier, err}
				}()
				return done
			}
			wait := func(done <-chan result) result {
				t.Helper()
				select {
				case got := <-done:
					return got
				case <-time.After(3 * time.Second):
					t.Fatal("WireGuard admission did not return")
					return result{}
				}
			}
			cold := listen(background)
			var lookup context.Context
			select {
			case lookup = <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("background activation did not reach its live resolver")
			}
			scoped := listen(manual)
			deadline := time.NewTimer(3 * time.Second)
			defer deadline.Stop()
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			for urltest.IsBackgroundProbe(lookup) {
				select {
				case <-ticker.C:
				case <-deadline.C:
					t.Fatal("the scoped foreground request did not affect the opening activation")
				}
			}
			cancelled := cold
			surviving := scoped
			if cancelOpener {
				cancelBackground()
			} else {
				cancelManual()
				cancelled, surviving = scoped, cold
				if got := wait(cancelled); !errors.Is(got.err, context.Canceled) || !urltest.IsBackgroundProbe(lookup) {
					t.Fatalf("cancelled manual demand did not restore background priority: %v", got.err)
				}
			}
			if lookup.Err() != nil {
				t.Fatal("an individual cancellation stopped its surviving borrow")
			}
			unblock()
			if cancelOpener {
				if got := wait(cancelled); !errors.Is(got.err, context.Canceled) {
					t.Fatalf("cancelled original opener = %v", got.err)
				}
			}
			got := wait(surviving)
			if got.err != nil {
				t.Fatal(got.err)
			}
			readIdleHandshake(t, peer)
			if err := got.carrier.Close(); err != nil || !endpoint.suspended.Load() {
				t.Fatalf("temporary scoped waiter became a persistent activation: %v", err)
			}
		})
	}
}

func TestWireGuardProbePriorityFollowsLiveJoinedDetours(t *testing.T) {
	primary, _ := newIdleTestEndpoint(t, nil, nil)
	relay, _ := newIdleTestEndpoint(t, nil, nil)
	manualSource, _ := newIdleTestEndpoint(t, nil, nil)
	nextPrimary, _ := newIdleTestEndpoint(t, nil, nil)
	nextRelay, _ := newIdleTestEndpoint(t, nil, nil)
	background := urltest.ContextWithBackgroundProbe(t.Context())
	manual := urltest.ContextWithScopedProbe(t.Context())
	destination := M.ParseSocksaddr("192.0.2.2:443")
	listen := func(endpoint *Endpoint, ctx context.Context) net.PacketConn {
		t.Helper()
		carrier, err := endpoint.ListenPacket(ctx, destination)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = carrier.Close() })
		return carrier
	}
	hold := func(endpoint *Endpoint, ctx context.Context) func() {
		t.Helper()
		release, err := endpoint.HoldProbe(ctx)
		if err != nil || release == nil {
			t.Fatalf("expected a scoped hold: %v", err)
		}
		t.Cleanup(release)
		return release
	}
	closeCarrier := func(carrier net.PacketConn) {
		t.Helper()
		if err := carrier.Close(); err != nil {
			t.Fatal(err)
		}
	}
	assertPriority := func(wantBackground bool) {
		t.Helper()
		for name, endpoint := range map[string]*Endpoint{"first relay": relay, "second relay": nextRelay} {
			foreground, persistent := endpoint.probe.Load().path.foregroundPriority()
			if urltest.IsBackgroundProbe(endpoint.activationContext()) != wantBackground || foreground == wantBackground || persistent {
				t.Fatalf("%s priority did not follow current temporary live sources: foreground=%t persistent=%t", name, foreground, persistent)
			}
		}
	}

	listen(primary, background)
	fromPrimary := listen(relay, primary.activationContext())
	priorityPath := relay.probe.Load().path
	var unsharedForeground bool
	if allocations := testing.AllocsPerRun(20, func() { unsharedForeground, _ = priorityPath.foregroundPriority() }); allocations != 0 || unsharedForeground {
		t.Fatalf("the unshared path changed priority or allocated: foreground=%t allocations=%g", unsharedForeground, allocations)
	}
	listen(nextPrimary, background)
	fromNextPrimary := listen(nextRelay, nextPrimary.activationContext())
	fromRelay := listen(nextRelay, relay.activationContext())
	// An already active return detour can form a read-side cycle. It must
	// neither manufacture foreground demand nor hide another live source.
	listen(primary, relay.activationContext())
	assertPriority(true)

	listen(manualSource, background)
	releaseManual := hold(manualSource, manual)
	fromManual := listen(relay, manualSource.activationContext())
	extraHold := hold(relay, manualSource.activationContext())
	assertPriority(false)
	extraHold()
	assertPriority(false)
	releaseManual()
	assertPriority(true)

	hold(manualSource, manual)
	assertPriority(false)
	closeCarrier(fromManual)
	assertPriority(true)

	stillBackground := listen(relay, background)
	hold(primary, manual)
	assertPriority(false)
	closeCarrier(fromPrimary)
	assertPriority(true)

	ordinary := listen(relay, t.Context())
	closeCarrier(stillBackground)
	if relay.suspended.Load() || urltest.IsBackgroundProbe(relay.activationContext()) {
		t.Fatal("removing probe sources cooled an endpoint taken over by ordinary foreground traffic")
	}
	closeCarrier(fromRelay)
	closeCarrier(fromNextPrimary)
	if !nextRelay.suspended.Load() {
		t.Fatal("joined sources permanently promoted the second relay")
	}
	closeCarrier(ordinary)
}

func TestBackgroundWireGuardProbeReleasesOnlyItsOwnActivation(t *testing.T) {
	endpoint, _ := newIdleTestEndpoint(t, nil, nil)
	destination := M.ParseSocksaddr("192.0.2.2:443")
	probeCtx := urltest.ContextWithBackgroundProbe(t.Context())
	first, err := endpoint.ListenPacket(probeCtx, destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := endpoint.ListenPacket(probeCtx, destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	activation := endpoint.probe.Load()
	if activation == nil {
		t.Fatal("cold probe did not own the activation")
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	if endpoint.suspended.Load() {
		t.Fatal("closing one of two probe carriers brought the device down")
	}
	if err = second.Close(); err != nil {
		t.Fatal(err)
	}
	if !endpoint.suspended.Load() || endpoint.probe.Load() != nil || activation.ctx.Err() == nil {
		t.Fatal("closing the last probe did not cancel its resolver and suspend the device")
	}

	// A failed TCP setup must release its activation even without a carrier.
	failed, err := endpoint.DialContext(probeCtx, N.NetworkTCP, M.ParseSocksaddr("2001:db8::2:443"))
	if failed != nil || err == nil || !endpoint.suspended.Load() || endpoint.probe.Load() != nil {
		t.Fatalf("failed probe retained its activation: connection %v, error %v", failed, err)
	}

	probeCarrier, err := endpoint.ListenPacket(probeCtx, destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = probeCarrier.Close() })
	detour, _ := newIdleTestEndpoint(t, nil, nil)
	detourCarrier, err := detour.ListenPacket(endpoint.activationContext(), destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = detourCarrier.Close() })
	detourContext := detour.activationContext()
	if !urltest.IsBackgroundProbe(detourContext) {
		t.Fatal("probe attribution did not reach the downstream WireGuard activation")
	}
	foreground, err := endpoint.ListenPacket(t.Context(), destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = foreground.Close() })
	if urltest.IsBackgroundProbe(endpoint.activationContext()) {
		t.Fatal("foreground takeover retained background attribution for native work")
	}
	if urltest.IsBackgroundProbe(detourContext) {
		t.Fatal("foreground takeover did not reach the already open WireGuard detour")
	}
	if err = probeCarrier.Close(); err != nil {
		t.Fatal(err)
	}
	if endpoint.suspended.Load() {
		t.Fatal("closing a probe suspended a device already taken over by foreground traffic")
	}
	if err = endpoint.Close(); err != nil {
		t.Fatal(err)
	}
	if !urltest.IsBackgroundProbe(detourContext) {
		t.Fatal("a closed ancestor retained foreground priority for the surviving detour")
	}
	if err = detourCarrier.Close(); err != nil || !detour.suspended.Load() {
		t.Fatalf("detour priority changed its existing carrier ownership: %v", err)
	}
}

func TestBackgroundWireGuardProbeOpeningCancelsPeerResolution(t *testing.T) {
	entered := make(chan context.Context, 1)
	resolverUnwind := make(chan struct{})
	var allowResolverUnwind sync.Once
	var first atomic.Bool
	endpoint, _ := newIdleTestEndpoint(t, nil, func(ctx context.Context, _ string) ([]netip.Addr, error) {
		if first.CompareAndSwap(false, true) {
			entered <- ctx
			<-ctx.Done()
			<-resolverUnwind
			return nil, ctx.Err()
		}
		return nil, nil
	})
	background, cancel := context.WithCancel(urltest.ContextWithBackgroundProbe(t.Context()))
	defer cancel()
	destination := M.ParseSocksaddr("192.0.2.2:443")
	probeDone := make(chan error, 1)
	go func() {
		carrier, err := endpoint.ListenPacket(background, destination)
		if carrier != nil {
			_ = carrier.Close()
		}
		probeDone <- err
	}()
	defer allowResolverUnwind.Do(func() { close(resolverUnwind) })
	var lookup context.Context
	select {
	case lookup = <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("initial keepalive did not enter the real WireGuard resolver")
	}
	if !urltest.IsBackgroundProbe(lookup) {
		t.Fatal("native peer resolution lost the probe attribution")
	}
	cancel()
	select {
	case <-lookup.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("probe cancellation did not reach native peer resolution")
	}
	foreground, stop := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer stop()
	carrier, err := endpoint.ListenPacket(foreground, destination)
	if carrier != nil {
		_ = carrier.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("foreground did not honor its own deadline while old native Up was joining: %v", err)
	}
	allowResolverUnwind.Do(func() { close(resolverUnwind) })
	select {
	case err := <-probeDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled probe returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("old probe did not retire after its native resolver unwound")
	}
	if !endpoint.suspended.Load() || endpoint.probe.Load() != nil {
		t.Fatal("old activation remained published after cancellation")
	}
	carrier, err = endpoint.ListenPacket(t.Context(), destination)
	if err != nil {
		t.Fatal(err)
	}
	_ = carrier.Close()
}

func TestBackgroundWireGuardProbeRechecksDetourPriorityAfterOpening(t *testing.T) {
	entered := make(chan struct{})
	unwind := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(unwind) })
	notify := sync.OnceFunc(func() { close(entered) })
	endpoint, _ := newIdleTestEndpoint(t, nil, func(ctx context.Context, _ string) ([]netip.Addr, error) {
		notify()
		select {
		case <-unwind:
			return nil, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	defer unblock()
	destination := M.ParseSocksaddr("192.0.2.2:443")
	type result struct {
		carrier net.PacketConn
		err     error
	}
	open := func(ctx context.Context) <-chan result {
		finished := make(chan result, 1)
		go func() {
			carrier, err := endpoint.ListenPacket(ctx, destination)
			finished <- result{carrier, err}
		}()
		return finished
	}
	first := open(urltest.ContextWithBackgroundProbe(t.Context()))
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("initial WireGuard activation did not enter its resolver")
	}
	parent := &probeDialPath{}
	parent.phase.Store(probeBorrowed)
	classified := make(chan struct{})
	notifyClassification := sync.OnceFunc(func() { close(classified) })
	waiter := urltest.ContextWithSharedBackgroundProbe(context.WithValue(t.Context(), probeDialPathKey{}, parent), func(check func(context.Context) bool) bool {
		background := parent.isBackground(check)
		notifyClassification()
		return background
	})
	second := open(waiter)
	select {
	case <-classified:
	case <-time.After(3 * time.Second):
		t.Fatal("detour request did not reach admission")
	}
	parent.phase.Store(probePromoted)
	unblock()
	for _, finished := range []<-chan result{first, second} {
		select {
		case opened := <-finished:
			if opened.err != nil {
				t.Fatal(opened.err)
			}
			if err := opened.carrier.Close(); err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("WireGuard request remained blocked after the original resolver returned")
		}
	}
	if endpoint.suspended.Load() || urltest.IsBackgroundProbe(endpoint.activationContext()) {
		t.Fatal("the queued foreground detour was admitted with its stale background priority")
	}
}

type probeBindTestCarrier struct{ *clientBindCloseCarrier }

func (c probeBindTestCarrier) Read(p []byte) (int, error) { return c.Conn.Read(p) }
func (probeBindTestCarrier) Write(p []byte) (int, error)  { return len(p), nil }

func TestBackgroundWireGuardProbeCoolingWaitsForNativeBind(t *testing.T) {
	t.Run("cooling", func(t *testing.T) { testWireGuardProbeStopsNativeBind(t, false) })
	t.Run("terminal", func(t *testing.T) { testWireGuardProbeStopsNativeBind(t, true) })
}

func testWireGuardProbeStopsNativeBind(t *testing.T, terminal bool) {
	t.Helper()
	pipe, peer := net.Pipe()
	t.Cleanup(func() { _ = pipe.Close(); _ = peer.Close() })
	physical := &clientBindCloseCarrier{Conn: pipe, started: make(chan struct{}), release: make(chan struct{})}
	releasePhysical := sync.OnceFunc(func() { close(physical.release) })
	defer releasePhysical()
	detourContext := make(chan context.Context, 1)
	endpoint, _ := newIdleTestEndpoint(t, clientBindCloseDialer{
		stream: probeBindTestCarrier{physical},
		onDial: func(ctx context.Context) {
			select {
			case detourContext <- ctx:
			default:
			}
		},
	}, nil)
	destination := M.ParseSocksaddr("192.0.2.2:443")
	probe, err := endpoint.ListenPacket(urltest.ContextWithBackgroundProbe(t.Context()), destination)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case ctx := <-detourContext:
		if !urltest.IsBackgroundProbe(ctx) {
			t.Fatal("the physical ClientBind detour lost background attribution")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the ClientBind detour did not open")
	}
	closed := make(chan error, 1)
	t.Cleanup(func() { _ = probe.Close() })
	go func() {
		if terminal {
			closed <- endpoint.Close()
		} else {
			closed <- probe.Close()
		}
	}()
	select {
	case <-physical.started:
	case <-time.After(3 * time.Second):
		t.Fatal("native Down did not start closing the ClientBind carrier")
	}
	if endpoint.AdmitInbound() {
		t.Fatal("retiring native ingress incorrectly took ownership")
	}
	want := context.DeadlineExceeded
	if terminal {
		want = net.ErrClosed
	}
	foreground, stop := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer stop()
	carrier, err := endpoint.ListenPacket(foreground, destination)
	if carrier != nil {
		_ = carrier.Close()
	}
	if !errors.Is(err, want) {
		t.Fatalf("foreground bypassed the native Down join: %v", err)
	}
	releasePhysical()
	select {
	case err = <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("probe Close did not finish after its original native bind closed")
	}
	if !endpoint.suspended.Load() || endpoint.probe.Load() != nil || physical.closes.Load() != 1 {
		t.Fatal("probe did not suspend exactly its own native bind")
	}
}

// This structural regression protects terminal ordering even on platforms
// without native sockets. It is not a replacement for native race coverage.
func TestRuntimeEgressTerminalCloseFollowsOriginalWorkerJoins(t *testing.T) {
	source, err := os.ReadFile("endpoint.go")
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "endpoint.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Recv != nil && function.Name.Name == "close" {
			body = function.Body
		}
	}
	if body == nil {
		t.Fatal("endpoint close implementation missing")
	}
	var nativeClose, runtimeWait, poolClose token.Pos
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if receiver, ok := selector.X.(*ast.Ident); ok && receiver.Name == "wgDevice" && selector.Sel.Name == "Close" {
			nativeClose = call.Pos()
		}
		field, ok := selector.X.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if field.Sel.Name == "runtime" && selector.Sel.Name == "wait" {
			runtimeWait = call.Pos()
		}
		if field.Sel.Name == "egressPool" && selector.Sel.Name == "Close" {
			if poolClose != token.NoPos {
				t.Fatal("multiple terminal pool closes")
			}
			poolClose = call.Pos()
		}
		return true
	})
	if nativeClose == token.NoPos || runtimeWait == token.NoPos || poolClose == token.NoPos || poolClose < nativeClose || poolClose < runtimeWait {
		t.Fatal("egress pool must close after original native and pause worker joins")
	}
}

type clientBindCloseCarrier struct {
	net.Conn
	started  chan struct{}
	release  chan struct{}
	closeErr error
	closes   atomic.Int32
}

func (*clientBindCloseCarrier) Read([]byte) (int, error)  { return 0, net.ErrClosed }
func (*clientBindCloseCarrier) Write([]byte) (int, error) { return 0, net.ErrClosed }
func (c *clientBindCloseCarrier) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, nil, err
}
func (c *clientBindCloseCarrier) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }
func (c *clientBindCloseCarrier) Close() error {
	if c.closes.Add(1) == 1 {
		close(c.started)
	}
	<-c.release
	_ = c.Conn.Close()
	return c.closeErr
}

type clientBindCloseDialer struct {
	stream net.Conn
	packet net.PacketConn
	onDial func(context.Context)
}

func (d clientBindCloseDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	if d.onDial != nil {
		d.onDial(ctx)
	}
	return d.stream, nil
}

func (d clientBindCloseDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return d.packet, nil
}

func TestRuntimeClientBindJoinsPublishedCarrier(t *testing.T) {
	closeFailure := errors.New("physical WireGuard close failed")
	for _, mode := range []struct {
		name      string
		connected bool
	}{{"packet", false}, {"connected", true}} {
		for _, scenario := range []struct {
			name       string
			ownerFirst bool
			closeErr   error
		}{
			{"native-first", false, nil},
			{"owner-first", true, closeFailure},
			{"read-error", false, nil},
			{"send-error", false, nil},
		} {
			t.Run(mode.name+"/"+scenario.name, func(t *testing.T) {
				pipe, peer := net.Pipe()
				t.Cleanup(func() { _ = pipe.Close(); _ = peer.Close() })
				physical := &clientBindCloseCarrier{Conn: pipe, started: make(chan struct{}), release: make(chan struct{}), closeErr: scenario.closeErr}
				releasePhysical := sync.OnceFunc(func() { close(physical.release) })
				t.Cleanup(releasePhysical)
				var dialer clientBindCloseDialer
				var fence *outbound.RuntimeIOFence
				if mode.connected {
					dialer.stream, fence = outbound.WrapRuntimeOwnedConn(struct{ net.Conn }{physical})
				} else {
					leaf, _ := outbound.WrapRuntimeOwnedPacketConn(physical)
					registered := outbound.NewRuntimeInterruptPacketConn(interrupt.NewGroup(), leaf, false)
					dialer.packet, fence = outbound.WrapRuntimeOwnedPacketConn(registered)
				}
				fences := outbound.NewRuntimeIOFenceSet()
				creation, err := fences.Begin()
				if err != nil {
					t.Fatal(err)
				}
				err = creation.Register(fence)
				creation.Done()
				if err != nil {
					t.Fatal(err)
				}
				peerAddr := netip.MustParseAddrPort("192.0.2.1:51820")
				native := NewClientBind(context.Background(), log.NewNOPFactory().Logger(), dialer, mode.connected, peerAddr, [3]uint8{})
				runtime := &endpointRuntime{callbacks: outbound.NewRuntimeIOFence(nil), stopSignal: make(chan struct{})}
				bind := &runtimeClientBind{ClientBind: native, owner: runtime}
				receive, _, err := bind.Open(0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = native.connect(native.currentContext()); err != nil {
					t.Fatal(err)
				}
				if scenario.ownerFirst {
					fences.Stop()
				}
				result := make(chan error, 1)
				go func() {
					switch scenario.name {
					case "read-error":
						_, err := receive[0]([][]byte{{0}}, []int{0}, []conn.Endpoint{nil})
						result <- err
					case "send-error":
						result <- bind.Send([][]byte{{0}}, remoteEndpoint(peerAddr), 0)
					default:
						result <- bind.Close()
					}
				}()
				select {
				case <-physical.started:
				case <-time.After(3 * time.Second):
					t.Fatal("physical Close did not start")
				}
				select {
				case err := <-result:
					t.Fatalf("bind finished before physical Close returned: %v", err)
				default:
				}
				fences.Stop()
				releasePhysical()
				want := scenario.closeErr
				if scenario.name == "send-error" {
					want = net.ErrClosed
				}
				select {
				case err := <-result:
					if !errors.Is(err, want) {
						t.Fatalf("bind result = %v, want %v", err, want)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("bind did not finish after physical Close returned")
				}
				if err := bind.Close(); !errors.Is(err, scenario.closeErr) {
					t.Fatalf("final native bind Close = %v, want %v", err, scenario.closeErr)
				}
				runtime.stop()
				if err := runtime.wait(); !errors.Is(err, scenario.closeErr) {
					t.Fatalf("native runtime recorded %v, want %v", err, scenario.closeErr)
				}
				if err := fences.Wait(); !errors.Is(err, scenario.closeErr) || physical.closes.Load() != 1 {
					t.Fatalf("owner result = %v, physical Close calls = %d", err, physical.closes.Load())
				}
			})
		}
	}
}

func TestClientBindPreservesSynchronousClose(t *testing.T) {
	ctx := context.Background()
	failure := errors.New("physical close failed")
	released := make(chan struct{})
	close(released)
	for _, connected := range []bool{false, true} {
		for _, legacy := range []bool{false, true} {
			pipe, peer := net.Pipe()
			t.Cleanup(func() { _ = pipe.Close(); _ = peer.Close() })
			physical := &clientBindCloseCarrier{Conn: pipe, started: make(chan struct{}), release: released, closeErr: failure}
			dialer := clientBindCloseDialer{stream: physical, packet: physical}
			if legacy {
				var err error
				if connected {
					leaf, _ := outbound.WrapRuntimeOwnedConn(struct{ net.Conn }{physical})
					dialer.stream, err = outbound.DialRuntimeConn(ctx, nil, func(context.Context) (net.Conn, error) { return leaf, nil })
				} else {
					leaf, _ := outbound.WrapRuntimeOwnedPacketConn(physical)
					dialer.packet, err = outbound.ListenRuntimePacket(ctx, nil, func(context.Context) (net.PacketConn, error) { return leaf, nil })
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			bind := NewClientBind(ctx, log.NewNOPFactory().Logger(), dialer, connected, netip.AddrPort{}, [3]uint8{})
			if _, err := bind.connect(ctx); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := bind.Close(); !errors.Is(err, failure) || physical.closes.Load() != 1 {
					t.Fatalf("connected=%v legacy=%v: Close = %v, physical calls = %d", connected, legacy, err, physical.closes.Load())
				}
			}
		}
	}
}
