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
	failBind.Store(false)
	endpoint.SetIdle(false)
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
	foreground, err := endpoint.ListenPacket(t.Context(), destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = foreground.Close() })
	if urltest.IsBackgroundProbe(endpoint.activationContext()) {
		t.Fatal("foreground takeover retained background attribution for native work")
	}
	if err = probeCarrier.Close(); err != nil {
		t.Fatal(err)
	}
	if endpoint.suspended.Load() {
		t.Fatal("closing a probe suspended a device already taken over by foreground traffic")
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

type probeBindTestCarrier struct{ *clientBindCloseCarrier }

func (c probeBindTestCarrier) Read(p []byte) (int, error) { return c.Conn.Read(p) }
func (probeBindTestCarrier) Write(p []byte) (int, error)  { return len(p), nil }

func TestBackgroundWireGuardProbeCoolingWaitsForNativeBind(t *testing.T) {
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
	go func() { closed <- probe.Close() }()
	select {
	case <-physical.started:
	case <-time.After(3 * time.Second):
		t.Fatal("native Down did not start closing the ClientBind carrier")
	}
	if endpoint.AdmitInbound() {
		t.Fatal("retiring native ingress incorrectly took ownership")
	}
	foreground, stop := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer stop()
	carrier, err := endpoint.ListenPacket(foreground, destination)
	if carrier != nil {
		_ = carrier.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
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
