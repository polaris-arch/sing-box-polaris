package wireguard

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/wireguard-go/conn"
)

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
}

func (d clientBindCloseDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
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
