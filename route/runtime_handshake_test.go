package route

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

type handshakeWireConn struct {
	output bytes.Buffer
	closed atomic.Bool
}

func (*handshakeWireConn) Read([]byte) (int, error)      { return 0, io.EOF }
func (c *handshakeWireConn) Write(p []byte) (int, error) { return c.output.Write(p) }
func (c *handshakeWireConn) Close() error                { c.closed.Store(true); return nil }
func (*handshakeWireConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10000}
}
func (*handshakeWireConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*handshakeWireConn) SetDeadline(time.Time) error      { return nil }
func (*handshakeWireConn) SetReadDeadline(time.Time) error  { return nil }
func (*handshakeWireConn) SetWriteDeadline(time.Time) error { return nil }

type handshakeConnReporter struct {
	handshakeWireConn
	success func(net.Conn) error
	failure func(error) error
}

func (c *handshakeConnReporter) ConnHandshakeSuccess(conn net.Conn) error { return c.success(conn) }
func (c *handshakeConnReporter) HandshakeFailure(err error) error         { return c.failure(err) }

type handshakePacketReporter struct {
	N.PacketConn
	closed  atomic.Bool
	success func(net.PacketConn) error
	failure func(error) error
}

func (c *handshakePacketReporter) Close() error { c.closed.Store(true); return nil }
func (c *handshakePacketReporter) PacketConnHandshakeSuccess(conn net.PacketConn) error {
	return c.success(conn)
}
func (c *handshakePacketReporter) HandshakeFailure(err error) error { return c.failure(err) }

func TestRuntimeHandshakeTCPAndPacketForwardExactResult(t *testing.T) {
	for _, packet := range []bool{false, true} {
		t.Run(map[bool]string{false: "TCP", true: "packet"}[packet], func(t *testing.T) {
			graph := newReferenceTestGraph(1, nil, nil)
			lease := graph.acquire()
			var once sync.Once
			finish := func(error) { once.Do(lease.Release) }
			result := errors.New("protocol write failure")
			rejected := errors.New("original route rejection")
			calls := 0
			check := func() error {
				calls++
				if graphs, _ := graph.counts(); graphs != 2 {
					t.Fatalf("handshake lacks its own continuation: %d", graphs)
				}
				return result
			}
			failure := func(err error) error {
				if err != rejected {
					t.Fatal("original failure changed before protocol report")
				}
				return check()
			}
			var owned interface {
				Close() error
				HandshakeFailure(error) error
			}
			var success func() error
			if packet {
				remote := &net.UDPConn{}
				raw := &handshakePacketReporter{failure: failure, success: func(conn net.PacketConn) error {
					if conn != remote {
						t.Fatal("packet peer identity changed")
					}
					return check()
				}}
				wrapped := &runtimePacketConn{PacketConn: raw, lease: lease, finish: finish}
				owned = wrapped
				success = func() error { return N.ReportPacketConnHandshakeSuccess(wrapped, remote) }
			} else {
				remote := &handshakeWireConn{}
				raw := &handshakeConnReporter{failure: failure, success: func(conn net.Conn) error {
					if conn != remote {
						t.Fatal("TCP peer identity changed")
					}
					return check()
				}}
				wrapped := &runtimeConn{Conn: raw, lease: lease, finish: finish}
				owned = wrapped
				success = func() error { return N.ReportConnHandshakeSuccess(wrapped, remote) }
			}
			if _, exposed := common.Cast[interface{ Upstream() any }](owned); exposed {
				t.Fatal("ownership barrier exposes a raw upstream")
			}
			if got := success(); got != result {
				t.Fatalf("success error = %v", got)
			}
			// Do not use ReportHandshakeFailure inside an implementation: it
			// would append rejected again instead of returning the write result.
			if got := owned.HandshakeFailure(rejected); got != result {
				t.Fatalf("failure result = %v", got)
			}
			if graphs, _ := graph.counts(); graphs != 1 || calls != 2 {
				t.Fatal("handshake completed the flow or leaked its continuation")
			}
			_ = owned.Close()
			_ = owned.Close()
			if graphs, _ := graph.counts(); graphs != 0 {
				t.Fatal("terminal close leaked flow")
			}
			if err := success(); err == nil || calls != 2 {
				t.Fatal("terminal flow admitted a new handshake")
			}
		})
	}
}

func TestRuntimeHandshakeCloseJoinsInFlightReport(t *testing.T) {
	for _, packet := range []bool{false, true} {
		t.Run(map[bool]string{false: "TCP", true: "packet"}[packet], func(t *testing.T) {
			graph := newReferenceTestGraph(1, nil, nil)
			lease := graph.acquire()
			entered, release := make(chan struct{}), make(chan struct{})
			var unblockOnce, finishOnce sync.Once
			unblock := func() { unblockOnce.Do(func() { close(release) }) }
			defer unblock()
			finish := func(error) { finishOnce.Do(lease.Release) }
			report := func() error { close(entered); <-release; return nil }
			var owned io.Closer
			var handshake func() error
			if packet {
				raw := &handshakePacketReporter{success: func(net.PacketConn) error { return report() }}
				wrapped := &runtimePacketConn{PacketConn: raw, lease: lease, finish: finish}
				owned, handshake = wrapped, func() error { return wrapped.PacketConnHandshakeSuccess(nil) }
			} else {
				raw := &handshakeConnReporter{success: func(net.Conn) error { return report() }}
				wrapped := &runtimeConn{Conn: raw, lease: lease, finish: finish}
				owned, handshake = wrapped, func() error { return wrapped.ConnHandshakeSuccess(nil) }
			}
			done := make(chan error, 1)
			go func() { done <- handshake() }()
			managerAwait(t, entered)
			_ = owned.Close()
			if graphs, _ := graph.counts(); graphs != 1 {
				t.Fatal("close released live handshake ownership")
			}
			unblock()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("handshake did not return")
			}
			if graphs, _ := graph.counts(); graphs != 0 {
				t.Fatal("returned handshake retained graph")
			}
		})
	}
}

type handshakeLegacyConn struct {
	handshakeWireConn
	calls int
}

func (c *handshakeLegacyConn) HandshakeSuccess() error { c.calls++; return nil }

type handshakeLegacyPacket struct {
	N.PacketConn
	calls int
}

func (c *handshakeLegacyPacket) HandshakeSuccess() error { c.calls++; return nil }

func TestRuntimeHandshakePreservesLegacyAndAbsentCapabilities(t *testing.T) {
	graph := newReferenceTestGraph(1, nil, nil)
	lease := graph.acquire()
	defer lease.Release()
	legacy := new(handshakeLegacyConn)
	conn := &runtimeConn{Conn: legacy, lease: lease}
	if err := N.ReportConnHandshakeSuccess(conn, nil); err != nil {
		t.Fatal(err)
	}
	if err := conn.HandshakeSuccess(); err != nil || legacy.calls != 2 {
		t.Fatal("legacy TCP capability lost")
	}
	packet := new(handshakeLegacyPacket)
	wrappedPacket := &runtimePacketConn{PacketConn: packet, lease: lease}
	if err := N.ReportPacketConnHandshakeSuccess(wrappedPacket, nil); err != nil {
		t.Fatal(err)
	}
	if err := wrappedPacket.HandshakeSuccess(); err != nil || packet.calls != 2 {
		t.Fatal("legacy packet capability lost")
	}
	plain := &runtimeConn{Conn: new(handshakeWireConn), lease: lease}
	if err := plain.ConnHandshakeSuccess(nil); err != nil {
		t.Fatal(err)
	}
	if err := plain.HandshakeFailure(io.EOF); err != nil {
		t.Fatal(err)
	}
	if graphs, _ := graph.counts(); graphs != 1 {
		t.Fatal("optional capability check leaked ownership")
	}
}

type handshakeRouterView struct {
	adapter.RuntimeView
	router adapter.Router
}

func (v handshakeRouterView) Router() adapter.Router { return v.router }

type handshakeRouterLease struct {
	adapter.RuntimeLease
	view adapter.RuntimeView
}

func (l handshakeRouterLease) View() adapter.RuntimeView { return l.view }
func (l handshakeRouterLease) Fork() (adapter.RuntimeLease, error) {
	lease, err := l.RuntimeLease.Fork()
	if err != nil {
		return nil, err
	}
	return handshakeRouterLease{RuntimeLease: lease, view: l.view}, nil
}

type handshakeRouterLeaf struct {
	adapter.Router
	conn   net.Conn
	finish N.CloseHandlerFunc
	err    error
}

func (r *handshakeRouterLeaf) RouteConnectionEx(_ context.Context, conn net.Conn, _ adapter.InboundContext, finish N.CloseHandlerFunc) {
	r.conn, r.finish = conn, finish
	r.err = N.ReportConnHandshakeSuccess(conn, new(handshakeWireConn))
}

func TestRuntimeRouterReportsSOCKSSuccessBeforeApplicationCopy(t *testing.T) {
	graph := newReferenceTestGraph(1, nil, nil)
	leaf := new(handshakeRouterLeaf)
	root := handshakeRouterLease{RuntimeLease: graph.acquire(), view: handshakeRouterView{router: leaf}}
	ctx := adapter.ContextWithRuntimeLease(context.Background(), root)
	raw := new(handshakeWireConn)
	terminals := 0
	NewRuntimeRouter(nil, RuntimeRouterStructure{}).RouteConnectionEx(ctx, socks.NewLazyConn(raw, 5), adapter.InboundContext{}, func(error) { terminals++ })
	root.Release()
	want := []byte{5, 0, 0, 1, 127, 0, 0, 1, 39, 16}
	if leaf.err != nil || !bytes.Equal(raw.output.Bytes(), want) || terminals != 0 {
		t.Fatalf("SOCKS success hidden until asynchronous copy: %v / %v / %d", leaf.err, raw.output.Bytes(), terminals)
	}
	if graphs, _ := graph.counts(); graphs != 1 {
		t.Fatal("handoff did not retain its flow")
	}
	_ = leaf.conn.Close()
	leaf.finish(nil)
	if graphs, _ := graph.counts(); graphs != 0 || terminals != 1 {
		t.Fatal("flow finish was not exact-once")
	}
}

type handshakeSynchronousLeaf struct {
	adapter.Router
	entered  chan struct{}
	canceled chan struct{}
	release  chan struct{}
	result   error
}

func (r *handshakeSynchronousLeaf) run(ctx context.Context) error {
	close(r.entered)
	select {
	case <-ctx.Done():
		close(r.canceled)
		<-r.release
		return ctx.Err()
	case <-r.release:
		return r.result
	}
}

func (r *handshakeSynchronousLeaf) RouteConnection(ctx context.Context, _ net.Conn, _ adapter.InboundContext) error {
	return r.run(ctx)
}

func (r *handshakeSynchronousLeaf) RoutePacketConnection(ctx context.Context, _ N.PacketConn, _ adapter.InboundContext) error {
	return r.run(ctx)
}

func TestRuntimeRouterLegacyInterfacesRemainSynchronous(t *testing.T) {
	// The unchanged legacy methods are used by Shadowsocks. Replacing them
	// with fire-and-forget Ex calls would recreate the premature nil completion.
	for _, packet := range []bool{false, true} {
		for _, mode := range []string{"success", "failure", "canceled"} {
			t.Run(map[bool]string{false: "TCP", true: "packet"}[packet]+"/"+mode, func(t *testing.T) {
				graph := newReferenceTestGraph(1, nil, nil)
				leaf := &handshakeSynchronousLeaf{entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}
				if mode == "failure" {
					leaf.result = errors.New("synchronous failure")
				}
				root := handshakeRouterLease{RuntimeLease: graph.acquire(), view: handshakeRouterView{router: leaf}}
				ctx, cancel := context.WithCancel(adapter.ContextWithRuntimeLease(context.Background(), root))
				defer cancel()
				defer root.Release()
				var releaseOnce sync.Once
				release := func() { releaseOnce.Do(func() { close(leaf.release) }) }
				defer release()
				router := NewRuntimeRouter(nil, RuntimeRouterStructure{})
				done := make(chan error, 1)
				go func() {
					if packet {
						done <- router.RoutePacketConnection(ctx, nil, adapter.InboundContext{})
					} else {
						done <- router.RouteConnection(ctx, nil, adapter.InboundContext{})
					}
				}()
				managerAwait(t, leaf.entered)
				root.Release()
				want := leaf.result
				if mode == "canceled" {
					cancel()
					managerAwait(t, leaf.canceled)
					want = context.Canceled
				}
				select {
				case <-done:
					t.Fatal("legacy wrapper returned before the actual synchronous handler")
				default:
				}
				if graphs, _ := graph.counts(); graphs != 1 {
					t.Fatal("live synchronous handler lost graph ownership")
				}
				release()
				select {
				case err := <-done:
					if !errors.Is(err, want) {
						t.Fatalf("terminal result=%v want=%v", err, want)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("terminal synchronous handler did not return")
				}
				if graphs, _ := graph.counts(); graphs != 0 {
					t.Fatal("completed synchronous handler leaked graph")
				}
			})
		}
	}
}
