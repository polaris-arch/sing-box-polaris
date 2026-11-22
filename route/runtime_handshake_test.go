package route

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/service"
)

type handshakeWireConn struct {
	output     bytes.Buffer
	closeCalls atomic.Int32
}

func (*handshakeWireConn) Read([]byte) (int, error)      { return 0, io.EOF }
func (c *handshakeWireConn) Write(p []byte) (int, error) { return c.output.Write(p) }
func (c *handshakeWireConn) Close() error                { c.closeCalls.Add(1); return nil }
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
	closeCalls atomic.Int32
	success    func(net.PacketConn) error
	failure    func(error) error
}

func (c *handshakePacketReporter) Close() error { c.closeCalls.Add(1); return nil }
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

type routeSelectionTestTracker struct {
	adapter.ConnectionTracker
	afterSelection func()
}

func (t routeSelectionTestTracker) RoutedConnection(_ context.Context, conn net.Conn, _ adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	t.afterSelection()
	return conn
}

func (t routeSelectionTestTracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn, _ adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	t.afterSelection()
	return conn
}

type routeSelectionTestOutbound struct {
	referenceTestOutbound
	calls   int
	udpOnly bool
}

func newHandshakeTestSelector(t *testing.T, outbounds adapter.OutboundManager, tag string, options option.SelectorOutboundOptions) *group.Selector {
	t.Helper()
	ctx := service.ContextWith[adapter.OutboundManager](t.Context(), outbounds)
	outbound, err := group.NewSelector(ctx, nil, log.NewNOPFactory().Logger(), tag, options)
	if err != nil {
		t.Fatal(err)
	}
	selector := outbound.(*group.Selector)
	if err = selector.Start(adapter.StartStateStart, nil); err != nil {
		t.Fatal(err)
	}
	return selector
}

func (o *routeSelectionTestOutbound) Network() []string {
	if o.udpOnly {
		return []string{N.NetworkUDP}
	}
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (o *routeSelectionTestOutbound) NewConnection(_ context.Context, conn net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	o.calls++
	_ = conn.Close()
	onClose(nil)
}

func (o *routeSelectionTestOutbound) NewPacketConnection(_ context.Context, conn N.PacketConn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	o.calls++
	_ = conn.Close()
	onClose(nil)
}

type routeSelectionTestAdmission func() (adapter.RuntimeLease, error)

func (a routeSelectionTestAdmission) Acquire() (adapter.RuntimeLease, error) { return a() }

type routeSelectionTestInterrupt struct {
	*group.Selector
	afterAttach func()
}

func (s routeSelectionTestInterrupt) AttachConnectionForSelection(closer io.Closer, selected adapter.Outbound) (func(), bool) {
	detach, current := s.Selector.AttachConnectionForSelection(closer, selected)
	s.afterAttach()
	if current && s.Selected(N.NetworkTCP) != selected {
		detach()
		return nil, false
	}
	return detach, current
}

func TestRouteSelectorChangesBeforeLeafDispatch(t *testing.T) {
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		for _, mode := range []string{"static", "managed", "non-interrupting", "retained-replacement", "interrupt-during-registration", "late-captured-interrupt"} {
			t.Run(network+"/"+mode, func(t *testing.T) {
				ctx := t.Context()
				newSelector := func(interrupt bool) (*group.Selector, *referenceTestOutbounds, *routeSelectionTestOutbound) {
					first := &routeSelectionTestOutbound{referenceTestOutbound: referenceTestOutbound{tag: "a"}}
					second := &routeSelectionTestOutbound{referenceTestOutbound: referenceTestOutbound{tag: "b"}}
					outbounds := &referenceTestOutbounds{values: []adapter.Outbound{first, second}, defaultTag: "selector"}
					selector := newHandshakeTestSelector(t, outbounds, "selector", option.SelectorOutboundOptions{
						Outbounds:                 []string{"a", "b"},
						InterruptExistConnections: interrupt,
					})
					outbounds.values = append(outbounds.values, selector)
					return selector, outbounds, first
				}
				selector, outbounds, first := newSelector(mode != "non-interrupting")
				var afterAttach, releaseCapturedInterrupt func()
				var interruptDone chan struct{}
				if mode == "interrupt-during-registration" {
					afterAttach = func() {
						if !selector.SelectOutbound("b") || !selector.SelectOutbound("a") {
							t.Fatal("could not interrupt registration")
						}
					}
				} else if mode == "late-captured-interrupt" {
					captured, resume := make(chan struct{}), make(chan struct{})
					releaseCapturedInterrupt = sync.OnceFunc(func() { close(resume) })
					defer releaseCapturedInterrupt()
					interruptDone = make(chan struct{})
					selector.AttachConnection(socketOriginalCloser(func() error {
						// Interrupt takes out the entire group before closing its first member.
						close(captured)
						<-resume
						return nil
					}))
					afterAttach = func() {
						go func() {
							selector.SelectOutbound("b")
							close(interruptDone)
						}()
						managerAwait(t, captured)
					}
				}
				if afterAttach != nil {
					outbounds.values[len(outbounds.values)-1] = &routeSelectionTestInterrupt{Selector: selector, afterAttach: afterAttach}
				}
				leaf := &Router{ctx: ctx, outbound: outbounds, logger: log.NewNOPFactory().Logger()}
				var router adapter.Router = leaf
				var active, original adapter.RuntimeLease
				var graph *referenceTestGraph
				if mode == "managed" || mode == "retained-replacement" || afterAttach != nil {
					graph = newReferenceTestGraph(1, outbounds.values, nil)
					original = handshakeRouterLease{RuntimeLease: graph.acquire(), view: handshakeRouterView{router: leaf}}
					defer original.Release()
					active = original
					router = NewRuntimeRouter(routeSelectionTestAdmission(func() (adapter.RuntimeLease, error) { return active.Fork() }), RuntimeRouterStructure{})
				}
				leaf.trackers = []adapter.ConnectionTracker{routeSelectionTestTracker{afterSelection: func() {
					if mode == "retained-replacement" {
						replacement, replacementOutbounds, _ := newSelector(true)
						if !replacement.SelectOutbound("b") {
							t.Fatal("could not pin replacement selector")
						}
						replacementLeaf := &Router{ctx: ctx, outbound: replacementOutbounds, logger: leaf.logger}
						replacementGraph := newReferenceTestGraph(2, replacementOutbounds.values, nil)
						active = handshakeRouterLease{RuntimeLease: replacementGraph.acquire(), view: handshakeRouterView{router: replacementLeaf}}
						t.Cleanup(active.Release)
					} else if afterAttach == nil && !selector.SelectOutbound("b") {
						t.Fatal("could not change captured selector")
					}
				}}}
				metadata := adapter.InboundContext{Destination: M.Socksaddr{Fqdn: "example.test", Port: 443}, Domain: "example.test"}
				var reported, terminal error
				failures, terminals := 0, 0
				failure := func(err error) error { reported = err; failures++; return nil }
				onClose := func(err error) { terminal = err; terminals++ }
				var closeCalls *atomic.Int32
				if network == N.NetworkUDP {
					conn := &handshakePacketReporter{failure: failure}
					router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
					closeCalls = &conn.closeCalls
				} else {
					conn := &handshakeConnReporter{failure: failure}
					router.RouteConnectionEx(ctx, conn, metadata, onClose)
					closeCalls = &conn.closeCalls
				}
				if releaseCapturedInterrupt != nil {
					releaseCapturedInterrupt()
					managerAwait(t, interruptDone)
				}
				if closeCalls.Load() != 1 || terminals != 1 {
					t.Fatalf("physical close calls=%d terminal calls=%d leaf calls=%d", closeCalls.Load(), terminals, first.calls)
				}
				if mode == "static" || mode == "managed" || afterAttach != nil {
					if first.calls != 0 || failures != 1 || !errors.Is(reported, net.ErrClosed) || !errors.Is(terminal, net.ErrClosed) {
						t.Fatalf("stale dispatch=%d handshake=%d/%v terminal=%v", first.calls, failures, reported, terminal)
					}
				} else if first.calls != 1 || failures != 0 || terminal != nil {
					t.Fatalf("captured dispatch=%d handshake=%d terminal=%v", first.calls, failures, terminal)
				}
				if graph != nil {
					if graphRefs, _ := graph.counts(); graphRefs != 1 {
						t.Fatalf("route retained %d graph references", graphRefs)
					}
				}
			})
		}
	}
}

type routeInterruptTestGroup struct {
	adapter.OutboundGroup
	closer io.Closer
}

func (g *routeInterruptTestGroup) AttachConnection(closer io.Closer) func() {
	g.closer = closer
	return func() {}
}

func TestRouteArmedInterruptCloseCanReenter(t *testing.T) {
	first, second := new(routeInterruptTestGroup), new(routeInterruptTestGroup)
	calls := 0
	closer := socketOriginalCloser(func() error {
		calls++
		return second.closer.Close()
	})
	onClose, attached := registerInterrupt([]adapter.Outbound{first, second, new(referenceTestOutbound)}, closer, nil, net.ErrClosed)
	if !attached {
		t.Fatal("route was rejected before an interrupt")
	}
	done := make(chan struct{})
	go func() {
		_ = first.closer.Close()
		close(done)
	}()
	managerAwait(t, done)
	onClose(nil)
	if calls != 1 {
		t.Fatalf("physical close calls=%d", calls)
	}
}

func TestRouteProbeMemberBinding(t *testing.T) {
	const (
		slot    = "probe-selector-0"
		inbound = "probe-in-0"
		member  = "节点"
	)
	for _, tc := range []struct {
		name, inbound, routed, expected, selected string
		change, reject                            bool
	}{
		{name: "bound nested member", inbound: inbound, routed: slot, expected: member},
		{name: "legacy unbound", inbound: inbound, routed: slot},
		{name: "wrong member", inbound: inbound, routed: slot, expected: "leaf", reject: true},
		{name: "wrong slot", inbound: "probe-in-1", routed: slot, expected: member, reject: true},
		{name: "wrong member without TCP", inbound: inbound, routed: slot, expected: member, selected: "udp-only", reject: true},
		{name: "direct fallback", inbound: inbound, routed: "leaf", expected: member, reject: true},
		{name: "changed during admission", inbound: inbound, routed: slot, expected: member, change: true, reject: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf := &routeSelectionTestOutbound{referenceTestOutbound: referenceTestOutbound{tag: "leaf"}}
			packet := &routeSelectionTestOutbound{referenceTestOutbound: referenceTestOutbound{tag: "udp-only"}, udpOnly: true}
			outbounds := &referenceTestOutbounds{values: []adapter.Outbound{leaf, packet}, defaultTag: tc.routed}
			nested := newHandshakeTestSelector(t, outbounds, member, option.SelectorOutboundOptions{Outbounds: []string{"leaf"}})
			outbounds.values = append(outbounds.values, nested)
			selector := newHandshakeTestSelector(t, outbounds, slot, option.SelectorOutboundOptions{
				Outbounds: []string{member, "leaf", "udp-only"}, Default: tc.selected, InterruptExistConnections: true,
			})
			outbounds.values = append(outbounds.values, selector)
			ctx := t.Context()
			if tc.expected != "" {
				ctx = adapter.ContextWithProbeMember(ctx, sha256.Sum256([]byte(tc.expected)))
			}
			router := &Router{ctx: ctx, outbound: outbounds, logger: log.NewNOPFactory().Logger()}
			if tc.change {
				router.trackers = []adapter.ConnectionTracker{routeSelectionTestTracker{afterSelection: func() {
					if !selector.SelectOutbound("leaf") {
						t.Fatal("could not reassign probe slot")
					}
				}}}
			}
			var reported, terminal error
			terminals := 0
			conn := &handshakeConnReporter{failure: func(err error) error {
				reported = err
				return nil
			}}
			router.RouteConnectionEx(ctx, conn, adapter.InboundContext{
				Inbound: tc.inbound, Destination: M.Socksaddr{Fqdn: "example.test", Port: 443}, Domain: "example.test",
			}, func(err error) { terminal = err; terminals++ })
			if conn.closeCalls.Load() != 1 || terminals != 1 {
				t.Fatalf("physical closes=%d terminal calls=%d", conn.closeCalls.Load(), terminals)
			}
			if tc.reject {
				if leaf.calls != 0 || !errors.Is(reported, adapter.ErrProbeBindingMismatch) || !errors.Is(terminal, adapter.ErrProbeBindingMismatch) {
					t.Fatalf("rejected dispatch=%d handshake=%v terminal=%v", leaf.calls, reported, terminal)
				}
			} else if leaf.calls != 1 || reported != nil || terminal != nil {
				t.Fatalf("admitted dispatch=%d handshake=%v terminal=%v", leaf.calls, reported, terminal)
			}
		})
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
