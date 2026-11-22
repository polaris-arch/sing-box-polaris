package route

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	R "github.com/sagernet/sing-box/route/rule"
	proxyhttp "github.com/sagernet/sing-box/transport/http"
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
		wantGraph, activeGraph                    uint64
		otherIncarnation, publishReplacement      bool
		change, reject                            bool
	}{
		{name: "bound nested member", inbound: inbound, routed: slot, expected: member},
		{name: "bound member on the admitted graph", inbound: inbound, routed: slot, expected: member, wantGraph: 1, activeGraph: 1},
		{name: "admitted graph retained through publication", inbound: inbound, routed: slot, expected: member, wantGraph: 1, activeGraph: 1, publishReplacement: true},
		{name: "same member tag on a replacement graph", inbound: inbound, routed: slot, expected: member, wantGraph: 1, activeGraph: 2, reject: true},
		{name: "same revision in another incarnation", inbound: inbound, routed: slot, expected: member, wantGraph: 1, activeGraph: 1, otherIncarnation: true, reject: true},
		{name: "missing graph lease", inbound: inbound, routed: slot, expected: member, wantGraph: 1, reject: true},
		{name: "same graph with the wrong member", inbound: inbound, routed: slot, expected: "leaf", wantGraph: 1, activeGraph: 1, reject: true},
		{name: "same graph with changed selection", inbound: inbound, routed: slot, expected: member, wantGraph: 1, activeGraph: 1, change: true, reject: true},
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
			verified := 0
			if tc.expected != "" {
				binding := adapter.ProbeBinding{Member: sha256.Sum256([]byte(tc.expected))}
				if tc.wantGraph != 0 {
					binding.Graph = adapter.RuntimeRevision{Incarnation: "reference-test", Revision: tc.wantGraph}
					if tc.otherIncarnation {
						binding.Graph.Incarnation = "different-run"
					}
					binding.OnVerified = func() { verified++ }
				}
				ctx = adapter.ContextWithProbeBinding(ctx, binding)
			}
			router := &Router{ctx: ctx, outbound: outbounds, logger: log.NewNOPFactory().Logger()}
			if tc.change {
				router.trackers = []adapter.ConnectionTracker{routeSelectionTestTracker{afterSelection: func() {
					if !selector.SelectOutbound("leaf") {
						t.Fatal("could not reassign probe slot")
					}
				}}}
			}
			var dispatch adapter.Router = router
			if tc.activeGraph != 0 {
				graph := newReferenceTestGraph(tc.activeGraph, outbounds.values, nil)
				root := handshakeRouterLease{RuntimeLease: graph.acquire(), view: handshakeRouterView{RuntimeView: graph.view, router: router}}
				defer root.Release()
				active := root
				if tc.publishReplacement {
					replacement := newReferenceTestGraph(tc.activeGraph+1, nil, nil)
					next := handshakeRouterLease{RuntimeLease: replacement.acquire(), view: handshakeRouterView{RuntimeView: replacement.view, router: router}}
					defer next.Release()
					router.trackers = []adapter.ConnectionTracker{routeSelectionTestTracker{afterSelection: func() { active = next }}}
				}
				dispatch = NewRuntimeRouter(routeSelectionTestAdmission(func() (adapter.RuntimeLease, error) { return active.Fork() }), RuntimeRouterStructure{})
			}
			var reported, terminal error
			terminals := 0
			conn := &handshakeConnReporter{failure: func(err error) error {
				reported = err
				return nil
			}}
			dispatch.RouteConnectionEx(ctx, conn, adapter.InboundContext{
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
			if verified != 0 {
				t.Fatalf("specialized handler produced %d graph proofs", verified)
			}
		})
	}
}

func TestRouteProbeConnectProofAfterFlowAdmission(t *testing.T) {
	const (
		slot        = "probe-selector-0"
		member      = "candidate"
		incarnation = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
		graphToken  = incarnation + "/1"
	)
	dialFailure := errors.New("outbound dial failed")
	for _, tc := range []struct {
		name       string
		stopBefore bool
		cancelDial bool
		stopInDial bool
		dialErr    error
		background bool
		wantStatus int
		wantProof  bool
		ticket     string
	}{
		{name: "final close rejects before dial", stopBefore: true, dialErr: dialFailure},
		{name: "real dial failure", dialErr: dialFailure, wantProof: true},
		{name: "closed outbound without another failure", dialErr: fmt.Errorf("outbound fence: %w", net.ErrClosed)},
		{name: "closed outbound with a real dial failure", dialErr: errors.Join(net.ErrClosed, dialFailure), wantProof: true},
		{name: "foreground probe not run", dialErr: urltest.ErrProbeNotRun},
		{name: "background probe not run with capacity cause", background: true, dialErr: errors.Join(urltest.ErrProbeNotRun, adapter.ErrOutboundForegroundSlot)},
		{name: "pure capacity refusal", background: true, dialErr: adapter.ErrOutboundForegroundSlot, wantStatus: http.StatusServiceUnavailable, wantProof: true},
		{name: "local context cancelled during dial", cancelDial: true, dialErr: dialFailure},
		{name: "local context cancelled before a successful dial returns", cancelDial: true},
		{name: "final close prevents publishing dialed connection", stopInDial: true},
		{name: "published outbound connection", wantProof: true},
		{name: "ticket uses member without changing selector", ticket: "valid", background: true, wantProof: true},
		{name: "ticket for a different slot", ticket: "slot", wantStatus: http.StatusBadGateway},
		{name: "ticket for a different destination", ticket: "destination", wantStatus: http.StatusBadGateway},
		{name: "ticket for a different purpose", ticket: "purpose", wantStatus: http.StatusBadGateway},
		{name: "ticket before a route change", ticket: "graph", wantStatus: http.StatusBadGateway},
		{name: "ticket without a matching rule", ticket: "rule", wantStatus: http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			logger := log.NewNOPFactory().Logger()
			manager := NewConnectionManager(logger)
			defer func() {
				manager.StopFinal()
				if err := finalAwaitClose(t, manager); err != nil {
					t.Error(err)
				}
			}()
			if tc.stopBefore {
				manager.StopFinal()
			}
			var dialCalls atomic.Int32
			leaf := &probeGraphTestOutbound{referenceTestOutbound: referenceTestOutbound{tag: member}, dial: func() (net.Conn, error) {
				dialCalls.Add(1)
				if tc.cancelDial {
					cancel()
				}
				if tc.stopInDial {
					manager.StopFinal()
				}
				if tc.dialErr != nil {
					return nil, tc.dialErr
				}
				out, peer := net.Pipe()
				t.Cleanup(func() { peer.Close() })
				return out, nil
			}}
			outbounds := &referenceTestOutbounds{values: []adapter.Outbound{leaf}, defaultTag: slot}
			options := option.SelectorOutboundOptions{Outbounds: []string{member}}
			if tc.ticket != "" {
				outbounds.values = append(outbounds.values, &probeGraphTestOutbound{referenceTestOutbound: referenceTestOutbound{tag: "direct"}})
				options.Outbounds = append(options.Outbounds, "direct")
				options.Default = "direct"
				options.InterruptExistConnections = true
			}
			selector := newHandshakeTestSelector(t, outbounds, slot, options)
			outbounds.values = append(outbounds.values, selector)
			router := &Router{ctx: ctx, logger: logger, outbound: outbounds, connection: manager}
			if tc.ticket != "" && tc.ticket != "rule" {
				rule, err := R.NewRule(ctx, logger, option.Rule{DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{Inbound: []string{"probe-in-0"}},
					RuleAction:     option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: slot}},
				}}, true)
				if err != nil {
					t.Fatal(err)
				}
				router.rules = []adapter.Rule{rule}
			}
			graph := newReferenceTestGraph(1, outbounds.values, nil)
			if tc.ticket == "graph" {
				graph = newReferenceTestGraph(2, outbounds.values, nil)
			}
			graph.view.identity.Incarnation = incarnation
			root := handshakeRouterLease{RuntimeLease: graph.acquire(), view: handshakeRouterView{RuntimeView: graph.view, router: router}}
			defer root.Release()
			stable := NewRuntimeRouter(routeSelectionTestAdmission(root.Fork), RuntimeRouterStructure{})
			server, client := finalTCPPair(t)
			if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			proxy := proxyhttp.NewServer(proxyhttp.ServerOptions{HTTP1: true, ProbeConnect: true, Logger: logger})
			handler := adapter.NewUpstreamHandler(adapter.InboundContext{Inbound: "probe-in-0", InboundType: C.TypeHTTP, Domain: "example.test"}, stable.RouteConnectionEx, nil)
			handled := make(chan struct{})
			go func() {
				defer close(handled)
				proxy.ServeConnection(ctx, server, proxyhttp.NewReader(server), handler, M.SocksaddrFromNet(server.RemoteAddr()), nil)
			}()
			probeMode := "1"
			if tc.background {
				probeMode = "background"
			}
			var ticketHeader string
			if tc.ticket != "" {
				var ticketSlot uint32
				authority, background := "example.test:443", tc.background
				switch tc.ticket {
				case "slot":
					ticketSlot = 1
				case "destination":
					authority = "other.test:443"
				case "purpose":
					background = !background
				}
				ticket, ok := urltest.IssuePoolProbeTicket(graphToken, ticketSlot, member, authority, background)
				if !ok {
					t.Fatal("issue test ticket")
				}
				ticketHeader = "X-Polaris-Probe-Ticket: " + ticket + "\r\n"
			}
			if _, err := fmt.Fprintf(client, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nX-Polaris-Probe: %s\r\nX-Polaris-Probe-Member: %x\r\nX-Polaris-Probe-Graph: %s\r\n%s\r\n", probeMode, sha256.Sum256([]byte(member)), graphToken, ticketHeader); err != nil {
				t.Fatal(err)
			}
			var wireResponse bytes.Buffer
			response, err := http.ReadResponse(bufio.NewReader(io.TeeReader(client, &wireResponse)), &http.Request{Method: http.MethodConnect})
			if err != nil {
				if !tc.stopInDial || (!errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF)) {
					t.Fatal(err)
				}
				// StopFinal can close the socket before the failure response is complete.
				wire := bytes.ToLower(wireResponse.Bytes())
				if bytes.HasPrefix(wire, []byte("http/1.1 200")) || bytes.Contains(wire, []byte("\r\nx-polaris-probe-graph:")) {
					t.Fatalf("final close emitted a success or graph proof: %q", wireResponse.Bytes())
				}
			} else {
				wantStatus, wantProof := http.StatusBadGateway, ""
				if tc.dialErr == nil && !tc.stopInDial {
					wantStatus = http.StatusOK
				}
				if tc.wantStatus != 0 {
					wantStatus = tc.wantStatus
				}
				if tc.wantProof {
					wantProof = graphToken
				}
				if got := response.Header.Get("X-Polaris-Probe-Graph"); response.StatusCode != wantStatus || got != wantProof {
					t.Fatalf("CONNECT status=%d graph=%q, want status=%d graph=%q", response.StatusCode, got, wantStatus, wantProof)
				}
			}
			managerAwait(t, handled)
			if tc.stopInDial {
				manager.access.Lock()
				sealed := manager.closed
				manager.access.Unlock()
				if !sealed {
					t.Fatal("final close did not seal flow admission")
				}
			}
			var wantDials int32 = 1
			if tc.stopBefore || (tc.ticket != "" && tc.ticket != "valid") {
				wantDials = 0
			}
			if got := dialCalls.Load(); got != wantDials {
				t.Fatalf("outbound dial calls=%d want %d", got, wantDials)
			}
			if tc.ticket != "" && selector.Selected(N.NetworkTCP).Tag() != "direct" {
				t.Fatal("ticket changed the persistent selector")
			}
		})
	}
}

type probeGraphTestOutbound struct {
	referenceTestOutbound
	dial func() (net.Conn, error)
}

func (o *probeGraphTestOutbound) Network() []string { return []string{N.NetworkTCP} }
func (o *probeGraphTestOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return o.dial()
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
