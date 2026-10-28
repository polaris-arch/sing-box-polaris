package listener

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

// These fixtures use channels and in-memory carriers only. No live socket,
// timing sleep, network namespace or system proxy is created by a fixture.
type admissionFixture struct {
	id           adapter.RuntimeResourceID
	graphRefs    atomic.Int64
	resourceRefs atomic.Int64
	sourceCalls  atomic.Int64
	entered      chan struct{}
	allow        chan struct{}
	membership   bool
}

func (a *admissionFixture) Acquire() (adapter.RuntimeLease, error) {
	if a.entered != nil {
		close(a.entered)
		<-a.allow
	}
	a.graphRefs.Add(1)
	return &graphFixture{owner: a}, nil
}

type sourceFixture struct{ owner *admissionFixture }

func (s sourceFixture) ID() adapter.RuntimeResourceID { return s.owner.id }
func (s sourceFixture) Acquire() (adapter.RuntimeResourceLease, error) {
	s.owner.sourceCalls.Add(1)
	return nil, errors.New("must not fall back to external resource admission")
}

type graphFixture struct {
	adapter.RuntimeLease
	owner *admissionFixture
	once  sync.Once
}

func (g *graphFixture) Fork() (adapter.RuntimeLease, error) {
	g.owner.graphRefs.Add(1)
	return &graphFixture{owner: g.owner}, nil
}
func (g *graphFixture) Release() { g.once.Do(func() { g.owner.graphRefs.Add(-1) }) }
func (g *graphFixture) RetainResource(id adapter.RuntimeResourceID) (adapter.RuntimeResourceLease, error) {
	if !g.owner.membership || id != g.owner.id {
		return nil, errors.New("resource outside graph")
	}
	g.owner.resourceRefs.Add(1)
	return &resourceFixture{owner: g.owner}, nil
}

type resourceFixture struct {
	owner *admissionFixture
	once  sync.Once
}

func (r *resourceFixture) ID() adapter.RuntimeResourceID { return r.owner.id }
func (r *resourceFixture) Fork() (adapter.RuntimeResourceLease, error) {
	r.owner.resourceRefs.Add(1)
	return &resourceFixture{owner: r.owner}, nil
}

func (r *resourceFixture) Release()                { r.once.Do(func() { r.owner.resourceRefs.Add(-1) }) }
func (*resourceFixture) Retiring() <-chan struct{} { return nil }
func newAdmissionFixture() *admissionFixture {
	return &admissionFixture{id: adapter.RuntimeResourceID{Incarnation: "listeners", Sequence: 1}, membership: true}
}

func waitFixture(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatal("barrier watchdog")
	}
}

func pendingFixture(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
		t.Fatal("barrier completed early")
	default:
	}
}

func TestAdmissionPauseJoinsAcquisitionButPreservesAdmittedSession(t *testing.T) {
	a := newAdmissionFixture()
	a.entered, a.allow = make(chan struct{}), make(chan struct{})
	g := NewAdmissionGateway(a, sourceFixture{a})
	if err := g.Resume(); err != nil {
		t.Fatal(err)
	}
	admitted := make(chan struct{})
	var release func()
	var acquireErr error
	go func() { _, release, acquireErr = g.Acquire(context.Background()); close(admitted) }()
	waitFixture(t, a.entered)
	g.mu.Lock()
	pausedBoundary := g.changed
	g.mu.Unlock()
	paused := make(chan struct{})
	go func() { g.PauseAndWait(); close(paused) }()
	// Observe the sealed admission boundary, not a guessed scheduling delay.
	waitFixture(t, pausedBoundary)
	pendingFixture(t, paused)
	close(a.allow)
	waitFixture(t, admitted)
	waitFixture(t, paused)
	if acquireErr != nil {
		t.Fatal(acquireErr)
	}
	if a.graphRefs.Load() != 1 || a.resourceRefs.Load() != 1 {
		t.Fatal("pause released session ownership")
	}
	if _, _, err := g.Acquire(context.Background()); !errors.Is(err, ErrAdmissionPaused) {
		t.Fatal("paused gateway admitted")
	}
	release()
	release()
	if a.graphRefs.Load() != 0 || a.resourceRefs.Load() != 0 {
		t.Fatal("session ownership not released exactly once")
	}
}

func TestAdmissionRejectsResourceOutsidePublishedGraph(t *testing.T) {
	a := newAdmissionFixture()
	a.membership = false
	g := NewAdmissionGateway(a, sourceFixture{a})
	if err := g.Resume(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Acquire(context.Background()); err == nil {
		t.Fatal("mixed graph/resource accepted")
	}
	if a.sourceCalls.Load() != 0 || a.graphRefs.Load() != 0 {
		t.Fatal("fallback admission or graph leak")
	}
}

type addrFixture struct{}

func (addrFixture) Network() string { return "tcp" }
func (addrFixture) String() string  { return "127.0.0.1:12345" }

type timeoutFixture struct{}

func (timeoutFixture) Error() string   { return "interrupted accept" }
func (timeoutFixture) Timeout() bool   { return true }
func (timeoutFixture) Temporary() bool { return false }

type acceptorFixture struct {
	mu           sync.Mutex
	accepted     chan struct{}
	wake         chan struct{}
	closed       bool
	deadline     bool
	closeEntered chan struct{}
	closeAllow   chan struct{}
}

func newAcceptorFixture() *acceptorFixture {
	return &acceptorFixture{accepted: make(chan struct{}, 8), wake: make(chan struct{})}
}

func (a *acceptorFixture) Accept() (net.Conn, error) {
	a.accepted <- struct{}{}
	a.mu.Lock()
	wake, closed, deadline := a.wake, a.closed, a.deadline
	a.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	if deadline {
		return nil, timeoutFixture{}
	}
	<-wake
	a.mu.Lock()
	closed = a.closed
	a.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	return nil, timeoutFixture{}
}

func (a *acceptorFixture) SetDeadline(value time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return net.ErrClosed
	}
	if value.IsZero() {
		a.deadline = false
		a.wake = make(chan struct{})
		return nil
	}
	if !a.deadline {
		a.deadline = true
		close(a.wake)
	}
	return nil
}

func (a *acceptorFixture) Close() error {
	if a.closeEntered != nil {
		close(a.closeEntered)
		<-a.closeAllow
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.closed {
		a.closed = true
		if !a.deadline {
			close(a.wake)
		}
	}
	return nil
}
func (*acceptorFixture) Addr() net.Addr { return addrFixture{} }

type handlerFixture struct{}

func (handlerFixture) NewConnection(context.Context, net.Conn, adapter.InboundContext, N.CloseHandlerFunc) {
}

func listenerFixture(a *admissionFixture, acceptor *acceptorFixture, phase string) *Listener {
	var socket net.Listener
	if acceptor != nil {
		socket = acceptor
	}
	return &Listener{
		ctx: context.Background(), logger: log.NewNOPFactory().Logger(), network: []string{N.NetworkTCP}, listenOptions: option.ListenOptions{ListenPort: 12345}, connHandler: handlerFixture{}, tcpListener: socket,
		runtime: &runtimeListener{phase: phase, gateway: NewAdmissionGateway(a, sourceFixture{a}), closeDone: make(chan struct{}), ownsTCP: acceptor != nil},
	}
}

func TestArmedCandidateDoesNotAcceptBeforePublication(t *testing.T) {
	a := newAdmissionFixture()
	acceptor := newAcceptorFixture()
	l := listenerFixture(a, acceptor, "prepared")
	if err := l.ArmIngress(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-acceptor.accepted:
		t.Fatal("candidate accepted before activation")
	default:
	}
	if err := l.Activate(); err != nil {
		t.Fatal(err)
	}
	waitFixture(t, acceptor.accepted)
	if err := l.PauseIngress(); err != nil {
		t.Fatal(err)
	}
	acceptor.mu.Lock()
	closed := acceptor.closed
	acceptor.mu.Unlock()
	if closed {
		t.Fatal("pause closed reusable acceptor")
	}
	if err := l.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
}

func TestReuseTCPCompensationReturnsSameAcceptorWithoutClosingIt(t *testing.T) {
	a := newAdmissionFixture()
	acceptor := newAcceptorFixture()
	previous := listenerFixture(a, acceptor, "prepared")
	if err := previous.ArmIngress(); err != nil {
		t.Fatal(err)
	}
	if err := previous.Activate(); err != nil {
		t.Fatal(err)
	}
	waitFixture(t, acceptor.accepted)
	next := listenerFixture(a, nil, "inert")
	replacement, err := ReserveReplacement(previous, next, false)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Impact().Mode != ReplacementReuseTCP {
		t.Fatal("unchanged TCP descriptor was not reusable")
	}
	if err := replacement.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if previous.tcpListener != nil || next.tcpListener != acceptor {
		t.Fatal("acceptor ownership did not transfer")
	}
	result := replacement.Compensate()
	if !result.Restored || result.LocalReconnect || result.Error != nil {
		t.Fatalf("wrong restoration: %+v", result)
	}
	if previous.tcpListener != acceptor || next.tcpListener != nil {
		t.Fatal("acceptor not restored")
	}
	acceptor.mu.Lock()
	closed := acceptor.closed
	acceptor.mu.Unlock()
	if closed {
		t.Fatal("compensation closed reusable socket")
	}
	if again := replacement.Compensate(); !again.Restored {
		t.Fatal("compensation was not idempotent")
	}
	if err := previous.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
}

func TestExclusiveSocketPlanRequiresAcceptedReconnectImpact(t *testing.T) {
	a := newAdmissionFixture()
	previous := listenerFixture(a, newAcceptorFixture(), "prepared")
	next := listenerFixture(a, nil, "inert")
	next.listenOptions.RoutingMark = 12
	impact, err := PlanReplacement(previous, next)
	if err != nil {
		t.Fatal(err)
	}
	if impact.Mode != ReplacementExclusive || !impact.LocalReconnect {
		t.Fatal("exclusive bind impact hidden")
	}
	if _, err := ReserveReplacement(previous, next, false); err == nil {
		t.Fatal("unaccepted reconnect admitted")
	}
}

func TestRuntimeCloseJoinsActualCloseAndRepeatedCall(t *testing.T) {
	a := newAdmissionFixture()
	acceptor := newAcceptorFixture()
	acceptor.closeEntered, acceptor.closeAllow = make(chan struct{}), make(chan struct{})
	l := listenerFixture(a, acceptor, "prepared")
	first, second := make(chan struct{}), make(chan struct{})
	go func() { _ = l.RuntimeCloseAndWait(); close(first) }()
	waitFixture(t, acceptor.closeEntered)
	go func() { _ = l.RuntimeCloseAndWait(); close(second) }()
	pendingFixture(t, first)
	pendingFixture(t, second)
	close(acceptor.closeAllow)
	waitFixture(t, first)
	waitFixture(t, second)
}

func TestListenOptionsFreezePointerAndNetworkInputs(t *testing.T) {
	fragment := true
	network := []string{N.NetworkTCP}
	l := New(Options{Context: context.Background(), Logger: log.NewNOPFactory().Logger(), Network: network, Listen: option.ListenOptions{UDPFragment: &fragment}})
	fragment = false
	network[0] = N.NetworkUDP
	if !*l.ListenOptions().UDPFragment || l.network[0] != N.NetworkTCP {
		t.Fatal("caller mutation reached listener")
	}
	view := l.ListenOptions()
	*view.UDPFragment = false
	if !*l.ListenOptions().UDPFragment {
		t.Fatal("returned options escaped mutable listener state")
	}
}

type connFixture struct{ closed atomic.Bool }

func (*connFixture) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (*connFixture) Write(p []byte) (int, error)      { return len(p), nil }
func (c *connFixture) Close() error                   { c.closed.Store(true); return nil }
func (*connFixture) LocalAddr() net.Addr              { return addrFixture{} }
func (*connFixture) RemoteAddr() net.Addr             { return addrFixture{} }
func (*connFixture) SetDeadline(time.Time) error      { return nil }
func (*connFixture) SetReadDeadline(time.Time) error  { return nil }
func (*connFixture) SetWriteDeadline(time.Time) error { return nil }

type retainedHandlerFixture struct {
	ready    chan net.Conn
	returned chan struct{}
}

func (h retainedHandlerFixture) NewConnection(ctx context.Context, conn net.Conn, _ adapter.InboundContext, _ N.CloseHandlerFunc) {
	if _, ok := adapter.RuntimeLeaseFromContext(ctx); !ok {
		panic("unadmitted handler")
	}
	h.ready <- conn
	close(h.returned)
}

func TestPauseDoesNotCloseEstablishedCarrier(t *testing.T) {
	a := newAdmissionFixture()
	acceptor := newAcceptorFixture()
	l := listenerFixture(a, acceptor, "prepared")
	handler := retainedHandlerFixture{ready: make(chan net.Conn, 1), returned: make(chan struct{})}
	l.connHandler = handler
	if err := l.ArmIngress(); err != nil {
		t.Fatal(err)
	}
	if err := l.Activate(); err != nil {
		t.Fatal(err)
	}
	waitFixture(t, acceptor.accepted)
	physical := &connFixture{}
	l.dispatchRuntimeConnection(context.Background(), physical, adapter.InboundContext{})
	waitFixture(t, handler.returned)
	carrier := <-handler.ready
	if err := l.PauseIngress(); err != nil {
		t.Fatal(err)
	}
	if physical.closed.Load() || a.resourceRefs.Load() < 1 {
		t.Fatal("pause destroyed existing connection ownership")
	}
	if err := carrier.Close(); err != nil {
		t.Fatal(err)
	}
	if !physical.closed.Load() {
		t.Fatal("carrier close did not reach physical connection")
	}
	if err := l.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
}

type terminalHandlerFixture struct{ callback chan N.CloseHandlerFunc }

func (h terminalHandlerFixture) NewConnection(_ context.Context, _ net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	h.callback <- onClose
}

func TestOwnedListenerTerminalCallbackIncludesSuccessfulCompletion(t *testing.T) {
	for _, failure := range []error{nil, errors.New("terminal route failure")} {
		a := newAdmissionFixture()
		acceptor := newAcceptorFixture()
		l := listenerFixture(a, acceptor, "prepared")
		handler := terminalHandlerFixture{callback: make(chan N.CloseHandlerFunc, 1)}
		l.connHandler = handler
		if err := l.ArmIngress(); err != nil {
			t.Fatal(err)
		}
		if err := l.Activate(); err != nil {
			t.Fatal(err)
		}
		waitFixture(t, acceptor.accepted)
		physical := &connFixture{}
		l.dispatchRuntimeConnection(context.Background(), physical, adapter.InboundContext{})
		var callback N.CloseHandlerFunc
		select {
		case callback = <-handler.callback:
		case <-time.After(5 * time.Second):
			t.Fatal("handler did not receive terminal ownership")
		}
		if physical.closed.Load() {
			t.Fatal("handler return closed the admitted carrier")
		}
		callback(failure)
		callback(failure)
		if !physical.closed.Load() {
			t.Fatal("terminal callback did not close its carrier")
		}
		if err := l.RuntimeCloseAndWait(); err != nil {
			t.Fatal(err)
		}
		if a.graphRefs.Load() != 0 || a.resourceRefs.Load() != 0 {
			t.Fatal("terminal callback left admitted graph/resource ownership")
		}
	}
}

func TestListenerSetPortSwapTransfersByPhysicalEndpoint(t *testing.T) {
	a := newAdmissionFixture()
	socketA, socketB := newAcceptorFixture(), newAcceptorFixture()
	oldA, oldB := listenerFixture(a, socketA, "prepared"), listenerFixture(a, socketB, "prepared")
	oldB.listenOptions.ListenPort++
	for _, old := range []*Listener{oldA, oldB} {
		if err := old.ArmIngress(); err != nil {
			t.Fatal(err)
		}
		if err := old.Activate(); err != nil {
			t.Fatal(err)
		}
	}
	waitFixture(t, socketA.accepted)
	waitFixture(t, socketB.accepted)
	nextB, nextA := listenerFixture(a, nil, "inert"), listenerFixture(a, nil, "inert")
	nextB.listenOptions.ListenPort++
	group, err := ReserveListenerSet([]*Listener{oldA, oldB}, []*Listener{nextB, nextA}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if nextB.tcpListener != socketB || nextA.tcpListener != socketA {
		t.Fatal("port swap matched by list position instead of endpoint")
	}
	if result := group.Compensate(); !result.Restored || result.LocalReconnect {
		t.Fatalf("wrong compensation: %+v", result)
	}
	if oldA.tcpListener != socketA || oldB.tcpListener != socketB {
		t.Fatal("port swap restoration changed descriptor ownership")
	}
	for _, old := range []*Listener{oldA, oldB} {
		if err := old.RuntimeCloseAndWait(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestListenerSetReportsFailedRestorationAfterExclusiveBindFailure(t *testing.T) {
	a := newAdmissionFixture()
	socket := newAcceptorFixture()
	old := listenerFixture(a, socket, "prepared")
	if err := old.ArmIngress(); err != nil {
		t.Fatal(err)
	}
	if err := old.Activate(); err != nil {
		t.Fatal(err)
	}
	waitFixture(t, socket.accepted)
	next := listenerFixture(a, nil, "inert")
	next.listenOptions.RoutingMark = 17
	next.runtime.prepareSockets = func() error { return errors.New("candidate bind rejected") }
	old.runtime.prepareSockets = func() error { return errors.New("old address restoration rejected") }
	group, err := ReserveListenerSet([]*Listener{old}, []*Listener{next}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Stage(context.Background()); err == nil {
		t.Fatal("injected candidate bind failure lost")
	}
	result := group.Compensate()
	if result.Restored || !result.LocalReconnect || result.Error == nil {
		t.Fatalf("failed restore claimed rollback: %+v", result)
	}
}

func TestListenerSetSuccessfulRestoreStillReportsReconnect(t *testing.T) {
	a := newAdmissionFixture()
	socket := newAcceptorFixture()
	old := listenerFixture(a, socket, "prepared")
	if err := old.ArmIngress(); err != nil {
		t.Fatal(err)
	}
	if err := old.Activate(); err != nil {
		t.Fatal(err)
	}
	waitFixture(t, socket.accepted)
	next := listenerFixture(a, nil, "inert")
	next.listenOptions.RoutingMark = 17
	next.runtime.prepareSockets = func() error { return errors.New("candidate bind rejected") }
	old.runtime.prepareSockets = func() error {
		old.runtime.mu.Lock()
		old.tcpListener = newAcceptorFixture()
		old.runtime.ownsTCP = true
		old.runtime.mu.Unlock()
		return nil
	}
	group, err := ReserveListenerSet([]*Listener{old}, []*Listener{next}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Stage(context.Background()); err == nil {
		t.Fatal("candidate bind failure lost")
	}
	result := group.Compensate()
	if !result.Restored || !result.LocalReconnect || result.Error != nil {
		t.Fatalf("successful rebind hid interruption: %+v", result)
	}
	if old.tcpListener == socket {
		t.Fatal("old closed descriptor pretended to survive")
	}
	if err := old.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
}
