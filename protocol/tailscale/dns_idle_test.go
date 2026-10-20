//go:build with_tailscale

package tailscale

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	mDNS "github.com/miekg/dns"
)

type endpointDNSIdleResolver struct {
	adapter.DNSTransport
	keep atomic.Bool
	idleCalls atomic.Int32
	resetCalls atomic.Int32
	closed atomic.Int32
	active atomic.Int32
	cleanupErr error
	startErr error
	access sync.Mutex
	callback func(*mDNS.Msg, error)
	startEntered chan struct{}
	startRelease chan struct{}
	idleEntered chan struct{}
	idleRelease chan struct{}
}

func (r *endpointDNSIdleResolver) Start(_ adapter.StartStage, scope *adapter.Scope) error {
	if r.startEntered != nil {
		close(r.startEntered)
		<-r.startRelease
	}
	scope.Add(func() error { r.closed.Add(1); return r.cleanupErr })
	return r.startErr
}

func (r *endpointDNSIdleResolver) Reset() { r.resetCalls.Add(1) }
func (r *endpointDNSIdleResolver) SetKeepIdleConnections(keep bool) { r.keep.Store(keep) }
func (r *endpointDNSIdleResolver) CloseIdleConnections() {
	r.idleCalls.Add(1)
	if r.idleEntered != nil {
		close(r.idleEntered)
		<-r.idleRelease
	}
}
func (r *endpointDNSIdleResolver) ExchangeAsync(_ context.Context, _ *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	r.access.Lock()
	r.callback = callback
	r.active.Add(1)
	r.access.Unlock()
}
func (r *endpointDNSIdleResolver) finish() {
	r.access.Lock()
	callback := r.callback
	r.callback = nil
	r.active.Add(-1)
	r.access.Unlock()
	response := new(mDNS.Msg)
	response.Response = true
	callback(response, nil)
}

func newEndpointDNSIdleFixture() *DNSTransport {
	return &DNSTransport{acceptDefaultResolvers: true}
}

func waitEndpointDNSIdle(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !condition() {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("idle-control operation did not reach its barrier")
		}
	}
}

func TestEndpointDNSIdleControlsPreserveActiveQuery(t *testing.T) {
	dns := newEndpointDNSIdleFixture()
	scope := adapter.NewScope(context.Background(), nil)
	defer scope.Close()
	resolver := new(endpointDNSIdleResolver)
	if err := dns.startDNSResolver(resolver, scope); err != nil { t.Fatal(err) }
	if !resolver.keep.Load() { t.Fatal("default idle policy must preserve reuse") }
	dns.defaultResolvers = []adapter.DNSTransport{resolver}
	var completed atomic.Bool
	message := &mDNS.Msg{Question: []mDNS.Question{{Name: "example.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}}}
	dns.ExchangeAsync(context.Background(), message, func(_ *mDNS.Msg, err error) {
		if err != nil { t.Errorf("active query failed: %v", err) }
		completed.Store(true)
	})
	dns.CloseIdleConnections()
	dns.SetKeepIdleConnections(false)
	if completed.Load() || resolver.active.Load() != 1 || resolver.closed.Load() != 0 || resolver.resetCalls.Load() != 0 {
		t.Fatal("idle control interrupted or reset an active query")
	}
	if resolver.idleCalls.Load() != 1 || resolver.keep.Load() { t.Fatal("idle control was not forwarded") }
	resolver.finish()
	if !completed.Load() { t.Fatal("original query callback was lost") }
	dns.SetKeepIdleConnections(true)
	if !resolver.keep.Load() { t.Fatal("idle reuse could not be restored") }
}

func TestEndpointDNSIdlePolicyReachesFutureAndUnroutedChildren(t *testing.T) {
	dns := newEndpointDNSIdleFixture()
	dns.SetKeepIdleConnections(false)
	firstScope := adapter.NewScope(context.Background(), nil)
	secondScope := adapter.NewScope(context.Background(), nil)
	defer firstScope.Close()
	defer secondScope.Close()
	first, second := new(endpointDNSIdleResolver), new(endpointDNSIdleResolver)
	if err := dns.startDNSResolver(first, firstScope); err != nil { t.Fatal(err) }
	if err := dns.startDNSResolver(second, secondScope); err != nil { t.Fatal(err) }
	// Neither resolver is in a route/default list: bootstrap and candidate
	// children must still receive policy and explicit idle closure.
	if first.keep.Load() || second.keep.Load() { t.Fatal("future resolver missed disabled idle policy") }
	dns.CloseIdleConnections()
	if first.idleCalls.Load() != 1 || second.idleCalls.Load() != 1 { t.Fatal("unrouted child skipped") }
	dns.SetKeepIdleConnections(true)
	if !first.keep.Load() || !second.keep.Load() { t.Fatal("existing child missed restored policy") }
	if err := firstScope.Close(); err != nil { t.Fatal(err) }
	dns.CloseIdleConnections()
	if first.idleCalls.Load() != 1 || second.idleCalls.Load() != 2 { t.Fatal("closed child was retained or live child omitted") }
}

func TestEndpointDNSIdlePolicyChangesDuringChildStart(t *testing.T) {
	dns := newEndpointDNSIdleFixture()
	scope := adapter.NewScope(context.Background(), nil)
	defer scope.Close()
	resolver := &endpointDNSIdleResolver{startEntered: make(chan struct{}), startRelease: make(chan struct{})}
	started := make(chan error, 1)
	go func() { started <- dns.startDNSResolver(resolver, scope) }()
	<-resolver.startEntered
	dns.SetKeepIdleConnections(false)
	close(resolver.startRelease)
	if err := <-started; err != nil { t.Fatal(err) }
	if resolver.keep.Load() { t.Fatal("resolver published with a stale idle policy") }
}

func TestEndpointDNSIdleCallPrecedesChildCleanup(t *testing.T) {
	dns := newEndpointDNSIdleFixture()
	scope := adapter.NewScope(context.Background(), nil)
	resolver := &endpointDNSIdleResolver{idleEntered: make(chan struct{}), idleRelease: make(chan struct{})}
	if err := dns.startDNSResolver(resolver, scope); err != nil { t.Fatal(err) }
	idleDone := make(chan struct{})
	go func() { defer close(idleDone); dns.CloseIdleConnections() }()
	<-resolver.idleEntered
	closed := make(chan error, 1)
	go func() { closed <- scope.Close() }()
	<-scope.Context().Done()
	if resolver.closed.Load() != 0 { t.Fatal("child cleanup overlapped its admitted idle call") }
	select { case <-closed: t.Fatal("scope did not join the admitted idle call"); default: }
	close(resolver.idleRelease)
	<-idleDone
	if err := <-closed; err != nil { t.Fatal(err) }
	if resolver.closed.Load() != 1 { t.Fatal("child cleanup was not performed exactly once") }
	dns.CloseIdleConnections()
	if resolver.idleCalls.Load() != 1 { t.Fatal("closed child received another idle call") }
}

func TestEndpointDNSShutdownJoinsIdleCall(t *testing.T) {
	dns := newEndpointDNSIdleFixture()
	dns.runtime = &runtimeDNSState{callbacks: outbound.NewRuntimeIOFence(nil), retiring: make(map[*runtimeDNSSnapshot]struct{}), closeDone: make(chan struct{})}
	scope := adapter.NewScope(context.Background(), nil)
	defer scope.Close()
	resolver := &endpointDNSIdleResolver{idleEntered: make(chan struct{}), idleRelease: make(chan struct{})}
	if err := dns.startDNSResolver(resolver, scope); err != nil { t.Fatal(err) }
	idleDone := make(chan struct{})
	go func() { defer close(idleDone); dns.CloseIdleConnections() }()
	<-resolver.idleEntered
	closed := make(chan error, 1)
	go func() { closed <- dns.closeRuntimeDNS() }()
	waitEndpointDNSIdle(t, dns.idleWork.Sealed)
	select { case <-closed: t.Fatal("wrapper released ownership before idle call returned"); default: }
	close(resolver.idleRelease)
	<-idleDone
	if err := <-closed; err != nil { t.Fatal(err) }
	dns.CloseIdleConnections()
	dns.SetKeepIdleConnections(false)
	if resolver.idleCalls.Load() != 1 || !resolver.keep.Load() { t.Fatal("shutdown admitted new idle controls") }
}

type endpointDNSNonIdleResolver struct { adapter.DNSTransport }
func (*endpointDNSNonIdleResolver) Start(adapter.StartStage, *adapter.Scope) error { return errors.New("must reject before Start") }

func TestEndpointDNSRejectsChildWithoutIdleContract(t *testing.T) {
	dns := newEndpointDNSIdleFixture()
	scope := adapter.NewScope(context.Background(), nil)
	defer scope.Close()
	if err := dns.startDNSResolver(new(endpointDNSNonIdleResolver), scope); err == nil || err.Error() != "endpoint DNS resolver requires idle-only connection control" {
		t.Fatalf("child without an idle-only contract was accepted: %v", err)
	}
}

func TestEndpointDNSChildStartOutlivesRetiringScope(t *testing.T) {
	dns := newEndpointDNSIdleFixture()
	scope := adapter.NewScope(context.Background(), nil)
	resolver := &endpointDNSIdleResolver{startEntered: make(chan struct{}), startRelease: make(chan struct{})}
	started := make(chan error, 1)
	go func() { started <- dns.startDNSResolver(resolver, scope) }()
	<-resolver.startEntered
	if err := scope.Close(); err != nil { t.Fatal(err) }
	if resolver.closed.Load() != 0 { t.Fatal("partly initialized child was closed") }
	close(resolver.startRelease)
	if err := <-started; !errors.Is(err, context.Canceled) { t.Fatalf("retired scope accepted publication: %v", err) }
	if resolver.closed.Load() != 1 { t.Fatal("late child cleanup escaped the retired scope") }
	dns.CloseIdleConnections()
	if resolver.idleCalls.Load() != 0 { t.Fatal("late closed child retained in idle registry") }
}

func TestEndpointDNSLateChildCleanupFailureStaysOwned(t *testing.T) {
	dns := newEndpointDNSIdleFixture()
	dns.runtime = &runtimeDNSState{callbacks: outbound.NewRuntimeIOFence(nil), retiring: make(map[*runtimeDNSSnapshot]struct{}), closeDone: make(chan struct{})}
	scope := adapter.NewScope(context.Background(), nil)
	resolver := &endpointDNSIdleResolver{
		startEntered: make(chan struct{}), startRelease: make(chan struct{}),
		cleanupErr: errors.New("late child cleanup failed"),
	}
	started := make(chan error, 1)
	go func() { started <- dns.startDNSResolver(resolver, scope) }()
	<-resolver.startEntered
	if err := scope.Close(); err != nil { t.Fatal(err) }
	close(resolver.startRelease)
	if err := <-started; err == nil || !strings.Contains(err.Error(), "late child cleanup failed") { t.Fatalf("late cleanup failure lost: %v", err) }
	first := dns.closeRuntimeDNS()
	if first == nil || !strings.Contains(first.Error(), "late child cleanup failed") || dns.closeRuntimeDNS() != first {
		t.Fatalf("wrapper forgot the uncertain late child cleanup: %v", first)
	}
}

func TestRuntimeDNSIdleControlsReachRetiringSnapshot(t *testing.T) {
	dns := newEndpointDNSIdleFixture()
	ctx, cancel := context.WithCancel(context.Background())
	scope := adapter.NewScope(ctx, nil)
	resolver := new(endpointDNSIdleResolver)
	if err := dns.startDNSResolver(resolver, scope); err != nil { t.Fatal(err) }
	snapshot := &runtimeDNSSnapshot{
		ctx: ctx, cancel: cancel, scope: scope,
		fence: outbound.NewRuntimeIOFence(nil), carriers: outbound.NewRuntimeIOFenceSet(), done: make(chan struct{}),
	}
	leave, err := snapshot.fence.Acquire()
	if err != nil { t.Fatal(err) }
	state := &runtimeDNSState{retiring: make(map[*runtimeDNSSnapshot]struct{})}
	state.retire(snapshot)
	dns.SetKeepIdleConnections(false)
	dns.CloseIdleConnections()
	if resolver.keep.Load() || resolver.idleCalls.Load() != 1 || resolver.closed.Load() != 0 {
		t.Fatal("retired active snapshot lost idle control or was closed prematurely")
	}
	leave()
	<-snapshot.done
	if snapshot.err != nil { t.Fatal(snapshot.err) }
	dns.CloseIdleConnections()
	if resolver.idleCalls.Load() != 1 || resolver.closed.Load() != 1 { t.Fatal("retired child was not removed after actual cleanup") }
}

func TestEndpointDNSFailedChildStartRemainsScopeOwned(t *testing.T) {
	dns := newEndpointDNSIdleFixture()
	scope := adapter.NewScope(context.Background(), nil)
	failure := errors.New("child start failed")
	resolver := &endpointDNSIdleResolver{startErr: failure}
	if err := dns.startDNSResolver(resolver, scope); !errors.Is(err, failure) { t.Fatalf("start error lost: %v", err) }
	dns.CloseIdleConnections()
	if resolver.idleCalls.Load() != 0 { t.Fatal("failed child entered the idle registry") }
	if err := scope.Close(); err != nil { t.Fatal(err) }
	if resolver.closed.Load() != 1 { t.Fatal("failed child initialization escaped its owner") }
}

func TestEndpointDNSStandaloneCloseRetainsLateCleanupFailure(t *testing.T) {
	dns := newEndpointDNSIdleFixture()
	scope := adapter.NewScope(context.Background(), nil)
	resolver := &endpointDNSIdleResolver{
		startEntered: make(chan struct{}), startRelease: make(chan struct{}),
		cleanupErr: errors.New("standalone late child cleanup failed"),
	}
	started := make(chan error, 1)
	go func() { started <- dns.startDNSResolver(resolver, scope) }()
	<-resolver.startEntered
	if err := scope.Close(); err != nil { t.Fatal(err) }
	close(resolver.startRelease)
	if err := <-started; err == nil { t.Fatal("late child cleanup failure lost during registration") }
	if err := dns.closeLegacyDNS(); err == nil || !strings.Contains(err.Error(), "standalone late child cleanup failed") {
		t.Fatalf("standalone wrapper forgot late child cleanup failure: %v", err)
	}
}
