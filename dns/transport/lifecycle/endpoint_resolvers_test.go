package lifecycle

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

func fixtureEndpointDNS(t *testing.T) *EndpointResolvers {
	t.Helper()
	dns := new(EndpointResolvers)
	if err := dns.Init(context.Background(), log.NewNOPFactory().Logger(), nil, nil); err != nil {
		t.Fatal(err)
	}
	return dns
}

type endpointDNSIdleResolver struct {
	adapter.DNSTransport
	keep         atomic.Bool
	idleCalls    atomic.Int32
	closed       atomic.Int32
	cleanupErr   error
	startErr     error
	startEntered chan struct{}
	startRelease chan struct{}
	idleEntered  chan struct{}
	idleRelease  chan struct{}
}

func (r *endpointDNSIdleResolver) Start(_ adapter.StartStage, scope *adapter.Scope) error {
	if r.startEntered != nil {
		close(r.startEntered)
		<-r.startRelease
	}
	scope.Add(func() error { r.closed.Add(1); return r.cleanupErr })
	return r.startErr
}

func (r *endpointDNSIdleResolver) SetKeepIdleConnections(keep bool) { r.keep.Store(keep) }
func (r *endpointDNSIdleResolver) CloseIdleConnections() {
	r.idleCalls.Add(1)
	if r.idleEntered != nil {
		close(r.idleEntered)
		<-r.idleRelease
	}
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

func TestEndpointDNSIdlePolicyReachesFutureAndUnroutedChildren(t *testing.T) {
	dns := fixtureEndpointDNS(t)
	dns.SetKeepIdleConnections(false)
	firstScope := adapter.NewScope(context.Background(), nil)
	secondScope := adapter.NewScope(context.Background(), nil)
	defer firstScope.Close()
	defer secondScope.Close()
	first, second := new(endpointDNSIdleResolver), new(endpointDNSIdleResolver)
	if err := dns.StartResolver(first, firstScope); err != nil {
		t.Fatal(err)
	}
	if err := dns.StartResolver(second, secondScope); err != nil {
		t.Fatal(err)
	}
	// Neither resolver is in a route/default list: bootstrap and candidate
	// children must still receive policy and explicit idle closure.
	if first.keep.Load() || second.keep.Load() {
		t.Fatal("future resolver missed disabled idle policy")
	}
	dns.CloseIdleConnections()
	if first.idleCalls.Load() != 1 || second.idleCalls.Load() != 1 {
		t.Fatal("unrouted child skipped")
	}
	dns.SetKeepIdleConnections(true)
	if !first.keep.Load() || !second.keep.Load() {
		t.Fatal("existing child missed restored policy")
	}
	if err := firstScope.Close(); err != nil {
		t.Fatal(err)
	}
	dns.CloseIdleConnections()
	if first.idleCalls.Load() != 1 || second.idleCalls.Load() != 2 {
		t.Fatal("closed child was retained or live child omitted")
	}
}

func TestEndpointDNSIdlePolicyChangesDuringChildStart(t *testing.T) {
	dns := fixtureEndpointDNS(t)
	scope := adapter.NewScope(context.Background(), nil)
	defer scope.Close()
	resolver := &endpointDNSIdleResolver{startEntered: make(chan struct{}), startRelease: make(chan struct{})}
	started := make(chan error, 1)
	go func() { started <- dns.StartResolver(resolver, scope) }()
	<-resolver.startEntered
	dns.SetKeepIdleConnections(false)
	close(resolver.startRelease)
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	if resolver.keep.Load() {
		t.Fatal("resolver published with a stale idle policy")
	}
}

func TestEndpointDNSIdleCallPrecedesChildCleanup(t *testing.T) {
	dns := fixtureEndpointDNS(t)
	scope := adapter.NewScope(context.Background(), nil)
	resolver := &endpointDNSIdleResolver{idleEntered: make(chan struct{}), idleRelease: make(chan struct{})}
	if err := dns.StartResolver(resolver, scope); err != nil {
		t.Fatal(err)
	}
	idleDone := make(chan struct{})
	go func() { defer close(idleDone); dns.CloseIdleConnections() }()
	<-resolver.idleEntered
	closed := make(chan error, 1)
	go func() { closed <- scope.Close() }()
	<-scope.Context().Done()
	if resolver.closed.Load() != 0 {
		t.Fatal("child cleanup overlapped its admitted idle call")
	}
	select {
	case <-closed:
		t.Fatal("scope did not join the admitted idle call")
	default:
	}
	close(resolver.idleRelease)
	<-idleDone
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if resolver.closed.Load() != 1 {
		t.Fatal("child cleanup was not performed exactly once")
	}
	dns.CloseIdleConnections()
	if resolver.idleCalls.Load() != 1 {
		t.Fatal("closed child received another idle call")
	}
}

func TestEndpointDNSShutdownJoinsIdleCall(t *testing.T) {
	dns := fixtureEndpointDNS(t)

	scope := adapter.NewScope(context.Background(), nil)
	defer scope.Close()
	resolver := &endpointDNSIdleResolver{idleEntered: make(chan struct{}), idleRelease: make(chan struct{})}
	if err := dns.StartResolver(resolver, scope); err != nil {
		t.Fatal(err)
	}
	idleDone := make(chan struct{})
	go func() { defer close(idleDone); dns.CloseIdleConnections() }()
	<-resolver.idleEntered
	closed := make(chan error, 1)
	go func() { closed <- dns.Close() }()
	waitEndpointDNSIdle(t, dns.work.Sealed)
	select {
	case <-closed:
		t.Fatal("wrapper released ownership before idle call returned")
	default:
	}
	close(resolver.idleRelease)
	<-idleDone
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	dns.CloseIdleConnections()
	dns.SetKeepIdleConnections(false)
	if resolver.idleCalls.Load() != 1 || !resolver.keep.Load() {
		t.Fatal("shutdown admitted new idle controls")
	}
}

type endpointDNSNonIdleResolver struct{ adapter.DNSTransport }

func (*endpointDNSNonIdleResolver) Start(adapter.StartStage, *adapter.Scope) error {
	return errors.New("must reject before Start")
}

func TestEndpointDNSRejectsChildWithoutIdleContract(t *testing.T) {
	dns := fixtureEndpointDNS(t)
	scope := adapter.NewScope(context.Background(), nil)
	defer scope.Close()
	if err := dns.StartResolver(new(endpointDNSNonIdleResolver), scope); err == nil || err.Error() != "endpoint DNS resolver requires idle-only connection control" {
		t.Fatalf("child without an idle-only contract was accepted: %v", err)
	}
}

func TestEndpointDNSChildStartOutlivesRetiringScope(t *testing.T) {
	dns := fixtureEndpointDNS(t)
	scope := adapter.NewScope(context.Background(), nil)
	resolver := &endpointDNSIdleResolver{startEntered: make(chan struct{}), startRelease: make(chan struct{})}
	started := make(chan error, 1)
	go func() { started <- dns.StartResolver(resolver, scope) }()
	<-resolver.startEntered
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if resolver.closed.Load() != 0 {
		t.Fatal("partly initialized child was closed")
	}
	close(resolver.startRelease)
	if err := <-started; !errors.Is(err, context.Canceled) {
		t.Fatalf("retired scope accepted publication: %v", err)
	}
	if resolver.closed.Load() != 1 {
		t.Fatal("late child cleanup escaped the retired scope")
	}
	dns.CloseIdleConnections()
	if resolver.idleCalls.Load() != 0 {
		t.Fatal("late closed child retained in idle registry")
	}
}

func TestEndpointDNSLateChildCleanupFailureStaysOwned(t *testing.T) {
	dns := fixtureEndpointDNS(t)

	scope := adapter.NewScope(context.Background(), nil)
	resolver := &endpointDNSIdleResolver{
		startEntered: make(chan struct{}), startRelease: make(chan struct{}),
		cleanupErr: errors.New("late child cleanup failed"),
	}
	started := make(chan error, 1)
	go func() { started <- dns.StartResolver(resolver, scope) }()
	<-resolver.startEntered
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	close(resolver.startRelease)
	if err := <-started; err == nil || !strings.Contains(err.Error(), "late child cleanup failed") {
		t.Fatalf("late cleanup failure lost: %v", err)
	}
	first := dns.Close()
	if first == nil || !strings.Contains(first.Error(), "late child cleanup failed") || dns.Close() != first {
		t.Fatalf("wrapper forgot the uncertain late child cleanup: %v", first)
	}
}

func TestEndpointDNSFailedChildStartRemainsScopeOwned(t *testing.T) {
	dns := fixtureEndpointDNS(t)
	scope := adapter.NewScope(context.Background(), nil)
	failure := errors.New("child start failed")
	resolver := &endpointDNSIdleResolver{startErr: failure}
	if err := dns.StartResolver(resolver, scope); !errors.Is(err, failure) {
		t.Fatalf("start error lost: %v", err)
	}
	dns.CloseIdleConnections()
	if resolver.idleCalls.Load() != 0 {
		t.Fatal("failed child entered the idle registry")
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if resolver.closed.Load() != 1 {
		t.Fatal("failed child initialization escaped its owner")
	}
}

func TestEndpointDNSCloseWaitsForCallback(t *testing.T) {
	dns := fixtureEndpointDNS(t)
	release, ok := dns.work.Reserve()
	if !ok {
		t.Fatal("reserve")
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = dns.Close() }()
	<-dns.operationCtx.Done()
	select {
	case <-done:
		t.Fatal("close skipped callback")
	default:
	}
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("callback not joined")
	}
}

func TestEndpointDNSRetirementFailureRemainsSticky(t *testing.T) {
	dns := fixtureEndpointDNS(t)
	scope, err := dns.NewScope()
	if err != nil {
		t.Fatal(err)
	}
	scope.Add(func() error { return errors.New("socket close failed") })
	dns.Retire(scope)
	first := dns.Close()
	if first == nil || dns.Close() != first {
		t.Fatal("cohort failure forgotten")
	}
}

func TestEndpointDNSProducerCancellationLinksExactOwner(t *testing.T) {
	dns := fixtureEndpointDNS(t)
	defer dns.Close()
	ctx, cancel := context.WithCancel(context.Background())
	dns.LinkProducer(ctx)
	cancel()
	select {
	case <-dns.producerCtx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("retiring endpoint failed to interrupt configuration producer")
	}
}
