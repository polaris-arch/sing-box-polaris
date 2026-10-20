package route

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

type referenceTestOutbound struct {
	adapter.Outbound
	tag string
	references []string
	keep func(bool)
	idle func()
}
func (o *referenceTestOutbound) Type() string { return "test" }
func (o *referenceTestOutbound) Tag() string { return o.tag }
func (o *referenceTestOutbound) Dependencies() []string { return nil }
func (o *referenceTestOutbound) References() []string { return o.references }
func (o *referenceTestOutbound) SetKeepIdleConnections(keep bool) { if o.keep != nil { o.keep(keep) } }
func (o *referenceTestOutbound) CloseIdleConnections() { if o.idle != nil { o.idle() } }

type referenceTestTransport struct {
	adapter.DNSTransport
	tag string
	dependencies []string
	references []string
	keep func(bool)
	idle func()
	resets atomic.Int32
}
func (d *referenceTestTransport) Type() string { return "test-dns" }
func (d *referenceTestTransport) Tag() string { return d.tag }
func (d *referenceTestTransport) Dependencies() []string { return d.dependencies }
func (d *referenceTestTransport) References() []string { return d.references }
func (d *referenceTestTransport) Reset() { d.resets.Add(1) }
func (d *referenceTestTransport) SetKeepIdleConnections(keep bool) { if d.keep != nil { d.keep(keep) } }
func (d *referenceTestTransport) CloseIdleConnections() { if d.idle != nil { d.idle() } }

type referenceTestUnsafeTransport struct { adapter.DNSTransport; resets atomic.Int32 }
func (d *referenceTestUnsafeTransport) Type() string { return "unsafe" }
func (d *referenceTestUnsafeTransport) Tag() string { return "unsafe" }
func (d *referenceTestUnsafeTransport) Dependencies() []string { return nil }
func (d *referenceTestUnsafeTransport) Reset() { d.resets.Add(1) }

type referenceTestOutbounds struct { adapter.OutboundManager; values []adapter.Outbound; defaultTag string }
func (m *referenceTestOutbounds) Outbounds() []adapter.Outbound { return m.values }
func (m *referenceTestOutbounds) Outbound(tag string) (adapter.Outbound, bool) {
	for _, value := range m.values { if value.Tag() == tag { return value, true } }
	return nil, false
}
func (m *referenceTestOutbounds) Default() adapter.Outbound { value, _ := m.Outbound(m.defaultTag); return value }

type referenceTestTransports struct { adapter.DNSTransportManager; values []adapter.DNSTransport; defaultTag string }
func (m *referenceTestTransports) Transports() []adapter.DNSTransport { return m.values }
func (m *referenceTestTransports) Transport(tag string) (adapter.DNSTransport, bool) {
	for _, value := range m.values { if value.Tag() == tag { return value, true } }
	return nil, false
}
func (m *referenceTestTransports) Default() adapter.DNSTransport { value, _ := m.Transport(m.defaultTag); return value }

type referenceTestEndpoints struct { adapter.EndpointManager; values []adapter.Endpoint }
func (m *referenceTestEndpoints) Endpoints() []adapter.Endpoint { return m.values }

type referenceTestInbounds struct { adapter.InboundManager }
func (*referenceTestInbounds) Inbounds() []adapter.Inbound { return nil }

type referenceTestServices struct { adapter.ServiceManager }
func (*referenceTestServices) Services() []adapter.Service { return nil }

type referenceTestHTTP struct { adapter.HTTPClientManager }

type referenceTestNetwork struct { adapter.NetworkManager; resolver string }
func (m *referenceTestNetwork) DefaultOptions() adapter.NetworkOptions { return adapter.NetworkOptions{DomainResolver: m.resolver} }

type referenceTestView struct {
	adapter.RuntimeView
	identity adapter.RuntimeRevision
	outbounds *referenceTestOutbounds
	transports *referenceTestTransports
	network *referenceTestNetwork
 endpoints []adapter.Endpoint
}
func (v *referenceTestView) Identity() adapter.RuntimeRevision { return v.identity }
func (v *referenceTestView) OutboundManager() adapter.OutboundManager { return v.outbounds }
func (v *referenceTestView) EndpointManager() adapter.EndpointManager { return &referenceTestEndpoints{values:v.endpoints} }
func (v *referenceTestView) DNSTransportManager() adapter.DNSTransportManager { return v.transports }
func (v *referenceTestView) NetworkManager() adapter.NetworkManager { return v.network }

type referenceTestGraph struct {
	view *referenceTestView
	mu sync.Mutex
	graphs int
	resources map[adapter.RuntimeResourceID]int
	ids map[any]adapter.RuntimeResourceID
	stable adapter.RuntimeResourceID
	retiring chan struct{}
}
func newReferenceTestGraph(revision uint64, outbounds []adapter.Outbound, transports []adapter.DNSTransport) *referenceTestGraph {
	g := &referenceTestGraph{
		view: &referenceTestView{identity: adapter.RuntimeRevision{Incarnation: "reference-test", Revision: revision}, outbounds: &referenceTestOutbounds{values: outbounds}, transports: &referenceTestTransports{values: transports}, network: new(referenceTestNetwork)},
		resources: make(map[adapter.RuntimeResourceID]int), ids: make(map[any]adapter.RuntimeResourceID),
		stable: adapter.RuntimeResourceID{Incarnation: "reference-test", Sequence: 1}, retiring: make(chan struct{}),
	}
	if len(outbounds) != 0 { g.view.outbounds.defaultTag = outbounds[0].Tag() }
	if len(transports) != 0 { g.view.transports.defaultTag = transports[0].Tag() }
	g.resources[g.stable] = 0
	sequence := revision*100 + 2
	for _, outbound := range outbounds { id := adapter.RuntimeResourceID{Incarnation: "reference-test", Sequence: sequence}; sequence++; g.ids[outbound] = id; g.resources[id] = 0 }
	for _, transport := range transports { id := adapter.RuntimeResourceID{Incarnation: "reference-test", Sequence: sequence}; sequence++; g.ids[transport] = id; g.resources[id] = 0 }
	return g
}
func (g *referenceTestGraph) acquire() adapter.RuntimeLease { g.mu.Lock(); defer g.mu.Unlock(); g.graphs++; return &referenceTestLease{graph: g} }
func (g *referenceTestGraph) counts() (int, int) {
	g.mu.Lock(); defer g.mu.Unlock()
	resources := 0
	for _, count := range g.resources { resources += count }
	return g.graphs, resources
}

type referenceTestLease struct { graph *referenceTestGraph; released bool }
func (l *referenceTestLease) View() adapter.RuntimeView { return l.graph.view }
func (l *referenceTestLease) Fork() (adapter.RuntimeLease, error) {
	g := l.graph; g.mu.Lock(); defer g.mu.Unlock()
	if l.released { return nil, errors.New("released graph") }
	g.graphs++; return &referenceTestLease{graph: g}, nil
}
func (l *referenceTestLease) RetainResource(id adapter.RuntimeResourceID) (adapter.RuntimeResourceLease, error) {
	g := l.graph; g.mu.Lock(); defer g.mu.Unlock()
	if l.released { return nil, errors.New("released graph") }
	if _, ok := g.resources[id]; !ok { return nil, errors.New("not in graph closure") }
	g.resources[id]++; return &referenceTestResourceLease{graph: g, id: id}, nil
}
func (l *referenceTestLease) Release() { g := l.graph; g.mu.Lock(); defer g.mu.Unlock(); if !l.released { l.released = true; g.graphs-- } }

type referenceTestResourceLease struct { graph *referenceTestGraph; id adapter.RuntimeResourceID; released bool }
func (l *referenceTestResourceLease) ID() adapter.RuntimeResourceID { return l.id }
func (l *referenceTestResourceLease) Retiring() <-chan struct{} { return l.graph.retiring }
func (l *referenceTestResourceLease) Fork() (adapter.RuntimeResourceLease, error) {
	g := l.graph; g.mu.Lock(); defer g.mu.Unlock()
	if l.released { return nil, errors.New("released resource") }
	g.resources[l.id]++; return &referenceTestResourceLease{graph: g, id: l.id}, nil
}
func (l *referenceTestResourceLease) Release() { g := l.graph; g.mu.Lock(); defer g.mu.Unlock(); if !l.released { l.released = true; g.resources[l.id]-- } }

type referenceTestProvider struct {
	mu sync.Mutex
	graph *referenceTestGraph
	options *RuntimeReferenceOptions
	mode string
	acquires int
}
func (p *referenceTestProvider) AcquireReferenceSnapshot() (RuntimeReferenceSnapshot, error) {
	p.mu.Lock(); defer p.mu.Unlock()
	p.acquires++
	return RuntimeReferenceSnapshot{Lease: p.graph.acquire(), Options: p.options,
		Inbounds: new(referenceTestInbounds), Services: new(referenceTestServices), HTTPClient: new(referenceTestHTTP),
		Mode: p.mode, StableResource: p.graph.stable, Resources: p.graph.ids,
	}, nil
}
func (p *referenceTestProvider) replace(g *referenceTestGraph, options *RuntimeReferenceOptions) { p.mu.Lock(); p.graph = g; p.options = options; p.mu.Unlock() }

type referenceTestHooks struct {
	mu sync.Mutex
	hook *observable.Subscriber[struct{}]
	adds int
	removes int
	unregister func() error
	register func()
}
func (h *referenceTestHooks) RegisterReferenceHook(hook *observable.Subscriber[struct{}]) (func() error, error) {
	h.mu.Lock(); h.hook = hook; h.adds++; h.mu.Unlock()
	if h.register != nil { h.register() }
	return func() error {
		if h.unregister != nil { if err := h.unregister(); err != nil { return err } }
		h.mu.Lock(); h.hook = nil; h.removes++; h.mu.Unlock()
		return nil
	}, nil
}
func (h *referenceTestHooks) emit() { h.mu.Lock(); hook := h.hook; h.mu.Unlock(); if hook != nil { hook.Emit(struct{}{}) } }

func awaitReferenceSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select { case <-signal: case <-time.After(3*time.Second): t.Fatal("reference barrier did not complete") }
}
func awaitReferenceKeep(t *testing.T, signal <-chan bool, want bool) {
	t.Helper()
	select { case got := <-signal: if got != want { t.Fatalf("keep idle = %v, want %v", got, want) }; case <-time.After(3*time.Second): t.Fatal("reference policy did not arrive") }
}
func referenceTestOptions(t *testing.T, options option.Options) *RuntimeReferenceOptions {
	t.Helper(); result, err := NewRuntimeReferenceOptions(context.Background(), options); if err != nil { t.Fatal(err) }; return result
}
func startReferenceTestManager(t *testing.T, ctx context.Context, provider *referenceTestProvider, hooks *referenceTestHooks) *RuntimeReferenceManager {
	t.Helper()
	logger := log.NewNOPFactory().Logger()
	m := NewRuntimeReferenceManager(ctx, logger, provider, hooks)
	scope := adapter.NewScope(ctx, logger)
	if err := m.Start(adapter.StartStateStarted, scope); err != nil { t.Fatal(err) }
	t.Cleanup(func() {
		m.Stop()
		wait, cancel := context.WithTimeout(context.Background(), 3*time.Second); defer cancel()
		if err := m.WaitStopped(wait); err != nil { t.Errorf("reference cleanup: %v", err) }
	})
	return m
}

func TestRuntimeReferenceDormantAndPauseFencesActualEffects(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	old := &referenceTestOutbound{tag: "same", keep: func(bool) { close(entered); <-release }}
	oldGraph := newReferenceTestGraph(1, []adapter.Outbound{old}, nil)
	provider := &referenceTestProvider{graph: oldGraph, options: referenceTestOptions(t, option.Options{})}
	hooks := new(referenceTestHooks)
	m := startReferenceTestManager(t, context.Background(), provider, hooks)
	hooks.emit()
	if err := m.CloseIdleConnections(context.Background()); !errors.Is(err, errRuntimeReferencePaused) { t.Fatalf("dormant observer admitted work: %v", err) }
	if graph, resources := oldGraph.counts(); graph != 0 || resources != 0 { t.Fatal("dormant observer retained resources") }
	if err := m.Activate(); err != nil { t.Fatal(err) }
	awaitReferenceSignal(t, entered)
	if graph, resources := oldGraph.counts(); graph != 1 || resources != 2 { t.Fatalf("effect lacks exact ownership: %d/%d", graph, resources) }
	paused := make(chan *RuntimeReferencePause, 1)
	pauseError := make(chan error, 1)
	go func() { token, err := m.Pause(context.Background()); paused <- token; pauseError <- err }()
	// Cancelled observation obtains an additional owned pause deterministically.
	cancelled, cancel := context.WithCancel(context.Background()); cancel()
	extra, err := m.Pause(cancelled)
	if !errors.Is(err, context.Canceled) || extra == nil { t.Fatal("pause timeout lost its token") }
	select { case <-paused: t.Fatal("pause completed before actual effect"); default: }
	close(release)
	var token *RuntimeReferencePause
	select { case token = <-paused: case <-time.After(3*time.Second): t.Fatal("pause failed to join effect") }
	if err := <-pauseError; err != nil { t.Fatal(err) }
	if graph, resources := oldGraph.counts(); graph != 0 || resources != 0 { t.Fatal("actual completed effect retained leases") }
	newCalls := make(chan bool, 1)
	current := &referenceTestOutbound{tag: "same", keep: func(keep bool) { newCalls <- keep }}
	newGraph := newReferenceTestGraph(2, []adapter.Outbound{current}, nil)
	provider.replace(newGraph, referenceTestOptions(t, option.Options{}))
	hooks.emit()
	token.Resume(); token.Resume() // duplicate release must not consume extra's pause
	if err := m.CloseIdleConnections(context.Background()); !errors.Is(err, errRuntimeReferencePaused) { t.Fatalf("overlapping pause escaped: %v", err) }
	if graph, resources := newGraph.counts(); graph != 0 || resources != 0 { t.Fatal("queued notification entered paused graph") }
	extra.Resume()
	awaitReferenceKeep(t, newCalls, true)
}

func TestRuntimeReferenceAbortResumesCurrentWithoutDuplicateHooks(t *testing.T) {
	values := make(chan bool, 2)
	outbound := &referenceTestOutbound{tag: "node", keep: func(keep bool) { values <- keep }}
	graph := newReferenceTestGraph(1, []adapter.Outbound{outbound}, nil)
	options := option.Options{Route: &option.RouteOptions{Rules: []option.Rule{{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{RawDefaultRule: option.RawDefaultRule{ClashMode: "blocked"}, RuleAction: option.RuleAction{Action: C.RuleActionTypeReject}}}}}}
	provider := &referenceTestProvider{graph: graph, options: referenceTestOptions(t, options), mode: "direct"}
	hooks := new(referenceTestHooks)
	m := startReferenceTestManager(t, context.Background(), provider, hooks)
	if err := m.Activate(); err != nil { t.Fatal(err) }; awaitReferenceKeep(t, values, true)
	token, err := m.Pause(context.Background()); if err != nil { t.Fatal(err) }
	// Abort leaves graph identity/options unchanged; current mode changed while paused.
	provider.mu.Lock(); provider.mode = "blocked"; provider.mu.Unlock()
	hooks.emit(); token.Resume(); awaitReferenceKeep(t, values, false)
	hooks.mu.Lock(); adds := hooks.adds; hooks.mu.Unlock()
	if adds != 1 { t.Fatal("abort installed duplicate hooks") }
}

func TestRuntimeReferenceIdleWaitCancellationRetainsActualWork(t *testing.T) {
	values := make(chan bool, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	outbound := &referenceTestOutbound{tag: "node", keep: func(keep bool) { values <- keep }, idle: func() { close(entered); <-release }}
	graph := newReferenceTestGraph(1, []adapter.Outbound{outbound}, nil)
	m := startReferenceTestManager(t, context.Background(), &referenceTestProvider{graph: graph, options: referenceTestOptions(t, option.Options{})}, new(referenceTestHooks))
	if err := m.Activate(); err != nil { t.Fatal(err) }; awaitReferenceKeep(t, values, true)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- m.CloseIdleConnections(ctx) }()
	awaitReferenceSignal(t, entered); cancel()
	if err := <-result; !errors.Is(err, context.Canceled) { t.Fatalf("wait cancellation: %v", err) }
	if graphs, resources := graph.counts(); graphs != 1 || resources != 2 { t.Fatal("caller cancellation released live idle effect") }
	m.Stop()
	alreadyCancelled, cancelWait := context.WithCancel(context.Background()); cancelWait()
	if err := m.WaitStopped(alreadyCancelled); !errors.Is(err, context.Canceled) { t.Fatalf("stop reported completion before actual effect: %v", err) }
	close(release)
	wait, cancelWait := context.WithTimeout(context.Background(), 3*time.Second); defer cancelWait()
	if err := m.WaitStopped(wait); err != nil { t.Fatal(err) }
	if graphs, resources := graph.counts(); graphs != 0 || resources != 0 { t.Fatal("finished idle effect did not release its reservations") }
}

func TestRuntimeReferenceStopJoinsProducerUnregistration(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	hooks := &referenceTestHooks{unregister: func() error { close(entered); <-release; return nil }}
	provider := &referenceTestProvider{graph: newReferenceTestGraph(1, nil, nil), options: referenceTestOptions(t, option.Options{})}
	m := startReferenceTestManager(t, context.Background(), provider, hooks)
	m.Stop(); awaitReferenceSignal(t, entered)
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if err := m.WaitStopped(ctx); !errors.Is(err, context.Canceled) { t.Fatal("unregister was treated as complete") }
	if err := m.Activate(); !errors.Is(err, errRuntimeReferenceStopped) { t.Fatal("late activation resurrected observer") }
	hooks.emit()
	close(release)
	wait, cancelWait := context.WithTimeout(context.Background(), 3*time.Second); defer cancelWait()
	if err := m.WaitStopped(wait); err != nil { t.Fatal(err) }
	provider.mu.Lock(); calls := provider.acquires; provider.mu.Unlock()
	if calls != 0 { t.Fatal("sealed hook admitted graph work") }
}

func TestRuntimeReferencePauseRegistryTailDoesNotHoldObserverLock(t *testing.T) {
	ctx := pause.WithDefaultManager(context.Background())
	pm := service.FromContext[pause.Manager](ctx)
	entered, release, pauseDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	blocker := pm.RegisterCallback(func(event int) { if event == pause.EventDevicePaused { close(entered); <-release } })
	defer func() {
		select { case <-release: default: close(release) }
		pm.UnregisterCallback(blocker)
	}()
	m := startReferenceTestManager(t, ctx, &referenceTestProvider{graph: newReferenceTestGraph(1, nil, nil), options: referenceTestOptions(t, option.Options{})}, new(referenceTestHooks))
	go func() { pm.DevicePause(); close(pauseDone) }()
	awaitReferenceSignal(t, entered)
	m.Stop()
	lockDone := make(chan struct{})
	go func() { m.mu.Lock(); m.mu.Unlock(); close(lockDone) }()
	awaitReferenceSignal(t, lockDone)
	cancelled, cancel := context.WithCancel(context.Background()); cancel()
	if err := m.WaitStopped(cancelled); !errors.Is(err, context.Canceled) { t.Fatal("pause callback tail was not joined") }
	close(release); awaitReferenceSignal(t, pauseDone)
	wait, cancelWait := context.WithTimeout(context.Background(), 3*time.Second); defer cancelWait()
	if err := m.WaitStopped(wait); err != nil { t.Fatal(err) }
}

func TestRuntimeReferenceEffectFailureKeepsUnknownReservations(t *testing.T) {
	entered := make(chan struct{})
	outbound := &referenceTestOutbound{tag: "node", keep: func(bool) { close(entered); panic("native effect uncertain") }}
	graph := newReferenceTestGraph(1, []adapter.Outbound{outbound}, nil)
	logger := log.NewNOPFactory().Logger()
	m := NewRuntimeReferenceManager(context.Background(), logger, &referenceTestProvider{graph: graph, options: referenceTestOptions(t, option.Options{})}, new(referenceTestHooks))
	if err := m.Start(adapter.StartStateStarted, adapter.NewScope(context.Background(), logger)); err != nil { t.Fatal(err) }
	if err := m.Activate(); err != nil { t.Fatal(err) }
	awaitReferenceSignal(t, entered)
	token, err := m.Pause(context.Background())
	if err == nil { t.Fatal("uncertain effect allowed publication") }
	token.Resume()
	m.Stop()
	wait, cancel := context.WithTimeout(context.Background(), 3*time.Second); defer cancel()
	if err := m.WaitStopped(wait); err == nil { t.Fatal("panic became successful cleanup") }
	if graphs, resources := graph.counts(); graphs != 1 || resources != 2 { t.Fatalf("uncertain actual effect was released: %d/%d", graphs, resources) }
}

func TestRuntimeReferenceIdlePolicyUsesCurrentResolverAndIdentity(t *testing.T) {
	outboundValues, dnsValues := make(chan bool, 4), make(chan bool, 4)
	outbound := &referenceTestOutbound{tag: "node", keep: func(keep bool) { outboundValues <- keep }}
	oldDNS := &referenceTestTransport{tag: "resolver", keep: func(keep bool) { dnsValues <- keep }}
	first := newReferenceTestGraph(1, []adapter.Outbound{outbound}, []adapter.DNSTransport{oldDNS})
	provider := &referenceTestProvider{graph: first, options: referenceTestOptions(t, option.Options{})}
	m := startReferenceTestManager(t, context.Background(), provider, new(referenceTestHooks))
	if err := m.Activate(); err != nil { t.Fatal(err) }; awaitReferenceKeep(t, outboundValues, true); awaitReferenceKeep(t, dnsValues, true)
	token, err := m.Pause(context.Background()); if err != nil { t.Fatal(err) }
	newDNS := &referenceTestTransport{tag: "resolver", keep: func(keep bool) { dnsValues <- keep }}
	newDefault := &referenceTestTransport{tag: "new-default"}
	second := newReferenceTestGraph(2, []adapter.Outbound{outbound}, []adapter.DNSTransport{newDefault, newDNS})
	second.view.network.resolver = "resolver"
	provider.replace(second, referenceTestOptions(t, option.Options{})); token.Resume()
	awaitReferenceKeep(t, dnsValues, true) // same tag, new allocation must receive policy
	token, err = m.Pause(context.Background()); if err != nil { t.Fatal(err) }
	third := newReferenceTestGraph(3, []adapter.Outbound{outbound}, []adapter.DNSTransport{newDefault, newDNS})
	third.view.network.resolver = "new-default"
	provider.replace(third, referenceTestOptions(t, option.Options{})); token.Resume()
	awaitReferenceKeep(t, dnsValues, false)
	if oldDNS.resets.Load() != 0 || newDNS.resets.Load() != 0 { t.Fatal("idle policy reset active DNS transport") }
}

func TestRuntimeReferenceRejectsUnprovenResetBeforeEffects(t *testing.T) {
	unsafe := new(referenceTestUnsafeTransport)
	graph := newReferenceTestGraph(1, nil, []adapter.DNSTransport{unsafe})
	r := &runtimeReferenceReservation{snapshot: RuntimeReferenceSnapshot{Lease: graph.acquire(), Options: referenceTestOptions(t, option.Options{}), Inbounds: new(referenceTestInbounds), Services: new(referenceTestServices), HTTPClient: new(referenceTestHTTP), StableResource: graph.stable, Resources: graph.ids}}
	if _, err := r.prepare(); err == nil { t.Fatal("unsafe reset-only transport admitted") }
	r.release()
	if unsafe.resets.Load() != 0 { t.Fatal("validation invoked destructive transport reset") }
	if graphs, resources := graph.counts(); graphs != 0 || resources != 0 { t.Fatal("validation failure leaked reservations") }
}

func TestRuntimeReferenceOptionsDetachNestedRuleState(t *testing.T) {
	options := option.Options{Route: &option.RouteOptions{Rules: []option.Rule{{
		Type: C.RuleTypeLogical,
		LogicalOptions: option.LogicalRule{
			RawLogicalRule: option.RawLogicalRule{Mode: C.LogicalTypeAnd, Rules: []option.Rule{{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{RawDefaultRule: option.RawDefaultRule{ClashMode: "direct"}},
			}}},
			RuleAction: option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: "node"}},
		},
	}}}}
	frozen := referenceTestOptions(t, options)
	options.Route.Rules[0].LogicalOptions.Rules[0].DefaultOptions.ClashMode = "changed"
	options.Route.Rules[0].LogicalOptions.RouteOptions.Outbound = "changed"
	var outbounds, transports []string
	collectRuleReferences(frozen.rules, "direct", &outbounds, &transports)
	if len(outbounds) != 1 || outbounds[0] != "node" { t.Fatal("candidate recipe aliases mutable option rules") }
}

func TestRuntimeReferenceCanceledScopeDoesNotJoinOwnSetup(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	scope := adapter.NewScope(context.Background(), logger)
	if err := scope.Close(); err != nil { t.Fatal(err) }
	hooks := new(referenceTestHooks)
	m := NewRuntimeReferenceManager(context.Background(), logger, &referenceTestProvider{graph: newReferenceTestGraph(1, nil, nil), options: referenceTestOptions(t, option.Options{})}, hooks)
	started := make(chan error, 1)
	go func() { started <- m.Start(adapter.StartStateStarted, scope) }()
	select {
	case err := <-started: if !errors.Is(err, context.Canceled) { t.Fatalf("canceled scope start: %v", err) }
	case <-time.After(3*time.Second): t.Fatal("immediate cleanup joined its own setup stack")
	}
	wait, cancel := context.WithTimeout(context.Background(), 3*time.Second); defer cancel()
	if err := m.WaitStopped(wait); !errors.Is(err, context.Canceled) { t.Fatalf("missing canceled setup result: %v", err) }
	hooks.mu.Lock(); adds := hooks.adds; hooks.mu.Unlock()
	if adds != 0 { t.Fatal("canceled scope registered producers") }
}

func TestRuntimeReferenceScopeCloseDuringHookSetupIsNonjoining(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	scope := adapter.NewScope(context.Background(), logger)
	entered, release := make(chan struct{}), make(chan struct{})
	hooks := &referenceTestHooks{register: func() { close(entered); <-release }}
	m := NewRuntimeReferenceManager(context.Background(), logger, &referenceTestProvider{graph: newReferenceTestGraph(1, nil, nil), options: referenceTestOptions(t, option.Options{})}, hooks)
	started := make(chan error, 1)
	go func() { started <- m.Start(adapter.StartStateStarted, scope) }()
	awaitReferenceSignal(t, entered)
	scopeClosed := make(chan struct{})
	go func() { _ = scope.Close(); close(scopeClosed) }()
	awaitReferenceSignal(t, scopeClosed)
	close(release)
	select {
	case err := <-started: if !errors.Is(err, context.Canceled) { t.Fatalf("closed scope start: %v", err) }
	case <-time.After(3*time.Second): t.Fatal("setup did not finish after producer registration")
	}
	wait, cancel := context.WithTimeout(context.Background(), 3*time.Second); defer cancel()
	if err := m.WaitStopped(wait); !errors.Is(err, context.Canceled) { t.Fatalf("closed scope setup result: %v", err) }
	hooks.mu.Lock(); removes := hooks.removes; hooks.mu.Unlock()
	if removes != 1 { t.Fatal("late registration producer not unregistered") }
}


type referenceTestPartialHooks struct { removed atomic.Int32; err error }
func (h *referenceTestPartialHooks) RegisterReferenceHook(*observable.Subscriber[struct{}]) (func() error, error) {
	return func() error { h.removed.Add(1); return nil }, h.err
}

func TestRuntimeReferencePartialRegistrationUnregistersAndStaysFailed(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	setupFailure := errors.New("second producer registration failed")
	hooks := &referenceTestPartialHooks{err: setupFailure}
	m := NewRuntimeReferenceManager(context.Background(), logger, &referenceTestProvider{}, hooks)
	if err := m.Start(adapter.StartStateStarted, adapter.NewScope(context.Background(), logger)); !errors.Is(err, setupFailure) { t.Fatalf("setup failure: %v", err) }
	wait, cancel := context.WithTimeout(context.Background(), 3*time.Second); defer cancel()
	if err := m.WaitStopped(wait); !errors.Is(err, setupFailure) { t.Fatalf("setup failure was not sticky: %v", err) }
	if hooks.removed.Load() != 1 { t.Fatal("partially registered producer not removed exactly once") }
	m.Stop()
	if hooks.removed.Load() != 1 { t.Fatal("repeated stop re-ran unregister") }
}

func TestRuntimeReferenceUnregisterFailureCannotClaimStoppedSuccess(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	failure := errors.New("hook removal uncertain")
	hooks := &referenceTestHooks{unregister: func() error { return failure }}
	m := NewRuntimeReferenceManager(context.Background(), logger, &referenceTestProvider{}, hooks)
	if err := m.Start(adapter.StartStateStarted, adapter.NewScope(context.Background(), logger)); err != nil { t.Fatal(err) }
	m.Stop()
	wait, cancel := context.WithTimeout(context.Background(), 3*time.Second); defer cancel()
	if err := m.WaitStopped(wait); !errors.Is(err, failure) { t.Fatalf("unregister result lost: %v", err) }
	if err := m.WaitStopped(wait); !errors.Is(err, failure) { t.Fatal("uncertain unregister result was not sticky") }
	// Even a producer whose unregister failed cannot resurrect graph work.
	hooks.emit()
	if err := m.Activate(); !errors.Is(err, errRuntimeReferenceStopped) { t.Fatal("failed producer stop reopened admission") }
}

func TestRuntimeReferenceMissingAllocationNeverEffectsSameTag(t *testing.T) {
	var effects atomic.Int32
	outbound := &referenceTestOutbound{tag: "same", keep: func(bool) { effects.Add(1) }}
	graph := newReferenceTestGraph(2, []adapter.Outbound{outbound}, nil)
	previous := &referenceTestOutbound{tag: "same"}
	// A stale tag-equivalent object is not the receiving allocation.
	resources := map[any]adapter.RuntimeResourceID{previous: graph.ids[outbound]}
	r := &runtimeReferenceReservation{snapshot: RuntimeReferenceSnapshot{Lease: graph.acquire(), Options: referenceTestOptions(t, option.Options{}), Inbounds: new(referenceTestInbounds), Services: new(referenceTestServices), HTTPClient: new(referenceTestHTTP), StableResource: graph.stable, Resources: resources}}
	if _, err := r.prepare(); err == nil { t.Fatal("tag-equivalent stale object authorized current effects") }
	r.release()
	if effects.Load() != 0 { t.Fatal("missing exact allocation still received idle policy") }
	if graphs, refs := graph.counts(); graphs != 0 || refs != 0 { t.Fatal("rejected snapshot leaked leases") }
}

func TestRuntimeReferenceCensusTraversesSelectedCurrentDependencies(t *testing.T) {
	selected, other, dnsValues := make(chan bool, 2), make(chan bool, 2), make(chan bool, 2)
	group := &referenceTestOutbound{tag: "group", references: []string{"selected"}}
	first := &referenceTestOutbound{tag: "selected", keep: func(keep bool) { selected <- keep }}
	second := &referenceTestOutbound{tag: "other", keep: func(keep bool) { other <- keep }}
	upstream := &referenceTestTransport{tag: "upstream", dependencies: []string{"resolver"}}
	resolver := &referenceTestTransport{tag: "resolver", keep: func(keep bool) { dnsValues <- keep }}
	graph := newReferenceTestGraph(1, []adapter.Outbound{group, first, second}, []adapter.DNSTransport{upstream, resolver})
	provider := &referenceTestProvider{graph: graph, options: referenceTestOptions(t, option.Options{})}
	hooks := new(referenceTestHooks)
	m := startReferenceTestManager(t, context.Background(), provider, hooks)
	if err := m.Activate(); err != nil { t.Fatal(err) }
	awaitReferenceKeep(t, selected, true); awaitReferenceKeep(t, other, false); awaitReferenceKeep(t, dnsValues, true)
	token, err := m.Pause(context.Background()); if err != nil { t.Fatal(err) }
	group.references = []string{"other"}
	hooks.emit(); token.Resume()
	awaitReferenceKeep(t, selected, false); awaitReferenceKeep(t, other, true)
	if upstream.resets.Load() != 0 || resolver.resets.Load() != 0 { t.Fatal("reference census reset a live dependency") }
}


func TestRuntimeReferenceStopFromEffectDoesNotJoinItself(t *testing.T) {
	entered := make(chan struct{})
	var m *RuntimeReferenceManager
	outbound := &referenceTestOutbound{tag: "node", keep: func(bool) { m.Stop(); close(entered) }}
	graph := newReferenceTestGraph(1, []adapter.Outbound{outbound}, nil)
	m = startReferenceTestManager(t, context.Background(), &referenceTestProvider{graph: graph, options: referenceTestOptions(t, option.Options{})}, new(referenceTestHooks))
	if err := m.Activate(); err != nil { t.Fatal(err) }
	awaitReferenceSignal(t, entered)
	wait, cancel := context.WithTimeout(context.Background(), 3*time.Second); defer cancel()
	if err := m.WaitStopped(wait); err != nil { t.Fatal(err) }
	if graphs, resources := graph.counts(); graphs != 0 || resources != 0 { t.Fatal("self-stop discarded unfinished work") }
}

func TestRuntimeReferencePauseTokenCannotResurrectStoppedObserver(t *testing.T) {
	provider := &referenceTestProvider{graph: newReferenceTestGraph(1, nil, nil), options: referenceTestOptions(t, option.Options{})}
	hooks := new(referenceTestHooks)
	m := startReferenceTestManager(t, context.Background(), provider, hooks)
	token, err := m.Pause(context.Background()); if err != nil { t.Fatal(err) }
	if err := m.Activate(); err != nil { t.Fatal(err) }
	copyOfToken := *token
	m.Stop()
	token.Resume(); copyOfToken.Resume(); hooks.emit()
	wait, cancel := context.WithTimeout(context.Background(), 3*time.Second); defer cancel()
	if err := m.WaitStopped(wait); err != nil { t.Fatal(err) }
	provider.mu.Lock(); acquires := provider.acquires; provider.mu.Unlock()
	if acquires != 0 { t.Fatal("pause token release reopened stopped observer") }
	m.mu.Lock(); pauses := m.pauses; m.mu.Unlock()
	if pauses != 0 { t.Fatal("value-copied pause token released more than once") }
}


func TestRuntimeReferenceLifecycleDoesNotFilterUncertainty(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	scope := adapter.NewScope(context.Background(), logger)
	m := NewRuntimeReferenceManager(context.Background(), logger, &referenceTestProvider{}, new(referenceTestHooks))
	if err := m.Start(adapter.StartStateStarted, scope); err != nil { t.Fatal(err) }
	// A sticky callback/producer deadline is still incomplete cleanup, even
	// after the observer loop has exited. Scope must not filter it to success.
	m.recordFailure(context.DeadlineExceeded)
	m.Stop()
	wait, cancel := context.WithTimeout(context.Background(), 3*time.Second); defer cancel()
	if err := m.WaitStopped(wait); !errors.Is(err, context.DeadlineExceeded) { t.Fatalf("direct observation lost its cause: %v", err) }
	if err := scope.Close(); err == nil || errors.Is(err, context.DeadlineExceeded) { t.Fatalf("lifecycle uncertainty was filtered or remained cancellation-shaped: %v", err) }
}


type referenceTestEndpoint struct { adapter.Endpoint; tag string }
func (e *referenceTestEndpoint) Tag() string { return e.tag }
func (e *referenceTestEndpoint) Type() string { return "test-endpoint" }
func (e *referenceTestEndpoint) Dependencies() []string { return nil }

func TestRuntimeReferenceRetainsExactEndpointAllocation(t *testing.T) {
 endpoint:=&referenceTestEndpoint{tag:"peer"}
 graph:=newReferenceTestGraph(1,nil,nil)
 graph.view.endpoints=[]adapter.Endpoint{endpoint}
 id:=adapter.RuntimeResourceID{Incarnation:"reference-test",Sequence:200}
 graph.ids[endpoint]=id;graph.resources[id]=0
 makeReservation:=func()*runtimeReferenceReservation{return &runtimeReferenceReservation{snapshot:RuntimeReferenceSnapshot{Lease:graph.acquire(),Options:referenceTestOptions(t,option.Options{}),Inbounds:new(referenceTestInbounds),Services:new(referenceTestServices),HTTPClient:new(referenceTestHTTP),StableResource:graph.stable,Resources:graph.ids}}}
 reservation:=makeReservation()
 if _,err:=reservation.prepare();err!=nil{t.Fatal(err)}
 graph.mu.Lock();retained:=graph.resources[id];graph.mu.Unlock()
 if retained!=1{t.Fatalf("endpoint reservations = %d, want 1",retained)}
 reservation.release()
 if graphs,resources:=graph.counts();graphs!=0||resources!=0{t.Fatal("endpoint reservation leaked")}
 // A matching tag is not allocation identity; reject an uncensused replacement.
 graph.view.endpoints=[]adapter.Endpoint{&referenceTestEndpoint{tag:"peer"}}
 reservation=makeReservation()
 if _,err:=reservation.prepare();err==nil{t.Fatal("same-tag endpoint bypassed exact allocation census")}
 reservation.release()
 if graphs,resources:=graph.counts();graphs!=0||resources!=0{t.Fatal("failed endpoint preparation leaked")}
}

type referenceTestOnDemandEndpoint struct { referenceTestEndpoint; keep func(bool) }
func(e *referenceTestOnDemandEndpoint)OnDemand()bool{return true}
func(e *referenceTestOnDemandEndpoint)SetKeepIdleConnections(keep bool){e.keep(keep)}

func TestRuntimeReferencePauseJoinsExactEndpointEffect(t *testing.T){
 entered,release:=make(chan struct{}),make(chan struct{})
 endpoint:=&referenceTestOnDemandEndpoint{referenceTestEndpoint:referenceTestEndpoint{tag:"peer"},keep:func(bool){close(entered);<-release}}
 graph:=newReferenceTestGraph(1,nil,nil);graph.view.endpoints=[]adapter.Endpoint{endpoint}
 id:=adapter.RuntimeResourceID{Incarnation:"reference-test",Sequence:200};graph.ids[endpoint]=id;graph.resources[id]=0
 provider:=&referenceTestProvider{graph:graph,options:referenceTestOptions(t,option.Options{})}
 m:=startReferenceTestManager(t,context.Background(),provider,new(referenceTestHooks))
 if err:=m.Activate();err!=nil{t.Fatal(err)}
 awaitReferenceSignal(t,entered)
 if graphs,resources:=graph.counts();graphs!=1||resources!=2{t.Fatalf("endpoint effect custody = %d/%d",graphs,resources)}
 canceled,cancel:=context.WithCancel(context.Background());cancel()
 token,err:=m.Pause(canceled)
 if token==nil||!errors.Is(err,context.Canceled){t.Fatal("blocked endpoint effect was not retained by pause")}
 close(release)
 joined,err:=m.Pause(context.Background());if err!=nil{t.Fatal(err)}
 if graphs,resources:=graph.counts();graphs!=0||resources!=0{t.Fatal("completed endpoint effect retained custody")}
 // Keep both pause tokens held until cleanup to avoid re-running the one-shot fixture.
 _=token;_=joined
}
