package group

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

type epochTestOutbound struct {
	adapter.Outbound
	tag string
}

func (o *epochTestOutbound) Tag() string       { return o.tag }
func (o *epochTestOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func epochTestGroup(t *testing.T) (*URLTestGroup, *urltest.HistoryStorage, pause.Manager) {
	t.Helper()
	history := urltest.NewHistoryStorage()
	ctx := pause.WithDefaultManager(context.Background())
	ctx = service.ContextWithPtr(ctx, history)
	g, err := NewURLTestGroup(ctx, nil, log.NewNOPFactory().Logger(), []adapter.Outbound{&epochTestOutbound{tag: "node"}}, "", time.Hour, 1, 2*time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close(); history.Close() })
	return g, history, service.FromContext[pause.Manager](ctx)
}

func awaitEpochSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal("missing barrier signal")
	}
}

func TestURLTestActualProbeDrainAndCoalescedEpoch(t *testing.T) {
	g, history, _ := epochTestGroup(t)
	firstEntered, firstRelease := make(chan struct{}), make(chan struct{})
	nextEntered, nextRelease := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	g.probe = func(ctx context.Context, _ string, _ N.Dialer) (uint16, error) {
		if calls.Add(1) == 1 {
			close(firstEntered)
			<-firstRelease
			return 5, nil
		}
		close(nextEntered)
		<-nextRelease
		return 11, nil
	}
	g.PostStart()
	awaitEpochSignal(t, firstEntered)
	epoch := history.AdvanceNetworkEpoch()
	for range 20 {
		g.requestCheck(g.ctx, true, false)
	}
	if calls.Load() != 1 {
		t.Fatal("successor started while actual old probe lives")
	}
	history.MarkReady(epoch)
	g.requestCheck(g.ctx, true, false)
	close(firstRelease)
	awaitEpochSignal(t, nextEntered)
	if history.LoadURLTestHistory("node") != nil {
		t.Fatal("old successful probe stored into new epoch")
	}
	g.Close()
	select {
	case <-g.Done():
		t.Fatal("close falsely joined uncooperative probe")
	default:
	}
	close(nextRelease)
	awaitEpochSignal(t, g.Done())
	if calls.Load() != 2 {
		t.Fatalf("coalesced calls: %d", calls.Load())
	}
	if history.LoadURLTestHistory("node") != nil {
		t.Fatal("closed owner published")
	}
	// Closing this group must not seal storage shared by sibling groups.
	if !history.StoreIfCurrent(epoch, "sibling", &adapter.URLTestHistory{Delay: 7}) {
		t.Fatal("sibling storage closed")
	}
}

func TestURLTestCloseBeforeTouchAndDevicePause(t *testing.T) {
	g, history, pm := epochTestGroup(t)
	epoch := history.Epoch()
	pm.DevicePause()
	entered, release := make(chan struct{}), make(chan struct{})
	g.probe = func(context.Context, string, N.Dialer) (uint16, error) { close(entered); <-release; return 4, nil }
	g.PostStart()
	if history.Epoch() != epoch {
		t.Fatal("device pause changed network epoch")
	}
	pm.DeviceWake()
	awaitEpochSignal(t, entered)
	g.Close()
	select {
	case <-g.Done():
		t.Fatal("startup probe missing from completion")
	default:
	}
	close(release)
	awaitEpochSignal(t, g.Done())
	pm.DevicePause()
	pm.DeviceWake() // callback unregistered; no recursive lock/join.
}

func TestURLTestCloseBeforePostStart(t *testing.T) {
	g, _, _ := epochTestGroup(t)
	g.Close()
	g.PostStart()
	g.Touch()
	awaitEpochSignal(t, g.Done())
	if g.started || g.ticker != nil {
		t.Fatal("closed group activated")
	}
}

type epochSelector struct {
	adapter.OutboundGroup
	selected adapter.Outbound
}

func (s *epochSelector) Tag() string                      { return "selector" }
func (s *epochSelector) Selected(string) adapter.Outbound { return s.selected }

func TestURLTestTargetFrozenBeforeSelectorChange(t *testing.T) {
	first, second := &epochTestOutbound{tag: "first"}, &epochTestOutbound{tag: "second"}
	selector := &epochSelector{selected: first}
	target, tag := URLTestTarget(selector, N.NetworkTCP)
	selector.selected = second
	if target != first || tag != "first" {
		t.Fatal("target and history key not frozen together")
	}
	selector.selected = selector
	if target, _ := URLTestTarget(selector, N.NetworkTCP); target != nil {
		t.Fatal("selector cycle admitted")
	}
	selector.selected = nil
	if target, _ := URLTestTarget(selector, N.NetworkTCP); target != nil {
		t.Fatal("nil target admitted")
	}
}

func TestCanceledCallerCannotConsumeRequiredRefresh(t *testing.T) {
	g, _, _ := epochTestGroup(t)
	g.requestCheck(g.ctx, true, false) // interface update before PostStart
	g.access.Lock()
	g.started = true
	g.access.Unlock() // PostStart admission barrier
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := g.requestCheck(canceled, true, true); err == nil {
		t.Fatal("canceled request admitted")
	}
	g.access.Lock()
	pending := g.pendingForce
	g.access.Unlock()
	if !pending {
		t.Fatal("required force consumed")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	g.probe = func(context.Context, string, N.Dialer) (uint16, error) { close(entered); <-release; return 9, nil }
	g.requestCheck(g.ctx, false, false)
	awaitEpochSignal(t, entered)
	g.Close()
	close(release)
	awaitEpochSignal(t, g.Done())
}

type failingEpochSelector struct {
	epochSelector
	onDial func()
}

func (s *failingEpochSelector) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	s.onDial()
	return nil, errors.New("fixture failure")
}
func (s *failingEpochSelector) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func TestDataFailureDoesNotEraseNestedSelectorHistory(t *testing.T) {
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		t.Run(network, func(t *testing.T) {
			g, history, _ := epochTestGroup(t)
			first, second := &epochTestOutbound{tag: "first"}, &epochTestOutbound{tag: "second"}
			selector := &failingEpochSelector{selected: first}
			selector.onDial = func() { selector.selected = second }
			epoch := history.Epoch()
			history.StoreIfCurrent(epoch, "first", &adapter.URLTestHistory{Delay: 5})
			history.StoreIfCurrent(epoch, "second", &adapter.URLTestHistory{Delay: 6})
			g.selection.Store(&urlTestSelection{tcp: selector, udp: selector})
			outbound := &URLTest{group: g, logger: log.NewNOPFactory().Logger()}
			if _, err := outbound.DialContext(context.Background(), network, M.Socksaddr{}); err == nil {
				t.Fatal("fixture succeeded")
			}
			if history.LoadURLTestHistory("first") == nil || history.LoadURLTestHistory("second") == nil {
				t.Fatal("wrapper failure erased unproven nested target")
			}
		})
	}
}

func TestLatchedRefreshOutlivesAdmittingCaller(t *testing.T) {
	g, _, _ := epochTestGroup(t)
	g.requestCheck(g.ctx, true, false)
	g.access.Lock()
	g.started = true
	g.access.Unlock()
	entered, inspect, observed, release := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var canceled atomic.Bool
	g.probe = func(ctx context.Context, _ string, _ N.Dialer) (uint16, error) {
		close(entered)
		<-inspect
		canceled.Store(ctx.Err() != nil)
		close(observed)
		<-release
		return 3, nil
	}
	caller, cancel := context.WithCancel(context.Background())
	g.requestCheck(caller, false, false)
	awaitEpochSignal(t, entered)
	cancel()
	close(inspect)
	awaitEpochSignal(t, observed)
	if canceled.Load() {
		t.Fatal("required refresh inherited short caller lifetime")
	}
	g.Close()
	close(release)
	awaitEpochSignal(t, g.Done())
}

func TestStaleNestedAdmissionPreservesPendingForce(t *testing.T) {
	g, history, _ := epochTestGroup(t)
	old := history.Epoch()
	next := history.AdvanceNetworkEpoch()
	history.MarkReady(next)
	g.requestCheck(g.ctx, true, false)
	if _, err := g.requestCheckEpoch(g.ctx, true, false, old); err == nil {
		t.Fatal("stale nested admission")
	}
	g.access.Lock()
	pending := g.pendingForce
	g.access.Unlock()
	if !pending {
		t.Fatal("stale request consumed new required force")
	}
}

type blockingNetworkOutbound struct {
	epochTestOutbound
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (o *blockingNetworkOutbound) Network() []string {
	o.once.Do(func() { close(o.entered); <-o.release })
	return []string{N.NetworkTCP}
}

func TestSelectionSnapshotInvalidatedBeforePublish(t *testing.T) {
	for _, closeOwner := range []bool{false, true} {
		t.Run(map[bool]string{false: "epoch", true: "close"}[closeOwner], func(t *testing.T) {
			g, history, _ := epochTestGroup(t)
			entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			outbound := &blockingNetworkOutbound{tag: "node", entered: entered, release: release}
			g.outbounds = []adapter.Outbound{outbound}
			epoch := history.Epoch()
			history.StoreIfCurrent(epoch, "node", &adapter.URLTestHistory{Delay: 5})
			// Network is called twice (TCP/UDP). Only block the first call.
			outbound.release = release
			go func() { g.performUpdateCheckEpoch(epoch); close(finished) }()
			awaitEpochSignal(t, entered)
			if closeOwner {
				g.Close()
			} else {
				history.AdvanceNetworkEpoch()
			}
			close(release)
			awaitEpochSignal(t, finished)
			if g.selection.Load() != nil {
				t.Fatal("stale selection published")
			}
		})
	}
}

func TestStoredResultInvalidatedBeforeBatchReturn(t *testing.T) {
	g, history, _ := epochTestGroup(t)
	g.outbounds = append(g.outbounds, &epochTestOutbound{tag: "held"})
	held, release := make(chan struct{}), make(chan struct{})
	hook := observable.NewSubscriber[struct{}](4)
	defer hook.Close()
	history.AddUpdateHook(hook)
	updates, _ := hook.Subscription()
	g.probe = func(_ context.Context, _ string, d N.Dialer) (uint16, error) {
		if d.(adapter.Outbound).Tag() == "held" {
			close(held)
			<-release
		}
		return 8, nil
	}
	g.access.Lock()
	g.started = true
	g.access.Unlock()
	result := make(chan groupCheckResult, 1)
	go func() { v, e := g.requestCheck(g.ctx, true, true); result <- groupCheckResult{v, e} }()
	awaitEpochSignal(t, held)
	select {
	case <-updates:
	case <-time.After(2 * time.Second):
		t.Fatal("first store not reached")
	}
	if history.LoadURLTestHistory("node") == nil {
		t.Fatal("store barrier missing")
	}
	history.AdvanceNetworkEpoch()
	close(release)
	select {
	case r := <-result:
		if len(r.values) != 0 {
			t.Fatal("old epoch API result")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("result did not return")
	}
}

func TestManualWaitCancellationDoesNotReleaseActualProbe(t *testing.T) {
	g, _, _ := epochTestGroup(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	g.probe = func(context.Context, string, N.Dialer) (uint16, error) {
		calls.Add(1)
		close(entered)
		<-release
		return 2, nil
	}
	g.access.Lock()
	g.started = true
	g.access.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	waiter := make(chan struct{})
	go func() { g.requestCheck(ctx, true, true); close(waiter) }()
	awaitEpochSignal(t, entered)
	cancel()
	awaitEpochSignal(t, waiter)
	overlap := make(chan groupCheckResult, 1)
	go func() { values, err := g.requestCheck(g.ctx, true, true); overlap <- groupCheckResult{values, err} }()
	select {
	case result := <-overlap:
		if result.err != nil || len(result.values) != 0 {
			t.Fatal("busy request did not return empty")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("overlap admitted work while actual probe lives")
	}
	if calls.Load() != 1 {
		t.Fatal("raw lease released with waiter")
	}
	g.Close()
	select {
	case <-g.Done():
		t.Fatal("premature completion")
	default:
	}
	close(release)
	awaitEpochSignal(t, g.Done())
}

func TestPauseCallbackAndCloseDoNotHoldGroupLockAcrossUnregister(t *testing.T) {
	g, _, pm := epochTestGroup(t)
	inside, release, pauseDone, closeDone, sealed := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	blocker := pm.RegisterCallback(func(event int) {
		if event == pause.EventDevicePaused {
			close(inside)
			<-release
		}
	})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		pm.UnregisterCallback(blocker)
	}()
	originalCancel := g.cancel
	g.cancel = func() { close(sealed); originalCancel() }
	go func() { pm.DevicePause(); close(pauseDone) }()
	awaitEpochSignal(t, inside)
	go func() { g.Close(); close(closeDone) }()
	awaitEpochSignal(t, sealed)
	// Close has sealed group admission, and is now permitted to wait only on
	// pause's registry mutex. It must not retain group access while doing so.
	acquired := make(chan struct{})
	go func() { g.access.Lock(); close(acquired); g.access.Unlock() }()
	awaitEpochSignal(t, acquired)
	close(release)
	awaitEpochSignal(t, pauseDone)
	awaitEpochSignal(t, closeDone)
	awaitEpochSignal(t, g.Done())
}

type epochOutboundManager struct {
	adapter.OutboundManager
	outbound adapter.Outbound
}

func (m *epochOutboundManager) Outbound(string) (adapter.Outbound, bool) { return m.outbound, true }

func TestStartScopeFailureClosesGroupBeforeStartedStage(t *testing.T) {
	history := urltest.NewHistoryStorage()
	defer history.Close()
	ctx := pause.WithDefaultManager(context.Background())
	ctx = service.ContextWithPtr(ctx, history)
	logger := log.NewNOPFactory().Logger()
	manager := &epochOutboundManager{outbound: &epochTestOutbound{tag: "node"}}
	outbound := &URLTest{ctx: ctx, outbound: manager, logger: logger, tags: []string{"node"}}
	scope := adapter.NewScope(ctx, logger)
	if err := outbound.Start(adapter.StartStateStart, scope); err != nil {
		t.Fatal(err)
	}
	// Simulate a different component failing before StartStateStarted.
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	awaitEpochSignal(t, outbound.group.Done())
	pm := service.FromContext[pause.Manager](ctx)
	pm.DevicePause()
	pm.DeviceWake()
	outbound.group.PostStart()
	if outbound.group.started {
		t.Fatal("late stage resurrected failed-start group")
	}
}
