package urltest

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

type runtimeHistoryOutbound struct {
	adapter.Outbound
	tag string
}

func (o *runtimeHistoryOutbound) Tag() string { return o.tag }

type runtimeHistoryManager struct {
	adapter.OutboundManager
	outbound adapter.Outbound
}

func (m *runtimeHistoryManager) Outbounds() []adapter.Outbound { return []adapter.Outbound{m.outbound} }

func (m *runtimeHistoryManager) Outbound(tag string) (adapter.Outbound, bool) {
	return m.outbound, tag == m.outbound.Tag()
}

type runtimeHistoryView struct {
	adapter.RuntimeView
	identity adapter.RuntimeRevision
	id       adapter.RuntimeResourceID
	history  *HistoryStorage
	manager  *runtimeHistoryManager
}

func (v *runtimeHistoryView) Identity() adapter.RuntimeRevision        { return v.identity }
func (v *runtimeHistoryView) OutboundManager() adapter.OutboundManager { return v.manager }
func (v *runtimeHistoryView) RuntimeURLTestHistory(tag string) (*HistoryStorage, adapter.RuntimeResourceID, bool) {
	return v.history, v.id, tag == "node"
}

func (v *runtimeHistoryView) RuntimeURLTestConsumers(tag string) []*HistoryStorage {
	if tag != "node" {
		return nil
	}
	return []*HistoryStorage{v.history}
}

func runtimeHistoryGraph(t *testing.T, root *HistoryStorage, revision uint64) (*runtimeHistoryView, *runtimegraph.ResourceOwner, *runtimegraph.Graph, adapter.RuntimeResourceLease) {
	t.Helper()
	history := NewIncarnationHistory(root)
	id := adapter.RuntimeResourceID{Incarnation: "history-test", Sequence: revision}
	owner, err := runtimegraph.NewResourceOwner(context.Background(), id, nil, history.Close)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := owner.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	view := &runtimeHistoryView{identity: adapter.RuntimeRevision{Incarnation: id.Incarnation, Revision: revision}, id: id, history: history, manager: &runtimeHistoryManager{outbound: &runtimeHistoryOutbound{tag: "node"}}}
	graph, err := runtimegraph.NewGraph(view, []adapter.RuntimeResourceLease{reservation})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reservation.Release(); owner.Seal() })
	return view, owner, graph, reservation
}

func runtimeHistoryWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("missing history ownership barrier")
	}
}

func runtimeHistoryPublish(t *testing.T, store *runtimegraph.Store, graph *runtimegraph.Graph) {
	t.Helper()
	expected := graph.Identity()
	expected.Revision--
	if _, err := store.Publish(expected, graph); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeHistoryVisibleReadsUsePublishedGraphBeforeNotificationSwap(t *testing.T) {
	root := NewHistoryStorage()
	defer root.Close()
	store, err := runtimegraph.NewStore("history-test")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Seal()
	root.BindRuntimeAdmission(store)
	subscriber := observable.NewSubscriber[struct{}](8)
	defer subscriber.Close()
	root.AddUpdateHook(subscriber)
	updates, _ := subscriber.Subscription()
	old, oldOwner, first, firstReservation := runtimeHistoryGraph(t, root, 1)
	old.history.StoreIfCurrent(old.history.Epoch(), "node", &adapter.URLTestHistory{Time: time.Unix(1, 0), Delay: 11})
	if root.LoadURLTestHistory("node") != nil {
		t.Fatal("unpublished history visible")
	}
	select {
	case <-updates:
		t.Fatal("candidate emitted root notification")
	default:
	}
	runtimeHistoryPublish(t, store, first)
	firstReservation.Release()
	root.SetRuntimeActiveHistories([]*HistoryStorage{old.history})
	<-updates
	oldProbe, err := AcquireRuntimeProbe(context.Background(), store, "node")
	if err != nil {
		t.Fatal(err)
	}
	defer oldProbe.Release()
	if got := root.LoadURLTestHistory("node"); got == nil || got.Delay != 11 {
		t.Fatal("initial active history unavailable")
	}
	next, _, second, secondReservation := runtimeHistoryGraph(t, root, 2)
	next.history.StoreIfCurrent(next.history.Epoch(), "node", &adapter.URLTestHistory{Time: time.Unix(2, 0), Delay: 22})
	runtimeHistoryPublish(t, store, second)
	secondReservation.Release()
	oldOwner.Seal()
	// Deliberately leave notification membership on the old graph. Values must
	// already come from the one Store publication, not a second projection cell.
	if got := root.LoadURLTestHistory("node"); got == nil || got.Delay != 22 {
		t.Fatal("new graph read old projection")
	}
	if !PublishRuntimeResult(oldProbe.Context(), oldProbe.Epoch(), "node", &adapter.URLTestHistory{Time: time.Unix(3, 0), Delay: 99}) {
		t.Fatal("retained old invocation could not finish its private write")
	}
	if got := root.LoadURLTestHistory("node"); got == nil || got.Delay != 22 {
		t.Fatal("late old same-tag probe poisoned current values")
	}
	root.SetRuntimeActiveHistories([]*HistoryStorage{next.history})
	for {
		select {
		case <-updates:
			continue
		default:
			goto drained
		}
	}
drained:
	old.history.NotifyUpdated()
	old.history.StoreIfCurrent(oldProbe.Epoch(), "node", &adapter.URLTestHistory{Delay: 88})
	select {
	case <-updates:
		t.Fatal("retired view notified root after membership replacement")
	default:
	}
	next.history.NotifyUpdated()
	select {
	case <-updates:
	default:
		t.Fatal("active private view did not notify root")
	}
	if oldProbe.IsCurrent() {
		t.Fatal("same tag aliased a replacement resource")
	}
	select {
	case <-oldOwner.Closed():
		t.Fatal("manual invocation did not retain retired receiver")
	default:
	}
	oldProbe.Release()
	runtimeHistoryWait(t, oldOwner.Closed())
	if PublishRuntimeResult(oldProbe.Context(), oldProbe.Epoch(), "node", &adapter.URLTestHistory{Delay: 1}) {
		t.Fatal("released invocation resurrected history capability")
	}
}

func TestRuntimeHistoryProjectionCopiesAndRejectsRootWrites(t *testing.T) {
	root := NewHistoryStorage()
	defer root.Close()
	store, _ := runtimegraph.NewStore("history-test")
	defer store.Seal()
	root.BindRuntimeAdmission(store)
	view, _, graph, reservation := runtimeHistoryGraph(t, root, 1)
	runtimeHistoryPublish(t, store, graph)
	reservation.Release()
	value := &adapter.URLTestHistory{Time: time.Unix(1, 0), Delay: 12}
	view.history.StoreURLTestHistory("node", value)
	value.Delay = 90
	loaded := root.LoadURLTestHistory("node")
	if loaded == nil || loaded.Delay != 12 {
		t.Fatal("store value aliased caller")
	}
	loaded.Delay = 91
	snapshot, valid := root.Snapshot(root.Epoch())
	if !valid || snapshot["node"].Delay != 12 {
		t.Fatal("snapshot missing active view")
	}
	snapshot["node"].Delay = 92
	if root.LoadURLTestHistory("node").Delay != 12 {
		t.Fatal("read result aliases private state")
	}
	if root.StoreIfCurrent(root.Epoch(), "node", &adapter.URLTestHistory{Delay: 3}) || root.DeleteIfCurrent(root.Epoch(), "node") {
		t.Fatal("root writer bypassed incarnation projection")
	}
	root.StoreURLTestHistory("node", &adapter.URLTestHistory{Delay: 4})
	root.DeleteURLTestHistory("node")
	if root.LoadURLTestHistory("node").Delay != 12 || root.LoadURLTestHistory("absent") != nil {
		t.Fatal("root tag fallback polluted projection")
	}
}

func TestRuntimeProbePauseNetworkEpochAndHostCancellation(t *testing.T) {
	root := NewHistoryStorage()
	defer root.Close()
	store, _ := runtimegraph.NewStore("history-test")
	defer store.Seal()
	view, _, graph, reservation := runtimeHistoryGraph(t, root, 1)
	runtimeHistoryPublish(t, store, graph)
	reservation.Release()
	ctx := pause.WithDefaultManager(context.Background())
	manager := service.FromContext[pause.Manager](ctx)
	epoch := root.Epoch()
	manager.DevicePause()
	if probe, err := AcquireRuntimeProbe(ctx, store, "node"); err == nil {
		probe.Release()
		t.Fatal("paused device admitted manual probe")
	}
	manager.DeviceWake()
	probe, err := AcquireRuntimeProbe(ctx, store, "node")
	if err != nil {
		t.Fatal(err)
	}
	manager.DevicePause()
	runtimeHistoryWait(t, probe.Context().Done())
	if PublishRuntimeResult(probe.Context(), epoch, "node", &adapter.URLTestHistory{Delay: 1}) {
		t.Fatal("paused manual invocation published")
	}
	probe.Release()
	probe.Release()
	if root.Epoch() != epoch {
		t.Fatal("device pause advanced network epoch")
	}
	manager.DeviceWake()
	next := root.AdvanceNetworkEpoch()
	if probe, err := AcquireRuntimeProbe(ctx, store, "node"); err == nil {
		probe.Release()
		t.Fatal("unready network epoch admitted probe")
	}
	if !root.MarkReady(next) {
		t.Fatal("network epoch not ready")
	}
	probe, err = AcquireRuntimeProbe(ctx, store, "node")
	if err != nil {
		t.Fatal(err)
	}
	root.AdvanceNetworkEpoch()
	runtimeHistoryWait(t, probe.Context().Done())
	if view.history.StoreIfCurrent(next, "node", &adapter.URLTestHistory{Delay: 2}) {
		t.Fatal("old network result survived transition")
	}
	probe.Release()
	root.MarkReady(root.Epoch())
	boundRegistry := ContextWithRuntimeAdmission(ctx, store)
	manager.DevicePause()
	if probe, bound, err := AcquireRuntimeProbeFromContext(boundRegistry, context.Background(), "node"); !bound || err == nil {
		if probe != nil {
			probe.Release()
		}
		t.Fatal("caller without host values bypassed pause authority")
	}
	manager.DeviceWake()
	host, cancelHost := context.WithCancel(ContextWithRuntimeAdmission(ctx, store))
	caller, cancelCaller := context.WithCancel(ctx)
	probe, bound, err := AcquireRuntimeProbeFromContext(host, caller, "node")
	if !bound || err != nil {
		t.Fatal(err)
	}
	cancelCaller()
	runtimeHistoryWait(t, probe.Context().Done())
	probe.Release()
	probe, bound, err = AcquireRuntimeProbeFromContext(host, ctx, "node")
	if !bound || err != nil {
		t.Fatal(err)
	}
	cancelHost()
	runtimeHistoryWait(t, probe.Context().Done())
	probe.Release()
}

func TestRuntimeHistoryHookRemovalSerializesAndClosedSubscriberIsSafe(t *testing.T) {
	root := NewHistoryStorage()
	defer root.Close()
	private := NewIncarnationHistory(root)
	defer private.Close()
	root.SetRuntimeActiveHistories([]*HistoryStorage{private})
	hook := observable.NewSubscriber[struct{}](16)
	root.AddUpdateHook(hook)
	root.AddUpdateHook(hook)
	root.AddUpdateHook(nil)
	updates, _ := hook.Subscription()
	// A live Emit and removal use the same history mutex. Removal must wait
	// for this read-side operation before it may certify the hook detached.
	root.access.RLock()
	removed := make(chan struct{})
	go func() { root.RemoveUpdateHook(hook); close(removed) }()
	root.notifyLocalLocked()
	select {
	case <-removed:
		t.Fatal("hook removal crossed an in-flight history lock")
	default:
	}
	root.access.RUnlock()
	runtimeHistoryWait(t, removed)
	for {
		select {
		case <-updates:
			continue
		default:
			goto drainedHook
		}
	}
drainedHook:
	private.NotifyUpdated()
	root.NotifyUpdated()
	root.RemoveUpdateHook(hook)
	select {
	case <-updates:
		t.Fatal("removed duplicate hook still received events")
	default:
	}
	// Subscriber.Close closes only its done channel. A racing or already
	// closed subscriber cannot panic an active history writer.
	root.AddUpdateHook(hook)
	start, emitted := make(chan struct{}), make(chan struct{})
	go func() {
		<-start
		for range 32 {
			private.NotifyUpdated()
		}
		close(emitted)
	}()
	close(start)
	hook.Close()
	root.RemoveUpdateHook(hook)
	runtimeHistoryWait(t, emitted)
	private.NotifyUpdated()
}
