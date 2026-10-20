package group

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

type runtimeGroupManager struct { adapter.OutboundManager; values []adapter.Outbound }
func (m *runtimeGroupManager) Outbounds() []adapter.Outbound { return append([]adapter.Outbound(nil), m.values...) }
func (m *runtimeGroupManager) Outbound(tag string) (adapter.Outbound, bool) { for _, value := range m.values { if value.Tag() == tag { return value, true } }; return nil, false }
type runtimeGroupView struct {
	adapter.RuntimeView
	manager *runtimeGroupManager
	id adapter.RuntimeResourceID
	history *urltest.HistoryStorage
}
func (v *runtimeGroupView) Identity() adapter.RuntimeRevision { return adapter.RuntimeRevision{Incarnation: v.id.Incarnation, Revision: 1} }
func (v *runtimeGroupView) OutboundManager() adapter.OutboundManager { return v.manager }
func (v *runtimeGroupView) RuntimeURLTestHistory(tag string) (*urltest.HistoryStorage, adapter.RuntimeResourceID, bool) { return v.history, v.id, tag == "group" }
func (v *runtimeGroupView) RuntimeURLTestConsumers(tag string) []*urltest.HistoryStorage { if tag == "node" { return []*urltest.HistoryStorage{v.history} }; return nil }

// The native group and graph/resource owners are real. Only the raw probe is a
// barrier: it deliberately ignores cancellation, as a blocked foreign dial may.
func TestRuntimeManualGroupRetainsAfterWaiterAndFacadeReturn(t *testing.T) {
	for _, facade := range []bool{false, true} {
		t.Run(map[bool]string{false: "waiter", true: "facade"}[facade], func(t *testing.T) {
			root := urltest.NewHistoryStorage(); defer root.Close()
			history := urltest.NewIncarnationHistory(root)
			ctx := pause.WithDefaultManager(context.Background())
			ctx = service.ContextWithPtr(ctx, history)
			var group *URLTestGroup
			cleanupEntered := make(chan struct{})
			id := adapter.RuntimeResourceID{Incarnation: "group-test", Sequence: 1}
			owner, err := runtimegraph.NewResourceOwner(ctx, id, nil, func() error { close(cleanupEntered); group.Close(); <-group.Done(); return history.Close() })
			if err != nil { t.Fatal(err) }
			ctx = adapter.ContextWithRuntimeResourceSource(ctx, owner)
			reservation, err := owner.Acquire(); if err != nil { t.Fatal(err) }
			manager := &runtimeGroupManager{}
			group, err = NewURLTestGroup(ctx, manager, log.NewNOPFactory().Logger(), []adapter.Outbound{&epochTestOutbound{tag: "node"}}, "", time.Hour, 1, 2*time.Hour, false)
			if err != nil { t.Fatal(err) }
			actual := &URLTest{Adapter: outbound.NewAdapter(C.TypeURLTest, "group", []string{N.NetworkTCP}, []string{"node"}), group: group, tags: []string{"node"}}
			manager.values = []adapter.Outbound{actual}
			view := &runtimeGroupView{manager: manager, id: id, history: history}
			graph, err := runtimegraph.NewGraph(view, []adapter.RuntimeResourceLease{reservation}); if err != nil { t.Fatal(err) }
			store, err := runtimegraph.NewStore(id.Incarnation); if err != nil { t.Fatal(err) }
			if _, err := store.Publish(adapter.RuntimeRevision{Incarnation: id.Incarnation}, graph); err != nil { t.Fatal(err) }
			reservation.Release()
			entered, release := make(chan struct{}), make(chan struct{})
			t.Cleanup(func() { select { case <-release: default: close(release) }; group.Close(); store.Seal(); owner.Seal(); reservation.Release() })
			group.probe = func(ctx context.Context, _ string, _ N.Dialer) (uint16, error) {
				if _, ok := adapter.RuntimeResourceLeaseFromContext(ctx, id); !ok { t.Error("native worker lost receiving resource continuation") }
				if _, ok := adapter.RuntimeLeaseFromContext(ctx); !ok { t.Error("native worker lost admitted graph") }
				close(entered); <-release; return 17, nil
			}
			// Isolate the manual path from the separate PostStart producer test.
			group.access.Lock(); group.started = true; group.access.Unlock()
			caller, cancel := context.WithCancel(ctx); defer cancel()
			probe, err := urltest.AcquireRuntimeProbe(caller, store, "group"); if err != nil { t.Fatal(err) }; defer probe.Release()
			waiter := make(chan struct{})
			go func() { if facade { actual.CheckOutboundsContext(probe.Context()) } else { _, _ = actual.URLTest(probe.Context()) }; close(waiter) }()
			awaitEpochSignal(t, entered); cancel(); awaitEpochSignal(t, waiter)
			probe.Release(); store.Seal(); owner.Seal()
			select { case <-cleanupEntered: t.Fatal("outer return released an actual raw worker"); default: }
			close(release); awaitEpochSignal(t, owner.Closed())
			if history.LoadURLTestHistory("node") != nil { t.Fatal("canceled worker published history") }
		})
	}
}

func TestRuntimeInternalProducerDoesNotSelfPinCleanup(t *testing.T) {
	group, history, _ := epochTestGroup(t)
	id := adapter.RuntimeResourceID{Incarnation: "internal-producer", Sequence: 1}
	closing := make(chan struct{})
	owner, err := runtimegraph.NewResourceOwner(group.ctx, id, nil, func() error { close(closing); group.Close(); <-group.Done(); return nil })
	if err != nil { t.Fatal(err) }
	group.ctx = adapter.ContextWithRuntimeResourceSource(group.ctx, owner)
	reservation, err := owner.Acquire(); if err != nil { t.Fatal(err) }
	entered, release := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { select { case <-release: default: close(release) }; reservation.Release(); owner.Seal() })
	group.probe = func(context.Context, string, N.Dialer) (uint16, error) { close(entered); <-release; return 9, nil }
	group.PostStart(); awaitEpochSignal(t, entered)
	owner.Seal(); reservation.Release(); awaitEpochSignal(t, closing)
	select { case <-owner.Closed(): t.Fatal("cleanup did not join raw producer"); default: }
	close(release); awaitEpochSignal(t, owner.Closed())
	if history.LoadURLTestHistory("node") != nil { t.Fatal("closed internal producer published") }
}

func TestNestedPrivateHistoryFeedsOnlyNativeSelectionOwner(t *testing.T) {
	root := urltest.NewHistoryStorage(); defer root.Close()
	childHistory, parentHistory := urltest.NewIncarnationHistory(root), urltest.NewIncarnationHistory(root)
	defer childHistory.Close(); defer parentHistory.Close()
	ctx := pause.WithDefaultManager(context.Background())
	manager := &runtimeGroupManager{}
	fast, slow := &epochTestOutbound{tag: "fast"}, &epochTestOutbound{tag: "slow"}
	child, err := NewURLTestGroup(service.ContextWithPtr(ctx, childHistory), manager, log.NewNOPFactory().Logger(), []adapter.Outbound{fast}, "", time.Hour, 1, 2*time.Hour, false)
	if err != nil { t.Fatal(err) }
	childOutbound := &URLTest{Adapter: outbound.NewAdapter(C.TypeURLTest, "child", []string{N.NetworkTCP, N.NetworkUDP}, []string{"fast"}), group: child, tags: []string{"fast"}}
	parent, err := NewURLTestGroup(service.ContextWithPtr(ctx, parentHistory), manager, log.NewNOPFactory().Logger(), []adapter.Outbound{childOutbound, slow}, "", time.Hour, 1, 2*time.Hour, false)
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { parent.Close(); child.Close(); awaitEpochSignal(t, parent.Done()); awaitEpochSignal(t, child.Done()) })
	manager.values = []adapter.Outbound{fast, slow, childOutbound}
	child.probe = func(context.Context, string, N.Dialer) (uint16, error) { return 5, nil }
	parent.probe = func(context.Context, string, N.Dialer) (uint16, error) { return 40, nil }
	child.access.Lock(); child.started = true; child.access.Unlock()
	parent.access.Lock(); parent.started = true; parent.access.Unlock()
	values, err := parent.URLTest(ctx); if err != nil { t.Fatal(err) }
	if values["fast"] != 5 || values["slow"] != 40 { t.Fatal("nested private-history batch lost completed results") }
	if childHistory.LoadURLTestHistory("slow") != nil { t.Fatal("unrelated parent history crossed child boundary") }
	if history := parentHistory.LoadURLTestHistory("fast"); history == nil || history.Delay != 5 { t.Fatal("parent selection cannot see completed captured child result") }
	if child.selected().tcp != fast || parent.selected().tcp != childOutbound { t.Fatal("native nested selection owner did not publish expected result") }
	if root.LoadURLTestHistory("fast") != nil { t.Fatal("private native workers wrote root tag storage") }
}
