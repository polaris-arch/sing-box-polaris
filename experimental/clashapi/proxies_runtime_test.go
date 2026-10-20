package clashapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	M "github.com/sagernet/sing/common/metadata"
)

type runtimeProxyOutbound struct { adapter.Outbound; dial func(context.Context) (net.Conn, error) }
func (*runtimeProxyOutbound) Tag() string { return "node" }
func (o *runtimeProxyOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) { return o.dial(ctx) }
type runtimeProxyManager struct { adapter.OutboundManager; actual adapter.Outbound }
func (m *runtimeProxyManager) Outbounds() []adapter.Outbound { return []adapter.Outbound{m.actual} }
func (m *runtimeProxyManager) Outbound(tag string) (adapter.Outbound, bool) { return m.actual, tag == "node" }
type runtimeProxyView struct { adapter.RuntimeView; manager *runtimeProxyManager; history *urltest.HistoryStorage; id adapter.RuntimeResourceID; revision uint64 }
func (v *runtimeProxyView) Identity() adapter.RuntimeRevision { return adapter.RuntimeRevision{Incarnation: v.id.Incarnation, Revision: v.revision} }
func (v *runtimeProxyView) OutboundManager() adapter.OutboundManager { return v.manager }
func (v *runtimeProxyView) RuntimeURLTestHistory(tag string) (*urltest.HistoryStorage, adapter.RuntimeResourceID, bool) { return v.history, v.id, tag == "node" }
func (v *runtimeProxyView) RuntimeURLTestConsumers(tag string) []*urltest.HistoryStorage { if tag == "node" { return []*urltest.HistoryStorage{v.history} }; return nil }
func runtimeProxyWait(t *testing.T, done <-chan struct{}) { t.Helper(); select { case <-done: case <-time.After(3*time.Second): t.Fatal("missing proxy lifetime barrier") } }
func runtimeProxyGraph(t *testing.T, root *urltest.HistoryStorage, store *runtimegraph.Store, revision uint64, actual adapter.Outbound) (*runtimeProxyView, *runtimegraph.ResourceOwner) {
	t.Helper()
	history := urltest.NewIncarnationHistory(root)
	id := adapter.RuntimeResourceID{Incarnation: "proxy-history", Sequence: revision}
	owner, err := runtimegraph.NewResourceOwner(context.Background(), id, nil, history.Close); if err != nil { t.Fatal(err) }
	reservation, err := owner.Acquire(); if err != nil { t.Fatal(err) }
	view := &runtimeProxyView{manager: &runtimeProxyManager{actual: actual}, history: history, id: id, revision: revision}
	graph, err := runtimegraph.NewGraph(view, []adapter.RuntimeResourceLease{reservation}); if err != nil { t.Fatal(err) }
	if _, err := store.Publish(adapter.RuntimeRevision{Incarnation: id.Incarnation, Revision: revision-1}, graph); err != nil { t.Fatal(err) }
	reservation.Release()
	root.SetRuntimeActiveHistories([]*urltest.HistoryStorage{history})
	t.Cleanup(func() { owner.Seal(); reservation.Release() })
	return view, owner
}

func TestRuntimeProxyDelayPinsActualDialUntilItReturns(t *testing.T) {
	for _, cancelRequest := range []bool{false, true} {
		t.Run(map[bool]string{false: "retired-result", true: "canceled-request"}[cancelRequest], func(t *testing.T) {
			root := urltest.NewHistoryStorage(); defer root.Close()
			store, err := runtimegraph.NewStore("proxy-history"); if err != nil { t.Fatal(err) }; defer store.Seal()
			root.BindRuntimeAdmission(store)
			entered, release := make(chan struct{}), make(chan struct{})
			t.Cleanup(func() { select { case <-release: default: close(release) } })
			old, owner := runtimeProxyGraph(t, root, store, 1, &runtimeProxyOutbound{dial: func(ctx context.Context) (net.Conn, error) {
				if _, ok := adapter.RuntimeLeaseFromContext(ctx); !ok { t.Error("raw probe has no admitted graph") }
				if _, ok := adapter.RuntimeResourceLeaseFromContext(ctx, adapter.RuntimeResourceID{Incarnation: "proxy-history", Sequence: 1}); !ok { t.Error("raw probe has no receiving resource") }
				close(entered); <-release; return nil, errors.New("late injected dial failure")
			}})
			old.history.StoreIfCurrent(old.history.Epoch(), "node", &adapter.URLTestHistory{Delay: 10})
			server := &Server{ctx: urltest.ContextWithRuntimeAdmission(context.Background(), store), outbound: old.manager, urlTestHistory: root}
			// The request carries only a tag facade. Dialing this stale placeholder
			// would panic; the handler must resolve its actual admitted target.
			requestContext, cancel := context.WithCancel(context.WithValue(context.Background(), CtxKeyProxy, &runtimeProxyOutbound{})); defer cancel()
			request := httptest.NewRequest(http.MethodGet, "/delay?timeout=30000", nil).WithContext(requestContext)
			recorder, finished := httptest.NewRecorder(), make(chan struct{})
			go func() { getProxyDelay(server)(recorder, request); close(finished) }()
			runtimeProxyWait(t, entered)
			next, _ := runtimeProxyGraph(t, root, store, 2, &runtimeProxyOutbound{})
			next.history.StoreIfCurrent(next.history.Epoch(), "node", &adapter.URLTestHistory{Time: time.Unix(2,0), Delay: 20})
			owner.Seal()
			if cancelRequest { cancel() }
			select { case <-owner.Closed(): t.Fatal("retired actual dial lost its lease"); default: }
			select { case <-finished: t.Fatal("outer HTTP handler completed before uncooperative raw dial"); default: }
			close(release); runtimeProxyWait(t, finished); runtimeProxyWait(t, owner.Closed())
			if got := root.LoadURLTestHistory("node"); got == nil || got.Delay != 20 { t.Fatal("old manual error deleted new same-tag history") }
			want := http.StatusServiceUnavailable; if cancelRequest { want = http.StatusGatewayTimeout }
			if recorder.Code != want { t.Fatalf("status %d, want %d", recorder.Code, want) }
		})
	}
}

func TestRuntimeProxyDelayRejectsBeforeFirstPublication(t *testing.T) {
	root := urltest.NewHistoryStorage(); defer root.Close()
	store, err := runtimegraph.NewStore("proxy-history"); if err != nil { t.Fatal(err) }; defer store.Seal()
	server := &Server{ctx: urltest.ContextWithRuntimeAdmission(context.Background(), store), urlTestHistory: root}
	request := httptest.NewRequest(http.MethodGet, "/delay?timeout=30000", nil)
	request = request.WithContext(context.WithValue(request.Context(), CtxKeyProxy, &runtimeProxyOutbound{}))
	recorder := httptest.NewRecorder(); getProxyDelay(server)(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable { t.Fatal("unready graph entered manual dial") }
}
