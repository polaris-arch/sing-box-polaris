package boxruntime

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type runtimeHistoryTestEndpoint struct {
	endpoint.Adapter
	N.Dialer
	id adapter.RuntimeResourceID
}

func (*runtimeHistoryTestEndpoint) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (*runtimeHistoryTestEndpoint) PrepareRuntime(adapter.StartStage, *adapter.Scope) error {
	return nil
}
func (*runtimeHistoryTestEndpoint) RuntimeValidate() error { return nil }
func (e *runtimeHistoryTestEndpoint) RuntimeResourceID() adapter.RuntimeResourceID {
	return e.id
}

func TestRuntimeEndpointHistoryFollowsActualOwner(t *testing.T) {
	const tag = "vpn"
	config := func(mtu uint32) []byte {
		return fmt.Appendf(nil, `{
			"log":{"disabled":true},
			"dns":{"servers":[{"type":"udp","tag":"resolver","server":"192.0.2.53"}],"final":"resolver"},
			"endpoints":[{"type":"wireguard","tag":"vpn","mtu":%d}],
			"outbounds":[{"type":"direct","tag":"direct"},{"type":"selector","tag":"select","outbounds":["direct","vpn"],"default":"direct"}],
			"route":{"final":"select"}
		}`, mtu)
	}
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "example.org"), nil)
	var rejected *urltest.HistoryStorage
	registry := service.FromContext[adapter.EndpointRegistry](f.ctx).(*endpoint.Registry)
	endpoint.Register[option.WireGuardEndpointOptions](registry, C.TypeWireGuard, func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options option.WireGuardEndpointOptions) (adapter.Endpoint, error) {
		if options.MTU == 1300 {
			rejected = service.PtrFromContext[urltest.HistoryStorage](ctx)
			return nil, errors.New("injected endpoint constructor failure")
		}
		source, _ := adapter.RuntimeResourceSourceFromContext(ctx)
		return &runtimeHistoryTestEndpoint{Adapter: endpoint.NewAdapter(C.TypeWireGuard, tag, []string{N.NetworkTCP}, nil), id: source.ID()}, nil
	})
	options.Options = option.Options{}
	if err := json.UnmarshalContext(f.ctx, config(1400), &options.Options); err != nil {
		t.Fatal(err)
	}
	var err error
	f.box, err = New(options)
	if err != nil {
		t.Fatal(err)
	}
	clientShapeFinish(t, f)
	f.start(t)
	_, oldView := f.acquire(t)
	ownerID := oldView.componentIDs["endpoint:"+tag]
	member, _ := oldView.EndpointManager().Get(tag)
	probe, connected, err := f.box.AcquireRuntimeURLTest(context.Background(), tag)
	if !connected || err != nil {
		t.Fatalf("endpoint probe admission failed: connected=%t, err=%v", connected, err)
	}
	defer probe.Release()
	history, id, ok := oldView.RuntimeURLTestHistory(tag)
	resource, retained := adapter.RuntimeResourceLeaseFromContext(probe.Context(), ownerID)
	if !ok || id != ownerID || !retained || resource.ID() != ownerID || probe.Outbound() != member || probe.History() != history {
		t.Fatal("endpoint probe did not retain the published endpoint owner and its history")
	}
	root := service.PtrFromContext[urltest.HistoryStorage](f.box.runtime.ctx)
	group, _, _ := oldView.RuntimeURLTestHistory("select")
	if history == root || !urltest.PublishRuntimeResult(probe.Context(), probe.Epoch(), tag, &adapter.URLTestHistory{Delay: 10}) {
		t.Fatal("endpoint owner could not publish an isolated probe result")
	}
	if got := group.LoadURLTestHistory(tag); got == nil || got.Delay != 10 {
		t.Fatal("endpoint result did not reach its declared group")
	}
	before := f.identity()
	_, request := f.plan(t, config(1300))
	operation, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil {
		t.Fatal(err)
	}
	runtimeTestRequireCleanSourceAbort(t, f, operation, before)
	if got := root.LoadURLTestHistory(tag); rejected == nil || rejected == root || rejected == history || rejected.Epoch() != nil || !probe.IsCurrent() || got == nil || got.Delay != 10 {
		t.Fatal("failed endpoint replacement did not close its private history or displaced the current result")
	}
	_, request = f.plan(t, config(1280))
	operation, err = f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || operation.Active.Revision != before.Revision+1 {
		t.Fatalf("endpoint replacement failed: %+v %v", operation, err)
	}
	_, newView := f.acquire(t)
	replacement, replacementID, ok := newView.RuntimeURLTestHistory(tag)
	if !ok || replacement == history || replacementID == ownerID || probe.IsCurrent() {
		t.Fatal("same-tag replacement did not create a new owner and history")
	}
	if !urltest.PublishRuntimeResult(probe.Context(), probe.Epoch(), tag, &adapter.URLTestHistory{Delay: 99}) || root.LoadURLTestHistory(tag) != nil {
		t.Fatal("late endpoint result lost its private graph or reached the replacement")
	}
}

func TestRuntimeURLTestTrustsComponentCertificateStore(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"log":{"disabled":true},"dns":{"servers":[{"type":"udp","tag":"resolver","server":"192.0.2.53"}],"final":"resolver"},"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`)
	for _, configured := range []bool{false, true} {
		content := config
		if configured {
			content = r3SourceRootConfig(t, config, path)
		}
		f := newRuntimeTestFixture(t, content, nil)
		f.start(t)
		probe, connected, err := f.box.AcquireRuntimeURLTest(runtimeTestContext(t), "direct")
		if !connected || err != nil {
			t.Fatalf("probe admission failed: connected=%t, err=%v", connected, err)
		}
		_, err = urltest.URLTest(probe.Context(), server.URL, probe.Outbound())
		probe.Release()
		if (err == nil) != configured {
			t.Fatalf("configured=%t: runtime probe trust diverged from the component store: %v", configured, err)
		}
	}
}

func TestRuntimeBoxHistoryFollowsActualPublicationAndBorrowedIncarnation(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	root := service.PtrFromContext[urltest.HistoryStorage](f.box.runtime.ctx)
	if root == nil {
		t.Fatal("stable root history missing")
	}
	if probe, connected, err := f.box.AcquireRuntimeURLTest(context.Background(), "a"); !connected || err == nil {
		if probe != nil {
			probe.Release()
		}
		t.Fatal("initial unpublished graph admitted a history writer")
	}
	if root.LoadURLTestHistory("a") != nil {
		t.Fatal("candidate history was visible before startup")
	}
	f.start(t)
	oldLease, oldView := f.acquire(t)
	oldA, oldID, ok := oldView.RuntimeURLTestHistory("a")
	if !ok {
		t.Fatal("actual plain outbound lacks incarnation history")
	}
	oldB, oldBID, ok := oldView.RuntimeURLTestHistory("b")
	if !ok {
		t.Fatal("unchanged plain outbound lacks history")
	}
	oldSelect, _, ok := oldView.RuntimeURLTestHistory("select")
	if !ok {
		t.Fatal("selector private history missing")
	}
	oldProbe, connected, err := f.box.AcquireRuntimeURLTest(context.Background(), "a")
	if !connected || err != nil {
		t.Fatal(err)
	}
	defer oldProbe.Release()
	if oldProbe.Outbound() != f.object(t, "a", 0) || oldProbe.History() != oldA {
		t.Fatal("manual admission returned tag facade or unrelated history")
	}
	if !urltest.PublishRuntimeResult(oldProbe.Context(), oldProbe.Epoch(), "a", &adapter.URLTestHistory{Time: time.Unix(1, 0), Delay: 10}) {
		t.Fatal("admitted actual writer failed")
	}
	if oldA.LoadURLTestHistory("a") == nil || oldSelect.LoadURLTestHistory("a") == nil || oldB.LoadURLTestHistory("a") != nil {
		t.Fatal("history fanout did not follow captured group consumers")
	}
	consumers := oldView.RuntimeURLTestConsumers("a")
	consumers[0] = nil
	if oldView.RuntimeURLTestConsumers("a")[0] == nil {
		t.Fatal("history consumer slice aliases immutable graph")
	}
	if got := root.LoadURLTestHistory("a"); got == nil || got.Delay != 10 {
		t.Fatal("root projection missed current actual value")
	}
	_, request := f.plan(t, runtimeTestConfig(1081, "example.org"))
	operation, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || operation.Active.Revision != 2 {
		t.Fatalf("actual Apply failed: %+v %v", operation, err)
	}
	newLease, newView := f.acquire(t)
	newA, newID, _ := newView.RuntimeURLTestHistory("a")
	newB, newBID, _ := newView.RuntimeURLTestHistory("b")
	if newID == oldID || newA == oldA {
		t.Fatal("changed same-tag resource aliased old history")
	}
	if newBID != oldBID || newB != oldB {
		t.Fatal("borrowed unchanged resource did not retain history identity")
	}
	if root.LoadURLTestHistory("a") != nil {
		t.Fatal("replacement inherited old-tag result")
	}
	newA.StoreIfCurrent(newA.Epoch(), "a", &adapter.URLTestHistory{Time: time.Unix(2, 0), Delay: 20})
	oldResource := runtimeTestResource(t, f, oldID)
	runtimeTestWait(t, oldResource.owner.Retiring(), "old history receiver seal")
	oldLease.Release()
	if !urltest.PublishRuntimeResult(oldProbe.Context(), oldProbe.Epoch(), "a", &adapter.URLTestHistory{Time: time.Unix(3, 0), Delay: 99}) {
		t.Fatal("live retired invocation could not complete privately")
	}
	if got := root.LoadURLTestHistory("a"); got == nil || got.Delay != 20 {
		t.Fatal("late old probe poisoned new same-tag visible history")
	}
	if oldProbe.IsCurrent() {
		t.Fatal("manual current check accepted same tag with different owner")
	}
	select {
	case <-oldResource.owner.Closed():
		t.Fatal("manual probe did not retain its graph closure")
	default:
	}
	oldProbe.Release()
	if err := oldResource.owner.WaitClosed(runtimeTestContext(t)); err != nil {
		t.Fatal(err)
	}
	newLease.Release()
}

func TestRuntimeHistoryFailedPrepareKeepsPublishedAuthority(t *testing.T) {
	for _, blockedCleanup := range []bool{false, true} {
		t.Run(map[bool]string{false: "immediate-cleanup", true: "blocked-cleanup"}[blockedCleanup], func(t *testing.T) {
			f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
			f.start(t)
			root := service.PtrFromContext[urltest.HistoryStorage](f.box.runtime.ctx)
			probe, connected, err := f.box.AcquireRuntimeURLTest(context.Background(), "a")
			if !connected || err != nil {
				t.Fatal(err)
			}
			defer probe.Release()
			urltest.PublishRuntimeResult(probe.Context(), probe.Epoch(), "a", &adapter.URLTestHistory{Time: time.Unix(1, 0), Delay: 10})
			before := f.identity()
			cleanup := newRuntimeTestBarrier()
			t.Cleanup(cleanup.open)
			var candidate *urltest.HistoryStorage
			f.setConstructorHook(func(outbound *runtimeTestSocks) error {
				if outbound.Tag() != "a" {
					return nil
				}
				if blockedCleanup {
					outbound.closeHook = func() error { cleanup.block(); return nil }
				}
				candidate = service.PtrFromContext[urltest.HistoryStorage](outbound.ctx)
				if candidate == nil || candidate == root || candidate == probe.History() {
					return errors.New("candidate has no private history")
				}
				candidate.StoreIfCurrent(candidate.Epoch(), "a", &adapter.URLTestHistory{Time: time.Unix(2, 0), Delay: 99})
				if got := root.LoadURLTestHistory("a"); got == nil || got.Delay != 10 {
					t.Error("unpublished candidate changed visible history")
				}
				return errors.New("injected actual constructor failure")
			})
			_, request := f.plan(t, runtimeTestConfig(1081, "example.org"))
			operation, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
			if err != nil {
				t.Fatalf("unexpected prepare result: %+v %v", operation, err)
			}
			if operation.Before != before || operation.Active != before {
				t.Fatalf("abort changed authority: %+v", operation)
			}
			if blockedCleanup {
				runtimeTestWait(t, cleanup.entered, "actual candidate history cleanup")
				if operation.State != "ABORTING_UNAPPLIED" {
					t.Fatalf("blocked candidate already reported terminal: %+v", operation)
				}
			}
			if candidate == nil || f.identity() != before || !probe.IsCurrent() {
				t.Fatal("failed candidate displaced current history authority")
			}
			if got := root.LoadURLTestHistory("a"); got == nil || got.Delay != 10 {
				t.Fatal("abort erased old current history")
			}
			cleanup.open()
			runtimeTestRequireCleanSourceAbort(t, f, operation, before)
			if current := root.LoadURLTestHistory("a"); !probe.IsCurrent() || current == nil || current.Delay != 10 {
				t.Fatal("terminal abort changed history authority")
			}
			f.setConstructorHook(nil)
			_, retry := f.plan(t, runtimeTestConfig(1082, "example.org"))
			committed, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", retry)
			if err != nil || committed.Before != before || committed.Active.Revision != before.Revision+1 || f.identity() != committed.Active {
				t.Fatalf("retry did not publish a new history authority: %+v %v", committed, err)
			}
			if private := probe.History().LoadURLTestHistory("a"); probe.IsCurrent() || root.LoadURLTestHistory("a") != nil || private == nil || private.Delay != 10 {
				t.Fatal("retry aliased old private history with the replacement")
			}
		})
	}
}
