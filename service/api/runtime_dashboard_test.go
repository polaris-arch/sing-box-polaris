package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

func TestRuntimeDashboardPreparedWorkerNeedsPublicationAndPreviousJoin(t *testing.T) {
	ctx, _ := dashboardFileContext(t)
	entered := make(chan struct{})
	transport := &dashboardTestTransport{id: "next", events: &dashboardEventLog{}}
	transport.roundTrip = func(*http.Request) (*http.Response, error) {
		close(entered)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("invalid archive"))}, nil
	}
	provider := &dashboardTestProvider{current: transport}
	ctx = service.ContextWith[adapter.RuntimeDashboardHTTPProvider](ctx, provider)
	d := newDashboard(ctx, log.NewNOPFactory().Logger(), "0", option.APIDashboardOptions{Path: filepath.Join(t.TempDir(), "dashboard")})
	activation, previous := make(chan struct{}), make(chan struct{})
	if err := d.startAfter(ctx, activation, previous); err != nil {
		t.Fatal(err)
	}
	defer d.close()
	if _, acquired := provider.counts(); acquired != 0 {
		t.Fatal("preparation fetched")
	}
	close(activation)
	if _, acquired := provider.counts(); acquired != 0 {
		t.Fatal("publication bypassed old worker join")
	}
	close(previous)
	dashboardWait(t, entered, "next fetch after both gates")
	if err := d.close(); err != nil {
		t.Fatal(err)
	}
	if active, acquired := provider.counts(); active != 0 || acquired != 1 {
		t.Fatal("lease not joined", active, acquired)
	}
}

func TestRuntimeDashboardUnpublishedAbortAndCanceledPrepareNeverFetch(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "abort", true: "canceled"}[canceled], func(t *testing.T) {
			ctx, _ := dashboardFileContext(t)
			provider := &dashboardTestProvider{}
			ctx = service.ContextWith[adapter.RuntimeDashboardHTTPProvider](ctx, provider)
			d := newDashboard(ctx, log.NewNOPFactory().Logger(), "0", option.APIDashboardOptions{Path: filepath.Join(t.TempDir(), "dashboard")})
			call, cancel := context.WithCancel(ctx)
			if canceled {
				cancel()
			} else {
				defer cancel()
			}
			err := d.startAfter(call, make(chan struct{}), nil)
			if canceled && !errors.Is(err, context.Canceled) || !canceled && err != nil {
				t.Fatal(err)
			}
			if err := d.close(); err != nil {
				t.Fatal(err)
			}
			if active, acquired := provider.counts(); active != 0 || acquired != 0 {
				t.Fatal("unpublished HTTP effect", active, acquired)
			}
		})
	}
}

func TestRuntimeDashboardReferencesKeepWorkerUntilLastIngressRetires(t *testing.T) {
	ctx, _ := dashboardFileContext(t)
	events := &dashboardEventLog{}
	entered, canceled, resume := make(chan struct{}), make(chan struct{}), make(chan struct{})
	transport := &dashboardTestTransport{id: "shared", events: events}
	transport.roundTrip = func(request *http.Request) (*http.Response, error) {
		body := &dashboardCancellationBody{ctx: request.Context(), entered: entered, cancelled: canceled, resume: resume}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: &dashboardTestBody{Reader: body, close: func() error { events.add("body:shared"); return nil }}}, nil
	}
	provider := &dashboardTestProvider{current: transport}
	ctx = service.ContextWith[adapter.RuntimeDashboardHTTPProvider](ctx, provider)
	d := newDashboard(ctx, log.NewNOPFactory().Logger(), "0", option.APIDashboardOptions{Path: filepath.Join(t.TempDir(), "dashboard")})
	if err := d.start(ctx); err != nil {
		t.Fatal(err)
	}
	dashboardWait(t, entered, "retained worker body")
	resource := &runtimeDashboardResource{dashboard: d}
	resource.retain()
	resource.retain()
	if err := resource.release(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
		t.Fatal("old API generation canceled the current shared worker")
	default:
	}
	closed := make(chan struct{})
	go func() { _ = resource.release(); close(closed) }()
	dashboardWait(t, canceled, "last owner cancellation")
	select {
	case <-closed:
		t.Fatal("retirement ignored active body")
	default:
	}
	if active, _ := provider.counts(); active != 1 {
		t.Fatal("released original graph before body joined")
	}
	close(resume)
	dashboardWait(t, closed, "last ingress worker join")
	if active, _ := provider.counts(); active != 0 {
		t.Fatal("lease leaked")
	}
}

func TestRuntimeDashboardPreparationRejectsInvalidHandlerRoot(t *testing.T) {
	ctx, _ := dashboardFileContext(t)
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := newDashboard(ctx, log.NewNOPFactory().Logger(), "0", option.APIDashboardOptions{Path: path})
	if err := d.startAfter(ctx, make(chan struct{}), nil); err == nil {
		t.Fatal("invalid directory admitted")
	}
	if err := d.close(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeDashboardPublishedWorkerOutlivesPreparationRPC(t *testing.T) {
	ctx, _ := dashboardFileContext(t)
	entered := make(chan struct{})
	transport := &dashboardTestTransport{id: "owned", events: &dashboardEventLog{}, roundTrip: func(*http.Request) (*http.Response, error) { close(entered); return nil, errors.New("fixture fetch") }}
	provider := &dashboardTestProvider{current: transport}
	ctx = service.ContextWith[adapter.RuntimeDashboardHTTPProvider](ctx, provider)
	d := newDashboard(ctx, log.NewNOPFactory().Logger(), "0", option.APIDashboardOptions{Path: filepath.Join(t.TempDir(), "dashboard")})
	request, cancel := context.WithCancel(ctx)
	activation := make(chan struct{})
	if err := d.prepareAfter(request, ctx, activation, nil); err != nil {
		t.Fatal(err)
	}
	cancel()
	close(activation)
	dashboardWait(t, entered, "owner-scoped worker after Apply response")
	if err := d.close(); err != nil {
		t.Fatal(err)
	}
	if active, acquired := provider.counts(); active != 0 || acquired != 1 {
		t.Fatal("published worker lost owner", active, acquired)
	}
}

func TestRuntimeDashboardPublicationCancelsOldAndWaitsBeforeNextFetch(t *testing.T) {
	ctx, _ := dashboardFileContext(t)
	events := &dashboardEventLog{}
	entered, canceled, resume := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var unblockOnce sync.Once
	unblock := func() { unblockOnce.Do(func() { close(resume) }) }
	oldTransport := &dashboardTestTransport{id: "old", events: events}
	oldTransport.roundTrip = func(request *http.Request) (*http.Response, error) {
		body := &dashboardCancellationBody{ctx: request.Context(), entered: entered, cancelled: canceled, resume: resume}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: &dashboardTestBody{Reader: body, close: func() error { events.add("body:old"); return nil }}}, nil
	}
	nextEntered := make(chan struct{})
	nextTransport := &dashboardTestTransport{id: "next", events: events, roundTrip: func(*http.Request) (*http.Response, error) {
		events.add("request:next")
		close(nextEntered)
		return nil, errors.New("next fixture fetch")
	}}
	provider := &dashboardTestProvider{current: oldTransport}
	ctx = service.ContextWith[adapter.RuntimeDashboardHTTPProvider](ctx, provider)
	path := filepath.Join(t.TempDir(), "dashboard")
	old := newDashboard(ctx, log.NewNOPFactory().Logger(), "0", option.APIDashboardOptions{Path: path})
	next := newDashboard(ctx, log.NewNOPFactory().Logger(), "0", option.APIDashboardOptions{Path: path})
	t.Cleanup(func() { unblock(); _ = old.close(); _ = next.close() })
	if err := old.start(ctx); err != nil {
		t.Fatal(err)
	}
	dashboardWait(t, entered, "old body admission")
	activation := make(chan struct{})
	if err := next.prepareAfter(ctx, ctx, activation, old.runtimeWorkerDone()); err != nil {
		t.Fatal(err)
	}
	oldResource, nextResource := &runtimeDashboardResource{dashboard: old}, &runtimeDashboardResource{dashboard: next}
	oldResource.retain()
	nextResource.retain()
	provider.selectTransport(nextTransport)
	handoff := &apiHandoff{
		origin: &apiGeneration{dashboard: old, dashboardResource: oldResource},
		next:   &apiGeneration{dashboard: next, dashboardResource: nextResource, dashboardActivation: activation},
	}
	handoff.PublishRuntimeAPI()
	handoff.PublishRuntimeAPI() // The real publication callback is idempotent.
	dashboardWait(t, canceled, "publication cancels old worker")
	select {
	case <-nextEntered:
		t.Fatal("successor fetched before old graph/body join")
	default:
	}
	if active, acquired := provider.counts(); active != 1 || acquired != 1 {
		t.Fatal("old lease not retained", active, acquired)
	}
	retired := make(chan struct{})
	go func() { _ = oldResource.release(); close(retired) }()
	select {
	case <-retired:
		t.Fatal("old resource retired before body joined")
	default:
	}
	unblock()
	dashboardWait(t, retired, "old dashboard retired")
	dashboardWait(t, nextEntered, "successor actual fetch")
	if err := nextResource.release(); err != nil {
		t.Fatal(err)
	}
	if active, acquired := provider.counts(); active != 0 || acquired != 2 {
		t.Fatal("old/new lease ownership", active, acquired)
	}
	seen := events.snapshot()
	released, requested := -1, -1
	for index, item := range seen {
		if item == "release:old" {
			released = index
		}
		if item == "request:next" {
			requested = index
		}
	}
	if released < 0 || requested <= released {
		t.Fatalf("publication worker order: %v", seen)
	}
}
