package box

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
)

type runtimeDashboardServiceFixture struct{ boxService.Adapter }

func (*runtimeDashboardServiceFixture) Start(adapter.StartStage, *adapter.Scope) error { return nil }

func runtimeDashboardTestOptions(t *testing.T) (*runtimeTestFixture, Options) {
	t.Helper()
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "before.example"), nil)
	registry := service.FromContext[adapter.ServiceRegistry](f.ctx).(*boxService.Registry)
	boxService.Register[option.APIServiceOptions](registry, C.TypeAPI, func(_ context.Context, _ log.ContextLogger, tag string, _ option.APIServiceOptions) (adapter.Service, error) {
		return &runtimeDashboardServiceFixture{boxService.NewAdapter(C.TypeAPI, tag)}, nil
	})
	listen := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	options.Services = []option.Service{{Type: C.TypeAPI, Options: &option.APIServiceOptions{
		Listen: &listen, Secret: "original", Dashboard: &option.APIDashboardOptions{
			Enabled: true, Path: "/initial", DownloadURL: "http://127.0.0.1/initial.zip", UpdateInterval: badoption.Duration(time.Hour),
			HTTPClient: &option.HTTPClientOptions{DialerOptions: option.DialerOptions{Detour: "select"}},
		},
	}}}
	return f, options
}

func TestRuntimeDashboardDerivedDependenciesAndNamespace(t *testing.T) {
	f, options := runtimeDashboardTestOptions(t)
	before, err := json.MarshalContext(f.ctx, options.Options)
	if err != nil {
		t.Fatal(err)
	}
	_, nodes, err := runtimeConfigNodes(f.ctx, options.Options)
	if err != nil {
		t.Fatal(err)
	}
	httpNode := nodes["http-manager"].node
	if !slices.Contains(httpNode.dependencies, "outbound:select") {
		t.Fatal("dashboard detour missing from graph closure")
	}
	if _, exists := nodes["service:0"]; exists {
		t.Fatal("stable API unexpectedly belongs to graph")
	}
	clients, err := runtimeDashboardHTTPConfigs(options.Options)
	if err != nil || len(clients) != 1 || clients[0].Key.ServiceTag != "0" {
		t.Fatalf("derived client identity: %+v %v", clients, err)
	}
	after, _ := json.MarshalContext(f.ctx, options.Options)
	if string(before) != string(after) || len(options.HTTPClients) != 0 {
		t.Fatal("derived client changed public options")
	}
	options.Services[0].Tag = "default"
	_, renamed, err := runtimeConfigNodes(f.ctx, options.Options)
	if err != nil || renamed["http-manager"].node.fingerprint == httpNode.fingerprint {
		t.Fatalf("owner key missing from fingerprint: %v", err)
	}
	options.Services[0].Options.(*option.APIServiceOptions).Dashboard.HTTPClient.Detour = "a"
	_, changed, err := runtimeConfigNodes(f.ctx, options.Options)
	if err != nil || !slices.Contains(changed["http-manager"].node.dependencies, "outbound:a") || changed["http-manager"].node.fingerprint == renamed["http-manager"].node.fingerprint {
		t.Fatalf("client missing from dependency/fingerprint: %v", err)
	}
	options.Services[0].Tag = ""
	duplicate := options.Services[0]
	duplicate.Tag = "0"
	options.Services = append(options.Services, duplicate)
	if _, err := runtimeDashboardHTTPConfigs(options.Options); err == nil {
		t.Fatal("effective service tag collision silently overwrote transport")
	}
}

func TestRuntimeDashboardLeaseUsesPublishedGraphAndReleases(t *testing.T) {
	f, options := runtimeDashboardTestOptions(t)
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.box = instance
	t.Cleanup(func() {
		if err := instance.CloseWithResult(); err != nil {
			t.Error(err)
		}
	})
	if lease, err := instance.AcquireDashboardHTTP(context.Background(), "0"); err == nil || lease != nil {
		t.Fatal("unpublished graph admitted")
	}
	f.start(t)
	lease, err := instance.AcquireDashboardHTTP(context.Background(), "0")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	graph, ok := adapter.RuntimeLeaseFromContext(lease.Context())
	if !ok || graph.View().Identity().Revision != 1 {
		t.Fatal("fetch lacks borrowed graph context")
	}
	if missing, err := instance.AcquireDashboardHTTP(context.Background(), "unprepared"); err == nil || missing != nil {
		t.Fatal("unknown dashboard client allocated after freeze")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := instance.AcquireDashboardHTTP(cancelled, "0"); err == nil {
		t.Fatal("canceled acquisition admitted")
	}
	// Repeated fetch admission borrows one immutable prepared client.
	for range 4 {
		next, err := instance.AcquireDashboardHTTP(context.Background(), "0")
		if err != nil || next.Transport() != lease.Transport() {
			t.Fatalf("live client allocation: %v", err)
		}
		next.Release()
		next.Release()
	}
	old := f.object(t, "a", 0)
	var next option.Options
	if err := json.UnmarshalContext(f.ctx, runtimeTestConfig(1081, "after.example"), &next); err != nil {
		t.Fatal(err)
	}
	next.Services = options.Services
	content, _ := json.MarshalContext(f.ctx, next)
	_, request := f.plan(t, content)
	operation, err := instance.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || operation.Active.Revision != 2 {
		t.Fatalf("apply: %+v %v", operation, err)
	}
	current, err := instance.AcquireDashboardHTTP(context.Background(), "0")
	if err != nil {
		t.Fatal(err)
	}
	defer current.Release()
	currentGraph, _ := adapter.RuntimeLeaseFromContext(current.Context())
	if currentGraph.View().Identity().Revision != 2 || current.Transport() == lease.Transport() {
		t.Fatal("current fetch captured old dependency graph")
	}
	select {
	case <-old.closed:
		t.Fatal("old graph closed before fetch release")
	default:
	}
	lease.Release()
	runtimeTestWait(t, old.closed, "retired dashboard graph after fetch release")
	current.Release()
	if instance.RuntimeCapabilities().FullConfiguration {
		t.Fatal("dashboard adapter advertised full configuration support")
	}
}

func TestRuntimeDashboardServiceChangesStillRequireRestart(t *testing.T) {
	f, options := runtimeDashboardTestOptions(t)
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.box = instance
	t.Cleanup(func() { _ = instance.CloseWithResult() })
	f.start(t)
	content, _ := json.MarshalContext(f.ctx, options.Options)
	for _, change := range [][2]string{{`"original"`, `"replacement"`}, {`"/initial"`, `"/other"`}, {`"http://127.0.0.1/initial.zip"`, `"http://127.0.0.1/other.zip"`}, {`"1h0m0s"`, `"2h0m0s"`}, {`"detour":"select"`, `"detour":"a"`}} {
		t.Run(change[0], func(t *testing.T) {
			candidate := strings.Replace(string(content), change[0], change[1], 1)
			if candidate == string(content) {
				t.Fatalf("test change did not occur: %s", content)
			}
			plan, err := instance.planRuntimeConfig(context.Background(), "actor-a", f.identity(), []byte(candidate))
			if err != nil || plan.Applicable || len(plan.Errors) == 0 || plan.Errors[0].Code != "RESTART_REQUIRED" {
				t.Fatalf("service structure admitted: %+v %v", plan, err)
			}
		})
	}
}

func TestRuntimeDashboardPreparedMapReuseAndAbort(t *testing.T) {
	f, options := runtimeDashboardTestOptions(t)
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.box = instance
	t.Cleanup(func() { _ = instance.CloseWithResult() })
	f.start(t)
	initial, err := instance.AcquireDashboardHTTP(context.Background(), "0")
	if err != nil {
		t.Fatal(err)
	}
	transport := initial.Transport()
	initial.Release()
	var next option.Options
	if err := json.UnmarshalContext(f.ctx, runtimeTestConfig(1080, "after.example"), &next); err != nil {
		t.Fatal(err)
	}
	next.Services = options.Services
	content, _ := json.MarshalContext(f.ctx, next)
	_, request := f.plan(t, content)
	if _, err := instance.applyRuntimeConfig(context.Background(), "actor-a", request); err != nil {
		t.Fatal(err)
	}
	reused, err := instance.AcquireDashboardHTTP(context.Background(), "0")
	if err != nil {
		t.Fatal(err)
	}
	if reused.Transport() != transport {
		t.Fatal("unchanged HTTP component did not reuse prepared transport")
	}
	reused.Release()
	before := f.identity()
	candidate := []byte(strings.Replace(string(content), `"server_port":1080`, `"server_port":1082`, 1))
	_, request = f.plan(t, candidate)
	f.setConstructorHook(func(*runtimeTestSocks) error { return errors.New("synthetic candidate abort") })
	operation, applyErr := instance.applyRuntimeConfig(context.Background(), "actor-a", request)
	if applyErr == nil && operation.State == "COMMITTED" {
		t.Fatal("failed candidate committed")
	}
	if f.identity() != before {
		t.Fatal("failed preparation changed active graph")
	}
	retained, err := instance.AcquireDashboardHTTP(context.Background(), "0")
	if err != nil {
		t.Fatal(err)
	}
	if retained.Transport() != transport {
		t.Fatal("aborted candidate replaced stable provider client")
	}
	retained.Release()
	runtimeTestWait(t, f.object(t, "a", 1).closed, "aborted dashboard dependency")
}
