package box

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
)

type runtimeAPIIngressFixture struct {
	boxService.Adapter
	owner    *Box
	outbound adapter.OutboundManager
	started  bool
	joined   chan struct{}
	once     sync.Once
}

func (s *runtimeAPIIngressFixture) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStarted {
		return nil
	}
	lease, _, connected, err := s.owner.AcquireRuntimeAPI()
	if err != nil || !connected {
		return err
	}
	s.started = true
	// Model a stalled admitted streaming RPC: ingress cancellation must run
	// before stable resource drain, and cleanup must join the lease owner.
	scope.Add(func() error {
		<-s.joined
		return nil
	})
	go func() {
		<-scope.Context().Done()
		lease.Release()
		s.once.Do(func() { close(s.joined) })
	}()
	return nil
}

func TestRuntimeStableAPICoexistsAndClosesBeforeGraphDrain(t *testing.T) {
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "before.example"), nil)
	registry := service.FromContext[adapter.ServiceRegistry](f.ctx).(*boxService.Registry)
	var created []*runtimeAPIIngressFixture
	boxService.Register[option.APIServiceOptions](registry, C.TypeAPI, func(ctx context.Context, _ log.ContextLogger, tag string, _ option.APIServiceOptions) (adapter.Service, error) {
		api := &runtimeAPIIngressFixture{
			Adapter:  boxService.NewAdapter(C.TypeAPI, tag),
			owner:    service.PtrFromContext[Box](ctx),
			outbound: service.FromContext[adapter.OutboundManager](ctx),
			joined:   make(chan struct{}),
		}
		created = append(created, api)
		return api, nil
	})
	listen := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	options.Services = []option.Service{{Type: C.TypeAPI, Options: &option.APIServiceOptions{
		Listen: &listen, ListenPort: 12345, Secret: "one",
	}}}
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.box = instance
	t.Cleanup(func() { _ = instance.CloseWithResult() })
	if instance.runtime == nil || len(created) != 1 || created[0].owner != instance {
		t.Fatal("API did not capture the one stable connected Box owner")
	}
	f.start(t)
	if !created[0].started {
		t.Fatal("API ingress did not start after graph publication")
	}
	before, _ := created[0].outbound.Outbound("a")
	var next option.Options
	if err := json.UnmarshalContext(f.ctx, runtimeTestConfig(1081, "after.example"), &next); err != nil {
		t.Fatal(err)
	}
	next.Services = options.Services
	content, err := json.MarshalContext(f.ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	_, request := f.plan(t, content)
	operation, err := instance.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || operation.Active.Revision != 2 || len(created) != 1 {
		t.Fatalf("unchanged API was rejected or recreated: %+v %v", operation, err)
	}
	after, _ := created[0].outbound.Outbound("a")
	if before.(*runtimeOutbound).id == after.(*runtimeOutbound).id {
		t.Fatal("attached outbound facade kept the original leaf")
	}
	changed := []byte(strings.Replace(string(content), `"secret":"one"`, `"secret":"two"`, 1))
	plan, err := instance.planRuntimeConfig(context.Background(), "actor-a", f.identity(), changed)
	if err != nil || plan.Applicable || len(plan.Errors) == 0 || plan.Errors[0].Code != "RESTART_REQUIRED" {
		t.Fatalf("API configuration change escaped structural boundary: %+v %v", plan, err)
	}
	if err := instance.closeRuntimeResourcesContext(runtimeTestContext(t)); err != nil {
		t.Fatal(err)
	}
	runtimeTestWait(t, created[0].joined, "API ingress RPC completion")
}

func TestRuntimeAPIDashboardAndRemoteListenersRemainLegacy(t *testing.T) {
	listen := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	options := &option.APIServiceOptions{Listen: &listen}
	item := option.Service{Type: C.TypeAPI, Options: options}
	if !runtimeStableAPIService(item) {
		t.Fatal("plain local API rejected")
	}
	options.Dashboard = &option.APIDashboardOptions{Enabled: true}
	if runtimeStableAPIService(item) {
		t.Fatal("dashboard dependency silently admitted")
	}
	options.Dashboard = nil
	listen = badoption.Addr(netip.MustParseAddr("0.0.0.0"))
	if runtimeStableAPIService(item) {
		t.Fatal("non-loopback API admitted")
	}
}

func TestRuntimeDashboardDetourOnlyEligibility(t *testing.T) {
	listen := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	for _, test := range []struct {
		name   string
		change func(*option.HTTPClientOptions)
	}{
		{"named", func(c *option.HTTPClientOptions) { c.Tag = "named" }},
		{"empty", func(c *option.HTTPClientOptions) { c.Detour = "" }},
		{"engine", func(c *option.HTTPClientOptions) { c.Engine = "go" }},
		{"version", func(c *option.HTTPClientOptions) { c.Version = 2 }},
		{"hidden_default", func(c *option.HTTPClientOptions) { c.DefaultOutbound = true }},
		{"hidden_resolve", func(c *option.HTTPClientOptions) { c.ResolveOnDetour = true }},
		{"hidden_direct", func(c *option.HTTPClientOptions) { c.DirectResolver = true }},
		{"hidden_skip_check", func(c *option.HTTPClientOptions) { c.DisableEmptyDirectCheck = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &option.HTTPClientOptions{DialerOptions: option.DialerOptions{Detour: "select"}}
			options := &option.APIServiceOptions{Listen: &listen, Dashboard: &option.APIDashboardOptions{Enabled: true, HTTPClient: client}}
			item := option.Service{Type: C.TypeAPI, Options: options}
			if !runtimeStableAPIService(item) {
				t.Fatal("App inline detour-only dashboard rejected")
			}
			test.change(client)
			if runtimeStableAPIService(item) {
				t.Fatal("unsupported dashboard client admitted")
			}
		})
	}
}
