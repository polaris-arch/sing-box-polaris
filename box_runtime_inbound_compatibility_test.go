package box

import (
	"context"
	stdjson "encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

type runtimeBoundaryInbound struct {
	*runtimeInboundFixture
	kind string
}

func (i *runtimeBoundaryInbound) Type() string { return i.kind }

func runtimeInboundBoundaryOptions(t *testing.T, kind, fields string) (*runtimeTestFixture, Options, *atomic.Int32) {
	t.Helper()
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "boundary.test"), nil)
	registry := service.FromContext[adapter.InboundRegistry](f.ctx).(*inbound.Registry)
	constructed := new(atomic.Int32)
	create := func(ctx context.Context, tag, actualKind string) (adapter.Inbound, error) {
		constructed.Add(1)
		member := &runtimeInboundFixture{tag: tag}
		if err := adapter.DeferConstructionCleanup(ctx, func() error { member.closed.Add(1); return nil }); err != nil {
			return nil, err
		}
		return &runtimeBoundaryInbound{runtimeInboundFixture: member, kind: actualKind}, nil
	}
	// The physical listener is inert; the actual registry's typed JSON options,
	// Box selector, graph construction and public planner are exercised.
	inbound.Register[option.SocksInboundOptions](registry, "socks", func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ option.SocksInboundOptions) (adapter.Inbound, error) {
		return create(ctx, tag, "socks")
	})
	inbound.Register[option.HTTPMixedInboundOptions](registry, "mixed", func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ option.HTTPMixedInboundOptions) (adapter.Inbound, error) {
		return create(ctx, tag, "mixed")
	})
	inbound.Register[option.HTTPInboundOptions](registry, "http", func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ option.HTTPInboundOptions) (adapter.Inbound, error) {
		return create(ctx, tag, "http")
	})
	var root map[string]stdjson.RawMessage
	if err := stdjson.Unmarshal(runtimeTestConfig(1080, "boundary.test"), &root); err != nil {
		t.Fatal(err)
	}
	if fields != "" {
		fields = "," + fields
	}
	root["inbounds"] = []byte(fmt.Sprintf(`[{"type":%q,"tag":"ingress","listen":"127.0.0.1"%s},{"type":"socks","tag":%q,"listen":"127.0.0.1"}]`, kind, fields, runtimeEligibilitySecret))
	encoded, err := stdjson.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.UnmarshalContext(f.ctx, encoded, &options.Options); err != nil {
		t.Fatal(err)
	}
	return f, options, constructed
}

var runtimeInboundBoundaryCases = []struct {
	name, fields string
	paths        []string
}{
	{name: "default"},
	{name: "explicit empty", fields: `"detour":"","domain_resolver":null`},
	{name: "detour", fields: `"detour":"` + runtimeEligibilitySecret + `"`, paths: []string{"inbounds[0].detour"}},
	{name: "resolver", fields: `"domain_resolver":{"server":"resolver"}`, paths: []string{"inbounds[0].domain_resolver"}},
	{name: "both", fields: `"detour":"` + runtimeEligibilitySecret + `","domain_resolver":{"server":"resolver"}`, paths: []string{"inbounds[0].detour", "inbounds[0].domain_resolver"}},
}

func runtimeAssertInboundBoundary(t *testing.T, problems []RuntimePlanError, paths []string) {
	t.Helper()
	var actual []string
	for _, problem := range problems {
		if problem.Code != "PENDING_ADAPTER" || problem.Message == "" {
			t.Fatal("incorrect inbound boundary reason", problems)
		}
		actual = append(actual, problem.Path)
	}
	if !reflect.DeepEqual(actual, paths) {
		t.Fatalf("inbound boundary paths = %v, want %v", actual, paths)
	}
	if strings.Contains(fmt.Sprint(problems), runtimeEligibilitySecret) {
		t.Fatal("boundary exposed a configuration value")
	}
}

func TestRuntimeInboundPayloadFencesActualColdSelector(t *testing.T) {
	for _, kind := range []string{"socks", "mixed", "http"} {
		for _, test := range runtimeInboundBoundaryCases {
			t.Run(kind+"/"+test.name, func(t *testing.T) {
				f, options, constructed := runtimeInboundBoundaryOptions(t, kind, test.fields)
				before := runtimeResourceEncode(t, f, options.Options)
				runtimeAssertInboundBoundary(t, runtimeInitialEligibilityErrors(f.ctx, options), test.paths)
				eligible := len(test.paths) == 0
				if RuntimeUsesResourceGraph(f.ctx, options.Options) != eligible {
					t.Fatal("cold selector lost real inbound payload")
				}
				instance, err := New(options)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if instance.runtime != nil {
						if err := instance.closeRuntimeResourcesContext(runtimeTestContext(t)); err != nil {
							t.Error(err)
						}
					}
					if err := instance.CloseWithResult(); err != nil {
						t.Error(err)
					}
				})
				if (instance.runtime != nil) != eligible || constructed.Load() != 2 {
					t.Fatal("Box.New selected wrong lifecycle or lost inbound", instance.runtimeEligibilityErrors)
				}
				if !eligible {
					runtimeAssertInboundBoundary(t, instance.runtimeEligibilityErrors, test.paths)
				}
				if string(runtimeResourceEncode(t, f, options.Options)) != string(before) {
					t.Fatal("cold eligibility mutated input")
				}
			})
		}
	}
}

func TestRuntimeInboundUnchangedPayloadFencesPublicPlan(t *testing.T) {
	for _, kind := range []string{"socks", "mixed", "http"} {
		for _, test := range runtimeInboundBoundaryCases {
			t.Run(kind+"/"+test.name, func(t *testing.T) {
				f, options, constructed := runtimeInboundBoundaryOptions(t, kind, test.fields)
				// Model a graph admitted by the old cold selector using the real
				// graph constructor. No active canonical bytes or coordinator
				// records are patched to make the inbound appear unchanged.
				ctx := service.ContextWithDefaultRegistry(f.ctx)
				ctx = pause.WithDefaultManager(ctx)
				ctx = service.ContextWithPtr(ctx, urltest.NewHistoryStorage())
				factory := log.NewNOPFactory()
				service.MustRegister[log.Factory](ctx, factory)
				scope := adapter.NewScope(ctx, factory.Logger())
				t.Cleanup(func() {
					if err := scope.Close(); err != nil {
						t.Error(err)
					}
				})
				instance, err := newRuntimeBox(options, scope, factory, time.Now(), nil)
				if err != nil {
					t.Fatal(err)
				}
				f.box = instance
				t.Cleanup(func() {
					if err := instance.closeRuntimeResourcesContext(runtimeTestContext(t)); err != nil {
						t.Error(err)
					}
					if err := instance.CloseWithResult(); err != nil {
						t.Error(err)
					}
				})
				f.start(t)
				before := f.identity()
				_, oldView := f.acquire(t)
				receiver, loaded := oldView.inbounds.Get("ingress")
				if !loaded {
					t.Fatal("constructed graph lost real inbound member")
				}
				count := constructed.Load()
				options.Outbounds[0].Options.(*option.SOCKSOutboundOptions).ServerPort++
				plan, err := instance.planRuntimeConfig(context.Background(), "actor-a", before, runtimeResourceEncode(t, f, options.Options))
				if err != nil {
					t.Fatal(err)
				}
				runtimeAssertInboundBoundary(t, plan.Errors, test.paths)
				if plan.Applicable != (len(test.paths) == 0) {
					t.Fatal("public Plan lost unchanged inbound payload", plan)
				}
				if len(test.paths) > 0 {
					request := RuntimeConfigApply{ContractVersion: RuntimeConfigContractVersion, PlanID: plan.PlanID, TransactionID: plan.TransactionID, Expected: before, CandidateDigest: plan.CandidateDigest, AcceptedImpactDigest: plan.ImpactDigest}
					if _, err := instance.applyRuntimeConfig(context.Background(), "actor-a", request); err == nil {
						t.Fatal("inapplicable inbound plan became executable")
					}
				}
				// A direct inbound detour edit must still take the earlier
				// structural gate, rather than becoming a supported hot edit.
				switch value := options.Inbounds[0].Options.(type) {
				case *option.SocksInboundOptions:
					value.Detour = "replacement-detour"
				case *option.HTTPMixedInboundOptions:
					value.Detour = "replacement-detour"
				case *option.HTTPInboundOptions:
					value.Detour = "replacement-detour"
				}
				structural, err := instance.planRuntimeConfig(context.Background(), "actor-a", before, runtimeResourceEncode(t, f, options.Options))
				if err != nil || structural.Applicable || len(structural.Errors) == 0 {
					t.Fatal("inbound edit bypassed structural boundary", structural, err)
				}
				for _, problem := range structural.Errors {
					if problem.Code != "RESTART_REQUIRED" || problem.Path != "inbounds" {
						t.Fatal("direct detour edit changed boundary classification", structural.Errors)
					}
				}
				_, current := f.acquire(t)
				member, loaded := current.inbounds.Get("ingress")
				if !loaded || !reflect.DeepEqual(current.componentIDs, oldView.componentIDs) || f.identity() != before || member != receiver || constructed.Load() != count || f.count("a") != 1 || f.count("b") != 1 {
					t.Fatal("rejected plan changed current graph or constructed candidate")
				}
			})
		}
	}
}
