package box

import (
	"context"
	stdjson "encoding/json"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	mdns "github.com/miekg/dns"
)

type runtimeInboundFixture struct {
	tag    string
	stages atomic.Int32
	closed atomic.Int32
}

func (i *runtimeInboundFixture) Type() string { return C.TypeSOCKS }
func (i *runtimeInboundFixture) Tag() string  { return i.tag }
func (i *runtimeInboundFixture) Start(adapter.StartStage, *adapter.Scope) error {
	panic("legacy inbound Start invoked")
}
func (i *runtimeInboundFixture) RuntimeValidate() error { return nil }
func (i *runtimeInboundFixture) PrepareRuntime(adapter.StartStage, *adapter.Scope) error {
	i.stages.Add(1)
	return nil
}
func (i *runtimeInboundFixture) RuntimeListeners() []*listener.Listener { return nil }

func TestRuntimeInboundInventoryPreservesUnchangedReceiver(t *testing.T) {
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "example.test"), nil)
	registry := service.FromContext[adapter.InboundRegistry](f.ctx).(*inbound.Registry)
	var objects []*runtimeInboundFixture
	inbound.Register[option.SocksInboundOptions](registry, C.TypeSOCKS, func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ option.SocksInboundOptions) (adapter.Inbound, error) {
		instance := &runtimeInboundFixture{tag: tag}
		objects = append(objects, instance)
		if err := adapter.DeferConstructionCleanup(ctx, func() error { instance.closed.Add(1); return nil }); err != nil {
			return nil, err
		}
		return instance, nil
	})
	options.Inbounds = []option.Inbound{{Type: C.TypeSOCKS, Tag: "ingress", Options: &option.SocksInboundOptions{}}}
	instance, err := New(options)
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
	oldLease, oldView := f.acquire(t)
	member, ok := oldView.inbounds.Get("ingress")
	if !ok || member != objects[0] {
		t.Fatal("initial graph lacks exact inbound")
	}
	if objects[0].stages.Load() != int32(len(adapter.ListStartStages)) {
		t.Fatal("initial inbound stages not run")
	}
	routeCopy := *options.Route
	options.Route = &routeCopy
	options.Route.Final = "a"
	encoded, err := json.MarshalContext(f.ctx, options.Options)
	if err != nil {
		t.Fatal(err)
	}
	_, request := f.plan(t, encoded)
	result, err := instance.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Active.Revision != request.Expected.Revision+1 {
		t.Fatalf("not committed: %+v", result)
	}
	newLease, newView := f.acquire(t)
	defer newLease.Release()
	current, ok := newView.inbounds.Get("ingress")
	if !ok || current != member || len(objects) != 1 {
		t.Fatal("route edit restarted unaffected inbound")
	}
	if objects[0].stages.Load() != int32(len(adapter.ListStartStages)) {
		t.Fatal("borrowed inbound restarted")
	}
	oldLease.Release()
}

func TestRuntimeClientIngressShapePolicyAndNegativeControls(t *testing.T) {
	old := `[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":1080}]`
	for _, test := range []struct {
		name, next string
		allowed    bool
	}{
		{"port", `[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":2080}]`, true},
		{"allowLAN", `[{"type":"mixed","tag":"mixed-in","listen":"0.0.0.0","listen_port":1080}]`, true},
		{"App allowLAN", `[{"type":"mixed","tag":"mixed-in","listen":"::","listen_port":1080}]`, true},
		{"first canary", `[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":1080},{"type":"direct","tag":"np-probe-in","listen":"127.0.0.1","listen_port":2080,"network":"udp"}]`, true},
		{"canary wildcard", `[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":1080},{"type":"direct","tag":"np-probe-in","listen":"0.0.0.0","listen_port":2080,"network":"udp"}]`, false},
		{"canary TCP", `[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":1080},{"type":"direct","tag":"np-probe-in","listen":"127.0.0.1","listen_port":2080,"network":"tcp"}]`, false},
		{"zero", `[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":0}]`, false},
		{"protocol", `[{"type":"http","tag":"mixed-in","listen":"127.0.0.1","listen_port":2080}]`, false},
		{"new auth", `[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":2080,"users":[{"username":"x","password":"private"}]}]`, false},
		{"new carrier", `[]`, false},
		{"duplicate", `[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":1080},{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":2080}]`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := runtimeClientInboundChanges([]byte(old), []byte(test.next), 1); got != test.allowed {
				t.Fatalf("shape=%v, want %v", got, test.allowed)
			}
			for _, policy := range []uint32{0, 2, ^uint32(0)} {
				if runtimeClientInboundChanges([]byte(old), []byte(test.next), policy) {
					t.Fatal("unknown/old consumer admitted a new shape", policy)
				}
			}
		})
	}
}

func TestRuntimeClientTunShapesPreservePlatformBoundaries(t *testing.T) {
	for _, platform := range []string{"linux", "windows", "darwin", "android", "ios"} {
		t.Run(platform, func(t *testing.T) {
			v4 := "172.19.0.1/16"
			if platform == "darwin" {
				v4 = "172.19.0.1/30"
			}
			content := fmt.Sprintf(`{"type":"tun","tag":"tun-in","address":%q,"mtu":1500,"auto_route":true}`, v4)
			var fields map[string]stdjson.RawMessage
			if err := stdjson.Unmarshal([]byte(content), &fields); err != nil {
				t.Fatal(err)
			}
			want := true // geometry only; registered-owner authority is tested through public Plan
			if runtimeClientTunShape(fields, platform) != want {
				t.Fatal("wrong platform boundary")
			}
			fields["address"] = stdjson.RawMessage(`["10.0.0.1/24"]`)
			if runtimeClientTunShape(fields, platform) {
				t.Fatal("arbitrary address editor admitted")
			}
			fields["address"] = stdjson.RawMessage(fmt.Sprintf("%q", v4))
			fields["include_mac_address"] = stdjson.RawMessage(`["02:00:00:00:00:01"]`)
			fields["auto_redirect"] = stdjson.RawMessage(`true`)
			if runtimeClientTunShape(fields, platform) != (platform == "linux") {
				t.Fatal("MAC filtering crossed platform")
			}
		})
	}
}

func runtimeClientFreePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// These tests exercise actual Box construction, public policy Plan, Apply and
// real local socket staging. They neither start Core TUN nor certify OS proxy.
func TestRuntimeClientMixedPublicPlanAndOccupiedPortRollback(t *testing.T) {
	for _, occupied := range []bool{false, true} {
		t.Run(fmt.Sprint(occupied), func(t *testing.T) {
			f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "client.test"), nil)
			mixed.RegisterInbound(service.FromContext[adapter.InboundRegistry](f.ctx).(*inbound.Registry))
			oldPort := runtimeClientFreePort(t)
			var oldOptions option.HTTPMixedInboundOptions
			if err := json.Unmarshal([]byte(fmt.Sprintf(`{"listen":"127.0.0.1","listen_port":%d}`, oldPort)), &oldOptions); err != nil {
				t.Fatal(err)
			}
			options.Inbounds = []option.Inbound{{Type: C.TypeMixed, Tag: "mixed-in", Options: &oldOptions}}
			instance, err := New(options)
			if err != nil {
				t.Fatal(err)
			}
			f.box = instance
			t.Cleanup(func() { _ = instance.CloseWithResult() })
			f.start(t)
			expected := f.identity()
			newPort := runtimeClientFreePort(t)
			if occupied {
				holder, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer holder.Close()
				newPort = holder.Addr().(*net.TCPAddr).Port
			}
			var nextOptions option.HTTPMixedInboundOptions
			if err := json.Unmarshal([]byte(fmt.Sprintf(`{"listen":"127.0.0.1","listen_port":%d}`, newPort)), &nextOptions); err != nil {
				t.Fatal(err)
			}
			options.Inbounds = []option.Inbound{{Type: C.TypeMixed, Tag: "mixed-in", Options: &nextOptions}}
			encoded, err := json.MarshalContext(f.ctx, options.Options)
			if err != nil {
				t.Fatal(err)
			}
			legacy, err := instance.PlanRuntimeConfigWithClientImpactPolicy(context.Background(), "actor-a", expected, encoded, nil, RuntimeClientImpactPolicyLegacy)
			if err != nil || legacy.Applicable {
				t.Fatal("legacy consumer lost the old structural guard", err)
			}
			plan, err := instance.PlanRuntimeConfigWithClientImpactPolicy(context.Background(), "actor-a", expected, encoded, nil, RuntimeClientImpactPolicyExplicit)
			if err != nil || !plan.Applicable || len(plan.Errors) != 0 {
				t.Fatal("client port not planned", plan, err)
			}
			request := RuntimeConfigApply{ContractVersion: RuntimeConfigContractVersion, PlanID: plan.PlanID, TransactionID: plan.TransactionID, Expected: plan.Expected, CandidateDigest: plan.CandidateDigest, AcceptedImpactDigest: plan.ImpactDigest}
			result, err := instance.applyRuntimeConfig(context.Background(), "actor-a", request)
			if err != nil {
				t.Fatal(err)
			}
			if occupied {
				if result.Active != expected || strings.HasPrefix(result.State, "COMMITTED") {
					t.Fatal("occupied port published a candidate", result)
				}
				if result.State != "ABORTED_UNAPPLIED" && result.State != "ABORTING_UNAPPLIED" {
					t.Fatal("unexpected physical compensation outcome", result)
				}
				bindFailure := false
				for _, problem := range result.Errors {
					bindFailure = bindFailure || problem.Code == "LISTENER_BIND_FAILED"
				}
				if !bindFailure {
					t.Fatal("failure was not the actual exclusive listener bind", result)
				}
				restored, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", oldPort), time.Second)
				if err != nil {
					t.Fatal("original TCP ingress was not physically restored", err)
				}
				_ = restored.Close()
			} else if result.Active.Revision != expected.Revision+1 {
				t.Fatal("successful candidate not published", result)
			}
		})
	}
}

func TestRuntimeClientCanaryUsesCanonicalListableAndClosedDNSPrefix(t *testing.T) {
	f, _ := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "canary.test"), nil)
	direct.RegisterInbound(service.FromContext[adapter.InboundRegistry](f.ctx).(*inbound.Registry))
	valid := `{"inbounds":[{"type":"direct","tag":"np-probe-in","listen":"127.0.0.1","listen_port":12345,"network":"udp"}],"route":{"rules":[{"inbound":["np-probe-in"],"action":"hijack-dns"}]},"dns":{"rules":[{"inbound":["np-probe-in"],"domain":["p0.np-canary.polaris.invalid"],"action":"predefined","rcode":"NOERROR","answer":["p0.np-canary.polaris.invalid. IN A 127.0.0.1"]},{"inbound":["np-probe-in"],"action":"predefined","rcode":"REFUSED"}]}}`
	for _, test := range []struct {
		name, content string
		valid         bool
	}{
		{"generator", valid, true},
		{"missing refused", strings.Replace(valid, `,"rcode":"REFUSED"`, "", 1), false},
		{"wrong route", strings.Replace(valid, "hijack-dns", "reject", 1), false},
		{"foreign domain", strings.ReplaceAll(valid, "p0.np-canary.polaris.invalid", "external.example"), false},
		{"public UDP", strings.Replace(valid, "127.0.0.1", "0.0.0.0", 1), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var next option.Options
			if err := json.UnmarshalContext(f.ctx, []byte(test.content), &next); err != nil {
				if test.valid {
					t.Fatal(err)
				}
				return
			}
			if got := len(runtimeClientCanaryProblems(f.ctx, next)) == 0; got != test.valid {
				t.Fatal("canary route/REFUSED custody mismatch", got)
			}
		})
	}
}

// Exercise the real direct UDP listener, graph route hijack and DNS prefix on
// first canary creation, rather than granting eligibility from the tag alone.
func TestRuntimeFirstClientCanaryPublicPlanPublishesClosedDNSIngress(t *testing.T) {
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "canary.test"), nil)
	direct.RegisterInbound(service.FromContext[adapter.InboundRegistry](f.ctx).(*inbound.Registry))
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.box = instance
	t.Cleanup(func() { _ = instance.CloseWithResult() })
	f.start(t)
	port := runtimeClientFreePort(t)
	var root map[string]stdjson.RawMessage
	if err := stdjson.Unmarshal(runtimeTestConfig(1080, "canary.test"), &root); err != nil {
		t.Fatal(err)
	}
	root["inbounds"] = stdjson.RawMessage(fmt.Sprintf(`[{"type":"direct","tag":"np-probe-in","listen":"127.0.0.1","listen_port":%d,"network":"udp"}]`, port))
	prepend := func(key string, prefix []stdjson.RawMessage) {
		var object map[string]stdjson.RawMessage
		if err := stdjson.Unmarshal(root[key], &object); err != nil {
			t.Fatal(err)
		}
		var previous []stdjson.RawMessage
		_ = stdjson.Unmarshal(object["rules"], &previous)
		object["rules"], _ = stdjson.Marshal(append(prefix, previous...))
		root[key], _ = stdjson.Marshal(object)
	}
	prepend("route", []stdjson.RawMessage{stdjson.RawMessage(`{"inbound":["np-probe-in"],"action":"hijack-dns"}`)})
	prepend("dns", []stdjson.RawMessage{
		stdjson.RawMessage(`{"inbound":["np-probe-in"],"domain":["p0.np-canary.polaris.invalid"],"action":"predefined","rcode":"NOERROR","answer":["p0.np-canary.polaris.invalid. IN A 127.0.0.1"]}`),
		stdjson.RawMessage(`{"inbound":["np-probe-in"],"action":"predefined","rcode":"REFUSED"}`),
	})
	content, err := stdjson.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := instance.PlanRuntimeConfig(context.Background(), "actor-a", f.identity(), content)
	if err != nil || legacy.Applicable {
		t.Fatal("legacy gained a new canary", legacy, err)
	}
	plan, err := instance.PlanRuntimeConfigWithClientImpactPolicy(context.Background(), "actor-a", f.identity(), content, nil, RuntimeClientImpactPolicyExplicit)
	if err != nil || !plan.Applicable || !plan.ImpactConfirmationRequired {
		t.Fatal("first canary not planned with explicit ingress impact", plan, err)
	}
	request := RuntimeConfigApply{ContractVersion: 1, PlanID: plan.PlanID, TransactionID: plan.TransactionID, Expected: plan.Expected, CandidateDigest: plan.CandidateDigest, AcceptedImpactDigest: plan.ImpactDigest}
	operation, err := instance.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || operation.Active.Revision != plan.Expected.Revision+1 {
		t.Fatal("canary not published", operation, err)
	}
	client := &mdns.Client{Net: "udp", Timeout: time.Second}
	for _, row := range []struct {
		name  string
		rcode int
	}{{"p0.np-canary.polaris.invalid.", mdns.RcodeSuccess}, {"foreign.example.", mdns.RcodeRefused}} {
		message := new(mdns.Msg)
		message.SetQuestion(row.name, mdns.TypeA)
		answer, _, err := client.Exchange(message, fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil || answer == nil || answer.Rcode != row.rcode {
			t.Fatal("published canary escaped closed DNS prefix", answer, err)
		}
	}
}

func TestRuntimeClientTunRejectsUnimplementedFieldsDespiteStableTag(t *testing.T) {
	for _, field := range []string{"stack", "netns", "route_address_set", "dns_address", "include_uid", "include_package", "gso", "multi_queue"} {
		var item map[string]stdjson.RawMessage
		_ = stdjson.Unmarshal([]byte(`{"type":"tun","tag":"tun-in","address":"172.19.0.1/16","auto_route":true}`), &item)
		item[field] = stdjson.RawMessage(`true`)
		if runtimeClientTunShape(item, "linux") {
			t.Fatal("unsupported field acquired physical migration via tag", field)
		}
	}
}
