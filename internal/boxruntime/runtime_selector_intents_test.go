package boxruntime

import (
	"bytes"
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	boxHTTP "github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing/common/json"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func TestSelectorIntentCandidateMembershipAndType(t *testing.T) {
	options := option.Options{Outbounds: []option.Outbound{{Type: C.TypeSelector, Tag: "default", Options: &option.SelectorOutboundOptions{Outbounds: []string{"a", "b"}}}}}
	intent := RuntimeSelectorIntent{Group: "default", Selected: "a", ExpectedSelectionPath: []string{"default", "auto", "a"}}
	if err := runtimeValidateSelectorIntents(options, []RuntimeSelectorIntent{intent}); err != nil {
		t.Fatal(err)
	}
	intent.Selected = "removed"
	if runtimeValidateSelectorIntents(options, []RuntimeSelectorIntent{intent}) == nil {
		t.Fatal("removed member admitted")
	}
	intent.Selected = "a"
	if runtimeValidateSelectorIntents(options, []RuntimeSelectorIntent{intent, intent}) == nil {
		t.Fatal("duplicate group admitted")
	}
	options.Outbounds[0].Type = C.TypeURLTest
	if runtimeValidateSelectorIntents(options, []RuntimeSelectorIntent{intent}) == nil {
		t.Fatal("non-selector target admitted")
	}
}

func TestSelectorIntentSnapshotOwnsCallerPath(t *testing.T) {
	input := []RuntimeSelectorIntent{{Group: "rule", Selected: "winner", ExpectedSelectionPath: []string{"rule", "winner"}}}
	frozen := cloneRuntimeSelectorIntents(input)
	input[0].ExpectedSelectionPath[1] = "other"
	if frozen[0].ExpectedSelectionPath[1] != "winner" {
		t.Fatal("plan aliases mutable caller state")
	}
}

func TestSelectorIntentFingerprintOnlyChangesTarget(t *testing.T) {
	nodes := []runtimegraph.DependencyNode{{Name: "outbound:default", Fingerprint: "same"}, {Name: "outbound:rule", Fingerprint: "same"}}
	runtimeBindSelectorIntentFingerprints(nodes, []RuntimeSelectorIntent{{Group: "default", Selected: "a"}})
	if nodes[0].Fingerprint == "same" || nodes[1].Fingerprint != "same" {
		t.Fatal("selection scope crossed independent rule group")
	}
}

func TestSelectorPinMustMatchConfirmedPhysicalWinner(t *testing.T) {
	options := option.Options{Outbounds: []option.Outbound{
		{Type: C.TypeSelector, Tag: "rule", Options: &option.SelectorOutboundOptions{Outbounds: []string{"a", "auto"}}},
		{Type: C.TypeDirect, Tag: "a", Options: &option.DirectOutboundOptions{}},
		{Type: C.TypeURLTest, Tag: "auto", Options: &option.URLTestOutboundOptions{Outbounds: []string{"a"}}},
	}}
	intent := RuntimeSelectorIntent{Group: "rule", Selected: "auto", ExpectedSelectionPath: []string{"rule", "auto", "a"}, PinCurrentTCP: true}
	if runtimeValidateSelectorIntents(options, []RuntimeSelectorIntent{intent}) == nil {
		t.Fatal("automatic group accepted as frozen physical winner")
	}
	intent.Selected = "a"
	if err := runtimeValidateSelectorIntents(options, []RuntimeSelectorIntent{intent}); err != nil {
		t.Fatal(err)
	}
	intent.ExpectedSelectionPath = nil
	if runtimeValidateSelectorIntents(options, []RuntimeSelectorIntent{intent}) == nil {
		t.Fatal("new group claimed an observed winner")
	}
}

func TestRuntimeProbeSlotDisregardsImportedChoiceAndReplacementSnapshot(t *testing.T) {
	const slot = "probe-selector-0"
	const custom = "probe-selector-9"
	path := filepath.Join(t.TempDir(), "cache.db")
	openCache := func() (*cachefile.CacheFile, *adapter.Scope) {
		logger := log.NewNOPFactory().Logger()
		scope := adapter.NewScope(t.Context(), logger)
		cache := cachefile.New(t.Context(), logger, option.CacheFileOptions{Path: path, CacheID: "test"})
		if err := cache.Start(adapter.StartStateInitialize, scope); err != nil {
			_ = scope.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = scope.Close() })
		return cache, scope
	}
	cache, scope := openCache()
	for _, group := range []string{slot, custom, "proxy-selector"} {
		if err := cache.StoreSelected(group, "a"); err != nil {
			t.Fatal(err)
		}
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	config := func(port int) []byte {
		return []byte(fmt.Sprintf(`{
			"log":{"disabled":true},
			"experimental":{"cache_file":{"enabled":true,"cache_id":"test","path":%q}},
			"inbounds":[{"type":"http","tag":"probe-in-0","listen":"127.0.0.1"}],
			"dns":{"servers":[{"type":"udp","tag":"resolver","server":"192.0.2.53"},
				{"type":"https","tag":"dns-probe-exit-0","server":"223.5.5.5","server_port":443,"path":"/dns-query","detour":%q}],
				"rules":[{"inbound":["probe-in-0"],"query_type":["A","AAAA"],"action":"route","server":"dns-probe-exit-0","disable_cache":true}],"final":"resolver"},
			"outbounds":[{"type":"direct","tag":"direct"},
				{"type":"socks","tag":"a","server":"192.0.2.1","server_port":%d},
				{"type":"socks","tag":"b","server":"192.0.2.2","server_port":1080},
				{"type":"selector","tag":%q,"outbounds":["a","b","direct"],"default":"direct","interrupt_exist_connections":true},
				{"type":"selector","tag":%q,"outbounds":["a","b","direct"],"default":"direct","interrupt_exist_connections":true},
				{"type":"selector","tag":"proxy-selector","outbounds":["a","b","direct"],"default":"direct"}],
			"route":{"rules":[{"inbound":["probe-in-0"],"action":"route","outbound":%q}],"final":"proxy-selector"}
		}`, path, slot, port, slot, custom, slot))
	}
	start := func(legacy bool) *runtimeTestFixture {
		f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "example.org"), nil)
		boxHTTP.RegisterInbound(service.FromContext[adapter.InboundRegistry](f.ctx).(*inbound.Registry))
		transport.RegisterHTTPS(service.FromContext[adapter.DNSTransportRegistry](f.ctx).(*dns.TransportRegistry))
		options.Options = option.Options{}
		if err := json.UnmarshalContext(f.ctx, config(1080), &options.Options); err != nil {
			t.Fatal(err)
		}
		if legacy {
			options.Certificate = &option.CertificateOptions{Store: C.CertificateStoreNone, CertificateDirectoryPath: []string{t.TempDir()}}
		}
		box, err := New(options)
		if err != nil {
			t.Fatal(err)
		}
		f.box = box
		t.Cleanup(func() { _ = box.CloseWithResult() })
		if (box.runtime == nil) != legacy {
			t.Fatal("fixture reached unexpected Box construction path")
		}
		f.start(t)
		return f
	}
	check := func(f *runtimeTestFixture, group, want string) {
		t.Helper()
		outbound, exists := f.box.Outbound().Outbound(group)
		if !exists {
			t.Fatalf("missing group %s", group)
		}
		if got := outbound.(adapter.OutboundGroup).Selected(N.NetworkTCP).Tag(); got != want {
			t.Errorf("%s selected %s; want %s", group, got, want)
		}
	}
	choose := func(f *runtimeTestFixture, group, member string) {
		t.Helper()
		outbound, exists := f.box.Outbound().Outbound(group)
		if !exists || !outbound.(interface{ SelectOutbound(string) bool }).SelectOutbound(member) {
			t.Fatalf("legacy-compatible selector mutation rejected %s → %s", group, member)
		}
		check(f, group, member)
	}

	f := start(false)
	apply := func(content []byte, revision uint64) {
		t.Helper()
		_, request := f.plan(t, content)
		operation, err := f.box.applyRuntimeConfig(t.Context(), "actor-a", request)
		if err != nil || operation.Active.Revision != revision {
			t.Fatalf("failed real graph replacement: revision=%d, err=%v", operation.Active.Revision, err)
		}
	}
	check(f, slot, "direct")
	check(f, custom, "a")
	check(f, "proxy-selector", "a")
	choose(f, slot, "b")
	choose(f, custom, "b")
	choose(f, "proxy-selector", "b")
	apply(config(1081), 2)
	check(f, slot, "direct")
	check(f, custom, "b")
	check(f, "proxy-selector", "b")
	choose(f, slot, "b")

	var typed option.Options
	if err := json.UnmarshalContext(f.ctx, config(1081), &typed); err != nil {
		t.Fatal(err)
	}
	if err := runtimeValidateSelectorIntents(typed, []RuntimeSelectorIntent{{Group: slot, Selected: "b"}}); err == nil {
		t.Fatal("durable intent accepted for an ephemeral pool slot")
	}
	if err := runtimeValidateSelectorIntents(typed, []RuntimeSelectorIntent{{Group: custom, Selected: "b"}}); err != nil {
		t.Fatal("durable intent rejected for ordinary selector with reserve-like tag", err)
	}
	t.Run("ordinary_consumers", func(t *testing.T) {
		isEphemeral := func(o option.Options) bool {
			index := slices.IndexFunc(o.Outbounds, func(outbound option.Outbound) bool { return outbound.Tag == slot })
			return o.Outbounds[index].Options.(*option.SelectorOutboundOptions).EphemeralPoolProbe
		}
		for _, test := range []struct {
			name    string
			consume func(*option.Options)
		}{
			{"ordinary selector member", func(o *option.Options) {
				group := o.Outbounds[len(o.Outbounds)-1].Options.(*option.SelectorOutboundOptions)
				group.Outbounds = append(group.Outbounds, slot)
			}},
			{"URL-test member", func(o *option.Options) {
				o.Outbounds = append(o.Outbounds, option.Outbound{Type: C.TypeURLTest, Tag: "custom-test", Options: &option.URLTestOutboundOptions{Outbounds: []string{slot}}})
			}},
			{"custom outbound detour", func(o *option.Options) {
				o.Outbounds[1].Options.(*option.SOCKSOutboundOptions).Detour = slot
			}},
			{"additional DNS route", func(o *option.Options) {
				rule := o.DNS.Rules[0]
				rule.DefaultOptions.Inbound = []string{"other-in"}
				o.DNS.Rules = append(o.DNS.Rules, rule)
			}},
			{"custom resolver", func(o *option.Options) {
				o.Route.DefaultDomainResolver = &option.DomainResolveOptions{Server: "dns-probe-exit-0"}
			}},
			{"remote rule-set download detour", func(o *option.Options) {
				o.Route.RuleSet = []option.RuleSet{{Type: C.RuleSetTypeRemote, RemoteOptions: option.RemoteRuleSet{DownloadDetour: slot}}}
			}},
			{"remote rule-set HTTP client", func(o *option.Options) {
				o.Route.RuleSet = []option.RuleSet{{Type: C.RuleSetTypeRemote, RemoteOptions: option.RemoteRuleSet{HTTPClient: &option.HTTPClientOptions{
					DialerOptions: option.DialerOptions{Detour: slot},
				}}}}
			}},
			{"certificate provider HTTP client", func(o *option.Options) {
				o.CertificateProviders = []option.CertificateProvider{{Options: &option.ACMECertificateProviderOptions{HTTPClient: &option.HTTPClientOptions{
					DialerOptions: option.DialerOptions{Detour: slot},
				}}}}
			}},
			{"implicit default outbound", func(o *option.Options) {
				o.Route.Final = ""
				o.Outbounds[0], o.Outbounds[3] = o.Outbounds[3], o.Outbounds[0]
			}},
			{"implicit default DNS", func(o *option.Options) {
				o.DNS.Final = ""
				o.DNS.Servers[0], o.DNS.Servers[1] = o.DNS.Servers[1], o.DNS.Servers[0]
			}},
			{"DNS wildcard", func(o *option.Options) {
				o.DNS.Rules[0].DefaultOptions.QueryType = nil
			}},
		} {
			t.Run(test.name, func(t *testing.T) {
				var ordinary option.Options
				if err := json.UnmarshalContext(f.ctx, config(1081), &ordinary); err != nil {
					t.Fatal(err)
				}
				configured := withAppProbeSelectionScope(ordinary)
				if isEphemeral(ordinary) || !isEphemeral(configured) {
					t.Fatal("selector ownership mutated shared configuration or missed the App slot")
				}
				test.consume(&configured)
				if replacement := withAppProbeSelectionScope(configured); isEphemeral(replacement) || !isEphemeral(configured) {
					t.Fatal("ordinary consumer retained an ephemeral slot or changed the borrowed owner")
				}
			})
		}
	})

	// Changing only the route role must replace the slot, even though its own
	// options and all resolved member outbounds are exactly the same.
	ordinary := bytes.Replace(config(1081), []byte(`"action":"route","outbound"`), []byte(`"action":"route","network":"tcp","outbound"`), 1)
	apply(ordinary, 3)
	check(f, slot, "a")
	choose(f, slot, "b")
	apply(config(1081), 4)
	check(f, slot, "direct")
	choose(f, slot, "b")
	choose(f, slot, "direct")
	if err := f.box.CloseWithResult(); err != nil {
		t.Fatal(err)
	}

	cache, scope = openCache()
	if err := cache.StoreSelected(slot, "a"); err != nil {
		t.Fatal(err)
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	legacy := start(true)
	check(legacy, slot, "direct")
	check(legacy, custom, "b")
	choose(legacy, slot, "b")
	if err := legacy.box.CloseWithResult(); err != nil {
		t.Fatal(err)
	}
	cache, _ = openCache()
	if got := cache.LoadSelected(slot); got != "a" {
		t.Errorf("probe slot rewrote the previously imported cache row: %q", got)
	}
	if got := cache.LoadSelected(custom); got != "b" {
		t.Fatalf("custom selector's persisted choice = %q", got)
	}
}
