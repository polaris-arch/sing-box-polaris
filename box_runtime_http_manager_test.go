package box

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing/service"
)

func TestRuntimeRealmActualConstructorPlanApplyRetainsExactOldClosure(t *testing.T) {
	if !C.WithQUIC {
		t.Skip("actual Realm adapter requires the with_quic build; typed rejection is tested separately")
	}
	for _, change := range []string{"named-http", "named-http-route-final", "default-http", "inline-http", "STUN-resolver", "mapping-resolver", "route-final"} {
		t.Run(change, func(t *testing.T) {
			f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "inert.test"), nil)
			candidate := runtimeRealmDependencyOptions()
			candidate.Log = options.Log
			candidate.HTTPClients = []option.HTTPClient{
				{Tag: "one", Version: 1, Detour: "carrier-a", DomainResolver: &option.DomainResolveOptions{Server: "bootstrap"}},
				{Tag: "two", Version: 1, Detour: "carrier-b", DomainResolver: &option.DomainResolveOptions{Server: "replacement"}},
			}
			candidate.Route.DefaultHTTPClient = "one"
			realm := candidate.Outbounds[2].Options.(*option.Hysteria2OutboundOptions)
			if change == "mapping-resolver" {
				realm.Realm.STUNServers = []string{"127.0.0.1:3478"}
				realm.Realm.PortMapping = &option.Hysteria2RealmPortMapping{Enabled: true}
			}
			switch change {
			case "named-http", "named-http-route-final":
				realm.Realm.HTTPClient = &option.HTTPClientOptions{Tag: "one"}
			case "inline-http":
				realm.Realm.HTTPClient = &option.HTTPClientOptions{Version: 1, Detour: "carrier-a"}
			case "route-final":
				// Only the implicit manager default captures Final. Named clients
				// above have explicit detours and must not invent this dependency.
				candidate.HTTPClients = nil
				candidate.Route.DefaultHTTPClient = ""
			}
			options.Options = candidate
			var captured []struct {
				http adapter.HTTPClientManager
				dns  adapter.DNSRouter
			}
			registry := service.FromContext[adapter.OutboundRegistry](f.ctx).(*outbound.Registry)
			outbound.Register[option.Hysteria2OutboundOptions](registry, C.TypeHysteria2, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, value option.Hysteria2OutboundOptions) (adapter.Outbound, error) {
				captured = append(captured, struct {
					http adapter.HTTPClientManager
					dns  adapter.DNSRouter
				}{service.FromContext[adapter.HTTPClientManager](ctx), service.FromContext[adapter.DNSRouter](ctx)})
				return hysteria2.NewOutbound(ctx, router, logger, tag, value)
			})
			runtimeResourceNew(t, f, options)
			if err := f.box.BindRuntimePersistenceOptions(func(RuntimeIdentity, []byte) error { return nil }, "owner_acknowledged", true); err != nil {
				t.Fatal(err)
			}
			f.start(t)
			oldLease, old := f.acquire(t)
			oldID := old.componentIDs["outbound:realm"]
			oldResource := runtimeTestResource(t, f, oldID)
			if len(captured) != 1 || captured[0].http != old.httpClients || captured[0].dns != old.dns {
				t.Fatal("actual initial Realm constructor missed its captured generation")
			}
			if change == "named-http" {
				for _, invalid := range []string{"missing-http", "self-http"} {
					oldTag, oldDetour, oldFinal := realm.Realm.HTTPClient.Tag, candidate.HTTPClients[0].Detour, candidate.Route.Final
					switch invalid {
					case "missing-http":
						realm.Realm.HTTPClient.Tag = "absent"
					case "self-http":
						candidate.HTTPClients[0].Detour = "realm"
					}
					before := f.identity()
					plan, err := f.box.planRuntimeConfig(context.Background(), "actor-a", before, runtimeResourceEncode(t, f, candidate))
					if err != nil || plan.Applicable || len(plan.Errors) == 0 || f.identity() != before || len(captured) != 1 {
						t.Fatal("invalid Realm closure changed or prepared the active graph", invalid, plan, err)
					}
					realm.Realm.HTTPClient.Tag, candidate.HTTPClients[0].Detour, candidate.Route.Final = oldTag, oldDetour, oldFinal
				}
			}
			if change == "route-final" {
				oldFinal := candidate.Route.Final
				candidate.Route.Final = "realm"
				before := f.identity()
				plan, err := f.box.planRuntimeConfig(context.Background(), "actor-a", before, runtimeResourceEncode(t, f, candidate))
				if err != nil || plan.Applicable || len(plan.Errors) == 0 || f.identity() != before || len(captured) != 1 {
					t.Fatal("actual implicit HTTP bootstrap cycle entered Plan", plan, err)
				}
				candidate.Route.Final = oldFinal
			}
			switch change {
			case "named-http":
				candidate.HTTPClients[0].Detour = "carrier-b"
			case "default-http":
				candidate.Route.DefaultHTTPClient = "two"
			case "inline-http":
				realm.Realm.HTTPClient.Detour = "carrier-b"
			case "STUN-resolver", "mapping-resolver":
				realm.DomainResolver.Server = "replacement"
			case "route-final":
				candidate.Route.Final = "carrier-b"
			case "named-http-route-final":
				candidate.Route.Final = "realm"
			}
			before := f.identity()
			_, apply := f.plan(t, runtimeResourceEncode(t, f, candidate))
			if len(captured) != 1 {
				t.Fatal("Plan ran a Realm constructor")
			}
			result := runtimeTestReceiveApply(t, runtimeTestApplyAsync(f, context.Background(), apply))
			_, current := f.acquire(t)
			reuse := change == "named-http-route-final"
			wantConstructors := 2
			if reuse {
				wantConstructors = 1
			}
			if result.Active.Revision != before.Revision+1 || (current.componentIDs["outbound:realm"] == oldID) != reuse || len(captured) != wantConstructors || captured[len(captured)-1].http != current.httpClients || captured[len(captured)-1].dns != current.dns {
				t.Fatal("same-tag Realm reused a previous closure", result)
			}
			if old.componentIDs["outbound:realm"] != oldID || captured[0].http != old.httpClients || captured[0].dns != old.dns {
				t.Fatal("new publication mutated the old Realm view")
			}
			select {
			case <-oldResource.owner.Closed():
				t.Fatal("old lease lost its Realm closure before release")
			default:
			}
			oldLease.Release()
			if reuse {
				select {
				case <-oldResource.owner.Closed():
					t.Fatal("active reused Realm lost its named HTTP/DNS closure")
				default:
				}
				return
			}
			if err := oldResource.owner.WaitClosed(runtimeTestContext(t)); err != nil {
				t.Fatal("unused old Realm did not join terminal cleanup", err)
			}
		})
	}
}

func runtimeHTTPNode(t *testing.T, options option.Options, name string) runtimeDependencyNode {
	t.Helper()
	nodes, _, err := runtimeConfigNodes(context.Background(), runtimeResolveGraphDefaults(options))
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		if node.name == name {
			return node
		}
	}
	t.Fatalf("missing component %q", name)
	return runtimeDependencyNode{}
}

func TestRuntimeRealmLiteralDiscoveryDoesNotCaptureUnusedDNS(t *testing.T) {
	if !C.WithQUIC {
		t.Skip("actual Realm adapter requires with_quic; no-build rejection remains separately covered")
	}
	f, value := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "inert.test"), nil)
	options := runtimeRealmDependencyOptions()
	options.Log = value.Log
	realm := options.Outbounds[2].Options.(*option.Hysteria2OutboundOptions)
	realm.DomainResolver = nil
	realm.Realm.ServerURL = "https://127.0.0.1:0"
	realm.Realm.STUNServers = []string{"127.0.0.1:3478"}
	realm.Realm.HTTPClient = &option.HTTPClientOptions{Tag: "control"}
	options.HTTPClients = []option.HTTPClient{{Tag: "control", Version: 1, Detour: "carrier-a"}}
	options.Route.DefaultHTTPClient = "control"
	for i := 0; i < 2; i++ {
		options.Outbounds[i].Type = C.TypeSOCKS
		options.Outbounds[i].Options = &option.SOCKSOutboundOptions{Version: "5", ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 9}}
		options.DNS.Servers[i].Options.(*option.RemoteDNSServerOptions).Detour = "realm"
	}
	node := runtimeHTTPNode(t, options, "outbound:realm")
	if slices.Contains(node.dependencies, "dns-router") || !slices.Contains(node.dependencies, "http-manager") {
		t.Fatal("literal-only discovery captured unused DNS or lost its HTTP owner", node)
	}
	registry := service.FromContext[adapter.OutboundRegistry](f.ctx).(*outbound.Registry)
	outbound.Register[option.SOCKSOutboundOptions](registry, C.TypeSOCKS, socks.NewOutbound)
	constructions := 0
	outbound.Register[option.Hysteria2OutboundOptions](registry, C.TypeHysteria2, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.Hysteria2OutboundOptions) (adapter.Outbound, error) {
		constructions++
		return hysteria2.NewOutbound(ctx, router, logger, tag, options)
	})
	value.Options = options
	runtimeResourceNew(t, f, value)
	if err := f.box.BindRuntimePersistenceOptions(func(RuntimeIdentity, []byte) error { return nil }, "owner_acknowledged", true); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	lease, old := f.acquire(t)
	oldID := old.componentIDs["outbound:realm"]
	oldResource := runtimeTestResource(t, f, oldID)
	options.HTTPClients[0].Detour = "carrier-b"
	_, apply := f.plan(t, runtimeResourceEncode(t, f, options))
	if constructions != 1 {
		t.Fatal("literal-only Plan constructed native Realm")
	}
	_ = runtimeTestReceiveApply(t, runtimeTestApplyAsync(f, context.Background(), apply))
	_, current := f.acquire(t)
	if constructions != 2 || current.componentIDs["outbound:realm"] == oldID {
		t.Fatal("captured HTTP detour replacement reused literal Realm")
	}
	select {
	case <-oldResource.owner.Closed():
		t.Fatal("old literal Realm closure retired before lease release")
	default:
	}
	lease.Release()
	if err := oldResource.owner.WaitClosed(runtimeTestContext(t)); err != nil {
		t.Fatal(err)
	}
	// A hostname or dynamic UPnP device does need this router. Its route through
	// the same Realm is then a genuine bootstrap cycle, never a global fallback.
	for _, mapping := range []bool{false, true} {
		realm.DomainResolver = &option.DomainResolveOptions{Server: "bootstrap"}
		realm.Realm.STUNServers = []string{"127.0.0.1:3478"}
		realm.Realm.PortMapping = &option.Hysteria2RealmPortMapping{Enabled: mapping}
		if !mapping {
			realm.Realm.STUNServers = []string{"needs-captured.invalid:3478"}
		}
		before := f.identity()
		plan, err := f.box.planRuntimeConfig(context.Background(), "actor-a", before, runtimeResourceEncode(t, f, options))
		if err != nil || plan.Applicable || len(plan.Errors) == 0 || f.identity() != before || constructions != 2 {
			t.Fatal("actual resolver self-dependency was not rejected without construction", mapping, plan, err)
		}
	}
}

func runtimeRealmDependencyOptions() option.Options {
	realm := &option.Hysteria2OutboundOptions{}
	realm.TLS = &option.OutboundTLSOptions{Enabled: true, ServerName: "peer.invalid"}
	realm.DomainResolver = &option.DomainResolveOptions{Server: "bootstrap"}
	realm.Realm = &option.Hysteria2Realm{
		ServerURL: "https://control.invalid", RealmID: "fixture",
		STUNServers: option.LegacyListable[string]{"stun.invalid:3478"},
	}
	options := option.Options{
		Route: &option.RouteOptions{Final: "carrier-a"},
		Outbounds: []option.Outbound{
			{Type: "direct", Tag: "carrier-a", Options: &option.DirectOutboundOptions{}},
			{Type: "direct", Tag: "carrier-b", Options: &option.DirectOutboundOptions{}},
			{Type: "hysteria2", Tag: "realm", Options: realm},
		},
		DNS: &option.DNSOptions{},
	}
	for _, tag := range []string{"bootstrap", "replacement"} {
		remote := &option.RemoteDNSServerOptions{}
		remote.Server = "192.0.2.53"
		options.DNS.Servers = append(options.DNS.Servers, option.DNSServerOptions{Type: "udp", Tag: tag, Options: remote})
	}
	return options
}

func TestRuntimeRealmLiteralSTUNMappingCapturesEffectiveResolver(t *testing.T) {
	for _, mode := range []string{"explicit", "default", "missing"} {
		t.Run(mode, func(t *testing.T) {
			options := runtimeRealmDependencyOptions()
			realm := options.Outbounds[2].Options.(*option.Hysteria2OutboundOptions)
			realm.Realm.STUNServers = []string{"127.0.0.1:3478"}
			realm.Realm.PortMapping = &option.Hysteria2RealmPortMapping{Enabled: true}
			if mode != "explicit" {
				realm.DomainResolver = nil
			}
			if mode == "default" {
				options.Route.DefaultDomainResolver = &option.DomainResolveOptions{Server: "replacement"}
			}
			nodes, _, err := runtimeConfigNodes(context.Background(), runtimeResolveGraphDefaults(options))
			if mode == "missing" {
				if err == nil {
					t.Fatal("ambiguous device hostname resolver accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := "dns-transport:bootstrap"
			if mode == "default" {
				want = "dns-transport:replacement"
			}
			found := false
			for _, node := range nodes {
				if node.name == "outbound:realm" {
					found = slices.Contains(node.dependencies, want) && slices.Contains(node.dependencies, "dns-router")
				}
			}
			if !found {
				t.Fatal("numeric STUN hid later device hostname dependency", want)
			}
		})
	}
}

func TestRuntimeRealmHTTPAndSTUNCaptureWithoutServer(t *testing.T) {
	for _, mode := range []string{"default", "named", "inline", "named-resolve-on-detour"} {
		t.Run(mode, func(t *testing.T) {
			options := runtimeRealmDependencyOptions()
			realm := options.Outbounds[2].Options.(*option.Hysteria2OutboundOptions)
			realm.Detour = "carrier-b"
			if mode != "default" {
				client := &option.HTTPClientOptions{}
				client.Detour = "carrier-a"
				client.DomainResolver = &option.DomainResolveOptions{Server: "replacement"}
				realm.Realm.HTTPClient = client
				if mode != "inline" {
					definition := option.HTTPClient(*client)
					definition.Tag = "control"
					options.HTTPClients = []option.HTTPClient{definition}
					realm.Realm.HTTPClient = &option.HTTPClientOptions{Tag: "control", ResolveOnDetour: mode == "named-resolve-on-detour"}
				}
			}
			nodes, configs, err := runtimeConfigNodes(context.Background(), runtimeResolveGraphDefaults(options))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := runtimeCohorts(nodes); err != nil {
				t.Fatal(err)
			}
			for _, dependency := range []string{"http-manager", "dns-router", "dns-transport:bootstrap", "outbound:carrier-b"} {
				if !slices.Contains(configs["outbound:realm"].node.dependencies, dependency) {
					t.Fatalf("empty Server lost %s: %+v", dependency, configs["outbound:realm"].node)
				}
			}
			if mode != "default" {
				for _, dependency := range []string{"outbound:carrier-a", "dns-router", "dns-transport:replacement"} {
					if !slices.Contains(configs["http-manager"].node.dependencies, dependency) {
						t.Fatalf("HTTP manager lost %s: %+v", dependency, configs["http-manager"].node)
					}
				}
			}
		})
	}
}

func TestRuntimeRealmSTUNAndMappingCaptureOnlyRequiredDNS(t *testing.T) {
	for _, server := range []string{"192.0.2.1:3478", "[2001:db8::1]:3478", "stun.invalid:3478"} {
		for _, version := range []int{0, 4, 6} {
			for _, mapping := range []bool{false, true} {
				options := runtimeRealmDependencyOptions()
				realm := options.Outbounds[2].Options.(*option.Hysteria2OutboundOptions)
				realm.Realm.STUNServers = option.LegacyListable[string]{server}
				realm.Realm.IPVersion = version
				realm.Realm.PortMapping = &option.Hysteria2RealmPortMapping{Enabled: mapping}
				node := runtimeHTTPNode(t, options, "outbound:realm")
				needsDNS := realm.Realm.STUNServersIsDomain() || mapping
				if slices.Contains(node.dependencies, "dns-router") != needsDNS || slices.Contains(node.dependencies, "dns-transport:bootstrap") != needsDNS {
					t.Fatal("Realm DNS closure differs from actual hostname/device discovery", server, version, mapping, node)
				}
				if !slices.Contains(node.dependencies, "http-manager") {
					t.Fatal("Realm lost its captured HTTP manager", server, version, mapping)
				}
				// Dependency projection remains pure even for the separately rejected
				// IPv6-only mapping variant; it cannot hide a future DNS callback.
			}
		}
	}
}

func TestRuntimeRealmInlineHTTPChangesInvalidateReceivingManager(t *testing.T) {
	for _, change := range []string{"detour", "resolver", "default-outbound", "resolve-on-detour", "direct-resolver", "empty-direct-check", "named-definition", "http-default", "route-final", "route-resolver"} {
		t.Run(change, func(t *testing.T) {
			options := runtimeRealmDependencyOptions()
			client := &option.HTTPClientOptions{}
			client.Detour = "carrier-a"
			client.DomainResolver = &option.DomainResolveOptions{Server: "bootstrap"}
			realm := options.Outbounds[2].Options.(*option.Hysteria2OutboundOptions)
			realm.Realm.HTTPClient = client
			if change == "named-definition" || change == "http-default" {
				one := option.HTTPClient(*client)
				one.Tag = "one"
				two := one
				two.Tag = "two"
				options.HTTPClients = []option.HTTPClient{one, two}
				options.Route.DefaultHTTPClient = "one"
				realm.Realm.HTTPClient = &option.HTTPClientOptions{Tag: "one"}
			}
			before := runtimeHTTPNode(t, options, "http-manager")
			beforeRealm := runtimeHTTPNode(t, options, "outbound:realm")
			digest, err := runtimePlannedDependencyDigest(context.Background(), options, "frozen")
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "detour":
				client.Detour = "carrier-b"
			case "resolver":
				client.DomainResolver = &option.DomainResolveOptions{Server: "replacement"}
			case "default-outbound":
				client.DefaultOutbound = true
			case "resolve-on-detour":
				client.ResolveOnDetour = true
			case "direct-resolver":
				client.DirectResolver = true
			case "empty-direct-check":
				client.DisableEmptyDirectCheck = true
			case "named-definition":
				options.HTTPClients[0].Detour = "carrier-b"
			case "http-default":
				options.Route.DefaultHTTPClient = "two"
			case "route-final":
				options.Route.Final = "carrier-b"
			case "route-resolver":
				options.Route.DefaultDomainResolver = &option.DomainResolveOptions{Server: "replacement"}
			}
			after := runtimeHTTPNode(t, options, "http-manager")
			if before.fingerprint == after.fingerprint && slices.Equal(before.dependencies, after.dependencies) {
				t.Fatal("receiving HTTP manager retained constructor capture after", change)
			}
			if !slices.Contains(beforeRealm.dependencies, "http-manager") || !slices.Contains(before.dependencies, "outbound:carrier-a") || slices.Contains(before.dependencies, "dns-transport:replacement") {
				t.Fatal("new closure mutated or disconnected the retained old generation")
			}
			changed, err := runtimePlannedDependencyDigest(context.Background(), options, "frozen")
			if err != nil || digest == changed {
				t.Fatal("planning did not bind the same new closure", err)
			}
		})
	}
}

func TestRuntimeRealmRejectsMissingReferencesAndBootstrapCycles(t *testing.T) {
	for _, problem := range []string{"missing-http", "duplicate-http", "missing-http-default", "missing-http-detour", "missing-stun-detour", "missing-resolver", "http-self", "named-http-self", "stun-self", "http-indirect", "stun-indirect", "implicit-final-self", "dns-cycle"} {
		t.Run(problem, func(t *testing.T) {
			options := runtimeRealmDependencyOptions()
			realm := options.Outbounds[2].Options.(*option.Hysteria2OutboundOptions)
			switch problem {
			case "missing-http":
				realm.Realm.HTTPClient = &option.HTTPClientOptions{Tag: "absent"}
			case "duplicate-http":
				realm.Realm.HTTPClient = &option.HTTPClientOptions{Tag: "repeated"}
				options.HTTPClients = []option.HTTPClient{{Tag: "repeated"}, {Tag: "repeated"}}
			case "missing-http-default":
				options.Route.DefaultHTTPClient = "absent"
			case "named-http-self":
				client := option.HTTPClient{Tag: "control"}
				client.Detour = "realm"
				options.HTTPClients = []option.HTTPClient{client}
				realm.Realm.HTTPClient = &option.HTTPClientOptions{Tag: "control"}
			case "missing-http-detour", "http-self", "http-indirect":
				client := &option.HTTPClientOptions{}
				client.Detour = "absent"
				if problem == "http-self" {
					client.Detour = "realm"
				} else if problem == "http-indirect" {
					client.Detour = "carrier-a"
					options.Outbounds[0].Options.(*option.DirectOutboundOptions).Detour = "realm"
				}
				realm.Realm.HTTPClient = client
			case "missing-stun-detour":
				realm.Detour = "absent"
			case "missing-resolver":
				realm.DomainResolver.Server = "absent"
			case "stun-self":
				realm.Detour = "realm"
			case "stun-indirect":
				realm.Detour = "carrier-b"
				options.Outbounds[1].Options.(*option.DirectOutboundOptions).Detour = "realm"
			case "implicit-final-self":
				options.Route.Final = "realm"
			case "dns-cycle":
				options.DNS.Servers[0].Options.(*option.RemoteDNSServerOptions).Detour = "realm"
			}
			_, _, err := runtimeConfigNodes(context.Background(), runtimeResolveGraphDefaults(options))
			if err == nil || (!strings.Contains(err.Error(), "Realm") && !strings.Contains(err.Error(), "realm")) {
				t.Fatalf("invalid Realm closure accepted or lost context: %v", err)
			}
		})
	}
}

func TestRuntimeRealmDefaultResolverAndNamedFlagsAreConstructorInputs(t *testing.T) {
	options := runtimeRealmDependencyOptions()
	realm := options.Outbounds[2].Options.(*option.Hysteria2OutboundOptions)
	realm.DomainResolver = nil
	realm.Detour = "carrier-a"
	options.Route.DefaultDomainResolver = &option.DomainResolveOptions{Server: "replacement"}
	node := runtimeHTTPNode(t, options, "outbound:realm")
	if !slices.Contains(node.dependencies, "dns-transport:replacement") {
		t.Fatal("STUN on a detour lost the effective default resolver", node)
	}
	manager := runtimeHTTPNode(t, options, "http-manager")
	if !slices.Contains(manager.dependencies, "dns-transport:replacement") {
		t.Fatal("inline HTTP lost the effective default resolver", manager)
	}
	options.Route.DefaultDomainResolver.Server = "absent"
	if _, _, err := runtimeConfigNodes(context.Background(), runtimeResolveGraphDefaults(options)); err == nil {
		t.Fatal("missing default resolver accepted")
	}
	options.Route.DefaultDomainResolver = nil
	if _, _, err := runtimeConfigNodes(context.Background(), runtimeResolveGraphDefaults(options)); err == nil {
		t.Fatal("STUN ambiguously chose among two DNS transports")
	}
	options = runtimeRealmDependencyOptions()
	realm = options.Outbounds[2].Options.(*option.Hysteria2OutboundOptions)
	options.HTTPClients = []option.HTTPClient{{Tag: "one"}, {Tag: "two"}}
	realm.Realm.HTTPClient = &option.HTTPClientOptions{Tag: "one"}
	before := runtimeHTTPNode(t, options, "http-manager")
	beforeRealm := runtimeHTTPNode(t, options, "outbound:realm")
	realm.Realm.HTTPClient.Tag = "two"
	after := runtimeHTTPNode(t, options, "http-manager")
	if before.fingerprint != after.fingerprint || beforeRealm.fingerprint == runtimeHTTPNode(t, options, "outbound:realm").fingerprint {
		t.Fatal("plain reference switch changed shared definitions or reused old consumer")
	}
	realm.Realm.HTTPClient.ResolveOnDetour = true
	if after.fingerprint == runtimeHTTPNode(t, options, "http-manager").fingerprint {
		t.Fatal("constructor-only named ResolveOnDetour reused the old receiving manager")
	}
}

func TestRuntimeHTTPImplicitDefaultCapturesSourceOrderFinal(t *testing.T) {
	options := option.Options{Outbounds: []option.Outbound{
		{Type: "direct", Tag: "z-first", Options: &option.DirectOutboundOptions{}},
		{Type: "direct", Tag: "a-second", Options: &option.DirectOutboundOptions{}},
	}}
	manager := runtimeHTTPNode(t, options, "http-manager")
	if !slices.Contains(manager.dependencies, "outbound:z-first") || slices.Contains(manager.dependencies, "outbound:a-second") {
		t.Fatalf("incorrect implicit capture: %v", manager.dependencies)
	}
	router := runtimeHTTPNode(t, options, "route-router")
	if !slices.Contains(router.dependencies, "http-manager") {
		t.Fatal("router's HTTP manager capture is missing")
	}
}

func TestRuntimeHTTPNamedDefinitionsCaptureResolverAndDetour(t *testing.T) {
	options := option.Options{HTTPClients: []option.HTTPClient{{Tag: "updates", Detour: "proxy", DomainResolver: &option.DomainResolveOptions{Server: "bootstrap"}}}}
	node := runtimeHTTPNode(t, options, "http-manager")
	for _, dependency := range []string{"outbound:proxy", "dns-router", "dns-transport:bootstrap"} {
		if !slices.Contains(node.dependencies, dependency) {
			t.Fatalf("missing %q: %v", dependency, node.dependencies)
		}
	}
	options.HTTPClients[0].DomainResolver = &option.DomainResolveOptions{Server: "replacement"}
	changed := runtimeHTTPNode(t, options, "http-manager")
	if node.fingerprint == changed.fingerprint {
		t.Fatal("HTTP definition edit did not invalidate owner")
	}
	if slices.Contains(node.dependencies, "dns-transport:replacement") {
		t.Fatal("detached dependency snapshot was mutated")
	}
}

func TestRuntimeHTTPDefaultSelectionAffectsFingerprint(t *testing.T) {
	options := option.Options{HTTPClients: []option.HTTPClient{{Tag: "a"}, {Tag: "b"}}, Route: &option.RouteOptions{DefaultHTTPClient: "a"}}
	first := runtimeHTTPNode(t, options, "http-manager")
	options.Route.DefaultHTTPClient = "b"
	second := runtimeHTTPNode(t, options, "http-manager")
	if first.fingerprint == second.fingerprint {
		t.Fatal("HTTP default selection missing from owner identity")
	}
}

func TestRuntimeInlineProviderHTTPCapturesReceivingManagerClosure(t *testing.T) {
	client := &option.HTTPClientOptions{Detour: "issuer-proxy", DomainResolver: &option.DomainResolveOptions{Server: "issuer-dns"}}
	options := option.Options{CertificateProviders: []option.CertificateProvider{{Type: "acme", Tag: "cert", Options: &option.ACMECertificateProviderOptions{HTTPClient: client}}}}
	first := runtimeHTTPNode(t, options, "http-manager")
	for _, dependency := range []string{"outbound:issuer-proxy", "dns-router", "dns-transport:issuer-dns"} {
		if !slices.Contains(first.dependencies, dependency) {
			t.Fatalf("missing inline provider capture %q", dependency)
		}
	}
	provider := runtimeHTTPNode(t, options, "certificate-provider:cert")
	if !slices.Contains(provider.dependencies, "http-manager") {
		t.Fatal("provider must retain its actual manager")
	}
	client.Detour = "new-proxy"
	second := runtimeHTTPNode(t, options, "http-manager")
	if first.fingerprint == second.fingerprint {
		t.Fatal("inline provider changed but receiving manager was reused")
	}
	if slices.Contains(first.dependencies, "outbound:new-proxy") {
		t.Fatal("old dependency snapshot mutated")
	}
}

func TestRuntimeNamedProviderHTTPReferenceDoesNotCreateInlineTransport(t *testing.T) {
	options := option.Options{HTTPClients: []option.HTTPClient{{Tag: "issuer", Detour: "shared-proxy"}}, CertificateProviders: []option.CertificateProvider{{Type: "acme", Tag: "cert", Options: &option.ACMECertificateProviderOptions{HTTPClient: &option.HTTPClientOptions{Tag: "issuer"}}}}}
	node := runtimeHTTPNode(t, options, "http-manager")
	if !slices.Contains(node.dependencies, "outbound:shared-proxy") {
		t.Fatal("shared HTTP definition lost")
	}
	options.CertificateProviders[0].Options = &option.ACMECertificateProviderOptions{HTTPClient: &option.HTTPClientOptions{Tag: "other"}}
	changed := runtimeHTTPNode(t, options, "http-manager")
	if changed.fingerprint != node.fingerprint {
		t.Fatal("reference-only change recreated unchanged HTTP definitions")
	}
	provider := runtimeHTTPNode(t, options, "certificate-provider:cert")
	if !slices.Contains(provider.dependencies, "http-manager") {
		t.Fatal("reference lacks manager ownership")
	}
}

func TestRuntimeHTTPResolveOnDetourCapturesNamedDefinitionAndProgrammaticFlags(t *testing.T) {
	client := &option.HTTPClientOptions{Tag: "issuer", ResolveOnDetour: true}
	options := option.Options{HTTPClients: []option.HTTPClient{{Tag: "issuer", Detour: "proxy"}}, CertificateProviders: []option.CertificateProvider{{Type: "cloudflare-origin-ca", Tag: "cert", Options: &option.CloudflareOriginCACertificateProviderOptions{HTTPClient: client}}}}
	before := runtimeHTTPNode(t, options, "http-manager")
	for _, dependency := range []string{"outbound:proxy", "dns-router"} {
		if !slices.Contains(before.dependencies, dependency) {
			t.Fatal("named ResolveOnDetour omitted receiving-manager capture", before.dependencies)
		}
	}
	client.ResolveOnDetour = false
	after := runtimeHTTPNode(t, options, "http-manager")
	if after.fingerprint == before.fingerprint {
		t.Fatal("constructor-only ResolveOnDetour did not invalidate HTTP owner")
	}
}
