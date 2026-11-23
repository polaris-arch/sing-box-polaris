package boxruntime

import (
	"context"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"

	mdns "github.com/miekg/dns"
)

// Box.New, the production TCP transport and its bound detour execute the wire
// query. Only the remote DNS peer is an in-memory fixture. The answer identifies
// the destination actually dialed, rather than the candidate's declared digest.
func TestRuntimeDNSOptionsReplaceActualTargetAndRetainOldLease(t *testing.T) {
	// A physical detour is captured exactly. A group detour is late-bound by the
	// reused router: it follows the admitted view, never the constructor graph.
	for _, detour := range []string{"a", "select"} {
		t.Run(detour, func(t *testing.T) { runtimeTestDNSOptionsReplace(t, detour) })
	}
}

// A pure-domain rule set used by DNS rules is late-bound by tag in each query's
// admitted view: a content change replaces only the set and the route router,
// while each lease matches its own generation through the retained DNS router.
func TestRuntimeDNSRuleSetContentKeepsRouter(t *testing.T) {
	config := func(port int, domain string, ruleSet string) []byte {
		content := strings.Replace(string(runtimeTestConfig(port, domain)), `"final":"resolver"}`,
			`"final":"resolver","rules":[{"rule_set":"sites","action":"predefined","answer":["hit. IN A 198.51.100.1"]},{"action":"predefined","answer":["miss. IN A 198.51.100.2"]}]}`, 1)
		return []byte(strings.Replace(content, `{"domain_suffix":["`+domain+`"]}`, ruleSet, 1))
	}
	sites := func(domain string) string { return `{"domain_suffix":["` + domain + `"]}` }
	f, options := newRuntimeTestConstruction(t, config(1080, "old.test", sites("old.test")), nil)
	runtimeResourceNew(t, f, options)
	f.start(t)
	// The first publication never reuses the initial platform borrowing.
	_, warm := f.plan(t, config(1081, "old.test", sites("old.test")))
	runtimeTestReceiveApply(t, runtimeTestApplyAsync(f, context.Background(), warm))
	oldLease, oldView := f.acquire(t)
	_, apply := f.plan(t, config(1081, "old.test", sites("new.test")))
	runtimeTestReceiveApply(t, runtimeTestApplyAsync(f, context.Background(), apply))
	newLease, newView := f.acquire(t)
	for name, id := range oldView.componentIDs {
		if replaced := newView.componentIDs[name] != id; replaced != (name == "rule-set:sites" || name == "route-router") {
			t.Fatalf("%s replaced=%t", name, replaced)
		}
	}
	answer := func(lease adapter.RuntimeLease, name string) string {
		t.Helper()
		ctx := runtimeTestContext(t)
		if lease != nil {
			ctx = adapter.ContextWithRuntimeLease(ctx, lease)
		}
		message := new(mdns.Msg)
		message.SetQuestion(name, mdns.TypeA)
		response, err := newView.DNSRouter().Exchange(ctx, message, adapter.DNSQueryOptions{})
		if err != nil || len(response.Answer) != 1 {
			t.Fatal(response, err)
		}
		return response.Answer[0].(*mdns.A).A.String()
	}
	for _, query := range []struct {
		lease adapter.RuntimeLease
		name  string
		want  string
	}{
		{oldLease, "a.old.test.", "198.51.100.1"},
		{oldLease, "a.new.test.", "198.51.100.2"},
		{newLease, "a.new.test.", "198.51.100.1"},
		{newLease, "a.old.test.", "198.51.100.2"},
		{nil, "b.new.test.", "198.51.100.1"},
	} {
		if got := answer(query.lease, query.name); got != query.want {
			t.Fatalf("%s: %s, want %s", query.name, got, query.want)
		}
	}
	addresses, err := newView.DNSRouter().Lookup(adapter.ContextWithRuntimeLease(runtimeTestContext(t), newLease), "c.new.test", adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only})
	if err != nil || len(addresses) != 1 || addresses[0].String() != "198.51.100.1" {
		t.Fatal("lookup did not match the admitted view's rule set", addresses, err)
	}
	// Adding or removing a set, or an IP predicate, still binds the router.
	router := func(content []byte) runtimeNodeOptions {
		t.Helper()
		options, err := json.UnmarshalExtendedContext[option.Options](f.ctx, content)
		if err != nil {
			t.Fatal(err)
		}
		_, configs, err := runtimeConfigNodes(f.ctx, options)
		if err != nil {
			t.Fatal(err)
		}
		return configs["dns-router"]
	}
	current := router(config(1081, "old.test", sites("new.test")))
	if slices.Contains(current.node.Dependencies, "rule-set:sites") {
		t.Fatal("pure-domain set remained a DNS router dependency")
	}
	if withIP := router(config(1081, "old.test", sites("new.test")+`,{"ip_cidr":["192.0.2.0/24"]}`)); !slices.Contains(withIP.node.Dependencies, "rule-set:sites") {
		t.Fatal("IP predicate did not bind the set to the DNS router")
	}
	removed := strings.Replace(string(config(1081, "old.test", sites("new.test"))), `{"type":"inline","tag":"sites","rules":[{"domain_suffix":["new.test"]}]}`, `{"type":"inline","tag":"other","rules":[{"domain_suffix":["new.test"]}]}`, 1)
	if router([]byte(removed)).node.Fingerprint == current.node.Fingerprint {
		t.Fatal("removing a late-bound set kept the DNS router fingerprint")
	}
}

func runtimeTestDNSOptionsReplace(t *testing.T, detour string) {
	// Register before Box/lease cleanup. Only production closes the clients;
	// this fixture subsequently seals and joins its server-side workers.
	wireServer := newRuntimeDNSWireServer(t, nil)
	var dialed atomic.Pointer[context.Context]
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "resolver.test"), func(o *runtimeTestSocks) error {
		o.dialHook = func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
			if network != "tcp" {
				t.Errorf("DNS did not use TCP: %s", network)
			}
			dialed.Store(&ctx)
			return wireServer.dial(ctx, destination.AddrString())
		}
		return nil
	})
	server := &option.RemoteDNSServerOptions{Server: "192.0.2.53", Detour: detour}
	options.DNS.Servers = []option.DNSServerOptions{{Type: "tcp", Tag: "fixture", Options: server}, {Type: "udp", Tag: "bootstrap", Options: &option.RemoteDNSServerOptions{Server: "192.0.2.1"}}}
	options.DNS.Final = "fixture"
	runtimeResourceNew(t, f, options)
	f.start(t)
	// The first publication never reuses the initial platform borrowing, so it
	// also replaces its DNS router.
	options.Outbounds[1].Options.(*option.SOCKSOutboundOptions).ServerPort++
	_, warm := f.plan(t, runtimeResourceEncode(t, f, options.Options))
	runtimeTestReceiveApply(t, runtimeTestApplyAsync(f, context.Background(), warm))
	oldLease, oldView := f.acquire(t)
	oldTransport, ok := oldView.DNSTransportManager().Transport("fixture")
	if !ok {
		t.Fatal("production DNS transport missing")
	}
	query := func(lease adapter.RuntimeLease, transport adapter.DNSTransport, want string) {
		t.Helper()
		message := new(mdns.Msg)
		message.SetQuestion("target.fixture.", mdns.TypeA)
		response, err := transport.Exchange(adapter.ContextWithRuntimeLease(runtimeTestContext(t), lease), message)
		if err != nil {
			t.Fatal(err)
		}
		if len(response.Answer) != 1 || response.Answer[0].(*mdns.A).A.String() != want {
			t.Fatalf("wire query reached the wrong target: %v, want %s", response.Answer, want)
		}
	}
	// A reset pool must dial again, under the transport that served the query.
	// A call without a graph lease admits current.
	routed := func(view adapter.RuntimeView, lease adapter.RuntimeLease, name string, want adapter.DNSTransport, id adapter.RuntimeResourceID) {
		t.Helper()
		want.Reset()
		dialed.Store(nil)
		message := new(mdns.Msg)
		message.SetQuestion(name, mdns.TypeA)
		ctx := runtimeTestContext(t)
		if lease != nil {
			ctx = adapter.ContextWithRuntimeLease(ctx, lease)
		}
		if _, err := view.DNSRouter().Exchange(ctx, message, adapter.DNSQueryOptions{}); err != nil {
			t.Fatal(err)
		}
		dial := dialed.Load()
		if dial == nil {
			t.Fatal("router query did not reach the expected transport")
		}
		// The pool dials in the operation or its owning transport's context.
		source, owned := adapter.RuntimeResourceSourceFromContext(*dial)
		if _, retained := adapter.RuntimeResourceLeaseFromContext(*dial, id); !retained && (!owned || source.ID() != id) {
			t.Fatal("router query used a transport outside its admitted view")
		}
	}
	query(oldLease, oldTransport, "192.0.2.53")
	wireServer.waitProbe(t, "192.0.2.53")
	routed(oldView, oldLease, "old.fixture.", oldTransport, oldView.componentIDs["dns-transport:fixture"])
	// A real unrelated publication must reuse the unchanged DNS router. Only
	// a group detour replaces the transport with the group.
	options.Outbounds[1].Options.(*option.SOCKSOutboundOptions).ServerPort++
	_, unchanged := f.plan(t, runtimeResourceEncode(t, f, options.Options))
	runtimeTestReceiveApply(t, runtimeTestApplyAsync(f, context.Background(), unchanged))
	stableLease, stableView := f.acquire(t)
	stableTransport, _ := stableView.DNSTransportManager().Transport("fixture")
	if stableView.DNSRouter() != oldView.DNSRouter() || stableView.componentIDs["dns-router"] != oldView.componentIDs["dns-router"] {
		t.Fatal("unrelated publication replaced the DNS router")
	}
	lateBound := detour == "select"
	if lateBound == (stableTransport == oldTransport) || lateBound == (stableView.componentIDs["dns-transport:fixture"] == oldView.componentIDs["dns-transport:fixture"]) {
		t.Fatal("DNS transport allocation does not follow its detour closure")
	}
	query(stableLease, stableTransport, "192.0.2.53")
	query(stableLease, stableTransport, "192.0.2.53")
	routed(stableView, stableLease, "stable.fixture.", stableTransport, stableView.componentIDs["dns-transport:fixture"])
	routed(stableView, nil, "admitted.fixture.", stableTransport, stableView.componentIDs["dns-transport:fixture"])
	routed(oldView, oldLease, "retained.fixture.", oldTransport, oldView.componentIDs["dns-transport:fixture"])
	server.Server = "192.0.2.54"
	_, change := f.plan(t, runtimeResourceEncode(t, f, options.Options))
	runtimeTestReceiveApply(t, runtimeTestApplyAsync(f, context.Background(), change))
	newLease, newView := f.acquire(t)
	newTransport, _ := newView.DNSTransportManager().Transport("fixture")
	if newTransport == oldTransport || newView.componentIDs["dns-transport:fixture"] == oldView.componentIDs["dns-transport:fixture"] {
		t.Fatal("changed DNS options reused the old transport")
	}
	query(newLease, newTransport, "192.0.2.54")
	wireServer.waitProbe(t, "192.0.2.54")
	query(oldLease, oldTransport, "192.0.2.53")
	oldResource := runtimeTestResource(t, f, oldView.componentIDs["dns-transport:fixture"])
	select {
	case <-oldResource.owner.Closed():
		t.Fatal("old graph lease lost the original DNS transport")
	default:
	}
	stableLease.Release()
	oldLease.Release()
	runtimeTestWait(t, oldResource.owner.Closed(), "released old DNS transport")
}
