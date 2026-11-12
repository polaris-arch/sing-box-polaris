package box

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	mdns "github.com/miekg/dns"
)

func runtimeFakeIPCandidate(t *testing.T, prefix string) *preparedRuntimeGraph {
	t.Helper()
	var configuration option.FakeIPDNSServerOptions
	content, err := json.Marshal(map[string]string{"inet4_range": prefix})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, &configuration); err != nil {
		t.Fatal(err)
	}
	server := option.DNSServerOptions{}
	server.Type = C.DNSTypeFakeIP
	server.Options = &configuration
	dns := &option.DNSOptions{}
	dns.Servers = []option.DNSServerOptions{server}
	return &preparedRuntimeGraph{options: option.Options{DNS: dns}}
}

func TestRuntimeFakeIPCandidateCannotAnswerBeforePublication(t *testing.T) {
	manager := fakeip.NewEmptyManager(context.Background(), log.NewNOPFactory().Logger())
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	instance := &Box{runtime: &runtimeCoordinator{ctx: context.Background(), fakeIP: manager}}
	prepared := runtimeFakeIPCandidate(t, "198.18.0.0/29")
	if err := instance.prepareRuntimeFakeIP(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	defer prepared.abort()
	store, err := prepared.fakeIPMigration.Borrow(netip.MustParsePrefix("198.18.0.0/29"), netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Create("before.example", false); !errors.Is(err, fakeip.ErrCandidateNotCommitted) {
		t.Fatal("candidate emitted an answer", err)
	}
	commit, err := prepared.fenceRuntimeFakeIP()
	if err != nil {
		t.Fatal(err)
	}
	defer commit.Abort()
	commit.Publish()
	if _, err := store.Create("after.example", false); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeFakeIPAbortLeavesOriginalAllocator(t *testing.T) {
	manager, err := fakeip.NewManager(context.Background(), log.NewNOPFactory().Logger(), netip.MustParsePrefix("198.18.0.0/29"), netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	old, err := manager.Borrow(netip.MustParsePrefix("198.18.0.0/29"), netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	first, err := old.Create("same.example", false)
	if err != nil {
		t.Fatal(err)
	}
	instance := &Box{runtime: &runtimeCoordinator{ctx: context.Background(), fakeIP: manager}}
	candidate := runtimeFakeIPCandidate(t, "198.19.0.0/29")
	if err := instance.prepareRuntimeFakeIP(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	candidate.abort()
	again, err := old.Create("same.example", false)
	if err != nil || again != first {
		t.Fatal("abort mutated original allocator", again, err)
	}
	removed := &preparedRuntimeGraph{}
	if err := instance.prepareRuntimeFakeIP(context.Background(), removed); err != nil {
		t.Fatal(err)
	}
	if domain, ok := manager.RecognitionStore().Lookup(first); !ok || domain != "same.example" {
		t.Fatal("removal lost old recognition")
	}
}

func runtimeClientFakeIPIPv6(t *testing.T, options option.Options) option.Options {
	t.Helper()
	// Work on detached DNS options; never mutate the active graph's pointers.
	copyDNS := *options.DNS
	copyDNS.Servers = append([]option.DNSServerOptions(nil), options.DNS.Servers...)
	for index, server := range copyDNS.Servers {
		if server.Type != C.DNSTypeFakeIP {
			continue
		}
		var configuration option.FakeIPDNSServerOptions
		if err := json.Unmarshal([]byte(`{"inet4_range":"198.18.0.0/15","inet6_range":"2001:2::/48"}`), &configuration); err != nil {
			t.Fatal(err)
		}
		copyDNS.Servers[index].Options = &configuration
	}
	options.DNS = &copyDNS
	return options
}

// Same-range hot reload hands retained mappings to the next graph through the
// one Box Manager. A store_fakeip IPv6 range switch is a restart decision.
func TestRuntimeFakeIPHotReloadHandsOffMappingsInMemory(t *testing.T) {
	f, options := runtimeFakeIPCleanupConstruction(t, filepath.Join(t.TempDir(), "cache.db"), nil)
	runtimeFakeIPCleanupBox(t, f, options)
	if err := f.box.BindRuntimePersistenceOptions(func(RuntimeIdentity, []byte) error { return nil }, "exact_configuration_file", true); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	v4 := netip.MustParsePrefix("198.18.0.0/15")
	old, err := f.box.runtime.fakeIP.Borrow(v4, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	address, err := old.Create("retained.example", false)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := f.box.runtime.fakeIP.ProtectAnswer(&mdns.Msg{Answer: []mdns.RR{&mdns.A{
		Hdr: mdns.RR_Header{Name: "retained.example.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 3600},
		A:   net.IP(address.AsSlice()),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	answer.Delivered(time.Now())
	var next option.Options
	if err := json.UnmarshalContext(f.ctx, runtimeTestConfig(1080, "example.net"), &next); err != nil {
		t.Fatal(err)
	}
	next.DNS.Servers = append(next.DNS.Servers, options.DNS.Servers[len(options.DNS.Servers)-1])
	next.Experimental = options.Experimental
	encoded, err := json.MarshalContext(f.ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	_, request := f.plan(t, encoded)
	op, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || op.Active.Revision != request.Expected.Revision+1 {
		t.Fatal("same-range hot reload not published", op, err)
	}
	if v4After, v6After, initialized := f.box.runtime.fakeIP.RuntimeRangeIdentity(); !initialized || v4After != v4 || v6After.IsValid() {
		t.Fatal("same-range hot reload replaced the allocator", v4After, v6After)
	}
	current, err := f.box.runtime.fakeIP.Borrow(v4, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	reused, err := current.Create("retained.example", false)
	_ = current.Close()
	if err != nil || reused != address {
		t.Fatal("hot reload lost the in-memory mapping handoff", reused, err)
	}
	ipv6 := runtimeClientFakeIPIPv6(t, next)
	problems := f.box.runtimeClientFakeIPRangeProblems(ipv6, 1)
	if len(problems) != 1 || problems[0].Code != "RESTART_REQUIRED" || len(problems[0].DependencyPath) != 1 || problems[0].DependencyPath[0] != "fakeip.store_fakeip" {
		t.Fatal("store_fakeip range switch was not a restart decision", problems)
	}
	encoded, err = json.MarshalContext(f.ctx, ipv6)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := f.box.PlanRuntimeConfigWithClientImpactPolicy(context.Background(), "actor-a", f.identity(), encoded, nil, RuntimeClientImpactPolicyExplicit)
	if err != nil || plan.Applicable {
		t.Fatal("store_fakeip IPv6 range switch was planned as hot reload", plan, err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	runtimeFakeIPCleanupAssertSuccess(t, f.box)
}
