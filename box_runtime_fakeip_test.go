package box

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

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

// The callback below is an inert exact-byte persistence-owner fixture. It tests
// the real Box migration/ACK chain; it is not native or filesystem durability proof.
func TestRuntimeFakeIPProductionJournalUsesOriginalTransactionAndACK(t *testing.T) {
	root := t.TempDir()
	f, options := runtimeFakeIPCleanupConstruction(t, filepath.Join(root, "cache.db"), nil)
	options.Context = adapter.ContextWithRuntimeRecoveryRoot(options.Context, root)
	physical := runtimeFakeIPCleanupBox(t, f, options)
	owner := f.box.runtime.fakeIPPersistence
	if owner == nil || !owner.ready || owner.backend != physical {
		t.Fatal("production bootstrap did not retain actual cache/journal owner")
	}
	calls := 0
	fail := true
	var persisted RuntimeIdentity
	if err := f.box.BindRuntimePersistenceOptions(func(identity RuntimeIdentity, content []byte) error {
		calls++
		if runtimeDigest(content) != identity.EffectiveDigest {
			t.Error("callback identity differs from exact canonical bytes")
		}
		persisted = identity
		if fail {
			return errors.New("fixture original owner sync uncertain")
		}
		return nil
	}, "exact_configuration_file", true); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	old, err := f.box.runtime.fakeIP.Borrow(netip.MustParsePrefix("198.18.0.0/15"), netip.Prefix{})
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
	next := runtimeClientFakeIPIPv6(t, options.Options)
	if len(f.box.runtimeClientFakeIPRangeProblems(next, 0)) == 0 || len(f.box.runtimeClientFakeIPRangeProblems(next, 1)) != 0 {
		t.Fatal("policy-specific range boundary lost")
	}
	encoded, err := json.MarshalContext(f.ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := f.box.PlanRuntimeConfigWithClientImpactPolicy(context.Background(), "actor-a", f.identity(), encoded, nil, RuntimeClientImpactPolicyExplicit)
	if err != nil || !plan.Applicable {
		t.Fatal("real fixed IPv6 candidate not planned", plan, err)
	}
	request := RuntimeConfigApply{ContractVersion: 1, PlanID: plan.PlanID, TransactionID: plan.TransactionID, Expected: plan.Expected, CandidateDigest: plan.CandidateDigest, AcceptedImpactDigest: plan.ImpactDigest}
	op, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || op.Active.Revision != request.Expected.Revision+1 || op.Durable || calls != 1 || persisted != op.Active {
		t.Fatal("persistence failure obscured actual publication", op, err, calls)
	}
	if domain, found := f.box.runtime.fakeIP.RecognitionStore().Lookup(address); !found || domain != "retained.example" {
		t.Fatal("hot range publication lost retained mapping")
	}
	catalog, err := owner.journal.FakeIPRuntimeCatalog(context.Background())
	if err != nil || len(catalog.Links) != 1 || catalog.Links[0].ID != plan.TransactionID ||
		catalog.Links[0].EffectiveConfigurationID != op.Active.EffectiveDigest || catalog.Links[0].Acknowledged {
		t.Fatal("journal not bound to original unacknowledged transaction", catalog, err)
	}
	bad := runtimeFakeIPCandidate(t, "198.18.0.0/15")
	ctx := runtimeContextWithFakeIPTransaction(context.Background(), "different-transaction")
	if err := f.box.prepareRuntimeFakeIP(ctx, bad, runtimeFakeIPBinding{Identity: op.Active}); !errors.Is(err, fakeip.ErrPersistencePending) {
		t.Fatal("unacknowledged original migration was replayed", err)
	}
	fail = false
	retry := RuntimePersistenceRetry{ContractVersion: 1, TransactionID: op.TransactionID, Active: op.Active, PersistenceMode: "exact_configuration_file"}
	ack, err := f.box.retryRuntimePersistence(context.Background(), "actor-a", retry)
	if err != nil || !ack.Durable || ack.Active != op.Active || calls != 2 {
		t.Fatal("original transaction ACK did not finish", ack, err, calls)
	}
	catalog, err = owner.journal.FakeIPRuntimeCatalog(context.Background())
	if err != nil || len(catalog.Links) == 0 || !catalog.Links[0].Acknowledged {
		t.Fatal("exact ACK not persisted", err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	runtimeFakeIPCleanupAssertSuccess(t, f.box)
	// A distinct Box and registry use the same real journal/cache bytes. The
	// selected startup config is explicit; journal recovery never chooses it.
	f2, restart := runtimeFakeIPCleanupConstruction(t, filepath.Join(root, "cache.db"), nil)
	restart.Context = adapter.ContextWithRuntimeRecoveryRoot(restart.Context, root)
	restart.Options = runtimeClientFakeIPIPv6(t, restart.Options)
	runtimeFakeIPCleanupBox(t, f2, restart)
	f2.start(t)
	v4, v6, initialized := f2.box.runtime.fakeIP.RuntimeRangeIdentity()
	if !initialized || v4 != netip.MustParsePrefix("198.18.0.0/15") || v6 != netip.MustParsePrefix("2001:2::/48") {
		t.Fatal("cold startup did not select exact configured allocator", v4, v6)
	}
	if domain, found := f2.box.runtime.fakeIP.RecognitionStore().Lookup(address); !found || domain != "retained.example" {
		t.Fatal("cold recognition lost a retained valid answer")
	}
	current, err := f2.box.runtime.fakeIP.Borrow(v4, v6)
	if err != nil {
		t.Fatal(err)
	}
	ipv6, err := current.Create("ipv6.example", true)
	if err != nil || !ipv6.Is6() || !v6.Contains(ipv6) {
		_ = current.Close()
		t.Fatal("IPv6 allocator and published range disagree", ipv6, err)
	}
	_ = current.Close()
	runtimeFakeIPCleanupAssertSuccess(t, f2.box)
}

type runtimeFakeIPOnceService struct {
	calls int
	err   error
}

func (*runtimeFakeIPOnceService) Name() string { return "inert-cache" }
func (s *runtimeFakeIPOnceService) Start(stage adapter.StartStage, _ *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		s.calls++
	}
	return s.err
}

func TestRuntimeFakeIPCacheEarlyInitializeRetainsFailureAndOriginalReceiver(t *testing.T) {
	for _, failure := range []error{nil, errors.New("open failed")} {
		inner := &runtimeFakeIPOnceService{err: failure}
		wrapper := &runtimeFakeIPCacheService{LifecycleService: inner}
		scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
		defer scope.Close()
		for range 2 {
			if err := scope.Start(wrapper.Name(), wrapper, adapter.StartStateInitialize); !errors.Is(err, failure) {
				t.Fatal("initialization did not retain the actual result", err)
			}
		}
		if inner.calls != 1 {
			t.Fatal("early cache Initialize repeated", inner.calls)
		}
	}
}

func TestRuntimeFakeIPPersistentRangeCannotBorrowMissingRecoveryOwner(t *testing.T) {
	f, options := runtimeFakeIPCleanupConstruction(t, filepath.Join(t.TempDir(), "cache.db"), nil)
	runtimeFakeIPCleanupBox(t, f, options)
	if err := f.box.BindRuntimePersistence(func(RuntimeIdentity, []byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	next := runtimeClientFakeIPIPv6(t, options.Options)
	problems := f.box.runtimeClientFakeIPRangeProblems(next, 1)
	if len(problems) != 1 || len(problems[0].DependencyPath) != 1 || problems[0].DependencyPath[0] != "fakeip.recovery_root" {
		t.Fatal("missing actual host recovery owner hidden", problems)
	}
	if f.box.runtime.fakeIPPersistence != nil {
		t.Fatal("no-root startup invented journal custody")
	}
	if _, ok := service.FromContext[adapter.CacheFile](f.box.runtime.ctx).(*cachefile.CacheFile); !ok {
		t.Fatal("legacy registered physical cache changed")
	}
}
