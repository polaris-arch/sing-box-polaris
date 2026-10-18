package dns

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func rulesLookupOptions(t *testing.T, strategy C.DomainStrategy, timeout time.Duration) adapter.DNSQueryOptions {
	options, err := dialer.NewDNSQueryOptions(context.Background(), &option.DomainResolveOptions{Mode: option.DomainResolverModeRules, Strategy: option.DomainStrategy(strategy)}, true)
	require.NoError(t, err)
	options.Timeout = timeout
	return options
}

func TestDNSRulesLookupPreservesIPv6AndCallerMetadata(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "evaluate_rules", true: "legacy_rules"}[legacy], func(t *testing.T) {
			final := &fakeDNSTransport{tag: "final", address: netip.MustParseAddr("192.0.2.99")}
			target := &fakeDNSTransport{tag: "target", address: netip.MustParseAddr("2001:db8::1")}
			router := raceTestRouter(t, final, target)
			router.defaultDomainStrategy = C.DomainStrategyIPv4Only
			router.legacyDNSMode = legacy
			nodeRule := routeRule("target", false)
			nodeRule.DefaultOptions.Domain = []string{"node.example"}
			probeRule := routeRule("final", false)
			probeRule.DefaultOptions.Inbound = []string{"probe-in-0"}
			router.rules = raceTestRules(t, []option.DNSRule{nodeRule, probeRule})
			original := &adapter.InboundContext{Inbound: "probe-in-0", Domain: "destination.example", Destination: M.ParseSocksaddr("destination.example:443")}
			ctx := adapter.WithContext(context.Background(), original)
			options := rulesLookupOptions(t, C.DomainStrategyPreferIPv4, time.Second)
			addresses, err := router.Lookup(ctx, "node.example", options)
			require.NoError(t, err)
			require.Equal(t, []netip.Addr{target.address}, addresses)
			require.Equal(t, "destination.example", original.Domain)
			require.Equal(t, "destination.example", original.Destination.Fqdn)
			require.Zero(t, final.queryCount.Load(), "node rule must precede probe exit DNS to avoid a bootstrap loop")
			// A named transport keeps its old bypass behavior, despite DNS rules.
			direct, err := router.Lookup(ctx, "node.example", adapter.DNSQueryOptions{Transport: final, Strategy: C.DomainStrategyIPv4Only})
			require.NoError(t, err)
			require.Equal(t, []netip.Addr{final.address}, direct)
		})
	}
}

func TestDNSRulesLookupHasOneBudgetAcrossFallbackLayers(t *testing.T) {
	first := &fakeDNSTransport{tag: "first", delay: 120 * time.Millisecond, exchangeErr: context.DeadlineExceeded}
	second := &fakeDNSTransport{tag: "second", delay: 120 * time.Millisecond, address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, first, second)
	router.rules = raceTestRules(t, []option.DNSRule{evaluateRule("first", "first-response", false), respondRule("first-response", false, true), routeRule("second", false)})
	started := time.Now()
	addresses, err := router.Lookup(context.Background(), "node.example", rulesLookupOptions(t, C.DomainStrategyIPv4Only, 180*time.Millisecond))
	require.Error(t, err)
	require.Empty(t, addresses, "fallback must not receive a fresh total budget")
	require.Less(t, time.Since(started), 500*time.Millisecond)
	require.EqualValues(t, 1, second.queryCount.Load(), "exercise the fallback, not just the first timeout")
}

type rulesCancelTransport struct {
	fakeDNSTransport
	started  chan uint16
	canceled chan uint16
	once     sync.Once
	deadline time.Time
}

func (t *rulesCancelTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.once.Do(func() { t.deadline, _ = ctx.Deadline() })
	qType := message.Question[0].Qtype
	t.started <- qType
	<-ctx.Done()
	t.canceled <- qType
	return nil, ctx.Err()
}

func (t *rulesCancelTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() { callback(t.Exchange(ctx, message)) }()
}

func TestDNSRulesLookupCancellationAndDefaultBudget(t *testing.T) {
	transport := &rulesCancelTransport{tag: "blocked", started: make(chan uint16, 2), canceled: make(chan uint16, 2)}
	router := raceTestRouter(t)
	router.transport = &fakeDNSTransportManager{transports: map[string]adapter.DNSTransport{"blocked": transport}, defaultTransport: transport}
	router.rules = raceTestRules(t, []option.DNSRule{evaluateRule("blocked", "pending", true), respondRule("pending", true, true)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	started := time.Now()
	options := rulesLookupOptions(t, C.DomainStrategyPreferIPv4, 0)
	go func() {
		_, err := router.Lookup(ctx, "node.example", options)
		result <- err
	}()
	for range 2 {
		select {
		case <-transport.started:
		case <-time.After(time.Second):
			t.Fatal("A/AAAA query did not start")
		}
	}
	require.WithinDuration(t, started.Add(C.DNSTimeout), transport.deadline, time.Second)
	cancel()
	select {
	case err := <-result:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("lookup ignored caller cancellation")
	}
	for range 2 {
		select {
		case <-transport.canceled:
		case <-time.After(time.Second):
			t.Fatal("evaluate query survived lookup cancellation")
		}
	}
}

func TestDNSRulesLookupCacheAndDisableCache(t *testing.T) {
	transport := &fakeDNSTransport{tag: "final", address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, transport)
	router.client = NewClient(ClientOptions{Context: context.Background(), Logger: router.logger})
	router.rules = raceTestRules(t, []option.DNSRule{routeRule("final", false)})
	options := rulesLookupOptions(t, C.DomainStrategyIPv4Only, time.Second)
	for range 2 {
		addresses, err := router.Lookup(context.Background(), "node.example", options)
		require.NoError(t, err)
		require.Equal(t, []netip.Addr{transport.address}, addresses)
	}
	require.EqualValues(t, 1, transport.queryCount.Load())
	options.DisableCache = true
	_, err := router.Lookup(context.Background(), "node.example", options)
	require.NoError(t, err)
	require.EqualValues(t, 2, transport.queryCount.Load())
	_, err = router.Lookup(context.Background(), "node.example", adapter.DNSQueryOptions{UseRules: true, Transport: transport})
	require.ErrorContains(t, err, "rules lookup cannot specify")
}

func TestDNSRulesLookupEarlierCallerDeadline(t *testing.T) {
	transport := &fakeDNSTransport{tag: "final", delay: time.Second, address: netip.MustParseAddr("192.0.2.2")}
	router := raceTestRouter(t, transport)
	router.rules = raceTestRules(t, []option.DNSRule{routeRule("final", false)})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := router.Lookup(ctx, "node.example", rulesLookupOptions(t, C.DomainStrategyIPv4Only, 2*time.Second))
	require.Error(t, err)
	require.Less(t, time.Since(started), 500*time.Millisecond)
}

// DNS servers reject rules mode before creating a dialer, for domain/IP/local
// servers alike. These constructors do not start a kernel or open a listener.
func TestDNSRulesModeRejectedByTransportBootstrap(t *testing.T) {
	options := option.DialerOptions{DomainResolver: &option.DomainResolveOptions{Mode: option.DomainResolverModeRules}}
	for _, server := range []string{"resolver.example", "192.0.2.1"} {
		_, err := NewRemoteDialer(context.Background(), option.RemoteDNSServerOptions{DialerOptions: options, Server: server})
		require.ErrorContains(t, err, "cannot use rules mode")
	}
	_, err := NewLocalDialer(context.Background(), option.LocalDNSServerOptions{DialerOptions: options})
	require.ErrorContains(t, err, "cannot use rules mode")
}

type rulesPoisonTransport struct {
	fakeDNSTransport
	poison bool
}

func (t *rulesPoisonTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.queryCount.Add(1)
	addresses := []netip.Addr{t.address}
	if t.poison {
		addresses = append(addresses, netip.MustParseAddr("203.0.113.1"))
	}
	return FixedResponse(message.Id, message.Question[0], addresses, 1), nil
}

func (t *rulesPoisonTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	callback(t.Exchange(ctx, message))
}

// Exercise the signed-off logical rule + route-back-to-server form through
// the new entry. A mixed answer must stay rejected even while cached. A
// recovered upstream is not re-queried until that rejected cache entry expires.
func TestDNSRulesLookupMixedAnswerRemainsRejectedInInnerCache(t *testing.T) {
	primary := &rulesPoisonTransport{tag: "primary", address: netip.MustParseAddr("192.0.2.11"), poison: true}
	fallback := &fakeDNSTransport{tag: "fallback", address: netip.MustParseAddr("192.0.2.12"), immediate: true}
	router := raceTestRouter(t)
	router.client = NewClient(ClientOptions{Context: context.Background(), Logger: router.logger})
	router.transport = &fakeDNSTransportManager{transports: map[string]adapter.DNSTransport{"primary": primary, "fallback": fallback}, defaultTransport: fallback}
	var rawRules []option.DNSRule
	require.NoError(t, json.UnmarshalContext(context.Background(), []byte(`[
  {"action":"evaluate","server":"primary","tag":"primary"},
  {"type":"logical","mode":"and","rules":[
   {"domain":"node.example"},
   {"match_response":"primary","ip_accept_any":true},
   {"match_response":"primary","ip_cidr":"203.0.113.0/24","invert":true}
  ],"action":"route","server":"primary","race":true},
  {"action":"evaluate","server":"fallback","tag":"fallback","speculative":true},
  {"match_response":"fallback","ip_accept_any":true,"action":"respond","race":true},
  {"action":"predefined","rcode":"SERVFAIL"}
 ]`), &rawRules))
	router.rules = raceTestRules(t, rawRules)
	options := rulesLookupOptions(t, C.DomainStrategyIPv4Only, time.Second)
	addresses, err := router.Lookup(context.Background(), "node.example", options)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{fallback.address}, addresses, "mixed decoy/clean answer must be rejected")
	require.EqualValues(t, 1, primary.queryCount.Load())
	primary.poison = false
	addresses, err = router.Lookup(context.Background(), "node.example", options)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{fallback.address}, addresses, "cached mixed answer must remain rejected after upstream recovery")
	require.EqualValues(t, 1, primary.queryCount.Load(), "rejected answer stays in the upstream's cache until TTL")
	time.Sleep(1100 * time.Millisecond)
	addresses, err = router.Lookup(context.Background(), "node.example", options)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{primary.address}, addresses)
	require.EqualValues(t, 2, primary.queryCount.Load(), "evaluate and route must reuse the fresh cached response")
}
