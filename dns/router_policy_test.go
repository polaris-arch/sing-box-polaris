package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

const testPolicyID = "node-bootstrap"

func policyTestRules(t *testing.T, tiers ...[]string) []option.DNSRule {
	t.Helper()
	var rules []option.DNSRule
	for _, tier := range tiers {
		for index, server := range tier {
			evaluate := evaluateRule(server, server+"-reply", index > 0)
			evaluate.DefaultOptions.ResolverPolicy = new(testPolicyID)
			evaluate.DefaultOptions.EvaluateOptions.Timeout = badoption.Duration(1500 * time.Millisecond)
			evaluate.DefaultOptions.EvaluateOptions.DisableCache = true
			evaluate.DefaultOptions.EvaluateOptions.DisableOptimisticCache = true
			rules = append(rules, evaluate)
			hit := respondRule(server+"-reply", true, false)
			hit.DefaultOptions.ResolverPolicy = new(testPolicyID)
			hit.DefaultOptions.ResponseClass = "hit"
			prefix := badoption.Prefixable(netip.MustParsePrefix("203.0.113.0/24"))
			hit.DefaultOptions.ResponseRejectIPCIDR = []*badoption.Prefixable{&prefix}
			empty := respondRule(server+"-reply", true, false)
			empty.DefaultOptions.ResolverPolicy = new(testPolicyID)
			empty.DefaultOptions.ResponseClass = "empty"
			empty.DefaultOptions.RespondOptions.Mode = "defer"
			rules = append(rules, hit, empty)
		}
	}
	fail := option.DNSRCode(mDNS.RcodeServerFailure)
	rules = append(rules, option.DNSRule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultDNSRule{
		RawDefaultDNSRule: option.RawDefaultDNSRule{ResolverPolicy: new(testPolicyID)},
		DNSRuleAction:     option.DNSRuleAction{Action: C.RuleActionTypeRespond, RespondOptions: option.DNSRespondActionOptions{Mode: "fallback", FallbackRcode: &fail}},
	}})
	for i := range rules {
		rules[i].Type = C.RuleTypeDefault
	}
	return rules
}

type policyTestTransport struct {
	tag      string
	calls    atomic.Int32
	epoch    atomic.Uint64
	exchange func(context.Context, *mDNS.Msg) (*mDNS.Msg, error)
}

func (t *policyTestTransport) Type() string                                   { return "test" }
func (t *policyTestTransport) Tag() string                                    { return t.tag }
func (t *policyTestTransport) Dependencies() []string                         { return nil }
func (t *policyTestTransport) Reset()                                         {}
func (t *policyTestTransport) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (t *policyTestTransport) Environment() []string                          { return []string{fmt.Sprint(t.epoch.Load())} }

func (t *policyTestTransport) Exchange(ctx context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
	t.calls.Add(1)
	return t.exchange(ctx, msg)
}

func (t *policyTestTransport) ExchangeAsync(ctx context.Context, msg *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() { callback(t.Exchange(ctx, msg)) }()
}

func policyReply(tag string, delay time.Duration, rcode int, addresses ...string) *policyTestTransport {
	return &policyTestTransport{tag: tag, exchange: func(ctx context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if rcode != mDNS.RcodeSuccess {
			response := FixedResponseStatus(msg, rcode)
			if rcode == mDNS.RcodeNameError {
				// Only a negative answer with a usable SOA TTL is cacheable.
				soa, err := mDNS.NewRR("example. 60 IN SOA ns.example. hostmaster.example. 1 60 60 60 60")
				if err != nil {
					return nil, err
				}
				response.Ns = []mDNS.RR{soa}
			}
			return response, nil
		}
		var ips []netip.Addr
		for _, address := range addresses {
			ips = append(ips, netip.MustParseAddr(address))
		}
		return FixedResponse(msg.Id, msg.Question[0], ips, 60), nil
	}}
}

func policyRouter(t *testing.T, rules []option.DNSRule, transports ...*policyTestTransport) *Router {
	t.Helper()
	router := raceTestRouter(t)
	mapping := make(map[string]adapter.DNSTransport)
	for _, transport := range transports {
		mapping[transport.tag] = transport
	}
	router.transport = &fakeDNSTransportManager{transports: mapping}
	router.rawRules = rules
	router.rules = raceTestRules(t, rules)
	require.NoError(t, router.validateDNSPolicies())
	router.client = NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
	return router
}

func policyOptions(timeout time.Duration) adapter.DNSQueryOptions {
	return adapter.DNSQueryOptions{UseRules: true, Policy: testPolicyID, Strategy: C.DomainStrategyIPv4Only, Timeout: timeout}
}

func policyExchange(t *testing.T, router *Router, ctx context.Context, timeout time.Duration) (*mDNS.Msg, error) {
	t.Helper()
	options := policyOptions(timeout)
	transport, err := router.policyTransport(testPolicyID, "node.example", options)
	require.NoError(t, err)
	ctx, cancel := withDNSPolicyBudget(ctx, timeout)
	defer cancel()
	return router.client.Exchange(ctx, transport, &mDNS.Msg{Id: 42, Question: []mDNS.Question{{Name: "node.example.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}}}, options, nil)
}

func TestResolverPolicyFastEmptyDoesNotBeatSlowHitOrStartTier2(t *testing.T) {
	empty := policyReply("empty", time.Millisecond, mDNS.RcodeNameError)
	hit := policyReply("hit", 30*time.Millisecond, mDNS.RcodeSuccess, "192.0.2.1")
	second := policyReply("tier2", 0, mDNS.RcodeSuccess, "192.0.2.2")
	router := policyRouter(t, policyTestRules(t, []string{"empty", "hit"}, []string{"tier2"}), empty, hit, second)
	answer, err := router.Lookup(context.Background(), "node.example", policyOptions(time.Second))
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, answer)
	require.Zero(t, second.calls.Load())
}

func TestResolverPolicyFirstEmptyAcrossTiersAndFinalNegativeCache(t *testing.T) {
	slower := policyReply("slower", 25*time.Millisecond, mDNS.RcodeSuccess)
	first := policyReply("first", time.Millisecond, mDNS.RcodeNameError)
	second := policyReply("second", time.Millisecond, mDNS.RcodeSuccess)
	router := policyRouter(t, policyTestRules(t, []string{"slower", "first"}, []string{"second"}), slower, first, second)
	for range 2 {
		response, err := policyExchange(t, router, context.Background(), time.Second)
		require.NoError(t, err)
		require.Equal(t, mDNS.RcodeNameError, response.Rcode)
		require.EqualValues(t, 42, response.Id)
	}
	require.EqualValues(t, 1, first.calls.Load())
	require.EqualValues(t, 1, second.calls.Load())
}

func TestResolverPolicyOwnDeadlineRetainsEmptyAndParentCancelDoesNot(t *testing.T) {
	for _, parentCancel := range []bool{false, true} {
		t.Run(fmt.Sprint(parentCancel), func(t *testing.T) {
			empty := policyReply("empty", time.Millisecond, mDNS.RcodeNameError)
			blocked := policyReply("blocked", time.Hour, mDNS.RcodeSuccess, "192.0.2.1")
			second := policyReply("second", 0, mDNS.RcodeSuccess, "192.0.2.2")
			router := policyRouter(t, policyTestRules(t, []string{"empty", "blocked"}, []string{"second"}), empty, blocked, second)
			parent := context.Background()
			cancel := func() {}
			if parentCancel {
				parent, cancel = context.WithTimeout(parent, 20*time.Millisecond)
			}
			defer cancel()
			started := time.Now()
			response, err := policyExchange(t, router, parent, 60*time.Millisecond)
			if parentCancel {
				require.Error(t, err)
				require.Nil(t, response)
			} else {
				require.NoError(t, err)
				require.Equal(t, mDNS.RcodeNameError, response.Rcode)
			}
			require.Less(t, time.Since(started), 300*time.Millisecond)
			require.Zero(t, second.calls.Load())
		})
	}
}

func TestResolverPolicyAllFailuresAreNotCachedAndNoDomesticFallthrough(t *testing.T) {
	fail := policyReply("fail", 0, mDNS.RcodeServerFailure)
	router := policyRouter(t, policyTestRules(t, []string{"fail"}), fail)
	for range 2 {
		response, err := policyExchange(t, router, context.Background(), time.Second)
		require.NoError(t, err)
		require.Equal(t, mDNS.RcodeServerFailure, response.Rcode)
	}
	require.EqualValues(t, 2, fail.calls.Load())
}

func TestResolverPolicyFinalCacheAndRejectedCandidateRecovery(t *testing.T) {
	poisoned := policyReply("poisoned", 0, mDNS.RcodeSuccess, "192.0.2.1", "203.0.113.9")
	fallback := policyReply("fallback", 10*time.Millisecond, mDNS.RcodeSuccess, "192.0.2.2")
	router := policyRouter(t, policyTestRules(t, []string{"poisoned", "fallback"}), poisoned, fallback)
	for range 2 {
		addresses, err := router.Lookup(context.Background(), "node.example", policyOptions(time.Second))
		require.NoError(t, err)
		require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.2")}, addresses)
	}
	require.EqualValues(t, 1, poisoned.calls.Load())
	require.EqualValues(t, 1, fallback.calls.Load())
	router.client.ClearCache()
	poisoned.exchange = policyReply("unused", 0, mDNS.RcodeSuccess, "192.0.2.3").exchange
	addresses, err := router.Lookup(context.Background(), "node.example", policyOptions(time.Second))
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.3")}, addresses)
	require.EqualValues(t, 2, poisoned.calls.Load())
}

func TestResolverPolicyCacheEpochAndDisabledCache(t *testing.T) {
	hit := policyReply("hit", time.Millisecond, mDNS.RcodeSuccess, "192.0.2.1")
	router := policyRouter(t, policyTestRules(t, []string{"hit"}), hit)
	options := policyOptions(time.Second)
	for range 2 {
		_, err := router.Lookup(context.Background(), "node.example", options)
		require.NoError(t, err)
	}
	require.EqualValues(t, 1, hit.calls.Load())
	hit.epoch.Add(1)
	_, err := router.Lookup(context.Background(), "node.example", options)
	require.NoError(t, err)
	require.EqualValues(t, 2, hit.calls.Load())
	options.DisableCache = true
	for range 2 {
		_, err = router.Lookup(context.Background(), "node.example", options)
		require.NoError(t, err)
	}
	require.EqualValues(t, 4, hit.calls.Load())
}

func TestResolverPolicyConcurrentIdenticalQueriesCoalesce(t *testing.T) {
	hit := policyReply("hit", 30*time.Millisecond, mDNS.RcodeSuccess, "192.0.2.1")
	router := policyRouter(t, policyTestRules(t, []string{"hit"}), hit)
	var group sync.WaitGroup
	errorsFound := make(chan error, 10)
	for range 10 {
		group.Go(func() {
			_, err := router.Lookup(context.Background(), "node.example", policyOptions(time.Second))
			errorsFound <- err
		})
	}
	group.Wait()
	close(errorsFound)
	for err := range errorsFound {
		require.NoError(t, err)
	}
	require.EqualValues(t, 1, hit.calls.Load())
}

func TestResolverPolicyAOnlySystemBindingDoesNotWaitForMissingAAAA(t *testing.T) {
	system := policyReply("system", 0, mDNS.RcodeSuccess, "192.0.2.1")
	rules := policyTestRules(t, []string{"system"})
	rules[0].DefaultOptions.QueryType = []option.DNSQueryType{option.DNSQueryType(mDNS.TypeA)}
	router := policyRouter(t, rules, system)
	options := policyOptions(time.Second)
	options.Strategy = C.DomainStrategyPreferIPv4
	started := time.Now()
	addresses, err := router.Lookup(context.Background(), "node.example", options)
	require.NoError(t, err)
	require.Len(t, addresses, 1)
	require.Less(t, time.Since(started), 300*time.Millisecond)
	require.EqualValues(t, 1, system.calls.Load())
}

func TestResolverPolicyDualStackJoinsBeforeReturn(t *testing.T) {
	finished := make(chan uint16, 2)
	transport := &policyTestTransport{tag: "dual", exchange: func(ctx context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
		q := msg.Question[0].Qtype
		if q == mDNS.TypeA {
			finished <- q
			return FixedResponse(msg.Id, msg.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 60), nil
		}
		<-ctx.Done()
		finished <- q
		return nil, ctx.Err()
	}}
	router := policyRouter(t, policyTestRules(t, []string{"dual"}), transport)
	options := policyOptions(40 * time.Millisecond)
	options.Strategy = C.DomainStrategyPreferIPv4
	addresses, err := router.Lookup(context.Background(), "node.example", options)
	require.NoError(t, err)
	require.Len(t, addresses, 1)
	// Native transport cancellation is cooperative; ensure the test transport sees it.
	for range 2 {
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("query worker did not cancel")
		}
	}
}

func TestResolverPolicyValidationAndSerialization(t *testing.T) {
	valid := policyTestRules(t, []string{"one"})
	encoded, err := json.Marshal(valid)
	require.NoError(t, err)
	var decoded []option.DNSRule
	require.NoError(t, json.UnmarshalContext(context.Background(), encoded, &decoded))
	require.Equal(t, valid, decoded)
	for _, mutate := range []func([]option.DNSRule){
		func(r []option.DNSRule) { r[0].DefaultOptions.Inbound = []string{"caller-dependent"} },
		func(r []option.DNSRule) { r[0].DefaultOptions.EvaluateOptions.DisableCache = false },
		func(r []option.DNSRule) { r[len(r)-1].DefaultOptions.Domain = []string{"conditional.example"} },
		func(r []option.DNSRule) { r[1].DefaultOptions.MatchResponse.Tag = "other-scope" },
	} {
		rules := policyTestRules(t, []string{"one"})
		mutate(rules)
		router := raceTestRouter(t)
		router.rawRules = rules
		require.Error(t, router.validateDNSPolicies())
	}
}

func TestResolverPolicyRecursionRejectedBeforeCacheWait(t *testing.T) {
	router := policyRouter(t, policyTestRules(t, []string{"one"}), policyReply("one", 0, 0, "192.0.2.1"))
	parent := context.WithValue(context.Background(), dnsPolicyActiveKey(testPolicyID), true)
	_, err := router.Lookup(parent, "node.example", policyOptions(time.Second))
	require.Error(t, err)
	require.False(t, errors.Is(err, context.DeadlineExceeded))
}

func TestResolverPolicyReadyHitUsesCompletionOrderNotRuleOrder(t *testing.T) {
	one := policyReply("one", 0, 0, "192.0.2.1")
	two := policyReply("two", 0, 0, "192.0.2.2")
	raw := policyTestRules(t, []string{"one", "two"})
	router := policyRouter(t, raw, one, two)
	message := &mDNS.Msg{Question: []mDNS.Question{{Name: "node.example.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}}}
	first := &dnsEvaluatedFuture{tag: "one-reply", transport: one, sequence: 2, done: make(chan struct{}), response: FixedResponse(0, message.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 60)}
	second := &dnsEvaluatedFuture{tag: "two-reply", transport: two, sequence: 1, done: make(chan struct{}), response: FixedResponse(0, message.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.2")}, 60)}
	close(first.done)
	close(second.done)
	state := &dnsRuleWalkState{policy: true, futures: []*dnsEvaluatedFuture{first, second}, namedFutures: map[string]*dnsEvaluatedFuture{"one-reply": first, "two-reply": second}}
	for _, index := range []int{1, 2, 4, 5} {
		state.armedRules = append(state.armedRules, &dnsArmedRule{ruleIndex: index, rule: router.rules[index]})
	}
	ctx := adapter.WithContext(context.Background(), &adapter.InboundContext{DNSResolverPolicy: testPolicyID, QueryType: mDNS.TypeA})
	router.settleDNSFutures(ctx, message, state)
	result, _, committed := router.sweepArmedDNSRules(ctx, message, state, false)
	require.True(t, committed)
	require.Equal(t, "two", result.transport.Tag())
}

func TestResolverPolicyInFlightEnvironmentChangeDoesNotStore(t *testing.T) {
	hit := policyReply("hit", 0, 0, "192.0.2.1")
	ordinary := hit.exchange
	hit.exchange = func(ctx context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
		if hit.calls.Load() == 1 {
			hit.epoch.Add(1)
		}
		return ordinary(ctx, msg)
	}
	router := policyRouter(t, policyTestRules(t, []string{"hit"}), hit)
	for range 3 {
		_, err := router.Lookup(context.Background(), "node.example", policyOptions(time.Second))
		require.NoError(t, err)
	}
	require.EqualValues(t, 2, hit.calls.Load(), "first query crossed environment change and cannot be cached")
}

func TestResolverPolicyOwnBudgetWithoutEmptyIsSERVFAIL(t *testing.T) {
	blocked := policyReply("blocked", time.Hour, 0, "192.0.2.1")
	router := policyRouter(t, policyTestRules(t, []string{"blocked"}), blocked)
	response, err := policyExchange(t, router, context.Background(), 20*time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeServerFailure, response.Rcode)
}

func TestResolverPolicyTTLExpiresAndDisabledOptimisticCacheRefreshes(t *testing.T) {
	hit := policyReply("hit", 0, 0, "192.0.2.1")
	router := policyRouter(t, policyTestRules(t, []string{"hit"}), hit)
	router.client = NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger(), OptimisticTimeout: time.Hour})
	options := policyOptions(time.Second)
	options.RewriteTTL = new(uint32(1))
	options.DisableOptimisticCache = true
	_, err := router.Lookup(context.Background(), "node.example", options)
	require.NoError(t, err)
	time.Sleep(1100 * time.Millisecond)
	_, err = router.Lookup(context.Background(), "node.example", options)
	require.NoError(t, err)
	require.EqualValues(t, 2, hit.calls.Load())
}

func TestResolverPolicyPolicyChangeGetsSeparateCacheNamespace(t *testing.T) {
	hit := policyReply("hit", 0, 0, "192.0.2.1")
	router := policyRouter(t, policyTestRules(t, []string{"hit"}), hit)
	_, err := router.Lookup(context.Background(), "node.example", policyOptions(time.Second))
	require.NoError(t, err)
	router.rawRules[1].DefaultOptions.ResponseRejectIPCIDR = nil
	router.rules = raceTestRules(t, router.rawRules)
	_, err = router.Lookup(context.Background(), "node.example", policyOptions(time.Second))
	require.NoError(t, err)
	require.EqualValues(t, 2, hit.calls.Load())
}

func TestResolverPolicyDoesNotChangeOrdinaryLegacyMode(t *testing.T) {
	legacy := routeRule("final", false)
	prefix := badoption.Prefixable(netip.MustParsePrefix("192.0.2.0/24"))
	legacy.DefaultOptions.IPCIDR = []*badoption.Prefixable{&prefix}
	raw := append([]option.DNSRule{legacy}, policyTestRules(t, []string{"node"})...)
	router := raceTestRouter(t)
	router.rawRules = raw
	rules, mode, _, err := router.buildRules(false)
	require.NoError(t, err)
	require.True(t, mode)
	router.rules = rules
	require.Len(t, router.ordinaryDNSRules(), 1)
	require.Len(t, rules, len(raw), "all scoped rules remain lifecycle-owned")
}

func TestResolverPolicyNeverRunsForOrdinaryExchangeEvenInheritedMetadata(t *testing.T) {
	node := policyReply("node", 0, 0, "192.0.2.1")
	final := policyReply("final", 0, 0, "192.0.2.99")
	raw := append(policyTestRules(t, []string{"node"}), routeRule("final", false))
	router := policyRouter(t, raw, node, final)
	ctx := adapter.WithContext(context.Background(), &adapter.InboundContext{DNSResolverPolicy: testPolicyID})
	response, err := router.Exchange(ctx, &mDNS.Msg{Question: []mDNS.Question{{Name: "node.example.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}}}, adapter.DNSQueryOptions{})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.99")}, MessageToAddresses(response))
	require.Zero(t, node.calls.Load())
}

func TestResolverPolicyOptimisticRefreshReconstructsScope(t *testing.T) {
	hit := policyReply("hit", 0, 0, "192.0.2.1")
	refreshed := make(chan struct{}, 1)
	original := hit.exchange
	hit.exchange = func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		response, err := original(ctx, message)
		if hit.calls.Load() > 1 {
			response = FixedResponse(message.Id, message.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.2")}, 60)
			select {
			case refreshed <- struct{}{}:
			default:
			}
		}
		return response, err
	}
	router := policyRouter(t, policyTestRules(t, []string{"hit"}), hit)
	router.client = NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger(), OptimisticTimeout: time.Hour})
	options := policyOptions(time.Second)
	options.RewriteTTL = new(uint32(1))
	caller := adapter.WithContext(context.Background(), &adapter.InboundContext{Inbound: "foreground-only"})
	_, err := router.Lookup(caller, "node.example", options)
	require.NoError(t, err)
	time.Sleep(1100 * time.Millisecond)
	stale, err := router.Lookup(caller, "node.example", options)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, stale)
	select {
	case <-refreshed:
	case <-time.After(time.Second):
		t.Fatal("refresh never entered policy")
	}
	require.Eventually(t, func() bool {
		result, err := router.Lookup(caller, "node.example", options)
		return err == nil && len(result) == 1 && result[0] == netip.MustParseAddr("192.0.2.2")
	}, time.Second, time.Millisecond)
}

func TestResolverPolicyGlobalDisableCacheRemainsEffective(t *testing.T) {
	hit := policyReply("hit", 0, 0, "192.0.2.1")
	router := policyRouter(t, policyTestRules(t, []string{"hit"}), hit)
	router.client = NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger(), DisableCache: true})
	for range 2 {
		_, err := router.Lookup(context.Background(), "node.example", policyOptions(time.Second))
		require.NoError(t, err)
	}
	require.EqualValues(t, 2, hit.calls.Load())
}

type policyPreferredTransport struct {
	*policyTestTransport
	enabled atomic.Bool
}

func (p *policyPreferredTransport) PreferredDomain(domain string) bool {
	return domain == "node.example." && p.enabled.Load()
}

func TestResolverPolicyDynamicMeshOwnershipInvalidatesPublicCache(t *testing.T) {
	public := policyReply("public", 0, 0, "192.0.2.1")
	private := policyReply("mesh-dns", 0, 0, "100.64.0.1")
	preferred := &policyPreferredTransport{policyTestTransport: private}
	protect := routeRule("mesh-dns", false)
	protect.Type = C.RuleTypeDefault
	protect.DefaultOptions.ResolverPolicy = new(testPolicyID)
	protect.DefaultOptions.PreferredBy = []string{"mesh-dns"}
	raw := append([]option.DNSRule{protect}, policyTestRules(t, []string{"public"})...)
	router := policyRouter(t, raw, public, private)
	router.transport.(*fakeDNSTransportManager).transports["mesh-dns"] = preferred
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), router.transport)
	for index, rawRule := range raw {
		rule, err := R.NewDNSRule(ctx, log.NewNOPFactory().Logger(), rawRule, true, false)
		require.NoError(t, err)
		require.NoError(t, rule.Start())
		t.Cleanup(func() { require.NoError(t, rule.Close()) })
		router.rules[index] = rule
	}
	for range 2 {
		ips, err := router.Lookup(context.Background(), "node.example", policyOptions(time.Second))
		require.NoError(t, err)
		require.Equal(t, netip.MustParseAddr("192.0.2.1"), ips[0])
	}
	require.EqualValues(t, 1, public.calls.Load())
	preferred.enabled.Store(true)
	ips, err := router.Lookup(context.Background(), "node.example", policyOptions(time.Second))
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("100.64.0.1"), ips[0])
	require.EqualValues(t, 1, public.calls.Load())
	require.EqualValues(t, 1, private.calls.Load())
}

func TestResolverPolicyDoesNotConsumeCompletionBeforeSettled(t *testing.T) {
	upstream := policyReply("one", 0, 0, "192.0.2.1")
	raw := policyTestRules(t, []string{"one"})
	router := policyRouter(t, raw, upstream)
	message := &mDNS.Msg{Question: []mDNS.Question{{Name: "node.example.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}}}
	future := &dnsEvaluatedFuture{tag: "one-reply", transport: upstream, sequence: 1, done: make(chan struct{}), response: FixedResponse(0, message.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 60)}
	close(future.done)
	state := &dnsRuleWalkState{policy: true, futures: []*dnsEvaluatedFuture{future}, namedFutures: map[string]*dnsEvaluatedFuture{"one-reply": future}}
	state.armedRules = []*dnsArmedRule{{ruleIndex: 1, rule: router.rules[1]}, {ruleIndex: 2, rule: router.rules[2]}}
	ctx := adapter.WithContext(context.Background(), &adapter.InboundContext{DNSResolverPolicy: testPolicyID, QueryType: mDNS.TypeA})
	// Callback completion can occur between settle and the snapshot. Until
	// the sweep must install metadata atomically with its ready snapshot.
	result, _, committed := router.sweepArmedDNSRules(ctx, message, state, false)
	require.True(t, committed)
	require.Equal(t, "one", result.transport.Tag())
}
