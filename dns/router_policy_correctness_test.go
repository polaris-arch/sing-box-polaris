package dns

import (
	"context"
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
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type correctnessCacheEntry struct {
	message []byte
	expire  time.Time
}

type correctnessCacheStore struct {
	mu          sync.Mutex
	entries     map[string]correctnessCacheEntry
	writes      int
	loadBarrier func()
	saveBarrier func()
}

func (s *correctnessCacheStore) LoadDNSCache(transport, name string, qtype uint16) ([]byte, time.Time, bool) {
	s.mu.Lock()
	entry, ok := s.entries[fmt.Sprint(transport, "|", name, "|", qtype)]
	barrier := s.loadBarrier
	s.mu.Unlock()
	if ok && barrier != nil {
		barrier()
	}
	return append([]byte(nil), entry.message...), entry.expire, ok
}

func (s *correctnessCacheStore) SaveDNSCache(transport, name string, qtype uint16, message []byte, expire time.Time) error {
	s.mu.Lock()
	if s.entries == nil {
		s.entries = make(map[string]correctnessCacheEntry)
	}
	s.entries[fmt.Sprint(transport, "|", name, "|", qtype)] = correctnessCacheEntry{append([]byte(nil), message...), expire}
	s.writes++
	barrier := s.saveBarrier
	s.mu.Unlock()
	if barrier != nil {
		barrier()
	}
	return nil
}

func (s *correctnessCacheStore) SaveDNSCacheAsync(transport, name string, qtype uint16, message []byte, expire time.Time, _ logger.Logger) {
	_ = s.SaveDNSCache(transport, name, qtype, message, expire)
}

func (s *correctnessCacheStore) ClearDNSCache() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = nil
	return nil
}

func (s *correctnessCacheStore) writeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes
}

type correctnessRDRC struct{ writes atomic.Int32 }

func (*correctnessRDRC) LoadRDRC(string, string, uint16) bool                  { return false }
func (s *correctnessRDRC) SaveRDRC(string, string, uint16) error               { s.writes.Add(1); return nil }
func (s *correctnessRDRC) SaveRDRCAsync(string, string, uint16, logger.Logger) { s.writes.Add(1) }

func correctnessQuestion(qtype uint16) *mDNS.Msg {
	return &mDNS.Msg{Id: 42, Question: []mDNS.Question{{Name: "node.example.", Qtype: qtype, Qclass: mDNS.ClassINET}}}
}

func correctnessRouter(t *testing.T, strategy C.DomainStrategy, rules []option.DNSRule, store *correctnessCacheStore, transport *policyTestTransport) *Router {
	t.Helper()
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), &fakeDNSTransportManager{transports: map[string]adapter.DNSTransport{transport.tag: transport}})
	options := option.DNSOptions{Strategy: option.DomainStrategy(strategy)}
	router, err := NewRouter(ctx, log.NewNOPFactory(), options)
	require.NoError(t, err)
	require.NoError(t, router.Initialize(rules))
	router.rules = raceTestRules(t, rules)
	t.Cleanup(func() { closeRules(router.rules) })
	// Use the existing persistent-store interface, shared across actual Router constructions.
	client := router.client.(*Client)
	client.initDNSCacheFunc = func() adapter.DNSCacheStore { return store }
	router.client.Start()
	return router
}

func correctnessWire(t *testing.T, router *Router, ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions, async bool) (*mDNS.Msg, error) {
	t.Helper()
	if !async {
		return router.Exchange(ctx, message, options)
	}
	type result struct {
		response *mDNS.Msg
		err      error
	}
	done := make(chan result, 1)
	router.ExchangeAsync(ctx, message, options, func(response *mDNS.Msg, err error) { done <- result{response, err} })
	select {
	case got := <-done:
		return got.response, got.err
	case <-time.After(5 * time.Second):
		t.Fatal("DNS callback did not complete")
		return nil, context.DeadlineExceeded
	}
}

func TestPolicyGlobalStrategyAcrossPersistentRouterCaches(t *testing.T) {
	for _, async := range []bool{false, true} {
		for _, family := range []struct {
			qtype          uint16
			only, override C.DomainStrategy
			address        string
		}{
			{mDNS.TypeAAAA, C.DomainStrategyIPv4Only, C.DomainStrategyIPv6Only, "2001:db8::1"},
			{mDNS.TypeA, C.DomainStrategyIPv6Only, C.DomainStrategyIPv4Only, "192.0.2.1"},
		} {
			t.Run(fmt.Sprint(async, "/", family.qtype), func(t *testing.T) {
				store := new(correctnessCacheStore)
				hit := policyReply("hit", 0, mDNS.RcodeSuccess, family.address)
				rules := policyTestRules(t, []string{"hit"})
				options := adapter.DNSQueryOptions{UseRules: true, Policy: testPolicyID, Timeout: time.Second}
				first := correctnessRouter(t, C.DomainStrategyAsIS, rules, store, hit)
				response, err := correctnessWire(t, first, context.Background(), correctnessQuestion(family.qtype), options, async)
				require.NoError(t, err)
				require.Len(t, response.Answer, 1)
				require.Positive(t, store.writeCount())
				second := correctnessRouter(t, family.only, rules, store, hit)
				require.NotEqual(t, first.policyConfigIdentity, second.policyConfigIdentity)
				same := correctnessRouter(t, family.only, rules, store, hit)
				require.Equal(t, second.policyConfigIdentity, same.policyConfigIdentity)
				before := hit.calls.Load()
				warm, err := correctnessWire(t, second, context.Background(), correctnessQuestion(family.qtype), options, async)
				require.NoError(t, err)
				require.Empty(t, warm.Answer)
				cold := correctnessRouter(t, family.only, rules, new(correctnessCacheStore), hit)
				coldResponse, err := correctnessWire(t, cold, context.Background(), correctnessQuestion(family.qtype), options, async)
				require.NoError(t, err)
				require.Equal(t, warm.Answer, coldResponse.Answer)
				require.Equal(t, before, hit.calls.Load(), "family rejection precedes transport/cache reuse")
				options.Strategy = family.override
				overridden, err := correctnessWire(t, second, context.Background(), correctnessQuestion(family.qtype), options, async)
				require.NoError(t, err)
				require.Len(t, overridden.Answer, 1)
				lookupOptions := adapter.DNSQueryOptions{UseRules: true, Policy: testPolicyID, Timeout: time.Second, LookupStrategy: family.override}
				addresses, err := second.Lookup(context.Background(), "node.example", lookupOptions)
				require.NoError(t, err)
				require.Equal(t, []netip.Addr{netip.MustParseAddr(family.address)}, addresses)
				require.Equal(t, C.DomainStrategyAsIS, lookupOptions.Strategy, "caller options remain unchanged")
				// Returning to the permissive configuration may reuse its valid namespace.
				back := correctnessRouter(t, C.DomainStrategyAsIS, rules, store, hit)
				options.Strategy = C.DomainStrategyAsIS
				response, err = correctnessWire(t, back, context.Background(), correctnessQuestion(family.qtype), options, async)
				require.NoError(t, err)
				require.Len(t, response.Answer, 1)
			})
		}
	}
}

func TestPolicyScopedActionStrategyRejectedDuringInitialize(t *testing.T) {
	for _, action := range []string{"", C.RuleActionTypeRoute, C.RuleActionTypeEvaluate, C.RuleActionTypeRouteOptions} {
		for _, strategy := range []C.DomainStrategy{C.DomainStrategyAsIS, C.DomainStrategyIPv4Only, C.DomainStrategyIPv6Only, C.DomainStrategyPreferIPv4, C.DomainStrategyPreferIPv6} {
			t.Run(fmt.Sprint(action, "/", strategy), func(t *testing.T) {
				rules := policyTestRules(t, []string{"hit"})
				first := routeRule("hit", false)
				first.DefaultOptions.ResolverPolicy = new(testPolicyID)
				first.DefaultOptions.Action = action
				switch action {
				case C.RuleActionTypeEvaluate:
					first = rules[0]
					first.DefaultOptions.EvaluateOptions.Strategy = option.DomainStrategy(strategy)
				case C.RuleActionTypeRouteOptions:
					first.DefaultOptions.RouteOptionsOptions.DisableCache = true
					first.DefaultOptions.RouteOptionsOptions.Strategy = option.DomainStrategy(strategy)
				default:
					first.DefaultOptions.RouteOptions.Strategy = option.DomainStrategy(strategy)
				}
				if action == C.RuleActionTypeEvaluate {
					rules[0] = first
				} else {
					rules = append([]option.DNSRule{first}, rules...)
				}
				// Marshal the default route with its canonical action so its
				// options survive. A zero action intentionally marshals as {}.
				wireRules := append([]option.DNSRule(nil), rules...)
				if action == "" {
					wireRules[0].DefaultOptions.Action = C.RuleActionTypeRoute
				}
				encoded, err := json.Marshal(wireRules)
				require.NoError(t, err)
				var wireObjects []map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(encoded, &wireObjects))
				// Exercise both omitted and explicit route actions on the wire.
				if action != "" {
					wireObjects[0]["action"], err = json.Marshal(action)
					require.NoError(t, err)
				}
				encoded, err = json.Marshal(wireObjects)
				require.NoError(t, err)
				var roundTrip []option.DNSRule
				require.NoError(t, json.UnmarshalContext(context.Background(), encoded, &roundTrip))
				decodedAction := roundTrip[0].DefaultOptions.DNSRuleAction
				var decodedStrategy option.DomainStrategy
				switch action {
				case C.RuleActionTypeEvaluate:
					decodedStrategy = decodedAction.EvaluateOptions.Strategy
				case C.RuleActionTypeRouteOptions:
					decodedStrategy = decodedAction.RouteOptionsOptions.Strategy
				default:
					decodedStrategy = decodedAction.RouteOptions.Strategy
				}
				require.Equal(t, option.DomainStrategy(strategy), decodedStrategy, "wire fixture must preserve the action strategy")
				for _, input := range []struct {
					name  string
					rules []option.DNSRule
				}{{"direct", rules}, {"json", roundTrip}} {
					t.Run(input.name, func(t *testing.T) {
						router := raceTestRouter(t)
						err := router.Initialize(input.rules)
						if strategy == C.DomainStrategyAsIS {
							require.NoError(t, err)
						} else {
							require.ErrorContains(t, err, "policy "+testPolicyID+" rule[0]")
							require.ErrorContains(t, err, "strategy")
						}
					})
				}
			})
		}
	}
}

func TestPolicyCompletionIgnoresOperationCancelButHonorsParentAndCutoff(t *testing.T) {
	parent, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()
	cutoff := time.Now().Add(time.Hour)
	ctx := context.WithValue(parent, dnsPolicyBudgetKey{}, &dnsPolicyBudget{parent: parent, deadline: cutoff})
	operation, cancel := context.WithCancel(ctx)
	cancel()
	require.NoError(t, dnsPolicyCompletionError(operation, cutoff))
	require.ErrorIs(t, dnsPolicyCompletionError(operation, cutoff.Add(time.Nanosecond)), context.DeadlineExceeded)
	parentCancel()
	require.ErrorIs(t, dnsPolicyCompletionError(operation, cutoff.Add(time.Nanosecond)), context.Canceled)
	require.NoError(t, dnsPolicyCompletionError(context.Background(), cutoff))
}

func TestPolicyLatePrivateRouteDoesNotCacheOrFallThrough(t *testing.T) {
	for _, async := range []bool{false, true} {
		for _, cancelParent := range []bool{false, true} {
			t.Run(fmt.Sprint(async, "/parent=", cancelParent), func(t *testing.T) {
				started := make(chan struct{})
				var once sync.Once
				private := &policyTestTransport{tag: "private", exchange: func(ctx context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
					once.Do(func() { close(started) })
					<-ctx.Done()
					return FixedResponse(msg.Id, msg.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 60), nil
				}}
				public := policyReply("public", 0, 0, "192.0.2.2")
				first := routeRule("private", false)
				first.DefaultOptions.ResolverPolicy = new(testPolicyID)
				rules := append([]option.DNSRule{first}, policyTestRules(t, []string{"public"})...)
				router := policyRouter(t, rules, private, public)
				store := new(correctnessCacheStore)
				router.client.(*Client).dnsCache = store
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				if cancelParent {
					go func() {
						select {
						case <-started:
							cancel()
						case <-parent.Done():
						}
					}()
				}
				response, err := correctnessWire(t, router, parent, correctnessQuestion(mDNS.TypeA), policyOptions(20*time.Millisecond), async)
				if cancelParent {
					require.ErrorIs(t, err, context.Canceled)
				} else {
					require.ErrorIs(t, err, context.DeadlineExceeded)
				}
				require.Nil(t, response)
				require.Zero(t, store.writeCount())
				require.Zero(t, public.calls.Load())
				// No successful inner or outer response was admitted to shared storage.
				require.EqualValues(t, 1, private.calls.Load())
			})
		}
	}
}

func TestPolicyDelayedCheckerCannotWriteResponseOrRDRC(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		for _, async := range []bool{false, true} {
			t.Run(fmt.Sprint(accepted, "/", async), func(t *testing.T) {
				store := new(correctnessCacheStore)
				rdrc := new(correctnessRDRC)
				client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
				client.dnsCache = store
				client.rdrc = rdrc
				hit := policyReply("hit", 0, 0, "192.0.2.1")
				parent := context.Background()
				budget := &dnsPolicyBudget{parent: parent, deadline: time.Now().Add(time.Hour)}
				ctx := context.WithValue(parent, dnsPolicyBudgetKey{}, budget)
				entered := make(chan struct{})
				release := make(chan struct{})
				checker := func(*mDNS.Msg) bool {
					close(entered)
					<-release
					return accepted
				}
				type result struct {
					response *mDNS.Msg
					err      error
				}
				done := make(chan result, 1)
				go func() {
					if async {
						client.ExchangeAsync(ctx, hit, correctnessQuestion(mDNS.TypeA), adapter.DNSQueryOptions{}, checker, func(response *mDNS.Msg, err error) { done <- result{response, err} })
					} else {
						response, err := client.Exchange(ctx, hit, correctnessQuestion(mDNS.TypeA), adapter.DNSQueryOptions{}, checker)
						done <- result{response, err}
					}
				}()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					close(release)
					t.Fatal("checker was not entered")
				}
				// Test-only cutoff advancement while the worker is blocked. No
				// budget reader runs in this phase; release establishes happens-before.
				// The context timer is deliberately not canceled: the absolute
				// recorded cutoff must reject the result despite delayed delivery.
				budget.deadline = time.Now().Add(-time.Nanosecond)
				close(release)
				got := <-done
				require.ErrorIs(t, got.err, context.DeadlineExceeded)
				require.Nil(t, got.response)
				require.Zero(t, store.writeCount())
				require.Zero(t, rdrc.writes.Load())
			})
		}
	}
}

func TestPolicyAsyncSuccessfulLocalCancelStillCaches(t *testing.T) {
	store := new(correctnessCacheStore)
	client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
	client.dnsCache = store
	hit := policyReply("hit", 0, 0, "192.0.2.1")
	ctx, cancel := withDNSPolicyBudget(context.Background(), time.Hour)
	defer cancel()
	done := make(chan error, 1)
	client.ExchangeAsync(ctx, hit, correctnessQuestion(mDNS.TypeA), adapter.DNSQueryOptions{}, nil, func(response *mDNS.Msg, err error) {
		if response == nil && err == nil {
			err = fmt.Errorf("missing successful response")
		}
		done <- err
	})
	require.NoError(t, <-done)
	require.Equal(t, 1, store.writeCount())
}

func TestPolicyDirectRouteChecksCachedAndPostAdmissionReturnBoundary(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(fmt.Sprint("cached=", cached), func(t *testing.T) {
			router := raceTestRouter(t)
			store := new(correctnessCacheStore)
			router.client = NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
			router.client.(*Client).dnsCache = store
			hit := policyReply("private", 0, 0, "192.0.2.1")
			question := correctnessQuestion(mDNS.TypeA)
			options := adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only}
			if cached {
				_, err := router.client.Exchange(context.Background(), hit, question.Copy(), options, nil)
				require.NoError(t, err)
			}
			parent := context.Background()
			budget := &dnsPolicyBudget{parent: parent, deadline: time.Now().Add(time.Hour)}
			ctx := context.WithValue(parent, dnsPolicyBudgetKey{}, budget)
			entered := make(chan struct{})
			release := make(chan struct{})
			barrier := func() { close(entered); <-release }
			if cached {
				store.loadBarrier = barrier
			} else {
				// Store entry proves the inner response passed its admission guard.
				store.saveBarrier = barrier
			}
			done := make(chan exchangeWithRulesResult, 1)
			go func() {
				done <- router.finishPendingExchange(ctx, question.Copy(), &dnsRuleWalkState{}, &dnsPendingExchange{transport: hit, options: options})
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				close(release)
				t.Fatal("cache boundary was not entered")
			}
			// Advance only the test-owned cutoff while no budget reader runs.
			// Cache admission in the store branch has already occurred; the
			// later route-return check must reject without undoing that admission.
			budget.deadline = time.Now().Add(-time.Nanosecond)
			close(release)
			result := <-done
			require.ErrorIs(t, result.err, context.DeadlineExceeded)
			require.Nil(t, result.response)
			require.Equal(t, 1, store.writeCount())
			require.EqualValues(t, 1, hit.calls.Load())
			store.loadBarrier = nil
			store.saveBarrier = nil
			response, err := router.client.Exchange(context.Background(), hit, question.Copy(), options, nil)
			require.NoError(t, err)
			require.Len(t, response.Answer, 1)
			require.EqualValues(t, 1, hit.calls.Load(), "a valid pre-cutoff inner cache entry remains reusable")
		})
	}
}
