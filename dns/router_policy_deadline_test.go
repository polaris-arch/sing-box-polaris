package dns

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// These one-shot hooks model a callback publishing while the walker is
// descheduled at a specific point. They do not alter the underlying rule.
type policyPublicationHookRule struct {
	adapter.DNSRule
	beforeTags func()
	beforeRace func()
	afterMatch func()
}

func (r *policyPublicationHookRule) MatchResponseTags() []string {
	if hook := r.beforeTags; hook != nil {
		r.beforeTags = nil
		hook()
	}
	return r.DNSRule.MatchResponseTags()
}

func (r *policyPublicationHookRule) Race() bool {
	if hook := r.beforeRace; hook != nil {
		r.beforeRace = nil
		hook()
	}
	return r.DNSRule.Race()
}

func (r *policyPublicationHookRule) Match(metadata *adapter.InboundContext) bool {
	matched := r.DNSRule.Match(metadata)
	if hook := r.afterMatch; hook != nil {
		r.afterMatch = nil
		hook()
	}
	return matched
}

func TestPolicyResponsePublicationCutoffDuringWalk(t *testing.T) {
	for _, racing := range []bool{false, true} {
		for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
			t.Run(fmt.Sprint("race=", racing, "/offset=", offset), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					one := policyReply("one", 0, 0, "192.0.2.1")
					two := policyReply("two", 0, 0, "192.0.2.2")
					raw := policyTestRules(t, []string{"one"}, []string{"two"})
					raw[1].DefaultOptions.Race = racing
					router := policyRouter(t, raw, one, two)
					msg := correctnessQuestion(mDNS.TypeA)
					ctx, cancel := withDNSPolicyBudget(context.Background(), time.Millisecond)
					defer cancel()
					ctx = adapter.WithContext(ctx, &adapter.InboundContext{DNSResolverPolicy: testPolicyID, QueryType: mDNS.TypeA})
					future := &dnsEvaluatedFuture{tag: "one-reply", transport: one, done: make(chan struct{})}
					state := &dnsRuleWalkState{policy: true, ruleIndex: 1, futures: []*dnsEvaluatedFuture{future}, namedFutures: map[string]*dnsEvaluatedFuture{future.tag: future}}
					router.rules[1] = &policyPublicationHookRule{DNSRule: router.rules[1], beforeTags: func() {
						// The top-of-iteration cutoff check has passed. Advance
						// only the virtual clock before publishing the callback.
						time.Sleep(time.Millisecond + offset)
						future.response = FixedResponse(0, msg.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 60)
						future.completedAt = time.Now()
						future.sequence = state.completion.Add(1)
						close(future.done)
					}}
					result, suspension := router.walkDNSRules(ctx, router.rules, msg, state, false)
					require.Nil(t, suspension)
					require.NoError(t, result.err)
					require.NotNil(t, result.response)
					require.Equal(t, offset, future.completedAt.Sub(dnsPolicyBudgetFrom(ctx).deadline))
					want := mDNS.RcodeSuccess
					if offset > 0 {
						want = mDNS.RcodeServerFailure
					}
					require.Equal(t, want, result.response.Rcode)
					require.Zero(t, two.calls.Load(), "deadline must not launch the next tier")
				})
			})
		}
	}
}

func TestPolicyResponsePublishedBetweenSettlementAndReadiness(t *testing.T) {
	for _, racing := range []bool{false, true} {
		t.Run(fmt.Sprint("race=", racing), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				one := policyReply("one", 0, 0, "192.0.2.1")
				raw := policyTestRules(t, []string{"one"})
				raw[1].DefaultOptions.Race = racing
				router := policyRouter(t, raw, one)
				msg := correctnessQuestion(mDNS.TypeA)
				ctx, cancel := withDNSPolicyBudget(context.Background(), time.Millisecond)
				defer cancel()
				ctx = adapter.WithContext(ctx, &adapter.InboundContext{DNSResolverPolicy: testPolicyID, QueryType: mDNS.TypeA})
				future := &dnsEvaluatedFuture{tag: "one-reply", transport: one, done: make(chan struct{})}
				state := &dnsRuleWalkState{policy: true, ruleIndex: 1, futures: []*dnsEvaluatedFuture{future}, namedFutures: map[string]*dnsEvaluatedFuture{future.tag: future}}
				router.rules[1] = &policyPublicationHookRule{DNSRule: router.rules[1], beforeRace: func() {
					// The first settlement scan already passed this unresolved
					// future. Publish before the walker checks whether to await it.
					future.response = FixedResponse(0, msg.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 60)
					future.completedAt = time.Now()
					future.sequence = state.completion.Add(1)
					close(future.done)
				}}
				result, suspension := router.walkDNSRules(ctx, router.rules, msg, state, false)
				require.Nil(t, suspension)
				require.NoError(t, result.err)
				require.NotNil(t, result.response)
				require.True(t, future.completedAt.Before(dnsPolicyBudgetFrom(ctx).deadline))
				require.Equal(t, mDNS.RcodeSuccess, result.response.Rcode, "a ready future must be installed before matching its response")
				require.Equal(t, "one", result.transport.Tag())
			})
		})
	}
}

func TestPolicyDeadlinePublishedSnapshotMatrix(t *testing.T) {
	for _, armed := range []bool{false, true} {
		for _, delivered := range []bool{false, true} {
			for _, empty := range []bool{false, true} {
				for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
					t.Run(fmt.Sprint("armed=", armed, "/timer=", delivered, "/empty=", empty, "/offset=", offset), func(t *testing.T) {
						synctest.Test(t, func(t *testing.T) {
							one := policyReply("one", 0, 0, "192.0.2.1")
							two := policyReply("two", 0, 0, "192.0.2.2")
							router := policyRouter(t, policyTestRules(t, []string{"one"}, []string{"two"}), one, two)
							msg := correctnessQuestion(mDNS.TypeA)
							parent := context.Background()
							var ctx context.Context
							if delivered {
								var cancel context.CancelFunc
								ctx, cancel = withDNSPolicyBudget(parent, time.Millisecond)
								defer cancel()
							} else {
								// The recorded cutoff expires even if its cancellation
								// timer has not run. No timer is attached in this branch.
								ctx = context.WithValue(parent, dnsPolicyBudgetKey{}, &dnsPolicyBudget{parent: parent, deadline: time.Now().Add(time.Millisecond)})
							}
							ctx = adapter.WithContext(ctx, &adapter.InboundContext{DNSResolverPolicy: testPolicyID, QueryType: mDNS.TypeA})
							response := FixedResponse(0, msg.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 60)
							if empty {
								response = FixedResponseStatus(msg, mDNS.RcodeNameError)
							}
							time.Sleep(time.Millisecond + offset)
							future := &dnsEvaluatedFuture{tag: "one-reply", transport: one, sequence: 1, completedAt: time.Now(), done: make(chan struct{}), response: response}
							close(future.done)
							state := &dnsRuleWalkState{policy: true, ruleIndex: 1, futures: []*dnsEvaluatedFuture{future}, namedFutures: map[string]*dnsEvaluatedFuture{future.tag: future}}
							if armed {
								state.ruleIndex = 3
								for _, index := range []int{1, 2} {
									state.armedRules = append(state.armedRules, &dnsArmedRule{ruleIndex: index, rule: router.rules[index], futures: []*dnsEvaluatedFuture{future}})
								}
							}
							// Model the walker resuming after its own cutoff.
							time.Sleep(time.Millisecond)
							require.True(t, dnsPolicyDeadlineExpired(ctx))
							if delivered {
								require.ErrorIs(t, context.Cause(ctx), errDNSPolicyBudget)
							} else {
								require.NoError(t, ctx.Err())
							}
							result, suspension := router.walkDNSRules(ctx, router.rules, msg, state, false)
							require.Nil(t, suspension)
							require.NoError(t, result.err)
							require.NotNil(t, result.response)
							require.Equal(t, offset, future.completedAt.Sub(dnsPolicyBudgetFrom(ctx).deadline))
							want := response.Rcode
							if offset > 0 {
								want = mDNS.RcodeServerFailure
							} else {
								wantWire, err := response.Pack()
								require.NoError(t, err)
								gotWire, err := result.response.Pack()
								require.NoError(t, err)
								require.Equal(t, wantWire, gotWire, "keep the complete admitted packet")
								require.Same(t, one, result.transport)
							}
							require.Equal(t, want, result.response.Rcode)
							require.Zero(t, two.calls.Load(), "deadline cannot launch the next tier")
						})
					})
				}
			}
		}
	}
}

func TestPolicyDeadlineRecheckedAfterMatching(t *testing.T) {
	for _, route := range []bool{false, true} {
		for _, stop := range []string{"own-deadline", "parent-cancel", "parent-deadline", "local-cancel"} {
			t.Run(fmt.Sprint("route=", route, "/", stop), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					one := policyReply("one", 0, 0, "192.0.2.1")
					raw := policyTestRules(t, []string{"one"})
					if route {
						first := routeRule("one", false)
						first.DefaultOptions.ResolverPolicy = new(testPolicyID)
						raw = append(raw[:0:0], first, raw[len(raw)-1])
					}
					router := policyRouter(t, raw, one)
					parent, cancelParent := context.WithCancel(context.Background())
					defer cancelParent()
					if stop == "parent-deadline" {
						var cancel context.CancelFunc
						parent, cancel = context.WithTimeout(parent, time.Millisecond/2)
						defer cancel()
					}
					ctx, cancel := withDNSPolicyBudget(parent, time.Millisecond)
					defer cancel()
					ctx = adapter.WithContext(ctx, &adapter.InboundContext{DNSResolverPolicy: testPolicyID, QueryType: mDNS.TypeA})
					router.rules[0] = &policyPublicationHookRule{DNSRule: router.rules[0], afterMatch: func() {
						switch stop {
						case "own-deadline", "parent-deadline":
							<-ctx.Done()
						case "parent-cancel":
							cancelParent()
						case "local-cancel":
							cancel()
						}
					}}
					state := &dnsRuleWalkState{policy: true, lastLoggedIndex: -1}
					result, suspension := router.walkDNSRules(ctx, router.rules, correctnessQuestion(mDNS.TypeA), state, false)
					require.Nil(t, suspension, "no pending route may escape after cancellation/cutoff")
					if stop == "own-deadline" {
						require.NoError(t, result.err)
						require.NotNil(t, result.response)
						require.Equal(t, mDNS.RcodeServerFailure, result.response.Rcode)
					} else {
						require.ErrorIs(t, result.err, ctx.Err())
						require.Nil(t, result.response)
					}
					require.Empty(t, state.futures, "no evaluate may be launched after cancellation/cutoff")
					require.Zero(t, one.calls.Load())
				})
			})
		}
	}
}

func TestOrdinaryResponsePublishedBetweenSettlementAndReadiness(t *testing.T) {
	for _, racing := range []bool{false, true} {
		t.Run(fmt.Sprint("race=", racing), func(t *testing.T) {
			one := policyReply("one", 0, 0, "192.0.2.1")
			router := raceTestRouter(t)
			rules := raceTestRules(t, []option.DNSRule{
				evaluateRule("one", "one-reply", false),
				respondRule("one-reply", racing, true),
				routeRule("final", false),
			})
			msg := correctnessQuestion(mDNS.TypeA)
			ctx := adapter.WithContext(context.Background(), &adapter.InboundContext{QueryType: mDNS.TypeA})
			future := &dnsEvaluatedFuture{tag: "one-reply", transport: one, done: make(chan struct{})}
			state := &dnsRuleWalkState{ruleIndex: 1, futures: []*dnsEvaluatedFuture{future}, namedFutures: map[string]*dnsEvaluatedFuture{future.tag: future}}
			rules[1] = &policyPublicationHookRule{DNSRule: rules[1], beforeRace: func() {
				future.response = FixedResponse(0, msg.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 60)
				future.completedAt = time.Now()
				future.sequence = state.completion.Add(1)
				close(future.done)
			}}
			result, suspension := router.walkDNSRules(ctx, rules, msg, state, false)
			require.Nil(t, suspension, "a ready response must not fall through to the default route")
			require.NoError(t, result.err)
			require.NotNil(t, result.response)
			require.Equal(t, mDNS.RcodeSuccess, result.response.Rcode)
			require.Same(t, one, result.transport)
		})
	}
}
