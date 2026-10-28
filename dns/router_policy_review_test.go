package dns

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestReviewPolicyMustNotPromoteEmptyHTTPSHintsToAddresses(t *testing.T) {
	upstream := &policyTestTransport{tag: "hint", exchange: func(ctx context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
		response := FixedResponseStatus(msg, mDNS.RcodeSuccess)
		rr, err := mDNS.NewRR("node.example. 60 IN HTTPS 1 . ipv4hint=203.0.113.9")
		if err != nil {
			return nil, err
		}
		response.Answer = []mDNS.RR{rr}
		return response, nil
	}}
	router := policyRouter(t, policyTestRules(t, []string{"hint"}), upstream)
	ips, err := router.Lookup(context.Background(), "node.example", policyOptions(time.Second))
	require.Error(t, err, "EMPTY containing only HTTPS hints must not become successful Lookup")
	require.Empty(t, ips)
}

func TestReviewPolicySettledSnapshotCannotSkipEarlierPublishedHit(t *testing.T) {
	one := policyReply("one", 0, 0, "192.0.2.1")
	two := policyReply("two", 0, 0, "192.0.2.2")
	raw := policyTestRules(t, []string{"one", "two"})
	router := policyRouter(t, raw, one, two)
	msg := &mDNS.Msg{Question: []mDNS.Question{{Name: "node.example.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}}}
	first := &dnsEvaluatedFuture{tag: "one-reply", transport: one, sequence: 1, done: make(chan struct{}), response: FixedResponse(0, msg.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 60)}
	second := &dnsEvaluatedFuture{tag: "two-reply", transport: two, sequence: 2, done: make(chan struct{}), response: FixedResponse(0, msg.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.2")}, 60), settled: true}
	close(first.done)
	close(second.done)
	// Valid interleaving: settle tests first.done before it closes; callbacks
	// publish first then second; settle reaches and installs only second.
	state := &dnsRuleWalkState{policy: true, futures: []*dnsEvaluatedFuture{first, second}, namedFutures: map[string]*dnsEvaluatedFuture{"one-reply": first, "two-reply": second}, namedResponses: map[string]*mDNS.Msg{"two-reply": second.response}, namedTransports: map[string]adapter.DNSTransport{"two-reply": two}}
	for _, i := range []int{1, 2, 4, 5} {
		state.armedRules = append(state.armedRules, &dnsArmedRule{ruleIndex: i, rule: router.rules[i]})
	}
	ctx := adapter.WithContext(context.Background(), &adapter.InboundContext{DNSResolverPolicy: testPolicyID, QueryType: mDNS.TypeA})
	result, _, committed := router.sweepArmedDNSRules(ctx, msg, state, false)
	if committed {
		require.Equal(t, "one", result.transport.Tag(), "earlier callback was published before sweep")
	}
}

func TestReviewPolicyDeadlineMustConsiderPublishedUnarmedHit(t *testing.T) {
	one := policyReply("one", 0, 0, "192.0.2.1")
	raw := policyTestRules(t, []string{"one"})
	router := policyRouter(t, raw, one)
	msg := &mDNS.Msg{Question: []mDNS.Question{{Name: "node.example.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}}}
	ctx, cancel := withDNSPolicyBudget(context.Background(), time.Millisecond)
	defer cancel()
	ctx = adapter.WithContext(ctx, &adapter.InboundContext{DNSResolverPolicy: testPolicyID, QueryType: mDNS.TypeA})
	first := &dnsEvaluatedFuture{tag: "one-reply", transport: one, sequence: 1, completedAt: time.Now(), done: make(chan struct{}), response: FixedResponse(0, msg.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 60)}
	close(first.done)
	// Evaluate has just returned and state.ruleIndex advances to its HIT rule.
	// The walker is descheduled until own deadline before arming that rule.
	state := &dnsRuleWalkState{policy: true, ruleIndex: 1, futures: []*dnsEvaluatedFuture{first}, namedFutures: map[string]*dnsEvaluatedFuture{"one-reply": first}}
	<-ctx.Done()
	result, _ := router.walkDNSRules(ctx, router.rules, msg, state, false)
	require.NoError(t, result.err)
	require.NotNil(t, result.response)
	require.Equal(t, mDNS.RcodeSuccess, result.response.Rcode, "published pre-cutoff HIT must survive deadline")
}

func TestReviewPolicyFinalLookupNeverWidensClassifierAddresses(t *testing.T) {
	for _, test := range []struct {
		name    string
		records []string
		want    []netip.Addr
	}{
		{name: "https-empty", records: []string{"node.example. 60 IN HTTPS 1 . ipv4hint=203.0.113.9"}},
		{name: "non-IN-empty", records: []string{"node.example. 60 CH A 203.0.113.9"}},
		{name: "wrong-family-empty", records: []string{"node.example. 60 IN AAAA 2001:db8::9", "node.example. 60 IN HTTPS 1 . ipv4hint=203.0.113.9"}},
		{name: "hit-with-hint-and-non-IN", records: []string{"node.example. 60 IN A 192.0.2.1", "node.example. 60 IN HTTPS 1 . ipv4hint=203.0.113.9", "node.example. 60 CH A 203.0.113.10"}, want: []netip.Addr{netip.MustParseAddr("192.0.2.1")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			upstream := &policyTestTransport{tag: "answer", exchange: func(_ context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
				response := FixedResponseStatus(msg, mDNS.RcodeSuccess)
				for _, text := range test.records {
					record, err := mDNS.NewRR(text)
					if err != nil {
						return nil, err
					}
					response.Answer = append(response.Answer, record)
				}
				soa, err := mDNS.NewRR("example. 60 IN SOA ns.example. hostmaster.example. 1 60 60 60 60")
				if err != nil {
					return nil, err
				}
				response.Ns = []mDNS.RR{soa}
				return response, nil
			}}
			router := policyRouter(t, policyTestRules(t, []string{"answer"}), upstream)
			for range 2 {
				ips, err := router.Lookup(context.Background(), "node.example", policyOptions(time.Second))
				if len(test.want) == 0 {
					require.Error(t, err)
					require.Empty(t, ips)
				} else {
					require.NoError(t, err)
					require.Equal(t, test.want, ips)
				}
			}
			require.EqualValues(t, 1, upstream.calls.Load(), "both cold and warm final response paths are exercised")
			cached, err := policyExchange(t, router, context.Background(), time.Second)
			require.NoError(t, err)
			require.Len(t, cached.Answer, len(test.records), "the final original EMPTY/HIT packet remains intact in cache")
		})
	}
}

func TestReviewPolicyDeadlineIncludesOnlyLaunchedPreCutoffResponses(t *testing.T) {
	for _, kind := range []string{"hit", "empty", "late-hit", "late-empty"} {
		t.Run(kind, func(t *testing.T) {
			one := policyReply("one", 0, 0, "192.0.2.1")
			second := policyReply("tier2", 0, 0, "192.0.2.2")
			router := policyRouter(t, policyTestRules(t, []string{"one"}, []string{"tier2"}), one, second)
			msg := &mDNS.Msg{Question: []mDNS.Question{{Name: "node.example.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}}}
			ctx, cancel := withDNSPolicyBudget(context.Background(), time.Millisecond)
			defer cancel()
			ctx = adapter.WithContext(ctx, &adapter.InboundContext{DNSResolverPolicy: testPolicyID, QueryType: mDNS.TypeA})
			response := FixedResponse(0, msg.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 60)
			if kind == "empty" || kind == "late-empty" {
				response = FixedResponseStatus(msg, mDNS.RcodeNameError)
			}
			completed := dnsPolicyBudgetFrom(ctx).deadline.Add(-time.Nanosecond)
			if kind == "late-hit" || kind == "late-empty" {
				completed = completed.Add(2 * time.Nanosecond)
			}
			future := &dnsEvaluatedFuture{tag: "one-reply", transport: one, sequence: 1, completedAt: completed, done: make(chan struct{}), response: response}
			close(future.done)
			state := &dnsRuleWalkState{policy: true, ruleIndex: 1, futures: []*dnsEvaluatedFuture{future}, namedFutures: map[string]*dnsEvaluatedFuture{"one-reply": future}}
			<-ctx.Done()
			result, _ := router.walkDNSRules(ctx, router.rules, msg, state, false)
			require.NoError(t, result.err)
			require.NotNil(t, result.response)
			want := response.Rcode
			if kind == "late-hit" || kind == "late-empty" {
				want = mDNS.RcodeServerFailure
			}
			require.Equal(t, want, result.response.Rcode)
			require.Zero(t, second.calls.Load(), "deadline may not launch next tier")
		})
	}
}

func TestReviewPolicyExchangeCallbackMustHonorPolicy(t *testing.T) {
	node := policyReply("node", 0, 0, "192.0.2.1")
	ordinary := policyReply("ordinary", 0, 0, "192.0.2.99")
	raw := append(policyTestRules(t, []string{"node"}), routeRule("ordinary", false))
	router := policyRouter(t, raw, node, ordinary)
	// Same call used by protocol/naive/outbound.go's Cronet DNSResolver callback,
	// with QueryOptions inherited from the generated node domain_resolver.
	response, err := router.Exchange(context.Background(), &mDNS.Msg{Question: []mDNS.Question{{Name: "node.example.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}}}, policyOptions(time.Second))
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, MessageToAddresses(response))
	require.Zero(t, ordinary.calls.Load())
}

func TestReviewPolicyExchangeRejectsUnsupportedQuestionsAndPreservesCancel(t *testing.T) {
	upstream := policyReply("node", 0, 0, "192.0.2.1")
	router := policyRouter(t, policyTestRules(t, []string{"node"}), upstream)
	for _, question := range [][]mDNS.Question{nil, {{Name: "node.example.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassCHAOS}}, {{Name: "node.example.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}, {Name: "node.example.", Qtype: mDNS.TypeAAAA, Qclass: mDNS.ClassINET}}} {
		_, err := router.Exchange(context.Background(), &mDNS.Msg{Question: question}, policyOptions(time.Second))
		require.Error(t, err)
	}
	require.Zero(t, upstream.calls.Load())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := &mDNS.Msg{Question: []mDNS.Question{{Name: "node.example.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}}}
	_, err := router.Exchange(ctx, request, policyOptions(time.Second))
	require.ErrorIs(t, err, context.Canceled)
	done := make(chan error, 1)
	router.ExchangeAsync(context.Background(), request, policyOptions(time.Second), func(response *mDNS.Msg, err error) {
		if err == nil && len(dnsPolicyAnswerAddresses(response, mDNS.TypeA)) != 1 {
			err = context.DeadlineExceeded
		}
		done <- err
	})
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("policy async callback stalled")
	}
}

func TestReviewPolicyAbsoluteCutoffWithoutTimerDelivery(t *testing.T) {
	upstream := policyReply("node", 0, 0, "192.0.2.1")
	router := policyRouter(t, policyTestRules(t, []string{"node"}), upstream)
	parent := context.Background()
	ctx := context.WithValue(parent, dnsPolicyBudgetKey{}, &dnsPolicyBudget{parent: parent, deadline: time.Now().Add(-time.Millisecond)})
	request := &mDNS.Msg{Question: []mDNS.Question{{Name: "node.example.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}}}
	require.NoError(t, ctx.Err(), "model a timer which has not delivered cancellation yet")
	response, err := router.Exchange(ctx, request, policyOptions(time.Second))
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeServerFailure, response.Rcode)
	require.Zero(t, upstream.calls.Load(), "absolute cutoff prevents launching an expired candidate")
}
