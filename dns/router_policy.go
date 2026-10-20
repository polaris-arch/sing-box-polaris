package dns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"

	mDNS "github.com/miekg/dns"
)

var errDNSPolicyBudget = errors.New("DNS resolver policy budget exhausted")

type (
	dnsPolicyBudgetKey struct{}
	dnsPolicyActiveKey string
	dnsPolicyBudget    struct {
		parent   context.Context
		deadline time.Time
	}
)

func withDNSPolicyBudget(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	budget := &dnsPolicyBudget{parent: parent, deadline: time.Now().Add(timeout)}
	ctx, cancel := context.WithDeadlineCause(parent, budget.deadline, errDNSPolicyBudget)
	return context.WithValue(ctx, dnsPolicyBudgetKey{}, budget), cancel
}

func dnsPolicyBudgetFrom(ctx context.Context) *dnsPolicyBudget {
	budget, _ := ctx.Value(dnsPolicyBudgetKey{}).(*dnsPolicyBudget)
	return budget
}

// dnsPolicyCompletionError checks the recorded policy budget at logical admission.
// Operation-local cancellation is deliberately ignored: ExchangeAsync cancels its
// operation before finishExchange, including on an otherwise successful result.
func dnsPolicyCompletionError(ctx context.Context, completedAt time.Time) error {
	budget := dnsPolicyBudgetFrom(ctx)
	if budget == nil {
		return nil
	}
	if err := budget.parent.Err(); err != nil {
		return err
	}
	if completedAt.After(budget.deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func dnsPolicyID(raw option.DNSRule) string {
	if raw.Type != "" && raw.Type != C.RuleTypeDefault {
		return ""
	}
	if raw.DefaultOptions.ResolverPolicy == nil {
		return ""
	}
	return *raw.DefaultOptions.ResolverPolicy
}

func unscopedDNSRules(rules []option.DNSRule) []option.DNSRule {
	var result []option.DNSRule
	for _, raw := range rules {
		if dnsPolicyID(raw) == "" {
			result = append(result, raw)
		}
	}
	return result
}

// Policy slices may depend on question/response/immutable configuration only.
// The allowlist fails closed when new generic match fields are added later.
func validateDNSPolicyCondition(raw option.RawDefaultDNSRule) error {
	allowed := map[string]bool{
		"ResolverPolicy": true, "ResponseClass": true, "ResponseRejectIPCIDR": true,
		"Domain": true, "DomainSuffix": true, "DomainKeyword": true, "DomainRegex": true,
		"QueryType": true, "IPVersion": true, "MatchResponse": true, "ResponseRcode": true,
		"ResponseAnswer": true, "ResponseNs": true, "ResponseExtra": true,
		"PreferredBy": true,
	}
	value := reflect.ValueOf(raw)
	kind := value.Type()
	for i := 0; i < value.NumField(); i++ {
		if !allowed[kind.Field(i).Name] && !value.Field(i).IsZero() {
			return E.New("resolver_policy cannot depend on ", kind.Field(i).Name)
		}
	}
	return nil
}

func (r *Router) validateDNSPolicies() error {
	groups := make(map[string][]option.DNSRule)
	for ruleIndex, raw := range r.rawRules {
		if raw.Type == C.RuleTypeLogical {
			if raw.LogicalOptions.RespondOptions.Mode != "" && raw.LogicalOptions.RespondOptions.Mode != "immediate" {
				return E.New("scoped respond is not supported on logical rules")
			}
			continue
		}
		opts := raw.DefaultOptions
		if opts.ResolverPolicy != nil && *opts.ResolverPolicy == "" {
			return E.New("empty resolver_policy")
		}
		if id := dnsPolicyID(raw); id != "" {
			if dnsRuleActionHasStrategy(opts.DNSRuleAction) {
				return E.New("policy ", id, " rule[", ruleIndex, "]: deprecated action strategy is not supported in resolver_policy")
			}
			if err := validateDNSPolicyCondition(opts.RawDefaultDNSRule); err != nil {
				return E.Cause(err, "policy ", id)
			}
			groups[id] = append(groups[id], raw)
		}
	}
	for id, rules := range groups {
		_, err := validateLegacyDNSModeDisabledRules(nil, rules, nil)
		if err != nil {
			return E.Cause(err, "policy ", id)
		}
		fallbacks := 0
		for index, raw := range rules {
			opts := raw.DefaultOptions
			if opts.Action == C.RuleActionTypeRespond && opts.RespondOptions.Mode == "fallback" {
				fallbacks++
				if index != len(rules)-1 {
					return E.New("policy fallback must be last: ", id)
				}
				// Terminal fallback cannot have a condition that could fall through.
				conditions := opts.RawDefaultDNSRule
				conditions.ResolverPolicy = nil
				if !reflect.ValueOf(conditions).IsZero() {
					return E.New("policy fallback must be unconditional: ", id)
				}
			}
			if opts.Race && (opts.Action != C.RuleActionTypeRespond || opts.ResponseClass == "") {
				return E.New("policy race requires classified respond: ", id)
			}
			if opts.Action == C.RuleActionTypeRoute && opts.RouteOptions.Speculative {
				return E.New("policy early route cannot be speculative: ", id)
			}
			if opts.Action == C.RuleActionTypeEvaluate {
				if !opts.EvaluateOptions.DisableCache || !opts.EvaluateOptions.DisableOptimisticCache {
					return E.New("policy candidate evaluate must disable candidate caches: ", id)
				}
				if opts.EvaluateOptions.Tag == "" {
					return E.New("policy evaluate requires an explicit tag: ", id)
				}
			}
		}
		if fallbacks != 1 {
			return E.New("policy requires exactly one terminal fallback: ", id)
		}
	}
	return nil
}

// HasResolverPolicy is used by dialer config validation; it does not start DNS.
func (r *Router) HasResolverPolicy(id string) bool {
	for _, raw := range r.rawRules {
		if dnsPolicyID(raw) == id && id != "" {
			return true
		}
	}
	return false
}

// dnsPolicyTransport is an internal cache boundary, not a registered transport.
// It owns no sockets and delegates all execution to the existing rule walker.
type dnsPolicyTransport struct {
	router       *Router
	policy       string
	tag          string
	rules        []adapter.DNSRule
	options      adapter.DNSQueryOptions
	dependencies []adapter.DNSTransport
	preferred    []adapter.DNSTransportWithPreferredDomain
	domain       string
}

func (t *dnsPolicyTransport) Type() string                                   { return "internal-rules-policy" }
func (t *dnsPolicyTransport) Tag() string                                    { return t.tag }
func (t *dnsPolicyTransport) Dependencies() []string                         { return nil }
func (t *dnsPolicyTransport) Reset()                                         {}
func (t *dnsPolicyTransport) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (t *dnsPolicyTransport) Environment() []string {
	values := []string{t.tag}
	for index, transport := range t.preferred {
		state := "false"
		if transport.PreferredDomain(mDNS.CanonicalName(t.domain)) {
			state = "true"
		}
		values = append(values, fmt.Sprint(index)+":"+state)
	}
	for _, dependency := range t.dependencies {
		values = append(values, dependency.Tag())
		if source, ok := dependency.(adapter.DNSTransportWithEnvironment); ok {
			values = append(values, source.Environment()...)
		}
	}
	return values
}

func (t *dnsPolicyTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if len(message.Question) != 1 || message.Question[0].Qclass != mDNS.ClassINET {
		return nil, E.New("resolver policy requires one IN question")
	}
	if dnsPolicyBudgetFrom(ctx) == nil {
		var cancel context.CancelFunc
		ctx, cancel = withDNSPolicyBudget(ctx, t.options.Timeout)
		defer cancel()
	}
	ctx = context.WithValue(ctx, dnsPolicyActiveKey(t.policy), true)
	// Fresh metadata, equally for a foreground query and an optimistic refresh.
	ctx = adapter.WithContext(ctx, &adapter.InboundContext{
		DNSResolverPolicy: t.policy,
		Domain:            FqdnToDomain(message.Question[0].Name),
		QueryType:         message.Question[0].Qtype,
	})
	ctx = withLookupQueryMetadata(ctx, message.Question[0].Qtype)
	result := t.router.exchangeWithRules(ctx, t.rules, message, t.options, false)
	if budget := dnsPolicyBudgetFrom(ctx); budget != nil && budget.parent.Err() != nil {
		return nil, budget.parent.Err()
	}
	if result.rejectAction != nil {
		return nil, result.rejectAction.Error(ctx)
	}
	if result.err != nil {
		return nil, result.err
	}
	if result.response == nil {
		return nil, E.New("resolver policy produced no response")
	}
	return result.response.Copy(), nil
}

func (t *dnsPolicyTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() { callback(t.Exchange(ctx, message)) }()
}

func (r *Router) policyTransport(id string, domain string, options adapter.DNSQueryOptions) (*dnsPolicyTransport, error) {
	r.rulesAccess.RLock()
	defer r.rulesAccess.RUnlock()
	if r.closing {
		return nil, E.New("dns router closed")
	}
	policy := &dnsPolicyTransport{router: r, policy: id, domain: FqdnToDomain(domain), options: options}
	var rawPolicy []option.DNSRule
	for index, raw := range r.rawRules {
		if dnsPolicyID(raw) != id {
			continue
		}
		if index >= len(r.rules) {
			return nil, E.New("DNS resolver policy is not started: ", id)
		}
		policy.rules = append(policy.rules, r.rules[index])
		if raw.Type == "" {
			raw.Type = C.RuleTypeDefault
		}
		rawPolicy = append(rawPolicy, raw)
		server := dnsRuleActionServer(raw)
		if server != "" {
			if transport, loaded := r.transport.Transport(server); loaded {
				policy.dependencies = append(policy.dependencies, transport)
			}
		}
		for _, tag := range raw.DefaultOptions.PreferredBy {
			transport, loaded := r.transport.Transport(tag)
			if !loaded {
				return nil, E.New("preferred_by DNS server not found: ", tag)
			}
			preferred, supported := transport.(adapter.DNSTransportWithPreferredDomain)
			if !supported {
				return nil, E.New("preferred_by DNS server unsupported: ", tag)
			}
			policy.preferred = append(policy.preferred, preferred)
			policy.dependencies = append(policy.dependencies, transport)
		}
	}
	if len(policy.rules) == 0 {
		return nil, E.New("unknown DNS resolver policy: ", id)
	}
	encoded, err := json.Marshal(struct {
		Config         string
		Rules          []option.DNSRule
		Strategy       C.DomainStrategy
		LookupStrategy C.DomainStrategy
		Timeout        time.Duration
		RewriteTTL     *uint32
	}{r.policyConfigIdentity, rawPolicy, options.Strategy, options.LookupStrategy, options.Timeout, options.RewriteTTL})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	policy.tag = "internal:resolver-policy:" + id + ":" + hex.EncodeToString(digest[:])
	if _, exists := r.transport.Transport(policy.tag); exists {
		return nil, E.New("reserved resolver policy cache namespace collision")
	}
	return policy, nil
}

func (r *Router) lookupPolicy(parent context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	if parent.Value(dnsPolicyActiveKey(options.Policy)) != nil {
		return nil, E.New("DNS resolver policy recursion: ", options.Policy)
	}
	if !options.UseRules || options.Transport != nil {
		return nil, E.New("resolver policy requires rules mode without a transport")
	}
	if options.Timeout == 0 {
		options.Timeout = C.DNSTimeout
	}
	strategy := r.resolveLookupStrategy(options)
	options.Strategy = strategy
	policy, err := r.policyTransport(options.Policy, domain, options)
	if err != nil {
		return nil, err
	}
	if active, loaded := adapter.DNSTransportTagFromContext(parent); loaded && active == policy.Tag() {
		return nil, E.New("DNS resolver policy loopback")
	}
	ctx, cancel := withDNSPolicyBudget(parent, options.Timeout)
	defer cancel()
	// Keep outer options immutable: candidate DisableCache is never propagated.
	outer := options
	outer.Strategy = strategy
	lookup := func(qtype uint16) ([]netip.Addr, error) {
		request := &mDNS.Msg{RecursionDesired: true, Question: []mDNS.Question{{Name: mDNS.Fqdn(domain), Qtype: qtype, Qclass: mDNS.ClassINET}}}
		response, e := r.client.Exchange(ctx, policy, request, outer, nil)
		if e != nil {
			return nil, e
		}
		if parent.Err() != nil {
			return nil, parent.Err()
		}
		if response.Rcode != mDNS.RcodeSuccess {
			return nil, RcodeError(response.Rcode)
		}
		addresses := dnsPolicyAnswerAddresses(response, qtype)
		if len(addresses) == 0 {
			return nil, E.New("empty result")
		}
		return addresses, nil
	}
	if strategy == C.DomainStrategyIPv4Only {
		return lookup(mDNS.TypeA)
	}
	if strategy == C.DomainStrategyIPv6Only {
		return lookup(mDNS.TypeAAAA)
	}
	var a4, a6 []netip.Addr
	var e4, e6 error
	var joined sync.WaitGroup
	joined.Add(2)
	go func() { defer joined.Done(); a4, e4 = lookup(mDNS.TypeA) }()
	go func() { defer joined.Done(); a6, e6 = lookup(mDNS.TypeAAAA) }()
	joined.Wait()
	if parent.Err() != nil {
		return nil, parent.Err()
	}
	if len(a4) == 0 && len(a6) == 0 {
		return nil, errors.Join(e4, e6)
	}
	return sortAddresses(a4, a6, strategy), nil
}

func policyArmedFuture(state *dnsRuleWalkState, armed *dnsArmedRule) *dnsEvaluatedFuture {
	if tag := armed.rule.MatchResponseTag(); tag != "" {
		return state.namedFutures[tag]
	}
	return armed.anonymousFuture
}

func policyFutureInBudget(ctx context.Context, future *dnsEvaluatedFuture) bool {
	budget := dnsPolicyBudgetFrom(ctx)
	return budget == nil || !future.completedAt.After(budget.deadline)
}

func dnsPolicyFallback(message *mDNS.Msg, state *dnsRuleWalkState) exchangeWithRulesResult {
	if state.deferred != nil {
		return exchangeWithRulesResult{response: state.deferred.response.Copy(), transport: state.deferred.transport}
	}
	return exchangeWithRulesResult{response: FixedResponseStatus(message, mDNS.RcodeServerFailure)}
}

func (r *Router) finishDNSPolicyDeadline(ctx context.Context, rules []adapter.DNSRule, message *mDNS.Msg, state *dnsRuleWalkState) exchangeWithRulesResult {
	budget := dnsPolicyBudgetFrom(ctx)
	if budget == nil || budget.parent.Err() != nil || (ctx.Err() != nil && !errors.Is(context.Cause(ctx), errDNSPolicyBudget)) {
		return exchangeWithRulesResult{err: ctx.Err()}
	}
	// A callback can publish before cutoff while the walker is descheduled
	// immediately after evaluate, before its response rules have been armed.
	// Register only response bindings to already launched futures. No evaluate,
	// route, or other side-effecting action may run after the budget expires.
	armedIndices := make(map[int]bool, len(state.armedRules))
	for _, armed := range state.armedRules {
		armedIndices[armed.ruleIndex] = true
	}
	for index := state.ruleIndex; index < len(rules); index++ {
		rule := rules[index]
		action, ok := rule.Action().(*R.RuleActionRespond)
		if !ok || action.Mode == "fallback" || armedIndices[index] {
			continue
		}
		var future *dnsEvaluatedFuture
		anonymous := rule.MatchResponseAnonymous()
		if tag := rule.MatchResponseTag(); tag != "" {
			future = state.namedFutures[tag]
		} else if anonymous {
			future = state.anonymousFuture
		}
		if future == nil {
			continue
		}
		armed := &dnsArmedRule{ruleIndex: index, rule: rule, options: state.effectiveOptions, bindsAnonymous: anonymous}
		if anonymous {
			armed.anonymousFuture = future
		}
		state.armedRules = append(state.armedRules, armed)
	}
	result, _, committed := r.sweepArmedDNSRules(ctx, message, state, false)
	if committed {
		return result
	}
	return dnsPolicyFallback(message, state)
}

// Called while holding rulesAccess. Scoped rules must not even be armed by an
// ordinary request, including a nested request carrying inherited metadata.
func (r *Router) ordinaryDNSRules() []adapter.DNSRule {
	if len(r.rawRules) != len(r.rules) {
		return r.rules
	} // direct test injection
	rules := make([]adapter.DNSRule, 0, len(r.rules))
	for index, raw := range r.rawRules {
		if dnsPolicyID(raw) == "" {
			rules = append(rules, r.rules[index])
		}
	}
	return rules
}

// Only addresses which constitute a scoped current-question HIT may reach a
// node dialer. Generic MessageToAddresses intentionally also exposes HTTPS/SVCB
// hints; using it here would promote a retained EMPTY into a successful lookup.
func dnsPolicyAnswerAddresses(response *mDNS.Msg, qtype uint16) []netip.Addr {
	if response == nil || !response.Response || response.Truncated || response.Rcode != mDNS.RcodeSuccess {
		return nil
	}
	var addresses []netip.Addr
	for _, record := range response.Answer {
		if record == nil || record.Header().Class != mDNS.ClassINET {
			continue
		}
		switch answer := record.(type) {
		case *mDNS.A:
			if qtype != mDNS.TypeA {
				continue
			}
			if raw := answer.A.To4(); raw != nil {
				address, _ := netip.AddrFromSlice(raw)
				addresses = append(addresses, address)
			}
		case *mDNS.AAAA:
			if qtype != mDNS.TypeAAAA || len(answer.AAAA) != 16 {
				continue
			}
			address, _ := netip.AddrFromSlice(answer.AAAA)
			addresses = append(addresses, address)
		}
	}
	return addresses
}

// Wire-message callers (notably the Naive/Cronet proxy DNS callback) carry the
// same explicit policy as lookup dialers. Each independent request owns one
// budget; callers already inside a scoped budget never receive a fresh one.
func (r *Router) exchangePolicy(parent context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	if !options.UseRules || options.Transport != nil {
		return nil, E.New("resolver policy requires rules mode without a transport")
	}
	if parent.Value(dnsPolicyActiveKey(options.Policy)) != nil {
		return nil, E.New("DNS resolver policy recursion: ", options.Policy)
	}
	if message == nil || len(message.Question) != 1 || message.Question[0].Qclass != mDNS.ClassINET {
		return nil, E.New("resolver policy requires one IN question")
	}
	if options.Timeout == 0 {
		options.Timeout = C.DNSTimeout
	}
	options = r.finalizeExchangeOptions(options)
	policy, err := r.policyTransport(options.Policy, FqdnToDomain(message.Question[0].Name), options)
	if err != nil {
		return nil, err
	}
	ctx := parent
	if dnsPolicyBudgetFrom(ctx) == nil {
		var cancel context.CancelFunc
		ctx, cancel = withDNSPolicyBudget(parent, options.Timeout)
		defer cancel()
	}
	response, err := r.client.Exchange(ctx, policy, message, options, nil)
	if parent.Err() != nil {
		return nil, parent.Err()
	}
	if err != nil {
		return nil, err
	}
	r.recordReverseMapping(message, response, policy)
	return response, nil
}

func dnsPolicyDeadlineExpired(ctx context.Context) bool {
	budget := dnsPolicyBudgetFrom(ctx)
	return budget != nil && !time.Now().Before(budget.deadline)
}
