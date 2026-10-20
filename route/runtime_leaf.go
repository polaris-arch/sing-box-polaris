package route

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	E "github.com/sagernet/sing/common/exceptions"
)

// ConfigureInitialRuntime makes OS/process resources Box-owned from their first
// allocation. Immutable rule-set versions remain owned by the graph scope.
func (r *Router) ConfigureInitialRuntime(stable *adapter.Scope) {
	r.runtimePlatformScope = stable
	r.immutableRuleSets = true
}

// BorrowRuntimePlatform is called before candidate Start. The Box must retain
// the stable platform owner through the candidate's actual lifetime.
func (r *Router) BorrowRuntimePlatform(initial *Router) {
	r.runtimeLeaf = true
	r.immutableRuleSets = true
	r.processSearcher = initial.processSearcher
	r.processCache = initial.processCache
	r.neighborResolver = initial.neighborResolver
}

type RuntimeRequirements struct {
	Process bool
	Neighbor bool
	WIFI bool
	DHCPLeaseFiles []string
}
func RuntimeRequirementsFor(options option.RouteOptions, dns option.DNSOptions) RuntimeRequirements {
	result := RuntimeRequirements{
		Process: options.FindProcess || hasRule(options.Rules, isProcessRule) || hasDNSRule(dns.Rules, isProcessDNSRule),
		Neighbor: options.FindNeighbor || hasRule(options.Rules, isNeighborRule) || hasDNSRule(dns.Rules, isNeighborDNSRule) || hasLocalNeighborDNSServer(dns.Servers),
		WIFI: hasRule(options.Rules, isWIFIRule) || hasDNSRule(dns.Rules, isWIFIDNSRule),
		DHCPLeaseFiles: append([]string(nil), options.DHCPLeaseFiles...),
	}
	for _, set := range options.RuleSet {
		metadata := R.RuntimeRuleSetMetadata(set.InlineOptions.Rules)
		result.Process = result.Process || metadata.ContainsProcessRule
		result.WIFI = result.WIFI || metadata.ContainsWIFIRule
	}
	return result
}

// InitializeRuntime binds already-frozen, separately owned rule-set versions.
// Their lifecycle belongs to their resource owners, not this leaf's rule scope.
func (r *Router) InitializeRuntime(rules []option.Rule, ruleSets []adapter.RuleSet) error {
	r.runtimeRuleSetsExternal = true
	r.immutableRuleSets = true
	r.ruleSets = append([]adapter.RuleSet(nil), ruleSets...)
	r.ruleSetMap = make(map[string]adapter.RuleSet, len(ruleSets))
	for _, set := range ruleSets {
		if _, exists := r.ruleSetMap[set.Name()]; exists { return E.New("duplicate runtime rule-set") }
		r.ruleSetMap[set.Name()] = set
	}
	return r.Initialize(rules, nil)
}

// RuntimeProvisionedRequirements reports actual stable resources after initial
// startup, including platform-provided process lookup that does not require a
// find_process flag (Android). It never provisions resources during Plan.
func (r *Router) RuntimeProvisionedRequirements(requested RuntimeRequirements) RuntimeRequirements {
 requested.Process = r.processSearcher != nil
 requested.Neighbor = r.neighborResolver != nil
 requested.WIFI = r.network != nil && r.network.NeedWIFIState()
 if !requested.Neighbor { requested.DHCPLeaseFiles = nil }
 return requested
}
