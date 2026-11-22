package boxruntime

import (
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

// appProbeSelectors recognizes the topology emitted by both old and current
// Apps, which share the schema with cores that reject unknown selector fields.
// Only these slots give their selection to the current runtime owner.
func appProbeSelectors(options option.Options) map[string]bool {
	if options.Route == nil || options.DNS == nil {
		return nil
	}
	defaultOutbound, defaultDNS := options.Route.Final, options.DNS.Final
	if defaultOutbound == "" && len(options.Outbounds) > 0 {
		defaultOutbound = options.Outbounds[0].Tag
	}
	if defaultDNS == "" && len(options.DNS.Servers) > 0 {
		defaultDNS = options.DNS.Servers[0].Tag
	}
	type slotTopology struct {
		http, route, doh, dnsRule bool
		routeUses, dnsUses        int
		shared                    bool
	}
	slots := make(map[string]*slotTopology)
	for _, outbound := range options.Outbounds {
		selector, ok := outbound.Options.(*option.SelectorOutboundOptions)
		if !ok || outbound.Type != C.TypeSelector || selector.Default != "direct" ||
			!selector.InterruptExistConnections || !slices.Contains(selector.Outbounds, "direct") {
			continue
		}
		suffix, found := strings.CutPrefix(outbound.Tag, "probe-selector-")
		index, err := strconv.ParseUint(suffix, 10, 32)
		if found && err == nil && strconv.FormatUint(index, 10) == suffix &&
			defaultOutbound != outbound.Tag && defaultDNS != "dns-probe-exit-"+suffix {
			slots[suffix] = new(slotTopology)
		}
	}
	if len(slots) == 0 {
		return nil
	}
	markShared := func(tag, prefix string) {
		if suffix, found := strings.CutPrefix(tag, prefix); found && slots[suffix] != nil {
			slots[suffix].shared = true
		}
	}
	markResolver := func(resolver *option.DomainResolveOptions) {
		if resolver != nil {
			markShared(resolver.Server, "dns-probe-exit-")
		}
	}
	markDialer := func(dial option.DialerOptions, ownDetour string) {
		if dial.Detour != ownDetour {
			markShared(dial.Detour, "probe-selector-")
		}
		markResolver(dial.DomainResolver)
	}
	for _, outbound := range options.Outbounds {
		var members []string
		switch value := outbound.Options.(type) {
		case *option.SelectorOutboundOptions:
			members = value.Outbounds
		case *option.URLTestOutboundOptions:
			members = value.Outbounds
		case option.DialerOptionsWrapper:
			markDialer(value.TakeDialerOptions(), "")
		}
		for _, member := range members {
			markShared(member, "probe-selector-")
		}
	}
	for _, endpoint := range options.Endpoints {
		if wrapper, ok := endpoint.Options.(option.DialerOptionsWrapper); ok {
			markDialer(wrapper.TakeDialerOptions(), "")
		}
	}
	for _, client := range options.HTTPClients {
		markDialer(client.Options().DialerOptions, "")
	}
	for _, ruleSet := range options.Route.RuleSet {
		if ruleSet.Type == C.RuleSetTypeRemote {
			//nolint:staticcheck
			markShared(ruleSet.RemoteOptions.DownloadDetour, "probe-selector-")
			if client := ruleSet.RemoteOptions.HTTPClient; client != nil {
				markDialer(client.DialerOptions, "")
			}
		}
	}
	for _, provider := range options.CertificateProviders {
		if client, _ := runtimeCertificateProviderHTTPClient(provider.Options); client != nil {
			markDialer(client.DialerOptions, "")
		}
	}
	if options.NTP != nil && options.NTP.Enabled {
		markDialer(options.NTP.DialerOptions, "")
	}
	markResolver(options.Route.DefaultDomainResolver)
	for _, service := range options.Services {
		dependencies, clients, _ := runtimeServiceDependencies(service.Options)
		for _, dependency := range dependencies {
			markShared(dependency, "outbound:probe-selector-")
			markShared(dependency, "dns-transport:dns-probe-exit-")
		}
		for _, client := range clients {
			markDialer(client.DialerOptions, "")
		}
	}
	for _, inbound := range options.Inbounds {
		suffix, found := strings.CutPrefix(inbound.Tag, "probe-in-")
		slot := slots[suffix]
		http, ok := inbound.Options.(*option.HTTPInboundOptions)
		if found && slot != nil && ok && inbound.Type == C.TypeHTTP &&
			http.Listen.Build(netip.Addr{}) == netip.AddrFrom4([4]byte{127, 0, 0, 1}) &&
			http.Detour == "" && !http.SetSystemProxy && (http.TLS == nil || !http.TLS.Enabled) && slices.Contains(http.Versions(), 1) {
			slot.http = true
		}
	}
	for _, rule := range options.Route.Rules {
		action := rule.DefaultOptions.RuleAction
		if rule.Type == C.RuleTypeLogical {
			action = rule.LogicalOptions.RuleAction
		}
		if action.Action == C.RuleActionTypeResolve {
			markShared(action.ResolveOptions.Server, "dns-probe-exit-")
		}
		outbound := action.RouteOptions.Outbound
		if action.Action == C.RuleActionTypeBypass {
			outbound = action.BypassOptions.Outbound
		}
		suffix, found := strings.CutPrefix(outbound, "probe-selector-")
		slot := slots[suffix]
		if !found || slot == nil {
			continue
		}
		slot.routeUses++
		raw := rule.DefaultOptions.RawDefaultRule
		inbounds := raw.Inbound
		raw.Inbound = nil
		if rule.Type == C.RuleTypeDefault && action.Action == C.RuleActionTypeRoute &&
			len(inbounds) == 1 && inbounds[0] == "probe-in-"+suffix &&
			action.RouteOptions.RawRouteOptionsActionOptions == (option.RawRouteOptionsActionOptions{}) &&
			reflect.DeepEqual(raw, option.RawDefaultRule{}) {
			slot.route = true
		}
	}
	for _, server := range options.DNS.Servers {
		suffix, found := strings.CutPrefix(server.Tag, "dns-probe-exit-")
		slot := slots[suffix]
		var ownDetour string
		if found && slot != nil {
			ownDetour = "probe-selector-" + suffix
		}
		if wrapper, ok := server.Options.(option.DialerOptionsWrapper); ok {
			markDialer(wrapper.TakeDialerOptions(), ownDetour)
		}
		https, ok := server.Options.(*option.RemoteHTTPSDNSServerOptions)
		if ownDetour == "" || !ok || server.Type != C.DNSTypeHTTPS || https.Detour != ownDetour ||
			https.Server != "223.5.5.5" || https.ServerPort != 443 || https.Path != "/dns-query" {
			continue
		}
		rest := *https
		rest.Detour, rest.Server, rest.ServerPort, rest.Path = "", "", 0, ""
		slot.doh = reflect.DeepEqual(rest, option.RemoteHTTPSDNSServerOptions{})
	}
	for _, rule := range options.DNS.Rules {
		value := rule.DefaultOptions
		action := value.DNSRuleAction
		if rule.Type == C.RuleTypeLogical {
			action = rule.LogicalOptions.DNSRuleAction
		}
		server := action.RouteOptions.Server
		if action.Action == C.RuleActionTypeEvaluate {
			server = action.EvaluateOptions.Server
		}
		suffix, found := strings.CutPrefix(server, "dns-probe-exit-")
		slot := slots[suffix]
		if !found || slot == nil {
			continue
		}
		slot.dnsUses++
		raw := value.RawDefaultDNSRule
		inbounds := raw.Inbound
		queryTypes := raw.QueryType
		raw.Inbound, raw.QueryType = nil, nil
		if rule.Type == C.RuleTypeDefault && value.Action == C.RuleActionTypeRoute && !value.Race && !value.RouteOptions.Speculative &&
			len(inbounds) == 1 && inbounds[0] == "probe-in-"+suffix &&
			slices.Equal(queryTypes, []option.DNSQueryType{option.DNSQueryType(mDNS.TypeA), option.DNSQueryType(mDNS.TypeAAAA)}) &&
			value.RouteOptions.AbstractDNSRouteActionOptions == (option.AbstractDNSRouteActionOptions{DisableCache: true}) &&
			reflect.DeepEqual(raw, option.RawDefaultDNSRule{}) {
			slot.dnsRule = true
		}
	}
	result := make(map[string]bool)
	for suffix, slot := range slots {
		if !slot.shared && slot.http && slot.route && slot.routeUses == 1 && slot.doh && slot.dnsRule && slot.dnsUses == 1 {
			result["probe-selector-"+suffix] = true
		}
	}
	return result
}

func withAppProbeSelectionScope(options option.Options) option.Options {
	slots := appProbeSelectors(options)
	var detached bool
	for index, outbound := range options.Outbounds {
		selector, ok := outbound.Options.(*option.SelectorOutboundOptions)
		ephemeral := slots[outbound.Tag]
		if !ok || selector == nil || selector.EphemeralPoolProbe == ephemeral {
			continue
		}
		if !detached {
			options.Outbounds = slices.Clone(options.Outbounds)
			detached = true
		}
		configured := *selector
		configured.EphemeralPoolProbe = ephemeral
		options.Outbounds[index].Options = &configured
	}
	return options
}

// Migration is candidate-private. The commit's control revision check rejects a
// concurrent manual choice; no cache write or old-flow interruption occurs here.
func (s *Box) migrateRuntimeSelections(candidate *preparedRuntimeGraph) {
	lease, err := s.runtime.store.Acquire()
	if err != nil {
		return
	}
	defer lease.Release()
	for _, resource := range candidate.created {
		for _, component := range resource.components {
			if component.outbound == nil {
				continue
			}
			migration, ok := component.outbound.(interface{ RuntimeSelectInitial(string) bool })
			if !ok {
				continue
			}
			if probe, ok := component.outbound.(interface{ EphemeralPoolProbe() bool }); ok && probe.EphemeralPoolProbe() {
				continue
			}
			previous, exists := lease.View().OutboundManager().Outbound(component.outbound.Tag())
			if !exists {
				continue
			}
			if probe, ok := previous.(interface{ EphemeralPoolProbe() bool }); ok && probe.EphemeralPoolProbe() {
				continue
			}
			group, ok := previous.(adapter.OutboundGroup)
			if !ok {
				continue
			}
			selected := group.Selected(N.NetworkTCP)
			if selected != nil {
				migration.RuntimeSelectInitial(selected.Tag())
			}
		}
	}
}
