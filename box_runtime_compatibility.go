package box

import (
	"bytes"
	"context"
	stdjson "encoding/json"
	"fmt"
	"sort"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

// This manifest describes the bounded daily-update surface, not the full schema.
// Unsupported custom/structural variants are explicit boundaries, not an implicit
// implementation queue. No fallback invokes destructive reload.
func runtimeConfigCompatibility(ctx context.Context, previous, next []byte, options option.Options) ([]RuntimeImpact, []RuntimePlanError) {
	var before, after map[string]stdjson.RawMessage
	if err := stdjson.Unmarshal(previous, &before); err != nil {
		return nil, []RuntimePlanError{{Code: "INVALID_ACTIVE_SNAPSHOT"}}
	}
	if err := stdjson.Unmarshal(next, &after); err != nil {
		return nil, []RuntimePlanError{{Code: "INVALID_CANDIDATE_SNAPSHOT"}}
	}
	if impacts, problems := runtimeDailyStructuralChanges(before, after); len(problems) != 0 {
		return impacts, problems
	}
	var problems []RuntimePlanError
	if options.Log != nil && options.Log.Level != "" {
		if _, err := log.ParseLevel(options.Log.Level); err != nil {
			problems = append(problems, RuntimePlanError{Code: "INVALID_LOG_LEVEL", Path: "log.level", Message: "invalid log level; current configuration retained"})
		}
	}
	pending := func(path string) {
		problems = append(problems, RuntimePlanError{Code: "PENDING_ADAPTER", Path: path, Message: "resource adapter has not been implemented for this configuration"})
	}
	keys := map[string]bool{}
	for key := range before {
		keys[key] = true
	}
	for key := range after {
		keys[key] = true
	}
	var changed []string
	for key := range keys {
		if bytes.Equal(before[key], after[key]) {
			continue
		}
		switch key {
		case "log", "outbounds", "endpoints", "dns", "route", "inbounds":
			changed = append(changed, key)
		default:
			pending(key)
		}
	}
	// Stable components with captured graph dependencies need their own reverse
	// dependency adapters, even when their source text is unchanged.
	for index, endpoint := range options.Endpoints {
		switch endpoint.Type {
		case C.TypeWireGuard, C.TypeOpenConnect, C.TypeOpenVPNClient, C.TypeMASQUEClient, C.TypeTailscale:
		default:
			pending(fmt.Sprintf("endpoints[%d]", index))
		}
		// WG physical identity and fixed-port overlap are classified by the pure
		// endpoint preflight and repeated against live owners before staging.
	}
	for _, item := range options.Services {
		if !runtimeStableAPIService(item) {
			pending("services")
			break
		}
	}
	if len(options.HTTPClients) != 0 {
		pending("http_clients")
	}
	if len(options.CertificateProviders) != 0 {
		pending("certificate_providers")
	}
	if options.NTP != nil && options.NTP.Enabled {
		pending("ntp")
	}

	for i, inbound := range options.Inbounds {
		switch inbound.Type {
		case C.TypeSOCKS, C.TypeHTTP, C.TypeMixed, C.TypeTun:
		default:
			pending(fmt.Sprintf("inbounds[%d].lifecycle", i))
		}
		if httpOptions, ok := inbound.Options.(*option.HTTPInboundOptions); ok {
			for _, version := range httpOptions.Versions() {
				if version == 3 {
					pending(fmt.Sprintf("inbounds[%d].http3", i))
				}
			}
			if httpOptions.SetSystemProxy {
				pending(fmt.Sprintf("inbounds[%d].set_system_proxy", i))
			}
		}
		if mixed, ok := inbound.Options.(*option.HTTPMixedInboundOptions); ok && mixed.SetSystemProxy {
			pending(fmt.Sprintf("inbounds[%d].set_system_proxy", i))
		}
		if wrapper, ok := inbound.Options.(option.InboundTLSOptionsWrapper); ok {
			value := wrapper.TakeInboundTLSOptions()
			if value != nil && value.Enabled {
				if value.CertificateProvider != nil || value.HasLegacyACME() {
					pending(fmt.Sprintf("inbounds[%d].tls.certificate_provider", i))
				}
				if value.Reality != nil && value.Reality.Enabled {
					pending(fmt.Sprintf("inbounds[%d].tls.reality", i))
				}
			}
		}
		encoded, err := json.MarshalContext(ctx, inbound)
		if err != nil {
			pending(fmt.Sprintf("inbounds[%d]", i))
			continue
		}
		var fields map[string]stdjson.RawMessage
		if stdjson.Unmarshal(encoded, &fields) != nil {
			pending(fmt.Sprintf("inbounds[%d]", i))
			continue
		}
		for _, key := range []string{"domain_resolver", "detour"} {
			if len(fields[key]) != 0 && string(fields[key]) != "null" {
				pending(fmt.Sprintf("inbounds[%d].%s", i, key))
			}
		}
	}
	for i, outbound := range options.Outbounds {
		path := fmt.Sprintf("outbounds[%d]", i)
		switch outbound.Type {
		case C.TypeDirect, C.TypeSelector, C.TypeURLTest, C.TypeShadowsocks, C.TypeVMess, C.TypeVLESS, C.TypeTrojan, C.TypeAnyTLS, C.TypeSnell, C.TypeShadowTLS, C.TypeSSH, C.TypeHysteria, C.TypeTUIC, C.TypeNaive, C.TypeTor, C.TypeTailcat:
		case C.TypeHysteria2:
			value, ok := outbound.Options.(*option.Hysteria2OutboundOptions)
			if !ok {
				pending(path)
			} else if value.Realm != nil {
				pending(path + ".realm")
			}
		case C.TypeSOCKS:
			if _, ok := outbound.Options.(*option.SOCKSOutboundOptions); !ok {
				pending(path)
				continue
			}
			// Supported UoT versions are synchronous framing over the same
			// retained stream; the constructor rejects unknown versions.
		case C.TypeHTTP:
			httpOptions, ok := outbound.Options.(*option.HTTPOutboundOptions)
			if !ok {
				pending(path)
				continue
			}
			// The selected TFO dependency joins original callbacks/racers.
			// DefaultDialer still requires numeric peers and Fallback=false.
			_ = httpOptions
		default:
			pending(path)
		}
	}
	if options.Route != nil {
		for index, source := range options.Route.RuleSet {
			if source.Type != "" && source.Type != C.RuleSetTypeInline && source.Type != C.RuleSetTypeLocal && source.Type != C.RuleSetTypeRemote {
				pending(fmt.Sprintf("route.rule_set[%d].source_producer", index))
			}
		}
	}
	if options.DNS != nil {
		for i, server := range options.DNS.Servers {
			path := fmt.Sprintf("dns.servers[%d]", i)
			switch server.Type {
			case C.DNSTypeUDP, C.DNSTypeTCP, C.DNSTypeTLS, C.DNSTypeHTTPS, C.DNSTypeQUIC, C.DNSTypeHTTP3, C.DNSTypeHosts, C.DNSTypeFakeIP, C.DNSTypeLocal, C.DNSTypeMDNS, C.DNSTypeDHCP, C.DNSTypeOpenConnect, C.DNSTypeOpenVPN, C.DNSTypeTailscale:
			default:
				pending(path)
			}

		}
	}
	var oldRoute, newRoute map[string]stdjson.RawMessage
	_ = stdjson.Unmarshal(before["route"], &oldRoute)
	_ = stdjson.Unmarshal(after["route"], &newRoute)
	for _, key := range []string{"find_process", "find_neighbor", "dhcp_lease_files", "auto_detect_interface", "override_android_vpn", "default_http_client"} {
		if !bytes.Equal(oldRoute[key], newRoute[key]) {
			pending("route." + key)
		}
	}
	sort.Strings(changed)
	sort.Slice(problems, func(i, j int) bool { return problems[i].Path < problems[j].Path })
	var impacts []RuntimeImpact
	for _, path := range changed {
		impact := RuntimeImpact{Path: path, UpdateClass: "LOCAL_REPLACE", Reason: "publish one validated runtime graph", AffectedSessionClasses: []string{"new admissions"}}
		if path == "inbounds" {
			impact.ReconnectRequired = true
			impact.Reason = "local listener handoff may require exclusive socket rebind; compensation can require reconnect"
			impact.AffectedSessionClasses = []string{"changed ingress admissions", "affected UDP associations"}
		}
		impacts = append(impacts, impact)
	}
	return impacts, problems
}
