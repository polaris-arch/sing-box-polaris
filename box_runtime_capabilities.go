package box

import (
	stdjson "encoding/json"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"

	C "github.com/sagernet/sing-box/constant"
)

// This is a protocol/implementation inventory, not a source signature. Hosts
// must also verify their pinned custom-kernel artifact/receipt. A field marked
// supported remains subject to Plan and to its registered platform adapters.
func runtimeCapabilityFields() []RuntimeFieldCapability {
	tags, known := "", false
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "-tags" {
				tags, known = setting.Value, true
			}
		}
	}
	return runtimeCapabilityFieldsForBuild(tags, known, C.WithQUIC, C.CGO_ENABLED)
}

func runtimeCapabilityFieldsForBuild(tags string, known, quic, cgo bool) []RuntimeFieldCapability {
	var fields []RuntimeFieldCapability
	add := func(path, variant, class string, conditions ...string) {
		fields = append(fields, RuntimeFieldCapability{
			Path: path, Variant: variant,
			PlatformBuild: runtime.GOOS + "/" + runtime.GOARCH, UpdateClass: class,
			AdapterVersion: "1", Conditions: conditions,
		})
	}
	add("runtime.protocol", "polaris-daily-runtime-v1", "RUNTIME_UPDATE_UNSPECIFIED",
		"GetRuntimeCapabilities", "PlanRuntimeConfig", "ApplyRuntimeConfig", "GetRuntimeConfigStatus", "RetryRuntimePersistence", "AcknowledgeRuntimePersistence")
	for _, path := range []string{"outbounds", "endpoints", "dns", "route.rules", "route.rule_set", "route.final", "route.default_domain_resolver", "route.default_interface", "route.default_mark", "route.default_network_strategy", "route.default_network_type", "route.default_fallback_network_type", "route.default_fallback_delay"} {
		add(path, "daily-graph", "LOCAL_REPLACE", "eligible-started-instance", "build-enabled-concrete-adapter; registered-stub-is-not-support", "immutable-plan-and-control-CAS", "physical-resource-preflight", "captured-TUN-egress-dependencies-unchanged")
	}
	features := runtimeCapabilityBuildFeatures(tags, known, quic, cgo)
	featureNames := make([]string, 0, len(features))
	for name := range features {
		featureNames = append(featureNames, name)
	}
	sort.Strings(featureNames)
	for _, name := range featureNames {
		add("runtime.build", name, "RUNTIME_UPDATE_UNSPECIFIED", "state="+features[name])
	}
	variant := func(path, name, tag string, extra ...string) {
		class := "LOCAL_REPLACE"
		conditions := []string{"eligible-started-instance", "concrete-constructor-and-Plan-validation", "resource-ownership-and-physical-preflight"}
		if tag != "" {
			conditions = append(conditions, "required-build-tag="+tag, "build-tag-state="+features[tag])
			if features[tag] != "enabled" {
				class = "RUNTIME_UPDATE_UNSPECIFIED"
			}
		}
		conditions = append(conditions, extra...)
		add(path, name, class, conditions...)
	}
	for _, name := range []string{C.TypeDirect, C.TypeSelector, C.TypeURLTest, C.TypeShadowsocks, C.TypeVMess, C.TypeVLESS, C.TypeTrojan, C.TypeAnyTLS, C.TypeSnell, C.TypeShadowTLS, C.TypeSSH, C.TypeTor, C.TypeSOCKS, C.TypeHTTP} {
		variant("outbounds", name, "")
	}
	for _, name := range []string{C.TypeHysteria, C.TypeHysteria2, C.TypeTUIC} {
		variant("outbounds", name, "with_quic", "hysteria2-Realm-not-supported")
	}
	variant("outbounds", C.TypeNaive, "with_naive_outbound", "selected-cronet-backend-required")
	variant("outbounds", C.TypeTailcat, "with_tailscale", "shared-identity-resource-preflight")
	for _, item := range []struct{ name, tag string }{
		{C.TypeWireGuard, "with_wireguard"}, {C.TypeOpenConnect, "with_openconnect"}, {C.TypeOpenVPNClient, "with_openvpn"}, {C.TypeTailscale, "with_tailscale"}, {C.TypeMASQUEClient, ""},
	} {
		variant("endpoints", item.name, item.tag, "userspace-node-only", "physical-identity-overlap-preflight")
	}
	for _, name := range []string{C.DNSTypeUDP, C.DNSTypeTCP, C.DNSTypeTLS, C.DNSTypeHTTPS, C.DNSTypeHosts, C.DNSTypeFakeIP, C.DNSTypeLocal, C.DNSTypeMDNS} {
		variant("dns.servers", name, "", "platform-transport-available", "FakeIP-range-capacity-reference-constraints")
	}
	for _, item := range []struct{ name, tag string }{
		{C.DNSTypeQUIC, "with_quic"}, {C.DNSTypeHTTP3, "with_quic"}, {C.DNSTypeDHCP, "with_dhcp"}, {C.DNSTypeOpenConnect, "with_openconnect"}, {C.DNSTypeOpenVPN, "with_openvpn"}, {C.DNSTypeTailscale, "with_tailscale"},
	} {
		variant("dns.servers", item.name, item.tag, "platform-transport-available", "exact-endpoint-dependency-if-required")
	}
	add("log.level", "builtin-level-control", "IN_PLACE", "eligible-started-instance", "valid-level")
	for _, path := range []string{"inbounds", "services", "experimental.cache_file", "network_namespaces", "log.output", "certificate"} {
		conditions := []string{"unchanged-supported-components-may-coexist", "explicit-host-restart-only"}
		if path == "services" {
			conditions = append(conditions, "unchanged-plain-loopback-api-may-coexist", "enabled-dashboard-requires-inline-detour-only-http-client", "dashboard-fetch-borrows-current-graph-until-body-close")
		}
		add(path, "structural-change", "RESTART_REQUIRED", conditions...)
	}
	for _, path := range runtimePendingAdapters() {
		add(path, "unsupported-dependency", "PENDING_ADAPTER", "presence-may-prevent-initial-runtime-graph")
	}
	add("runtime.persistence", "owner-contract", "RUNTIME_UPDATE_UNSPECIFIED", "unbound-or-failed-owner-remains-durability-pending", "retry-requires-original-repeat-safe-owner", "regeneration-requires-separate-owner-ack")
	sort.Slice(fields, func(i, j int) bool {
		if fields[i].Path == fields[j].Path {
			return fields[i].Variant < fields[j].Variant
		}
		return fields[i].Path < fields[j].Path
	})
	return fields
}

// Match the existing TLS capability build-info source. Missing metadata is
// explicitly unknown; registry stubs are never evidence of feature inclusion.
func runtimeCapabilityBuildFeatures(tags string, known, quic, cgo bool) map[string]string {
	states := make(map[string]string)
	for _, tag := range []string{"with_quic", "with_wireguard", "with_tailscale", "with_openconnect", "with_openvpn", "with_naive_outbound", "with_dhcp", "with_utls", "with_purego"} {
		states[tag] = "unknown"
		if known {
			states[tag] = "disabled"
		}
	}
	if known {
		for _, tag := range strings.FieldsFunc(tags, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			if _, exists := states[tag]; exists {
				states[tag] = "enabled"
			}
		}
	}
	states["with_quic"] = "disabled"
	if quic {
		states["with_quic"] = "enabled"
	}
	states["cgo"] = "disabled"
	if cgo {
		states["cgo"] = "enabled"
	}
	return states
}

func runtimePendingAdapters() []string {
	return []string{"outbounds[hysteria2.realm]", "services[non-api-or-api-dependent-listener]", "http_clients", "certificate_providers", "ntp"}
}

func (s *Box) RuntimeCapabilities() RuntimeConfigCapabilities {
	fields := runtimeCapabilityFields()
	// Only strings/slices enter this encoding; no unsupported JSON value exists.
	encoded, _ := stdjson.Marshal(struct {
		ContractVersion uint32                   `json:"contract_version"`
		Fields          []RuntimeFieldCapability `json:"fields"`
	}{RuntimeConfigContractVersion, fields})
	result := RuntimeConfigCapabilities{
		ContractVersion:   RuntimeConfigContractVersion,
		FullConfiguration: false, Fields: fields, ImplementationManifestDigest: runtimeDigest(encoded),
		PendingAdapters: runtimePendingAdapters(),
	}
	seenPaths := make(map[string]bool)
	for _, field := range fields {
		if (field.UpdateClass == "LOCAL_REPLACE" || field.UpdateClass == "IN_PLACE") && !seenPaths[field.Path] {
			result.SupportedPaths = append(result.SupportedPaths, field.Path)
			seenPaths[field.Path] = true
		}
	}
	reason := func(code, path string) {
		result.Fields = append(result.Fields, RuntimeFieldCapability{
			Path: "runtime.instance", Variant: code,
			UpdateClass: "RUNTIME_UPDATE_UNSPECIFIED", Conditions: []string{path},
		})
	}
	if s == nil {
		reason("RUNTIME_GRAPH_UNAVAILABLE", "runtime")
		return result
	}
	if s.runtime == nil {
		// Read completion before close intent: stopped takes precedence even when
		// Start completion and Close race. Neither flag ever returns to false.
		started, stopped := s.started.Load(), s.closeStarted.Load()
		unsupported := len(s.runtimeEligibilityErrors) != 0
		for _, problem := range s.runtimeEligibilityErrors {
			if problem.Code != "PENDING_ADAPTER" {
				unsupported = false
			}
		}
		switch {
		case stopped:
			reason("RUNTIME_STOPPED", "runtime")
		case !unsupported:
			reason("RUNTIME_GRAPH_UNAVAILABLE", "runtime")
		case !started:
			reason("RUNTIME_STARTING", "runtime")
		default:
			reason("RUNTIME_STARTED_UNSUPPORTED", "runtime")
		}
		for _, problem := range s.runtimeEligibilityErrors {
			reason(problem.Code, problem.Path)
		}
		return result
	}
	s.runtime.access.Lock()
	// Startup owners need this identity before Start to bind persistence. Never
	// hide it merely because new transactions are not yet admitted.
	result.Identity = s.runtime.active
	stopped := s.runtime.stopped || s.closeStarted.Load()
	result.Enabled = s.runtime.initialPhase == 2 && !stopped && s.runtime.active.Incarnation != "" && s.runtime.active.Revision != 0 && s.runtime.active.EffectiveDigest != ""
	if stopped {
		reason("RUNTIME_STOPPED", "runtime")
	} else if s.runtime.initialPhase != 2 {
		reason("RUNTIME_STARTING", "runtime")
	}
	if s.runtime.persist == nil {
		reason("OWNER_PERSISTENCE_UNBOUND", "runtime.persistence")
	}
	s.runtime.access.Unlock()
	return result
}
