package box

import (
	stdjson "encoding/json"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/sagernet/sing-box/adapter/certificate"
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
	for _, path := range []string{"outbounds", "endpoints", "dns", "route.rules", "route.rule_set", "route.final", "route.default_domain_resolver", "route.default_http_client", "route.default_interface", "route.default_mark", "route.default_network_strategy", "route.default_network_type", "route.default_fallback_network_type", "route.default_fallback_delay"} {
		add(path, "daily-graph", "LOCAL_REPLACE", "eligible-started-instance", "build-enabled-concrete-adapter; registered-stub-is-not-support", "immutable-plan-and-control-CAS", "physical-resource-preflight", "captured-TUN-egress-dependencies-unchanged")
	}
	add("route.find_process", "desktop-private-process-owner-v1", "LOCAL_REPLACE", "client-impact-policy=1", "existing-private-process-owner; desktop-only; native-initialize-may-fail")
	for _, path := range []string{"route.find_neighbor", "route.dhcp_lease_files"} {
		add(path, "native-neighbor-and-lease-reader-v1", "LOCAL_REPLACE", "client-impact-policy=1", "Linux-or-Darwin-desktop-native-reader", "absolute-clean-bounded-lease-files", "fresh-private-sample-required", "one-second-refresh; native-I/O-joined-before-close", "new-platform-subscription-without-independent-owner-unavailable")
	}
	for _, path := range []string{"route.rules.wifi_ssid", "route.rules.wifi_bssid", "dns.rules.wifi_ssid", "dns.rules.wifi_bssid"} {
		add(path, "graph-owned-wifi-reader-v1", "LOCAL_REPLACE", "client-impact-policy=1", "Linux-or-Windows-native-reader-or-existing-platform-getter", "fresh-private-read", "one-second-refresh; native-I/O-joined-before-close", "no-new-platform-permission")
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
		if name == C.TypeHysteria2 {
			variant("outbounds", name, "with_quic", "Realm-requires-hysteria2-realm-adapter")
		} else {
			variant("outbounds", name, "with_quic")
		}
	}
	variant("outbounds", "hysteria2-realm", "with_quic",
		"IPv4-IPv6-dual;port-mapping-requires-IPv4",
		"captured-named-default-inline-HTTP-and-STUN-resolver-detour-closure",
		"discovery-XML-SOAP-and-delete-borrow-the-captured-HTTP-closure",
		"UPnP-device-hostnames-captured-once-in-the-discovery-generation",
		"demand-only-control-STUN-punch-and-optional-NAT-mapping",
		"standard-QUIC-TLS;salamander-gecko-owned-selected-peer-carrier",
		"joined-workers-late-results-and-mapper-retirement",
		"uncancelable-native-NAT-calls-remain-owned-until-return",
		"unknown-mapping-or-delete-failure-remains-cleanup-debt")
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
	variant("http_clients", "go-http1-http2", "", "unique-nonempty-tags", "captured-detour-default-and-resolver-closure", "old-request-and-body-epoch-retained", "remote-source-download-routing-change-requires-restart")
	variant("http_clients", "go-http3", "with_quic", "owned-QUIC-fallback-and-TLS-callback-join")
	appleClass := "RUNTIME_UPDATE_UNSPECIFIED"
	if runtime.GOOS == "darwin" && cgo {
		appleClass = "LOCAL_REPLACE"
	}
	add("http_clients", "apple", appleClass, "requires-darwin-cgo", "concrete-Apple-session-guardrails", "owned-native-callback-and-bridge-join")
	variant("inbounds.tls.certificate_provider", "named-or-inline", "", "only-provider-reference-may-change", "all-other-listener-and-TLS-fields-unchanged", "dependent-listener-handoff-may-reconnect")
	originClass := "LOCAL_REPLACE"
	if !certificate.RuntimeDirectoryStorageAvailable {
		originClass = "PENDING_ADAPTER"
	}
	add("certificate_providers", "cloudflare-origin-ca", originClass, "named-or-inline-TLS-reference", "exact-provider-HTTP-clock-closure", "inode-bound-directory-root-and-joined-compatible-cache-lease", "directory-root-unavailable-on-js-plan9", "overlapping-cache-or-challenge-owner-requires-restart", "issuance-may-precede-publication-and-remain-after-abort")
	add("certificate_providers", "acme", "PENDING_ADAPTER", "required-build-tag=with_acme", "build-tag-state="+features["with_acme"], "requires-owned-certmagic-DNS-OCSP-challenge-and-handshake-workers", "ordinary-cold-start-retained")
	variant("certificate_providers", "tailscale", "with_tailscale", "exact-staged-Tailscale-endpoint-and-directory", "endpoint-identity-overlap-preflight")
	variant("ntp", "offset-only", "", "enable-disable-source-change", "rebuild-all-captured-clock-consumers", "no-construction-plan-or-prepare-sampling", "synchronous-certificate-effect-may-bootstrap-one-private-offset-sample", "joined-ordinary-sample-failure-retains-best-effort-time", "retired-owner-cannot-write-system-time")
	add("ntp.write_to_system", "irreversible", "RESTART_REQUIRED", "explicit-host-managed-restart-only", "never-downgrade-to-offset-only", "security-feature-check-preserved")
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
	variant("services", "api-loopback-handoff-v1", "", "one-API-service;stable-tag;listen-port-secret-only", "no-TLS-ReuseAddr-interface-netns-detour-or-dashboard-change", "server-owned-socket-custody-through-publication-and-ack", "original-captured-carrier-key;new-channel-HMAC-challenge;separate-handoff-ack", "prepublish-unary-and-stream-task-join;header-safe-secret", "unknown-result-status-only;never-repeat-Apply", "pending-handoff-or-close-failure-retains-claims")
	add("runtime.persistence", "owner-contract", "RUNTIME_UPDATE_UNSPECIFIED", "unbound-or-failed-owner-remains-durability-pending", "retry-requires-original-repeat-safe-owner", "regeneration-requires-separate-owner-ack")
	add("inbounds", "polaris-client-listener-policy1", "LOCAL_REPLACE", "stored-client-impact-policy=1;capability-is-not-consent", "fixed-mixed-in-port;127.0.0.1-loopback-or-::-allowLAN;legacy-0.0.0.0-preserved", "np-probe-in-UDP-loopback-with-closed-hijack-and-REFUSED-DNS-prefix", "main-carrier-count-and-tag-unchanged", "full-occupancy-reservation-exclusive-bind-and-compensation", "accepted-impact-digest;affected-UDP-associations-may-reset")
	tunClass := "RUNTIME_UPDATE_UNSPECIFIED"
	if runtime.GOOS == "linux" || runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		tunClass = "LOCAL_REPLACE"
	}
	add("inbounds", "polaris-client-tun-policy1", tunClass, "stored-client-impact-policy=1;capability-is-not-consent", "closed-client-shape;fixed-addresses;no-stack-or-foreign-TUN-options", "desktop-local-owner-or-actually-registered-original-provider-V1;GOOS-is-not-registration", "native-path-requires-original-owner-session;old-SDK-absent-or-quarantined-bridge-rejected-by-Plan", "implementation-inventory-only;mobile-readiness-is-not-advertised-by-build", "Android-fixed-/16;ios-fixed-/16-default-or-explicit-/30;optional-fixed-IPv6", "mobile-no-interface-name-dns-mode-MAC-auto-redirect-strict-route-or-platform-proxy", "Android-only-bounded-exclude-package;include-package-unimplemented", "captured-physical-dependencies-rechecked-after-stage-before-publication", "accepted-impact-digest;existing-TUN-TCP-and-UDP-sessions-reset", "MAC-filter-only-Linux-auto-route-auto-redirect", "darwin-strict-route-value-unchanged;main-carrier-count-and-tag-unchanged", "compensation-retains-unknown-physical-owner-and-does-not-resurrect-sessions")
	add("dns.servers", "polaris-fixed-fakeip-ipv6-policy1", "LOCAL_REPLACE", "stored-client-impact-policy=1;capability-is-not-consent", "fixed-198.18.0.0/15-and-conditional-2001:2::/48-only", "original-config-persistence-owner-required", "persistent-ranges-require-private-recovered-host-root-and-bound-cache", "journal-links-bind-original-transaction-and-effective-config-identity", "original-WaitPersistence-owner-ACK-and-repeat-safe-retry", "old-valid-answer-recognition-retained")
	add("log", "stable-options-policy1", "IN_PLACE", "stored-client-impact-policy=1;capability-is-not-consent", "disabled-toggle-with-factory-bound-original-output-and-format", "hot-file-output-must-already-exist;no-path-creation-or-change", "stable-logger-and-observable-owner", "prepare-abort-and-publication-Finish-on-every-exit", "retirement-joins-old-emission-before-close;timeout-is-not-drained")
	add("services", "polaris-dashboard-toggle-policy1", "LOCAL_REPLACE", "stored-client-impact-policy=1;capability-is-not-consent", "one-plain-loopback-API-service;stable-tag;no-TLS-CORS-or-socket-expansion", "disabled-to-or-from-detour-only-default-URL-and-interval-dashboard", "no-enabled-to-enabled-path-URL-or-client-edit", "services-impact-reconnect-and-api_generation_handoff_v1", "same-endpoint-and-secret-still-require-fresh-HMAC-carrier-and-original-ACK", "publication-activates-prepared-worker-after-previous-worker-join;abort-keeps-old-worker")
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
	for _, tag := range []string{"with_quic", "with_acme", "with_wireguard", "with_tailscale", "with_openconnect", "with_openvpn", "with_naive_outbound", "with_dhcp", "with_utls", "with_purego"} {
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
	return []string{"inbounds[hysteria2.realm]", "services[non-api-or-api-dependent-listener]", "certificate_providers[acme]", "ntp[write_to_system]"}
}

func (s *Box) RuntimeCapabilities() RuntimeConfigCapabilities {
	fields := runtimeCapabilityFields()
	impactPolicies := []RuntimeClientImpactPolicyVersion{RuntimeClientImpactPolicyExplicit}
	// Only strings/slices enter this encoding; no unsupported JSON value exists.
	encoded, _ := stdjson.Marshal(struct {
		ContractVersion                     uint32                             `json:"contract_version"`
		Fields                              []RuntimeFieldCapability           `json:"fields"`
		SupportedClientImpactPolicyVersions []RuntimeClientImpactPolicyVersion `json:"supported_client_impact_policy_versions"`
	}{RuntimeConfigContractVersion, fields, impactPolicies})
	result := RuntimeConfigCapabilities{
		ContractVersion:                     RuntimeConfigContractVersion,
		FullConfiguration:                   false,
		Fields:                              fields,
		ImplementationManifestDigest:        runtimeDigest(encoded),
		PendingAdapters:                     runtimePendingAdapters(),
		SupportedClientImpactPolicyVersions: impactPolicies,
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
