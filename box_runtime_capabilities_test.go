package box

import (
	"encoding/hex"
	stdjson "encoding/json"
	"reflect"
	"slices"
	"testing"
)

func TestRuntimeRealmCapabilityUsesExistingProtocolAndConcreteBuild(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		tags := ""
		if enabled {
			tags = "with_quic"
		}
		fields := runtimeCapabilityFieldsForBuild(tags, true, enabled, false)
		var realm, protocol *RuntimeFieldCapability
		for i := range fields {
			field := &fields[i]
			if field.Path == "outbounds" && field.Variant == "hysteria2-realm" {
				realm = field
			}
			if field.Path == "runtime.protocol" {
				protocol = field
			}
		}
		if realm == nil || (realm.UpdateClass == "LOCAL_REPLACE") != enabled || realm.AdapterVersion != "1" {
			t.Fatalf("Realm capability disagrees with its concrete adapter: %+v", realm)
		}
		for _, condition := range []string{
			"captured-named-default-inline-HTTP-and-STUN-resolver-detour-closure",
			"discovery-XML-SOAP-and-delete-borrow-the-captured-HTTP-closure",
			"UPnP-device-hostnames-captured-once-in-the-discovery-generation",
			"joined-workers-late-results-and-mapper-retirement",
			"uncancelable-native-NAT-calls-remain-owned-until-return",
			"unknown-mapping-or-delete-failure-remains-cleanup-debt",
		} {
			if !slices.Contains(realm.Conditions, condition) {
				t.Fatal("Realm capability omitted its real boundary", condition)
			}
		}
		if protocol == nil || protocol.Variant != "polaris-daily-runtime-v1" || protocol.AdapterVersion != "1" || !reflect.DeepEqual(protocol.Conditions, []string{
			"GetRuntimeCapabilities", "PlanRuntimeConfig", "ApplyRuntimeConfig", "GetRuntimeConfigStatus", "RetryRuntimePersistence", "AcknowledgeRuntimePersistence",
		}) {
			t.Fatal("Realm changed the shared wire contract", protocol)
		}
	}
	if capability := (*Box)(nil).RuntimeCapabilities(); capability.FullConfiguration || slices.Contains(capability.PendingAdapters, "outbounds[hysteria2.realm]") {
		t.Fatal("Realm completion widened FullConfig or remained category-pending", capability)
	}
	if !slices.Contains(runtimePendingAdapters(), "inbounds[hysteria2.realm]") {
		t.Fatal("outbound Realm completion advertised inbound remote activation")
	}
}

func TestRuntimeCapabilitiesDashboardChangesStayStructuralWithConditionalAPIHandoff(t *testing.T) {
	capability := (*Box)(nil).RuntimeCapabilities()
	if capability.FullConfiguration {
		t.Fatal("narrow dashboard adapter advertised full configuration")
	}
	if !slices.Contains(capability.SupportedPaths, "services") {
		t.Fatal("missing bounded API listener handoff capability")
	}
	var handoff bool
	for _, field := range capability.Fields {
		if field.Path == "services" && field.Variant == "api-loopback-handoff-v1" && field.UpdateClass == "LOCAL_REPLACE" {
			handoff = true
		}
	}
	if !handoff {
		t.Fatal("services path lacks the explicit conditional API variant")
	}

	for _, field := range capability.Fields {
		if field.Path != "services" || field.Variant != "structural-change" {
			continue
		}
		if field.UpdateClass != "RESTART_REQUIRED" || !reflect.DeepEqual(field.Conditions, []string{
			"unchanged-supported-components-may-coexist", "explicit-host-restart-only",
			"unchanged-plain-loopback-api-may-coexist", "enabled-dashboard-requires-inline-detour-only-http-client",
			"dashboard-fetch-borrows-current-graph-until-body-close",
		}) {
			t.Fatalf("dashboard coexistence boundary missing: %+v", field)
		}
		return
	}
	t.Fatal("missing service structural-change capability")
}

func TestRuntimeCapabilitiesManifestIsDetachedAndInstanceIndependent(t *testing.T) {
	instance := new(Box)
	first := instance.RuntimeCapabilities()
	if first.Enabled || first.FullConfiguration || len(first.SupportedPaths) == 0 || len(first.Fields) == 0 {
		t.Fatal("zero Box must describe the protocol without advertising a running graph")
	}
	digest, err := hex.DecodeString(first.ImplementationManifestDigest)
	if err != nil || len(digest) != 32 {
		t.Fatal("missing bounded implementation digest")
	}
	second := instance.RuntimeCapabilities()
	if !reflect.DeepEqual(second, (*Box)(nil).RuntimeCapabilities()) {
		t.Fatal("nil and zero Box protocol inventory diverged")
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("manifest is not deterministic")
	}
	first.Fields[0].Conditions[0] = "modified-by-caller"
	first.SupportedPaths[0] = "modified-by-caller"
	if !reflect.DeepEqual(second, instance.RuntimeCapabilities()) {
		t.Fatal("caller mutated capability storage")
	}
	instance.runtimeEligibilityErrors = []RuntimePlanError{{Code: "PENDING_ADAPTER", Path: "services"}}
	legacy := instance.RuntimeCapabilities()
	if legacy.Enabled || legacy.ImplementationManifestDigest != second.ImplementationManifestDigest {
		t.Fatal("instance eligibility changed implementation identity")
	}
	last := legacy.Fields[len(legacy.Fields)-1]
	if last.Path != "runtime.instance" || last.Variant != "PENDING_ADAPTER" || !reflect.DeepEqual(last.Conditions, []string{"services"}) {
		t.Fatalf("missing precise legacy reason: %+v", last)
	}
}

func TestRuntimeCapabilitiesRetainsIdentityAcrossReadinessAndStop(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	initial := f.box.RuntimeCapabilities()
	if initial.Enabled || initial.Identity.Incarnation == "" {
		t.Fatal("startup owner lost identity")
	}
	f.start(t)
	active := f.box.RuntimeCapabilities()
	if !active.Enabled || active.Identity.Incarnation != initial.Identity.Incarnation {
		t.Fatal("ready graph not enabled")
	}
	f.box.runtime.access.Lock()
	f.box.runtime.preparing = true
	f.box.runtime.access.Unlock()
	busy := f.box.RuntimeCapabilities()
	f.box.runtime.access.Lock()
	f.box.runtime.preparing = false
	f.box.runtime.access.Unlock()
	if !busy.Enabled {
		t.Fatal("temporary transaction admission became a product switch")
	}
	if err := f.box.CloseWithResult(); err != nil {
		t.Fatal(err)
	}
	stopped := f.box.RuntimeCapabilities()
	if stopped.Enabled || stopped.Identity != active.Identity || stopped.ImplementationManifestDigest != active.ImplementationManifestDigest {
		t.Fatal("stopped instance capability/receipt identity is incorrect")
	}
}

func TestRuntimeCapabilityBuildInventoryIsCanonicalAndHonest(t *testing.T) {
	encode := func(tags string, known bool) string {
		t.Helper()
		value, err := stdjson.Marshal(runtimeCapabilityFieldsForBuild(tags, known, true, false))
		if err != nil {
			t.Fatal(err)
		}
		return runtimeDigest(value)
	}
	if encode("with_tailscale,with_naive_outbound", true) != encode("with_naive_outbound with_tailscale", true) {
		t.Fatal("tag ordering changed implementation identity")
	}
	if encode("with_tailscale", true) == encode("with_tailscale,with_naive_outbound", true) {
		t.Fatal("different concrete build variants share a manifest identity")
	}
	unknown := runtimeCapabilityBuildFeatures("", false, true, false)
	if unknown["with_tailscale"] != "unknown" || unknown["with_quic"] != "enabled" || unknown["cgo"] != "disabled" {
		t.Fatal("missing metadata disguised as disabled or compile constants lost")
	}
	known := runtimeCapabilityBuildFeatures("with_tailscale", true, false, true)
	if known["with_naive_outbound"] != "disabled" || known["with_tailscale"] != "enabled" || known["with_quic"] != "disabled" || known["cgo"] != "enabled" {
		t.Fatal("known build inventory incorrect")
	}
}

func TestRuntimeLegacyCapabilityRequiresActualStartCompletion(t *testing.T) {
	instance := &Box{runtimeEligibilityErrors: []RuntimePlanError{{Code: "PENDING_ADAPTER", Path: "services"}}}
	state := func() string {
		t.Helper()
		capability := instance.RuntimeCapabilities()
		if capability.Enabled {
			t.Fatal("unsupported legacy graph advertised HOT")
		}
		for _, field := range capability.Fields {
			if field.Path == "runtime.instance" {
				return field.Variant
			}
		}
		t.Fatal("missing legacy lifecycle evidence")
		return ""
	}
	if state() != "RUNTIME_STARTING" {
		t.Fatal("unstarted legacy instance claimed ready")
	}
	instance.started.Store(true)
	if state() != "RUNTIME_STARTED_UNSUPPORTED" {
		t.Fatal("started unsupported graph has no explicit truthful state")
	}
	instance.runtimeEligibilityErrors = []RuntimePlanError{{Code: "INITIAL_CONFIG_ENCODING_FAILED", Path: "runtime"}}
	if state() != "RUNTIME_GRAPH_UNAVAILABLE" {
		t.Fatal("unknown eligibility was mistaken for supported legacy admission")
	}
	instance.closeStarted.Store(true)
	if state() != "RUNTIME_STOPPED" {
		t.Fatal("closed legacy instance claimed ready")
	}
}

func TestRuntimeResourceAdapterManifestRetainsExactUnsupportedVariants(t *testing.T) {
	fields := runtimeCapabilityFieldsForBuild("with_acme,with_tailscale,with_quic", true, true, false)
	find := func(path, variant string) RuntimeFieldCapability {
		t.Helper()
		for _, field := range fields {
			if field.Path == path && field.Variant == variant {
				return field
			}
		}
		t.Fatalf("missing capability %s/%s", path, variant)
		return RuntimeFieldCapability{}
	}
	for _, item := range [][2]string{{"http_clients", "go-http1-http2"}, {"http_clients", "go-http3"}, {"certificate_providers", "cloudflare-origin-ca"}, {"certificate_providers", "tailscale"}, {"ntp", "offset-only"}, {"inbounds.tls.certificate_provider", "named-or-inline"}} {
		if field := find(item[0], item[1]); field.UpdateClass != "LOCAL_REPLACE" {
			t.Fatal("concrete adapter not exposed", field)
		}
	}
	if field := find("certificate_providers", "acme"); field.UpdateClass != "PENDING_ADAPTER" {
		t.Fatal("unowned certmagic tasks were advertised as closed", field)
	}
	if field := find("ntp.write_to_system", "irreversible"); field.UpdateClass != "RESTART_REQUIRED" {
		t.Fatal("system clock write was advertised as reversible", field)
	}
	capability := (*Box)(nil).RuntimeCapabilities()
	if capability.FullConfiguration {
		t.Fatal("resource adapters claimed full schema")
	}
	for _, pending := range capability.PendingAdapters {
		if pending == "http_clients" || pending == "certificate_providers" || pending == "ntp" {
			t.Fatal("category-wide pending hid actual variant support", pending)
		}
	}
}
