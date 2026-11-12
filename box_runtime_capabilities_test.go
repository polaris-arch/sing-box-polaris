package box

import (
	"encoding/hex"
	"reflect"
	"testing"
)

// Only the fields that Android, iOS and desktop App decoders accept are pinned here.
func TestRuntimeCapabilitiesKeepAppReadContract(t *testing.T) {
	capability := (*Box)(nil).RuntimeCapabilities()
	digest, err := hex.DecodeString(capability.ImplementationManifestDigest)
	if err != nil || len(digest) != 32 {
		t.Fatal("missing bounded implementation digest")
	}
	var protocol *RuntimeFieldCapability
	var handoff bool
	for i, field := range capability.Fields {
		if field.Path == "runtime.protocol" {
			protocol = &capability.Fields[i]
		}
		if field.Path == "services" && field.Variant == "api-loopback-handoff-v1" && field.UpdateClass == "LOCAL_REPLACE" {
			handoff = true
		}
	}
	if protocol == nil || protocol.Variant != "polaris-daily-runtime-v1" || protocol.AdapterVersion != "1" || !reflect.DeepEqual(protocol.Conditions, []string{
		"GetRuntimeCapabilities", "PlanRuntimeConfig", "ApplyRuntimeConfig", "GetRuntimeConfigStatus", "RetryRuntimePersistence", "AcknowledgeRuntimePersistence",
	}) {
		t.Fatal("shared wire contract changed", protocol)
	}
	if !handoff {
		t.Fatal("services path lacks the explicit conditional API variant")
	}
	legacy := (&Box{runtimeEligibilityErrors: []RuntimePlanError{{Code: "PENDING_ADAPTER", Path: "services"}}}).RuntimeCapabilities()
	last := legacy.Fields[len(legacy.Fields)-1]
	if legacy.Enabled || legacy.ImplementationManifestDigest != capability.ImplementationManifestDigest || last.Path != "runtime.instance" || last.Variant != "PENDING_ADAPTER" || !reflect.DeepEqual(last.Conditions, []string{"services"}) {
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
