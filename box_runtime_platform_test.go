package box

import (
	"testing"

	"github.com/sagernet/sing-box/route"
)

func TestRuntimePlatformDemandCanShrinkAndReuse(t *testing.T) {
	have := route.RuntimeRequirements{Process: true, WIFI: true, DHCPLeaseFiles: []string{"/lease"}}
	if !runtimePlatformRequirementsAvailable(have, route.RuntimeRequirements{}) {
		t.Fatal("removal rejected")
	}
	if !runtimePlatformRequirementsAvailable(have, route.RuntimeRequirements{Process: true}) {
		t.Fatal("provisioned capability rejected")
	}
	if runtimePlatformRequirementsAvailable(have, route.RuntimeRequirements{Neighbor: true}) {
		t.Fatal("unprovisioned capability admitted")
	}
	if runtimePlatformRequirementsAvailable(have, route.RuntimeRequirements{DHCPLeaseFiles: []string{"/other"}}) {
		t.Fatal("uncaptured lease source admitted")
	}
}

func TestRuntimeFirstProcessRuleUsesReviewedPrivatePreparation(t *testing.T) {
	got := runtimePlatformRequirementsAvailable(route.RuntimeRequirements{}, route.RuntimeRequirements{Process: true})
	if got != runtimeCanPrepareProcessSearcher() {
		t.Fatal("process preparation platform gate drift")
	}
	if runtimePlatformRequirementsAvailable(route.RuntimeRequirements{}, route.RuntimeRequirements{WIFI: true}) {
		t.Fatal("process support relaxed Wi-Fi gate")
	}
	if runtimePlatformRequirementsAvailable(route.RuntimeRequirements{}, route.RuntimeRequirements{Neighbor: true}) {
		t.Fatal("process support relaxed neighbor gate")
	}
}
