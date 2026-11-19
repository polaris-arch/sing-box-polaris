//go:build with_tailscale

package daemon

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	protocolTS "github.com/sagernet/sing-box/protocol/tailscale"
	"github.com/sagernet/sing/service"
)

func TestRuntimeTailscaleStartupCohortRetainsPhysicalChildrenAcrossStrictReload(t *testing.T) {
	host, config, state := runtimeTailscaleStartupFixture(t)
	var original []string
	for index := range 2 {
		cohort := startWithTailscaleCohort(t, host, config)
		if index == 1 {
			rows := host.snapshotTailscaleRetirementRuns()
			if row := rows[1].snapshot(); row.RunNonce != original[1] || !row.CensusComplete || row.Terminal == "Unknown" {
				t.Fatalf("strict Reload returned before the original initial child observer completed: %+v", row)
			}
		}
		if len(cohort.Parent.Nodes) != 0 || len(cohort.InitialChildren) != 1 {
			t.Fatalf("startup did not separate the original parent and physical child: %+v", cohort)
		}
		child := cohort.InitialChildren[0]
		if child.RunNonce == cohort.Parent.RunNonce || len(child.RunNonce) != 64 ||
			child.ConfigDigest == cohort.Parent.ConfigDigest || len(child.ConfigDigest) != 64 ||
			child.CensusComplete || child.Terminal != "Unknown" || len(child.Nodes) != 1 ||
			child.Nodes[0].Tag != "retained" || child.Nodes[0].StateDirectory != state ||
			child.Nodes[0].StateFile != filepath.Join(state, "tailscaled.state") {
			t.Fatalf("invalid original physical startup scope: %+v", child)
		}
		original = append(original, cohort.Parent.RunNonce, child.RunNonce)
	}
	if err := host.CloseService(); err != nil {
		t.Fatal(err)
	}
	if got := retirementExportNonces(t, host.ExportTailscaleStoreRetirement()); !reflect.DeepEqual(original, got) {
		t.Fatalf("original parent and physical child history changed: got %v, want %v", got, original)
	}
	for _, run := range host.snapshotTailscaleRetirementRuns() {
		if row := run.snapshot(); !row.CensusComplete || row.Terminal == "Unknown" {
			t.Fatalf("original retained startup census was not terminal: %+v", row)
		}
	}
}

func TestRuntimeTailscaleStartupCohortChecksCapacityBeforeDetachingOldCore(t *testing.T) {
	host, config, _ := runtimeTailscaleStartupFixture(t)
	startWithTailscaleCohort(t, host, config)
	original := host.instance
	host.tailscaleRetirementAccess.Lock()
	for len(host.tailscaleRetirementRuns) < maxTailscaleRetirementRuns-1 {
		history := completedEmptyRetirementRun(t)
		history.historyPinned = true
		host.tailscaleRetirementRuns = append(host.tailscaleRetirementRuns, history)
	}
	host.tailscaleRetirementAccess.Unlock()
	payload, err := host.StartOrReloadServiceWithTailscaleStartup(context.Background(), config, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "tailscale retirement census capacity") || payload != "" {
		t.Fatalf("only one slot remains for a parent and child: %q, %v", payload, err)
	}
	if host.instance != original || host.serviceStatus.Status != ServiceStatus_STARTED {
		t.Fatal("cohort admission rejected after stopping the original instance")
	}
	select {
	case <-original.closeFinished:
		t.Fatal("cohort admission closed the original instance")
	default:
	}
}

func runtimeTailscaleStartupFixture(t *testing.T) (*StartedService, string, string) {
	t.Helper()
	host, _ := retirementPureHost(t)
	t.Setenv("TS_NO_LOGS_NO_SUPPORT", "true")
	protocolTS.RegisterEndpoint(service.FromContext[adapter.EndpointRegistry](host.ctx).(*endpoint.Registry))
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "state")
	config, err := json.Marshal(map[string]any{
		"log": map[string]any{"disabled": true},
		"endpoints": []map[string]any{{
			"type": "tailscale", "tag": "retained", "state_directory": state, "taildrop_directory": filepath.Join(root, "drop"),
			"hostname": "cohort-test", "control_url": "http://127.0.0.1:1", "on_demand": true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return host, string(config), state
}
