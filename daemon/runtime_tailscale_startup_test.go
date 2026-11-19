//go:build with_tailscale

package daemon

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	protocolTS "github.com/sagernet/sing-box/protocol/tailscale"
	"github.com/sagernet/sing/service"
)

func TestRuntimeTailscaleStartupCohortRetainsPhysicalChildrenAcrossStrictReload(t *testing.T) {
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
	var original []string
	for range 2 {
		cohort := startWithTailscaleCohort(t, host, string(config))
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
