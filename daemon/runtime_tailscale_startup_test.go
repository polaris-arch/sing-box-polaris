//go:build with_tailscale

package daemon

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/protocol/group"
	protocolTS "github.com/sagernet/sing-box/protocol/tailscale"
	"github.com/sagernet/sing/service"
)

func TestRuntimeTailscaleNativeAdditionKeepsOriginalPhysicalChildInDNSCohort(t *testing.T) {
	host, raw, originalState := runtimeTailscaleStartupFixture(t)
	platform := &nativeTailscaleClaimsFixture{owners: make(map[string]adapter.RuntimeTailscaleWriterScope)}
	host.ctx = service.ContextWith[adapter.PlatformInterface](host.ctx, platform)
	transport.RegisterUDP(service.FromContext[adapter.DNSTransportRegistry](host.ctx).(*dns.TransportRegistry))
	group.RegisterSelector(service.FromContext[adapter.OutboundRegistry](host.ctx).(*outbound.Registry))
	var config map[string]any
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		t.Fatal(err)
	}
	remote := map[string]any{
		"type": "udp", "tag": "remote", "server": "127.0.0.1", "detour": "choose",
	}
	config["dns"] = map[string]any{"servers": []map[string]any{remote}}
	logOptions := config["log"].(map[string]any)
	logOptions["level"] = "info"
	selector := map[string]any{"type": "selector", "tag": "choose", "outbounds": []string{"direct", "retained"}, "default": "direct"}
	config["outbounds"] = []map[string]any{{"type": "direct", "tag": "direct"}, selector}
	config["route"] = map[string]any{"final": "choose"}
	encode := func() string {
		t.Helper()
		content, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		return string(content)
	}
	start := startWithTailscaleCohort(t, host, encode())
	if len(start.InitialChildren) != 1 || len(start.InitialChildren[0].Nodes) != 1 ||
		start.InitialChildren[0].Nodes[0].StateDirectory != originalState {
		t.Fatal("initial cohort did not capture the original Tailscale writer")
	}
	original := start.InitialChildren[0]
	ctx := ContextWithRuntimeActor(context.Background(), "owner")
	active, err := host.GetRuntimeCapabilities(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	planConfig := func() *RuntimeConfigPlan {
		t.Helper()
		plan, err := host.PlanRuntimeConfig(ctx, &PlanRuntimeConfigRequest{
			ContractVersion: box.RuntimeConfigContractVersion, Expected: active.Active, ExpectedControlRevision: active.ControlRevision,
			ConfigContent: encode(), ClientImpactPolicyVersion: uint32(box.RuntimeClientImpactPolicyExplicit),
		})
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}
	apply := func(plan *RuntimeConfigPlan) {
		t.Helper()
		if !plan.Applicable {
			t.Fatalf("original writers could not be retained: %v", plan.Errors)
		}
		operation, err := host.ApplyRuntimeConfig(ctx, &ApplyRuntimeConfigRequest{
			ContractVersion: box.RuntimeConfigContractVersion, Expected: active.Active, ExpectedControlRevision: active.ControlRevision,
			PlanId: plan.PlanId, TransactionId: plan.TransactionId, CandidateDigest: plan.CandidateDigest, AcceptedImpactDigest: plan.ImpactDigest,
		})
		if err != nil {
			t.Fatal(err)
		}
		if (operation.State != RuntimeOperationState_COMMITTED && operation.State != RuntimeOperationState_COMMITTED_DURABILITY_PENDING) ||
			operation.Active.Incarnation != active.Active.Incarnation || operation.Active.AppliedRevision != active.Active.AppliedRevision+1 {
			t.Fatalf("Apply did not publish the next graph of the original instance: %v %v", operation.State, operation.Errors)
		}
		active.Active, active.ControlRevision = operation.Active, operation.ControlRevision
	}
	retained := func() (logical, physical *protocolTS.Endpoint) {
		t.Helper()
		lease, _, connected, err := host.instance.instance.AcquireRuntimeAPI()
		if err != nil || !connected {
			t.Fatalf("active graph unavailable: %v", err)
		}
		defer lease.Release()
		value, _ := lease.View().EndpointManager().Get("retained")
		logical, ok := value.(*protocolTS.Endpoint)
		if !ok {
			t.Fatal("active graph lost the original Tailscale binding")
		}
		physical, _ = logical.NATIdentity().(*protocolTS.Endpoint)
		if physical == nil {
			t.Fatal("active graph lost the original Tailscale owner")
		}
		return logical, physical
	}
	_, physical := retained()
	logOptions["level"] = "debug"
	apply(planConfig())
	beforeDNS, afterLog := retained()
	remote["server_port"] = 5353 // Force a logical rebuild with zero new Tailscale writers.
	apply(planConfig())
	afterDNS, afterDNSPhysical := retained()
	if afterDNS == beforeDNS || afterLog != physical || afterDNSPhysical != physical {
		t.Fatal("logical DNS cohort replacement did not reuse the original physical child")
	}

	children := config["endpoints"].([]any)
	old := children[0].(map[string]any)
	addedState := filepath.Join(filepath.Dir(originalState), "new-state")
	added := map[string]any{
		"type": "tailscale", "tag": "new-child", "state_directory": addedState,
		"taildrop_directory": filepath.Join(filepath.Dir(originalState), "new-drop"),
		"hostname":           "new-node", "control_url": "http://127.0.0.1:1", "on_demand": true,
	}
	config["endpoints"] = append(children, added)
	selector["outbounds"] = []string{"direct", "retained", "new-child"}
	expectRestart := func(path string) {
		t.Helper()
		plan := planConfig()
		if plan.Applicable || len(plan.Errors) != 1 || plan.Errors[0].Code != "RESTART_REQUIRED" || plan.Errors[0].EffectivePath != path {
			t.Fatalf("expected %s to require restart: %v", path, plan.Errors)
		}
	}
	old["auth_key"] = "changed-fixture-auth"
	expectRestart("endpoints.retained")
	delete(old, "auth_key")
	config["endpoints"] = []any{added}
	selector["outbounds"] = []string{"direct", "new-child"}
	expectRestart("endpoints.retained")
	old["tag"] = "renamed"
	config["endpoints"] = append(children, added)
	selector["outbounds"] = []string{"direct", "renamed", "new-child"}
	expectRestart("endpoints.retained")
	old["tag"] = "retained"
	selector["outbounds"] = []string{"direct", "retained", "new-child"}

	added["state_directory"] = originalState
	overlap := planConfig()
	if overlap.Applicable || len(overlap.Errors) != 1 || overlap.Errors[0].Code != "RESTART_REQUIRED" {
		t.Fatalf("an overlapping new writer was admitted: %v", overlap.Errors)
	}
	added["state_directory"] = addedState
	config["endpoints"] = append(children, added, map[string]any{
		"type": "tailscale", "tag": "extra", "state_directory": filepath.Join(filepath.Dir(originalState), "extra-state"),
		"taildrop_directory": filepath.Join(filepath.Dir(originalState), "extra-drop"), "on_demand": true,
	})
	expectRestart("endpoints.new-child")
	config["endpoints"] = append(children, added)

	plan := planConfig()
	platform.mu.Lock()
	unclaimed := len(platform.owners) == 0 && len(platform.releases) == 0
	platform.mu.Unlock()
	if len(host.snapshotTailscaleRetirementRuns()) != 2 || !unclaimed {
		t.Fatal("zero-writer Apply or advisory Plan changed the original native census")
	}
	apply(plan)
	runs := host.snapshotTailscaleRetirementRuns()
	platform.mu.Lock()
	scope, hasWriter := platform.owners[addedState]
	writerCount := len(platform.owners)
	platform.mu.Unlock()
	_, afterAddition := retained()
	if len(runs) != 3 || !hasWriter || writerCount != 1 || scope.Binding.ConfigDigest != plan.CandidateDigest ||
		afterAddition != physical ||
		runs[1].snapshot().RunNonce != original.RunNonce || runs[1].snapshot().Terminal != "Unknown" ||
		runs[2].snapshot().RunNonce != scope.Binding.RunNonce {
		t.Fatal("Apply recreated the original physical child or failed to admit only the exact new writer")
	}
	if err := host.CloseService(); err != nil {
		t.Fatal(err)
	}
	for _, run := range runs {
		if row := run.snapshot(); !row.CensusComplete || row.Terminal == "Unknown" {
			t.Fatal("Close left an original writer unconfirmed")
		}
	}
	platform.mu.Lock()
	defer platform.mu.Unlock()
	if len(platform.owners) != 0 || !reflect.DeepEqual(platform.releases, []bool{true}) {
		t.Fatal("Close did not release the exact warm writer once")
	}
}

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
