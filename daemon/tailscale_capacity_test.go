package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

func completedEmptyRetirementRun(t *testing.T) *tailscaleRetirementRun {
	t.Helper()
	r, err := newTailscaleRetirementRun(`{}`, option.Options{})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	r.closeFinished = done
	r.freeze(nil, true)
	r.freezeDirectories(nil, true)
	r.originalCloseSucceeded = true
	close(done)
	return r
}

func TestRetirementCapacityRequiresOriginalCompleteEmptyProof(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*tailscaleRetirementRun)
	}{
		{"not completed", func(r *tailscaleRetirementRun) { r.closeFinished = make(chan struct{}) }},
		{"no original completion", func(r *tailscaleRetirementRun) { r.closeFinished = nil }},
		{"close failed", func(r *tailscaleRetirementRun) { r.originalCloseSucceeded = false }},
		{"expected TS", func(r *tailscaleRetirementRun) { r.expected = []string{"node"} }},
		{"store unknown", func(r *tailscaleRetirementRun) { r.final.Terminal = "Unknown" }},
		{"directory unknown", func(r *tailscaleRetirementRun) { r.directoryFinal.Terminal = "Unknown" }},
		{"store incomplete", func(r *tailscaleRetirementRun) { r.final.CensusComplete = false }},
		{"directory incomplete", func(r *tailscaleRetirementRun) { r.directoryFinal.CensusComplete = false }},
		{"store node", func(r *tailscaleRetirementRun) { r.final.Nodes = []adapter.TailscaleStoreNode{{}} }},
		{"directory node", func(r *tailscaleRetirementRun) { r.directoryFinal.Nodes = []adapter.TailscaleDirectoryNode{{}} }},
		{"construction failed", func(r *tailscaleRetirementRun) {
			r.final = nil
			r.directoryFinal = nil
			r.freeze(nil, false)
			r.freezeDirectories(nil, false)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := completedEmptyRetirementRun(t)
			test.change(r)
			if r.reclaimableEmptyRun() {
				t.Fatal("incomplete or resource-bearing original run was reclaimable")
			}
		})
	}
	if !completedEmptyRetirementRun(t).reclaimableEmptyRun() {
		t.Fatal("completed empty proof not reclaimable")
	}
}

func TestRetirementCapacityDoesNotTrustDuplicateCloseOrLiveRun(t *testing.T) {
	r := completedEmptyRetirementRun(t)
	r.closeFinished = make(chan struct{})
	i := &Instance{tailscaleRetirement: r}
	i.closeStarted.Store(true)
	if err := i.Close(); err != nil {
		t.Fatal(err)
	}
	if r.reclaimableEmptyRun() {
		t.Fatal("early nil duplicate Close was treated as completion")
	}
	host := NewStartedService(ServiceOptions{Context: context.Background()})
	defer host.Close()
	r = completedEmptyRetirementRun(t)
	host.instance = &Instance{tailscaleRetirement: r}
	host.tailscaleRetirementRuns = []*tailscaleRetirementRun{r}
	if err := host.admitTailscaleRetirementRun(); err != nil {
		t.Fatal(err)
	}
	if len(host.tailscaleRetirementRuns) != 1 || host.tailscaleRetirementRuns[0] != r {
		t.Fatal("live run removed")
	}
}

// Constructor-only regression: no real service is started. The normal reload
// admission uses the same helper while holding lifecycleAccess.
func TestRetirementCapacityRepeatedEmptyConstructionBeyondLimit(t *testing.T) {
	host, _ := retirementPureHost(t)
	seen := make(map[string]bool)
	for range 2*maxTailscaleRetirementRuns + 1 {
		host.lifecycleAccess.Lock()
		i, err := host.newInstance(context.Background(), `{}`, nil, false)
		host.lifecycleAccess.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		nonce := i.tailscaleRetirement.binding.RunNonce
		if seen[nonce] || len(nonce) != 64 {
			t.Fatal("run identity reused or malformed")
		}
		seen[nonce] = true
		if len(host.tailscaleRetirementRuns) != 1 {
			t.Fatalf("retained %d empty runs", len(host.tailscaleRetirementRuns))
		}
		if err := i.CloseWithResult(); err != nil {
			t.Fatal(err)
		}
		if len(host.tailscaleRetirementRuns) != 1 {
			t.Fatal("stop pruned the terminal census")
		}
	}
}

func TestRetirementCapacityRejectsBeforeStoppingStartedInstance(t *testing.T) {
	host, _ := retirementPureHost(t)
	for range maxTailscaleRetirementRuns {
		r := completedEmptyRetirementRun(t)
		r.final.Terminal = "Unknown"
		host.tailscaleRetirementRuns = append(host.tailscaleRetirementRuns, r)
	}
	oldCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	old := &Instance{ctx: oldCtx, cancel: cancel}
	host.instance = old
	host.serviceStatus = &ServiceStatus{Status: ServiceStatus_STARTED}
	started := time.Now()
	host.startedAt = started
	callback := false
	err := host.StartOrReloadServiceWithBeforeStart(context.Background(), `{}`, nil, func() { callback = true })
	if err == nil || !strings.Contains(err.Error(), "census capacity") {
		t.Fatalf("capacity rejection = %v", err)
	}
	if callback || host.instance != old || old.closeStarted.Load() || oldCtx.Err() != nil || host.startedAt != started || host.serviceStatus.Status != ServiceStatus_STARTED {
		t.Fatal("capacity rejection modified the stable running service")
	}
}

func retirementExportNonces(t *testing.T, payload string) []string {
	t.Helper()
	var value struct {
		Instances []struct {
			RunNonce string `json:"runNonce"`
		} `json:"instances"`
	}
	if err := json.Unmarshal([]byte(payload), &value); err != nil {
		t.Fatal(err)
	}
	result := make([]string, len(value.Instances))
	for n, r := range value.Instances {
		result[n] = r.RunNonce
	}
	return result
}

func TestRetirementCapacityPreservesObservedTerminalCensus(t *testing.T) {
	host, _ := retirementPureHost(t)
	host.lifecycleAccess.Lock()
	i, err := host.newInstance(context.Background(), `{}`, nil, false)
	host.lifecycleAccess.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	host.strictCleanup = false
	host.instance = i
	host.serviceStatus = &ServiceStatus{Status: ServiceStatus_STARTED}
	storeBefore := retirementExportNonces(t, host.ExportTailscaleStoreRetirement())
	directoryBefore := retirementExportNonces(t, host.ExportTailscaleDirectoryRetirement())
	if err := host.CloseService(); err != nil {
		t.Fatal(err)
	}
	storeAfter := retirementExportNonces(t, host.ExportTailscaleStoreRetirement())
	directoryAfter := retirementExportNonces(t, host.ExportTailscaleDirectoryRetirement())
	if len(storeBefore) != 1 || len(storeAfter) != 1 || storeBefore[0] != storeAfter[0] || len(directoryBefore) != 1 || len(directoryAfter) != 1 || directoryBefore[0] != directoryAfter[0] {
		t.Fatal("close/export changed the observed native nonce census")
	}
	host.lifecycleAccess.Lock()
	next, err := host.newInstance(context.Background(), `{}`, nil, false)
	host.lifecycleAccess.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	defer next.CloseWithResult()
	if len(host.tailscaleRetirementRuns) != 1 || next.tailscaleRetirement.binding.RunNonce == storeBefore[0] {
		t.Fatal("next admission failed to compact with a fresh identity")
	}
}

func TestPreparedInstanceSnapshotsOOMWithoutConstructing(t *testing.T) {
	host, _ := retirementPureHost(t)
	host.SetOOMKillerOptions(true, true, 123)
	prepared, err := host.prepareInstance(context.Background(), `{}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	host.SetOOMKillerOptions(false, false, 456)
	if len(prepared.options.Services) != 1 {
		t.Fatal("missing prepared OOM override")
	}
	oom, ok := prepared.options.Services[0].Options.(*option.OOMKillerServiceOptions)
	if !ok || !oom.KillerDisabled || oom.MemoryLimitOverride != 123 {
		t.Fatal("prepared options followed a later host setting")
	}
	if len(host.tailscaleRetirementRuns) != 0 {
		t.Fatal("pure preparation allocated a retained run")
	}
}

func TestPreparedInstanceConsumesDecodedOptionsWithoutReparse(t *testing.T) {
	host, _ := retirementPureHost(t)
	type options struct {
		Value string `json:"value"`
	}
	registry := service.FromContext[adapter.EndpointRegistry](host.ctx).(*endpoint.Registry)
	var got string
	failure := errors.New("stop after observing prepared options")
	endpoint.Register[options](registry, "test-prepared", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, _ string, value options) (adapter.Endpoint, error) {
		got = value.Value
		return nil, failure
	})
	prepared, err := host.prepareInstance(context.Background(), `{"endpoints":[{"type":"test-prepared","value":"raw"}]}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A reparse would restore raw. The constructor must consume this exact graph.
	prepared.options.Endpoints[0].Options.(*options).Value = "prepared"
	host.lifecycleAccess.Lock()
	_, err = host.newPreparedInstance(prepared, false)
	host.lifecycleAccess.Unlock()
	if !errors.Is(err, failure) || got != "prepared" {
		t.Fatalf("prepared constructor got %q, %v", got, err)
	}
	if len(host.tailscaleRetirementRuns) != 1 || host.tailscaleRetirementRuns[0].reclaimableEmptyRun() {
		t.Fatal("failed construction was not retained")
	}
}

func TestPreparedInstanceCopiesOverrideSlices(t *testing.T) {
	host, _ := retirementPureHost(t)
	registry := service.FromContext[adapter.InboundRegistry](host.ctx).(*inbound.Registry)
	inbound.Register[option.TunInboundOptions](registry, "test-tun-prepare", func(context.Context, adapter.Router, log.ContextLogger, string, option.TunInboundOptions) (adapter.Inbound, error) {
		t.Fatal("preparation constructed inbound")
		return nil, nil
	})
	overrides := &OverrideOptions{AutoRedirect: true, IncludePackage: []string{"included"}, ExcludePackage: []string{"excluded"}}
	prepared, err := host.prepareInstance(context.Background(), `{"inbounds":[{"type":"test-tun-prepare","auto_route":true}]}`, overrides)
	if err != nil {
		t.Fatal(err)
	}
	overrides.IncludePackage[0] = "changed"
	overrides.ExcludePackage[0] = "changed"
	overrides.AutoRedirect = false
	tun := prepared.options.Inbounds[0].Options.(*option.TunInboundOptions)
	if !tun.AutoRedirect || len(tun.IncludePackage) != 1 || tun.IncludePackage[0] != "included" || len(tun.ExcludePackage) != 1 || tun.ExcludePackage[0] != "excluded" {
		t.Fatal("prepared override retained caller-owned values")
	}
}

func TestRetirementCapacityExactAdmissionBoundary(t *testing.T) {
	host, _ := retirementPureHost(t)
	for range maxTailscaleRetirementRuns - 1 {
		r := completedEmptyRetirementRun(t)
		r.expected = []string{"node"}
		host.tailscaleRetirementRuns = append(host.tailscaleRetirementRuns, r)
	}
	host.lifecycleAccess.Lock()
	i, err := host.newInstance(context.Background(), `{}`, nil, false)
	host.lifecycleAccess.Unlock()
	if err != nil || len(host.tailscaleRetirementRuns) != maxTailscaleRetirementRuns {
		t.Fatalf("255 boundary: %v", err)
	}
	defer i.CloseWithResult()
	host.lifecycleAccess.Lock()
	_, err = host.newInstance(context.Background(), `{}`, nil, false)
	host.lifecycleAccess.Unlock()
	if err == nil || !strings.Contains(err.Error(), "census capacity") {
		t.Fatalf("256 boundary: %v", err)
	}
}

func TestRetirementCapacityPreservesExistingStartingInterruption(t *testing.T) {
	host, _ := retirementPureHost(t)
	for range maxTailscaleRetirementRuns {
		r := completedEmptyRetirementRun(t)
		r.final.Terminal = "Unknown"
		host.tailscaleRetirementRuns = append(host.tailscaleRetirementRuns, r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	old := &Instance{ctx: ctx, cancel: cancel}
	host.instance = old
	host.serviceStatus = &ServiceStatus{Status: ServiceStatus_STARTING}
	err := host.StartOrReloadService(context.Background(), `{}`, nil)
	if err == nil || ctx.Err() == nil || !host.startInterrupted || old.closeStarted.Load() {
		t.Fatal("pre-lock STARTING interruption contract changed")
	}
}

func TestPreparedAdmissionRechecksTerminalAfterCallback(t *testing.T) {
	host, _ := retirementPureHost(t)
	called := false
	err := host.StartOrReloadServiceWithBeforeStart(context.Background(), `{}`, nil, func() {
		called = true
		host.serviceAccess.Lock()
		host.shutdownRequested = true
		host.serviceAccess.Unlock()
	})
	if err == nil || !called || len(host.tailscaleRetirementRuns) != 0 || host.instance != nil {
		t.Fatal("terminal callback admitted construction")
	}
}

func TestPreparedInstanceParseFailurePreservesInitialDiagnostics(t *testing.T) {
	host, _ := retirementPureHost(t)
	callbacks := 0
	err := host.StartOrReloadServiceWithBeforeStart(context.Background(), "invalid config", nil, func() { callbacks++ })
	if err == nil || callbacks != 1 || host.instance != nil || host.serviceStatus.Status != ServiceStatus_FATAL || host.serviceStatus.ErrorMessage != err.Error() {
		t.Fatalf("initial parse failure lost diagnostics: callbacks=%d status=%v err=%v", callbacks, host.serviceStatus, err)
	}
	if len(host.tailscaleRetirementRuns) != 0 {
		t.Fatal("invalid initial config allocated a retirement run")
	}
}

func TestPreparedInstanceParseFailureKeepsLiveRuntime(t *testing.T) {
	host, _ := retirementPureHost(t)
	oldCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	old := &Instance{ctx: oldCtx, cancel: cancel}
	host.instance = old
	host.serviceStatus = &ServiceStatus{Status: ServiceStatus_STARTED}
	started := time.Now()
	host.startedAt = started
	callbacks := 0
	err := host.StartOrReloadServiceWithBeforeStart(context.Background(), "invalid config", nil, func() { callbacks++ })
	if err == nil || callbacks != 0 || host.instance != old || old.closeStarted.Load() || oldCtx.Err() != nil || host.startedAt != started || host.serviceStatus.Status != ServiceStatus_STARTED {
		t.Fatal("invalid reload changed live runtime or diagnostics")
	}
}
