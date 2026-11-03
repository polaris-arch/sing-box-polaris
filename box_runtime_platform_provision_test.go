package box

import (
	"bytes"
	"context"
	stdjson "encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	mdns "github.com/miekg/dns"
)

type runtimeProvisionWIFIPlatform struct {
	runtimeTestPlatform
	access sync.Mutex
	reads  int
	state  adapter.WIFIState
}

func (p *runtimeProvisionWIFIPlatform) ReadWIFIState(context.Context) adapter.WIFIState {
	p.access.Lock()
	defer p.access.Unlock()
	p.reads++
	return p.state
}

func (p *runtimeProvisionWIFIPlatform) snapshot() (adapter.WIFIState, int) {
	p.access.Lock()
	defer p.access.Unlock()
	return p.state, p.reads
}

func runtimeProvisionCandidate(t *testing.T, routeFields map[string]stdjson.RawMessage) []byte {
	t.Helper()
	var root map[string]stdjson.RawMessage
	var route map[string]stdjson.RawMessage
	if err := stdjson.Unmarshal(runtimeTestConfig(1080, "provision.test"), &root); err != nil {
		t.Fatal(err)
	}
	if err := stdjson.Unmarshal(root["route"], &route); err != nil {
		t.Fatal(err)
	}
	for key, value := range routeFields {
		route[key] = value
	}
	root["route"], _ = stdjson.Marshal(route)
	content, err := stdjson.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func runtimeProvisionWIFIFixture(t *testing.T) (*runtimeTestFixture, *runtimeProvisionWIFIPlatform) {
	t.Helper()
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "provision.test"), nil)
	platform := &runtimeProvisionWIFIPlatform{state: adapter.WIFIState{SSID: "fresh-ssid", BSSID: "02:00:00:00:00:01"}}
	f.ctx = service.ContextWith[adapter.PlatformInterface](f.ctx, platform)
	options.Context = f.ctx
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.box = instance
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := instance.closeRuntimeResourcesContext(ctx); err != nil {
			t.Error(err)
			return
		}
		if err := instance.CloseWithResult(); err != nil {
			t.Error(err)
		}
	})
	f.start(t)
	return f, platform
}

func TestRuntimeFirstWIFIPublicPlanApplyUsesFreshPlatformReader(t *testing.T) {
	f, platform := runtimeProvisionWIFIFixture(t)
	content := runtimeProvisionCandidate(t, map[string]stdjson.RawMessage{"rules": []byte("[{\"wifi_ssid\":[\"fresh-ssid\"],\"action\":\"route\",\"outbound\":\"select\"}]")})
	_, reads := platform.snapshot()
	legacy, err := f.box.PlanRuntimeConfig(context.Background(), "actor-a", f.identity(), content)
	if err != nil || legacy.Applicable {
		t.Fatal("legacy first WIFI guard changed", legacy, err)
	}
	_, request := runtimeClientPlan(t, f, content)
	_, afterPlan := platform.snapshot()
	if reads != afterPlan {
		t.Fatal("Plan read native WIFI")
	}
	lease, err := f.box.runtime.store.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	old := lease.View().(*runtimeView)
	op, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || op.Active.Revision != request.Expected.Revision+1 {
		t.Fatal(op, err)
	}
	state, afterApply := platform.snapshot()
	actual := f.box.network.WIFIState()
	if afterApply <= reads || !f.box.network.NeedWIFIState() || actual.SSID != state.SSID || actual.BSSID != adapter.NormalizeWIFIBSSID(state.BSSID) {
		t.Fatal("new demand consumed an unprovisioned cache", actual, afterApply, reads)
	}
	if old.platform.NeedWIFIState() {
		t.Fatal("private first WIFI changed retained graph demand")
	}
	platform.access.Lock()
	platform.state.SSID = "updated-ssid"
	platform.access.Unlock()
	f.box.network.UpdateWIFIState(context.Background())
	if f.box.network.WIFIState().SSID != "updated-ssid" {
		t.Fatal("explicit refresh did not execute the platform getter")
	}
	// Removal retires the reader's graph owner; the original stable demand stays
	// false and the selected graph ceases to report a WIFI requirement.
	_, remove := runtimeClientPlan(t, f, runtimeTestConfig(1080, "provision.test"))
	removed, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", remove)
	if err != nil || removed.Active.Revision != op.Active.Revision+1 || f.box.network.NeedWIFIState() {
		t.Fatal("WIFI removal did not publish", removed, err)
	}
}

func TestRuntimeFirstWIFIAbortLeavesPublishedGraphAndReaderUnchanged(t *testing.T) {
	f, platform := runtimeProvisionWIFIFixture(t)
	content := runtimeProvisionCandidate(t, map[string]stdjson.RawMessage{"rules": []byte("[{\"wifi_ssid\":[\"fresh-ssid\"],\"action\":\"route\",\"outbound\":\"select\"}]")})
	var root map[string]stdjson.RawMessage
	_ = stdjson.Unmarshal(content, &root)
	root["outbounds"] = []byte("[{\"type\":\"socks\",\"tag\":\"a\",\"server\":\"192.0.2.1\",\"server_port\":1081,\"version\":\"5\"},{\"type\":\"socks\",\"tag\":\"b\",\"server\":\"192.0.2.2\",\"server_port\":1080,\"version\":\"5\"},{\"type\":\"selector\",\"tag\":\"select\",\"outbounds\":[\"a\",\"b\"]}]")
	content, _ = stdjson.Marshal(root)
	_, request := runtimeClientPlan(t, f, content)
	f.setConstructorHook(func(o *runtimeTestSocks) error {
		o.startHook = func(stage adapter.StartStage) error {
			if stage == adapter.StartStateStart {
				return errors.New("fail after private platform Initialize")
			}
			return nil
		}
		return nil
	})
	_, before := platform.snapshot()
	operation, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	_, after := platform.snapshot()
	if err != nil || operation.Active != request.Expected || len(operation.Errors) == 0 || after <= before || f.box.network.NeedWIFIState() {
		t.Fatal("failed graph published or never prepared fresh WIFI", operation, err, after, before)
	}
}

func TestRuntimeFirstProcessPublicPreparationKeepsOriginalStableOwner(t *testing.T) {
	if !runtimeCanPrepareProcessSearcher() {
		t.Skip("no independently owned desktop process searcher")
	}
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "provision.test"), nil)
	f.start(t)
	content := runtimeProvisionCandidate(t, map[string]stdjson.RawMessage{"find_process": []byte("true")})
	gateway := f.box.Router()
	if gateway == nil || gateway != f.box.runtime.gateway || gateway.NeedFindProcess() {
		t.Fatal("actual initial runtime gateway has unexpected process demand")
	}
	oldLease, old := f.acquire(t)
	defer oldLease.Release()
	if old.router != f.box.runtime.initialRouter || old.router.NeedFindProcess() {
		t.Fatal("initial leased graph was not the original stable process owner")
	}
	_, request := runtimeClientPlan(t, f, content)
	op, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || op.Active.Revision != request.Expected.Revision+1 {
		t.Fatal(op, err)
	}
	lease, err := f.box.runtime.store.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if !lease.View().(*runtimeView).router.NeedFindProcess() || old.router.NeedFindProcess() ||
		f.box.runtime.initialRouter.NeedFindProcess() || f.box.Router() != gateway || !gateway.NeedFindProcess() {
		t.Fatal("private process owner was confused with initial stable graph")
	}
}

func TestRuntimeFirstNeighborDHCPPublicFailureIsBeforePublication(t *testing.T) {
	native := C.IsLinux && !C.IsAndroid || C.IsDarwin && !C.IsIos
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "provision.test"), nil)
	f.start(t)
	path := filepath.Join(t.TempDir(), "missing.leases")
	encodedPath, _ := stdjson.Marshal([]string{path})
	content := runtimeProvisionCandidate(t, map[string]stdjson.RawMessage{"find_neighbor": []byte("true"), "dhcp_lease_files": encodedPath})
	legacy, err := f.box.PlanRuntimeConfig(context.Background(), "actor-a", f.identity(), content)
	if err != nil || legacy.Applicable {
		t.Fatal("legacy native provision guard changed", legacy, err)
	}
	plan, err := f.box.PlanRuntimeConfigWithClientImpactPolicy(context.Background(), "actor-a", f.identity(), content, nil, RuntimeClientImpactPolicyExplicit)
	if err != nil || plan.Applicable != native {
		t.Fatal("native owner inventory mismatch", plan, err)
	}
	if !native {
		return
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Plan created the requested lease file", err)
	}
	request := RuntimeConfigApply{ContractVersion: 1, PlanID: plan.PlanID, TransactionID: plan.TransactionID, Expected: plan.Expected, CandidateDigest: plan.CandidateDigest, AcceptedImpactDigest: plan.ImpactDigest}
	operation, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || operation.Active != request.Expected || len(operation.Errors) == 0 {
		t.Fatal("unreadable first native resource published", operation, err)
	}
}

func TestRuntimeFakeIPNamespacesCannotColdStartWithoutRecoveryRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "cache.db")
	f, options := runtimeFakeIPCleanupConstruction(t, path, nil)
	options.Context = adapter.ContextWithRuntimeRecoveryRoot(options.Context, root)
	runtimeFakeIPCleanupBox(t, f, options)
	if err := f.box.BindRuntimePersistenceOptions(func(RuntimeIdentity, []byte) error { return nil }, "exact_configuration_file", true); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	next := runtimeClientFakeIPIPv6(t, options.Options)
	content, err := json.MarshalContext(f.ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	_, request := runtimeClientPlan(t, f, content)
	operation, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || !operation.Durable {
		t.Fatal("real journal migration", operation, err)
	}
	store, err := f.box.runtime.fakeIP.Borrow(netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("2001:2::/48"))
	if err != nil {
		t.Fatal(err)
	}
	address, err := store.Create("actually-issued.example", false)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := f.box.runtime.fakeIP.ProtectAnswer(&mdns.Msg{Answer: []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: "actually-issued.example.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 3600}, A: net.IP(address.AsSlice())}}})
	if err != nil {
		t.Fatal(err)
	}
	answer.Delivered(time.Now())
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	runtimeFakeIPCleanupAssertSuccess(t, f.box)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blocked, withoutRoot := runtimeFakeIPCleanupConstruction(t, path, nil)
	withoutRoot.Options = runtimeClientFakeIPIPv6(t, withoutRoot.Options)
	runtimeFakeIPCleanupBox(t, blocked, withoutRoot)
	if err := blocked.box.Start(); !errors.Is(err, cachefile.ErrFakeIPRecoveryRoot) {
		t.Fatal("namespace fallback silently lost issued mappings", err)
	}
	if err := blocked.box.CloseWithResult(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed unbound cold start rewrote the cache", err)
	}
	recovered, withRoot := runtimeFakeIPCleanupConstruction(t, path, nil)
	withRoot.Context = adapter.ContextWithRuntimeRecoveryRoot(withRoot.Context, root)
	withRoot.Options = runtimeClientFakeIPIPv6(t, withRoot.Options)
	runtimeFakeIPCleanupBox(t, recovered, withRoot)
	recovered.start(t)
	if domain, ok := recovered.box.runtime.fakeIP.RecognitionStore().Lookup(address); !ok || domain != "actually-issued.example" {
		t.Fatal("explicit recovery lost issued mapping", domain, ok)
	}
}

func TestRuntimeFirstNeighborDHCPPublicApplyCapturesRealLeaseSample(t *testing.T) {
	if !(C.IsLinux && !C.IsAndroid || C.IsDarwin && !C.IsIos) {
		t.Skip("no independent native neighbor reader")
	}
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "provision.test"), nil)
	f.start(t)
	path := filepath.Join(t.TempDir(), "dnsmasq.leases")
	if err := os.WriteFile(path, []byte("0 02:00:00:00:00:01 192.0.2.7 first-host *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths, _ := stdjson.Marshal([]string{path})
	content := runtimeProvisionCandidate(t, map[string]stdjson.RawMessage{"find_neighbor": []byte("true"), "dhcp_lease_files": paths})
	_, request := runtimeClientPlan(t, f, content)
	operation, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || operation.Active.Revision != request.Expected.Revision+1 {
		t.Fatal("fresh native neighbor/lease prepare", operation, err)
	}
	resolver := f.box.Router().NeighborResolver()
	if resolver == nil || !f.box.Router().NeedFindNeighbor() {
		t.Fatal("published native resolver absent from stable gateway")
	}
	address := netip.MustParseAddr("192.0.2.7")
	if name, ok := resolver.LookupHostname(address); !ok || name != "first-host" {
		t.Fatal("initial DHCP sample absent", name, ok)
	}
	if err := os.WriteFile(path, []byte("0 02:00:00:00:00:01 192.0.2.7 second-host *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lease, err := f.box.runtime.store.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	lease.View().(*runtimeView).platform.Refresh(context.Background())
	lease.Release()
	if name, ok := resolver.LookupHostname(address); !ok || name != "second-host" {
		t.Fatal("refresh used the old callback cache", name, ok)
	}
}
