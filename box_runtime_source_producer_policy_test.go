package box

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	stdjson "encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	mdns "github.com/miekg/dns"
)

func r3SourceWrite(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path+".next", content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".next", path); err != nil {
		t.Fatal(err)
	}
}

func r3SourceCanonical(f *runtimeTestFixture) []byte {
	f.box.runtime.access.Lock()
	defer f.box.runtime.access.Unlock()
	return append([]byte(nil), f.box.runtime.canonical...)
}

func r3SourceCanaryConfig(t *testing.T, content []byte) []byte {
	t.Helper()
	var root map[string]stdjson.RawMessage
	if err := stdjson.Unmarshal(content, &root); err != nil {
		t.Fatal(err)
	}
	root["inbounds"] = []byte(fmt.Sprintf("[{\"type\":\"direct\",\"tag\":\"np-probe-in\",\"listen\":\"127.0.0.1\",\"listen_port\":%d,\"network\":\"udp\"}]", runtimeClientFreePort(t)))
	for _, key := range []string{"route", "dns"} {
		var object map[string]stdjson.RawMessage
		var previous []stdjson.RawMessage
		if err := stdjson.Unmarshal(root[key], &object); err != nil {
			t.Fatal(err)
		}
		_ = stdjson.Unmarshal(object["rules"], &previous)
		prefix := []stdjson.RawMessage{[]byte("{\"inbound\":[\"np-probe-in\"],\"action\":\"hijack-dns\"}")}
		if key == "dns" {
			prefix = []stdjson.RawMessage{[]byte("{\"inbound\":[\"np-probe-in\"],\"domain\":[\"p0.np-canary.polaris.invalid\"],\"action\":\"predefined\",\"rcode\":\"NOERROR\",\"answer\":[\"p0.np-canary.polaris.invalid. IN A 127.0.0.1\"]}"), []byte("{\"inbound\":[\"np-probe-in\"],\"action\":\"predefined\",\"rcode\":\"REFUSED\"}")}
		}
		object["rules"], _ = stdjson.Marshal(append(prefix, previous...))
		root[key], _ = stdjson.Marshal(object)
	}
	result, err := stdjson.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func r3SourceRoute(t *testing.T, content []byte, fields map[string]stdjson.RawMessage) []byte {
	t.Helper()
	var root, route map[string]stdjson.RawMessage
	if err := stdjson.Unmarshal(content, &root); err != nil {
		t.Fatal(err)
	}
	if err := stdjson.Unmarshal(root["route"], &route); err != nil {
		t.Fatal(err)
	}
	for key, value := range fields {
		route[key] = value
	}
	root["route"], _ = stdjson.Marshal(route)
	result, err := stdjson.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func r3SourceFixture(t *testing.T, content []byte, platform adapter.PlatformInterface, persist func(RuntimeIdentity, []byte) error, safe bool, beforeStart ...func(*runtimeTestFixture)) *runtimeTestFixture {
	t.Helper()
	// Build the registries before decoding the actual canary configuration.
	f, options := newRuntimeTestConstruction(t, []byte("{}"), nil)
	direct.RegisterInbound(service.FromContext[adapter.InboundRegistry](f.ctx).(*inbound.Registry))
	if platform != nil {
		f.ctx = service.ContextWith[adapter.PlatformInterface](f.ctx, platform)
		options.Context = f.ctx
	}
	if err := json.UnmarshalContext(f.ctx, content, &options.Options); err != nil {
		t.Fatal(err)
	}
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.box = instance
	t.Cleanup(func() {
		if instance.runtime != nil {
			if err := instance.closeRuntimeResourcesContext(runtimeTestContext(t)); err != nil {
				t.Error(err)
				return
			}
		}
		if err := instance.CloseWithResult(); err != nil {
			t.Error(err)
		}
	})
	if instance.runtime == nil {
		t.Fatal("source fixture did not construct a connected runtime", instance.runtimeEligibilityErrors)
	}
	if persist != nil {
		if err := instance.BindRuntimePersistenceOptions(persist, "exact_configuration_file", safe); err != nil {
			t.Fatal(err)
		}
	}
	for _, hook := range beforeStart {
		hook(f)
	}
	f.start(t)
	return f
}

func r3SourceCommit(t *testing.T, committed <-chan RuntimeIdentity, revision uint64) RuntimeIdentity {
	t.Helper()
	for {
		select {
		case id := <-committed:
			if id.Revision == revision {
				return id
			}
			if id.Revision > revision {
				t.Fatal("source skipped expected immutable revision", id, revision)
			}
		case <-runtimeTestContext(t).Done():
			t.Fatal("source producer did not publish expected revision", revision)
			return RuntimeIdentity{}
		}
	}
}

func r3SourceSettled(t *testing.T, f *runtimeTestFixture) {
	t.Helper()
	waitRetryState(t, f.box.runtime, func() bool { return !f.box.runtime.preparing })
}

func r3SourceRequest(plan RuntimeConfigPlan) RuntimeConfigApply {
	return RuntimeConfigApply{ContractVersion: RuntimeConfigContractVersion, PlanID: plan.PlanID, TransactionID: plan.TransactionID, Expected: plan.Expected, CandidateDigest: plan.CandidateDigest, AcceptedImpactDigest: plan.ImpactDigest}
}

func r3SourceHasProblem(plan RuntimeConfigPlan, code string) bool {
	return slices.ContainsFunc(plan.Errors, func(problem RuntimePlanError) bool { return problem.Code == code })
}

func TestRuntimeSourceProducerPolicyCanarySRSRetainsImmutableLeases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.srs")
	first := runtimeTestPrivateSRS(t, "domain", false, true, C.RuleSetVersion3)
	second := runtimeTestPrivateSRS(t, "domain", true, true, C.RuleSetVersion3)
	r3SourceWrite(t, path, first)
	config := r3SourceCanaryConfig(t, runtimeTestBinaryLocalConfig(path))
	committed := make(chan RuntimeIdentity, 8)
	f := r3SourceFixture(t, config, nil, func(id RuntimeIdentity, _ []byte) error { committed <- id; return nil }, true)
	before := f.identity()
	oldLease, old := f.acquire(t)
	oldSet, _ := old.router.RuleSet("sites")
	if !oldSet.Match(&adapter.InboundContext{Domain: "a.example"}) {
		t.Fatal("actual SRS initial predicate missing")
	}
	producer := runtimeTestProducer(t, f)
	legacy, err := f.box.PlanRuntimeConfig(context.Background(), "actor-a", f.identity(), r3SourceCanonical(f))
	if err != nil || legacy.Applicable {
		t.Fatal("public legacy acquired the finite canary", legacy, err)
	}
	r3SourceWrite(t, path, second)
	producer.signal()
	id := r3SourceCommit(t, committed, 2)
	r3SourceSettled(t, f)
	_, next := f.acquire(t)
	nextSet, _ := next.router.RuleSet("sites")
	if id.EffectiveDigest != before.EffectiveDigest || oldLease.View().Identity().Revision != 1 ||
		!oldSet.Match(&adapter.InboundContext{Domain: "a.example"}) || oldSet.Match(&adapter.InboundContext{Domain: "b.example"}) ||
		nextSet.Match(&adapter.InboundContext{Domain: "a.example"}) || !nextSet.Match(&adapter.InboundContext{Domain: "b.example"}) ||
		next.componentIDs["rule-set:sites"] == old.componentIDs["rule-set:sites"] || next.componentIDs["inbound:np-probe-in"] != old.componentIDs["inbound:np-probe-in"] ||
		next.componentIDs["outbound:a"] != old.componentIDs["outbound:a"] || runtimeTestProducer(t, f) != producer {
		t.Fatal("source-only canary update broke immutable closure or replaced physical ingress")
	}
	f.box.runtime.access.Lock()
	var actual *runtimePlanRecord
	for _, record := range f.box.runtime.plans {
		if record.operation != nil && record.operation.Active == id {
			actual = record
			break
		}
	}
	if actual == nil || actual.actor != runtimeSourceProducerActor || actual.plan.ClientImpactPolicyVersion != RuntimeClientImpactPolicyExplicit || actual.plan.ImpactConfirmationRequired {
		f.box.runtime.access.Unlock()
		t.Fatal("internal source refresh acquired a consent-bearing transaction")
	}
	f.box.runtime.access.Unlock()
	oldLease.Release()
}

func TestRuntimeSourceProducerRefreshAfterFirstPrivateWIFIPublication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.json")
	r3SourceWrite(t, path, runtimeTestSourceBytes("first.example"))
	config := r3SourceCanaryConfig(t, runtimeTestLocalConfig(path))
	committed := make(chan RuntimeIdentity, 8)
	platform := &runtimeProvisionWIFIPlatform{state: adapter.WIFIState{SSID: "fresh-ssid", BSSID: "02:00:00:00:00:01"}}
	f := r3SourceFixture(t, config, platform, func(id RuntimeIdentity, _ []byte) error { committed <- id; return nil }, true)
	var root, route map[string]stdjson.RawMessage
	_ = stdjson.Unmarshal(config, &root)
	_ = stdjson.Unmarshal(root["route"], &route)
	var rules []stdjson.RawMessage
	_ = stdjson.Unmarshal(route["rules"], &rules)
	rules = append(rules, []byte("{\"wifi_ssid\":[\"fresh-ssid\"],\"action\":\"route\",\"outbound\":\"select\"}"))
	encoded, _ := stdjson.Marshal(rules)
	candidate := r3SourceRoute(t, config, map[string]stdjson.RawMessage{"rules": encoded})
	_, request := runtimeClientPlan(t, f, candidate)
	op, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || op.Active.Revision != 2 {
		t.Fatal("first public WIFI failed", op, err)
	}
	r3SourceCommit(t, committed, 2)
	r3SourceSettled(t, f)
	_, before := f.acquire(t)
	_, reads := platform.snapshot()
	if f.box.runtime.platformRequirements.WIFI || !before.platform.NeedWIFIState() {
		t.Fatal("fixture did not create a genuinely private WIFI owner")
	}
	r3SourceWrite(t, path, runtimeTestSourceBytes("second.example"))
	runtimeTestProducer(t, f).signal()
	r3SourceCommit(t, committed, 3)
	r3SourceSettled(t, f)
	_, next := f.acquire(t)
	_, after := platform.snapshot()
	if next.platform != before.platform || next.componentIDs["platform-runtime"] != before.componentIDs["platform-runtime"] || !next.platform.NeedWIFIState() || after < reads {
		t.Fatal("source refresh ignored or retired actual private WIFI owner")
	}
	set, _ := next.router.RuleSet("sites")
	if !set.Match(&adapter.InboundContext{Domain: "second.example"}) {
		t.Fatal("WIFI graph blocked source refresh")
	}
}

func TestRuntimeSourceProducerRefreshAfterFirstPrivateNeighborPublicCommit(t *testing.T) {
	if !(C.IsLinux && !C.IsAndroid || C.IsDarwin && !C.IsIos) {
		t.Skip("no independent native neighbor owner")
	}
	path := filepath.Join(t.TempDir(), "sites.json")
	r3SourceWrite(t, path, runtimeTestSourceBytes("first.example"))
	leases := filepath.Join(t.TempDir(), "dnsmasq.leases")
	r3SourceWrite(t, leases, []byte("0 02:00:00:00:00:01 192.0.2.7 accepted-host *\n"))
	config := r3SourceCanaryConfig(t, runtimeTestLocalConfig(path))
	committed := make(chan RuntimeIdentity, 8)
	f := r3SourceFixture(t, config, nil, func(id RuntimeIdentity, _ []byte) error { committed <- id; return nil }, true)
	files, _ := stdjson.Marshal([]string{leases})
	candidate := r3SourceRoute(t, config, map[string]stdjson.RawMessage{"find_neighbor": []byte("true"), "dhcp_lease_files": files})
	_, request := runtimeClientPlan(t, f, candidate)
	op, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || op.Active.Revision != 2 {
		t.Fatal("first neighbor publication failed", op, err)
	}
	r3SourceCommit(t, committed, 2)
	r3SourceSettled(t, f)
	_, before := f.acquire(t)
	if f.box.runtime.platformRequirements.Neighbor || before.platform.NeighborResolver() == nil {
		t.Fatal("not the private native neighbor fixture")
	}
	r3SourceWrite(t, path, runtimeTestSourceBytes("second.example"))
	runtimeTestProducer(t, f).signal()
	r3SourceCommit(t, committed, 3)
	r3SourceSettled(t, f)
	_, next := f.acquire(t)
	name, found := next.router.NeighborResolver().LookupHostname(netip.MustParseAddr("192.0.2.7"))
	if next.platform != before.platform || !found || name != "accepted-host" || next.componentIDs["inbound:np-probe-in"] != before.componentIDs["inbound:np-probe-in"] {
		t.Fatal("source refresh lost original actual neighbor/lease owner", name, found)
	}
}

func TestRuntimeSourceProducerRejectsNewMaterializedPlatformDemand(t *testing.T) {
	for _, rules := range []string{
		"[{\"process_name\":[\"new-process\"]}]",
		"[{\"type\":\"logical\",\"mode\":\"and\",\"rules\":[{\"wifi_ssid\":[\"new-ssid\"]}]}]",
	} {
		t.Run(rules, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sites.json")
			accepted := runtimeTestSourceBytes("accepted.example")
			r3SourceWrite(t, path, accepted)
			f := r3SourceFixture(t, r3SourceCanaryConfig(t, runtimeTestLocalConfig(path)), nil, nil, false)
			producer := runtimeTestProducer(t, f)
			before := f.identity()
			canonical := r3SourceCanonical(f)
			r3SourceWrite(t, path, []byte("{\"version\":3,\"rules\":"+rules+"}"))
			plan, err := producer.planSourceRefresh(context.Background(), before, canonical)
			if err != nil || plan.Applicable || !r3SourceHasProblem(plan, "SOURCE_REFRESH_REQUIRES_CONFIRMATION") {
				t.Fatal("source bytes acquired new native lookup authority", plan, err)
			}
			producer.signal()
			if _, retry := producer.refresh(); retry || f.identity() != before {
				t.Fatal("rejected source published or self-retried as consent")
			}
			f.box.runtime.access.Lock()
			sources := append([]runtimeSourceSnapshot(nil), f.box.runtime.currentSources...)
			f.box.runtime.access.Unlock()
			if len(sources) != 1 || !bytes.Equal(sources[0].content, accepted) {
				t.Fatal("rejected source replaced accepted snapshot")
			}
		})
	}
}

func TestRuntimeSourceProducerRejectsEditsForgedMemberCancellationAndSourceDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.json")
	accepted := runtimeTestSourceBytes("accepted.example")
	r3SourceWrite(t, path, accepted)
	config := r3SourceCanaryConfig(t, runtimeTestLocalConfig(path))
	f := r3SourceFixture(t, config, nil, nil, false)
	producer := runtimeTestProducer(t, f)
	before := f.identity()
	canonical := r3SourceCanonical(f)
	forged := &runtimeSourceProducer{box: f.box, ctx: producer.ctx, fingerprint: producer.fingerprint}
	if plan, err := forged.planSourceRefresh(context.Background(), before, canonical); err == nil || plan.Applicable {
		t.Fatal("same fingerprint/actor replaced actual producer capability", plan, err)
	}
	edited := r3SourceRoute(t, canonical, map[string]stdjson.RawMessage{"find_neighbor": []byte("true")})
	if plan, err := producer.planSourceRefresh(context.Background(), before, edited); err == nil || plan.Applicable {
		t.Fatal("source-only entry edited accepted configuration", plan, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if plan, err := producer.planSourceRefresh(ctx, before, canonical); err == nil || plan.Applicable {
		t.Fatal("canceled source admission", plan, err)
	}
	plan, err := producer.planSourceRefresh(context.Background(), before, canonical)
	if err != nil || !plan.Applicable || !plan.NoOp {
		t.Fatal("unchanged source plan unavailable", plan, err)
	}
	r3SourceWrite(t, path, []byte("invalid JSON"))
	if _, err := f.box.ApplyRuntimeConfig(context.Background(), runtimeSourceProducerActor, r3SourceRequest(plan)); err == nil {
		t.Fatal("stale source snapshot acquired no-op receipt")
	}
	invalid, err := producer.planSourceRefresh(context.Background(), before, canonical)
	if err != nil || invalid.Applicable {
		t.Fatal("invalid source accepted", invalid, err)
	}
	if f.identity() != before {
		t.Fatal("invalid source changed active identity")
	}
	producer.stop()
	runtimeTestWait(t, producer.done, "stopped producer")
	runtimeTestWait(t, producer.eventsDone, "stopped watcher")
	r3SourceWrite(t, path, runtimeTestSourceBytes("late.example"))
	producer.signal()
	if _, retry := producer.refresh(); retry || f.identity() != before {
		t.Fatal("Stop admitted source transaction")
	}
}

func TestRuntimeSourceProducerStalePlanCannotPublishAfterPublicCAS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.json")
	r3SourceWrite(t, path, runtimeTestSourceBytes("accepted.example"))
	config := r3SourceCanaryConfig(t, runtimeTestLocalConfig(path))
	f := r3SourceFixture(t, config, nil, nil, false)
	p := runtimeTestProducer(t, f)
	before := f.identity()
	plan, err := p.planSourceRefresh(context.Background(), before, r3SourceCanonical(f))
	if err != nil || !plan.Applicable {
		t.Fatal(plan, err)
	}
	candidate := bytes.Replace(config, []byte("\"server_port\":1080"), []byte("\"server_port\":1081"), 1)
	_, request := runtimeClientPlan(t, f, candidate)
	op, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || op.Active.Revision != before.Revision+1 {
		t.Fatal(op, err)
	}
	if _, err := f.box.ApplyRuntimeConfig(context.Background(), runtimeSourceProducerActor, r3SourceRequest(plan)); err == nil || f.identity() != op.Active {
		t.Fatal("stale source CAS changed graph", err)
	}
	if next, err := p.planSourceRefresh(context.Background(), before, r3SourceCanonical(f)); err == nil || next.Applicable {
		t.Fatal("stale expected accepted by source planner", next, err)
	}
}

func TestRuntimeSourceProducerPreservesOriginalPersistenceDebtAndReconciles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.json")
	r3SourceWrite(t, path, runtimeTestSourceBytes("first.example"))
	committed := make(chan RuntimeIdentity, 16)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	f := r3SourceFixture(t, r3SourceCanaryConfig(t, runtimeTestLocalConfig(path)), nil, func(id RuntimeIdentity, _ []byte) error {
		committed <- id
		switch calls.Add(1) {
		case 1:
			return errors.New("temporary synchronous write failure")
		case 2:
			close(entered)
			<-release
		}
		return nil
	}, true)
	var released atomic.Bool
	unblock := func() {
		if released.CompareAndSwap(false, true) {
			close(release)
		}
	}
	t.Cleanup(unblock)
	p := runtimeTestProducer(t, f)
	r3SourceWrite(t, path, runtimeTestSourceBytes("second.example"))
	p.signal()
	active := r3SourceCommit(t, committed, 2)
	select {
	case <-entered:
	case <-runtimeTestContext(t).Done():
		t.Fatal("production original-owner driver did not enter")
	}
	c := f.box.runtime
	c.access.Lock()
	original := c.pendingPersistence
	count := len(c.plans)
	c.access.Unlock()
	if original == nil || original.actor != runtimeSourceProducerActor || !original.persistenceTailEntered {
		t.Fatal("fixture lost original persistence owner")
	}
	r3SourceWrite(t, path, runtimeTestSourceBytes("third.example"))
	p.signal()
	if wait, retry := p.refresh(); wait != nil || !retry || f.identity() != active {
		t.Fatal("source refresh superseded pending original tail")
	}
	if plan, err := p.planSourceRefresh(context.Background(), active, r3SourceCanonical(f)); err == nil || plan.Applicable {
		t.Fatal("pending durability became source consent", plan, err)
	}
	c.access.Lock()
	retained := c.pendingPersistence == original && len(c.plans) == count && !original.operation.Durable
	c.access.Unlock()
	if !retained || calls.Load() != 2 {
		t.Fatal("source refresh borrowed original persistence owner")
	}
	unblock()
	// No private Retry and no further signal: the instance driver finishes the
	// original tail, then the actual producer reconciles the deferred file.
	r3SourceCommit(t, committed, 3)
	r3SourceSettled(t, f)
	if calls.Load() != 3 {
		t.Fatal("callback repeated or deferred source update lost", calls.Load())
	}
	_, view := f.acquire(t)
	set, _ := view.router.RuleSet("sites")
	if !set.Match(&adapter.InboundContext{Domain: "third.example"}) || !original.operation.Durable {
		t.Fatal("deferred source update lost accepted snapshot/original receipt")
	}
}

func TestRuntimeSourceProducerUnsafePersistenceFailureCannotBeSuperseded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.json")
	r3SourceWrite(t, path, runtimeTestSourceBytes("first.example"))
	committed := make(chan RuntimeIdentity, 8)
	f := r3SourceFixture(t, r3SourceCanaryConfig(t, runtimeTestLocalConfig(path)), nil, func(id RuntimeIdentity, _ []byte) error {
		committed <- id
		return errors.New("non-repeatable original write")
	}, false)
	p := runtimeTestProducer(t, f)
	r3SourceWrite(t, path, runtimeTestSourceBytes("second.example"))
	p.signal()
	active := r3SourceCommit(t, committed, 2)
	r3SourceSettled(t, f)
	f.box.runtime.access.Lock()
	unpinned := f.box.runtime.pendingPersistence == nil
	f.box.runtime.access.Unlock()
	if !unpinned {
		t.Fatal("unsafe callback acquired retry permission")
	}
	r3SourceWrite(t, path, runtimeTestSourceBytes("third.example"))
	if _, retry := p.refresh(); !retry || f.identity() != active {
		t.Fatal("unpinned durability debt was silently superseded")
	}
	if plan, err := p.planSourceRefresh(context.Background(), active, r3SourceCanonical(f)); err == nil || plan.Applicable {
		t.Fatal("source entry ignored unresolved non-repeatable tail", plan, err)
	}
}

func r3SourceRootPEM(t *testing.T, serial int64) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(4102444800, 0)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func r3SourceRootConfig(t *testing.T, config []byte, path string) []byte {
	t.Helper()
	var root map[string]stdjson.RawMessage
	if err := stdjson.Unmarshal(config, &root); err != nil {
		t.Fatal(err)
	}
	root["certificate"], _ = stdjson.Marshal(map[string]any{"store": "none", "certificate_path": []string{path}})
	result, err := stdjson.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestRuntimeSourceProducerRootDependencyCannotAutoAcceptPhysicalOwners(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.json")
	r3SourceWrite(t, path, runtimeTestSourceBytes("accepted.example"))
	rootPath := filepath.Join(t.TempDir(), "roots.pem")
	r3SourceWrite(t, rootPath, r3SourceRootPEM(t, 1))
	config := r3SourceRootConfig(t, r3SourceCanaryConfig(t, runtimeTestLocalConfig(path)), rootPath)
	f := r3SourceFixture(t, config, nil, nil, false)
	p := runtimeTestProducer(t, f)
	before := f.identity()
	oldRevision := p.rootStore.RuntimeRevision()
	oldLease, oldView := f.acquire(t)
	// The actual watched PEM file changes its namespace content. Root watcher
	// callback completion is observed through its real published root revision.
	r3SourceWrite(t, rootPath, r3SourceRootPEM(t, 2))
	waitRetryState(t, f.box.runtime, func() bool { return p.rootStore.RuntimeRevision() > oldRevision })
	plan, err := p.planSourceRefresh(context.Background(), before, r3SourceCanonical(f))
	if err != nil || plan.Applicable || !slices.ContainsFunc(plan.Errors, func(problem RuntimePlanError) bool {
		return problem.Path == "inbound:np-probe-in" && problem.Code == "SOURCE_REFRESH_REQUIRES_CONFIRMATION"
	}) {
		t.Fatal("changed root silently acquired physical canary handoff", plan, err)
	}
	p.signal()
	if _, retry := p.refresh(); retry || f.identity() != before {
		t.Fatal("root refresh auto-accepted listener handoff")
	}
	_, current := f.acquire(t)
	if current != oldView || oldLease.View().Identity().Revision != 1 {
		t.Fatal("rejected root replacement changed retained closure")
	}
}

func TestRuntimeSourceProducerRootWatchRefreshesNonPhysicalClosure(t *testing.T) {
	rootPath := filepath.Join(t.TempDir(), "roots.pem")
	r3SourceWrite(t, rootPath, r3SourceRootPEM(t, 1))
	config := r3SourceRootConfig(t, runtimeTestConfig(1080, "roots.example"), rootPath)
	committed := make(chan RuntimeIdentity, 8)
	f := r3SourceFixture(t, config, nil, func(id RuntimeIdentity, _ []byte) error { committed <- id; return nil }, true)
	p := runtimeTestProducer(t, f)
	oldLease, old := f.acquire(t)
	before := f.identity()
	canonical := r3SourceCanonical(f)
	oldRoots := service.FromContext[adapter.CertificateStore](f.object(t, "a", 0).ctx)
	if oldRoots == nil {
		t.Fatal("public construction did not capture its configured root snapshot")
	}
	oldPool := oldRoots.Pool()
	f.box.runtime.access.Lock()
	oldRootDigest := f.box.runtime.rootDigest
	f.box.runtime.access.Unlock()
	oldRevision := p.rootStore.RuntimeRevision()
	r3SourceWrite(t, rootPath, r3SourceRootPEM(t, 2))
	waitRetryState(t, f.box.runtime, func() bool { return p.rootStore.RuntimeRevision() > oldRevision })
	p.signal()
	id := r3SourceCommit(t, committed, 2)
	r3SourceSettled(t, f)
	_, next := f.acquire(t)
	if id.EffectiveDigest != before.EffectiveDigest || next.componentIDs["outbound:a"] == old.componentIDs["outbound:a"] || oldLease.View().Identity().Revision != 1 {
		t.Fatal("root content did not replace only its immutable consumer closure")
	}
	nextRoots := service.FromContext[adapter.CertificateStore](f.object(t, "a", 1).ctx)
	if nextRoots == nil || !oldPool.Equal(oldRoots.Pool()) || oldPool.Equal(nextRoots.Pool()) {
		t.Fatal("root watcher mutated a retained consumer or lost the new root snapshot")
	}
	c := f.box.runtime
	c.access.Lock()
	var record *runtimePlanRecord
	for _, candidate := range c.plans {
		if candidate.operation != nil && candidate.operation.Active == id {
			record = candidate
			break
		}
	}
	owned := record != nil && record.sourceProof != nil && record.actor == runtimeSourceProducerActor &&
		record.sourceProof.producer == p && record.sourceProof.expected == before &&
		record.sourceProof.rootDigest == c.rootDigest && c.rootDigest != oldRootDigest &&
		record.plan.ClientImpactPolicyVersion == RuntimeClientImpactPolicyExplicit && !record.plan.ImpactConfirmationRequired &&
		record.operation.Before == before && record.operation.Active == id &&
		record.operation.State == "COMMITTED" && record.operation.Durable && record.operation.PersistenceMode == "exact_configuration_file" &&
		!record.operation.OwnerReloadAcknowledged && record.operation.DesiredStateDigest == "" && record.operation.DesiredStateRevision == "" &&
		bytes.Equal(record.canonical, canonical) && bytes.Equal(c.canonical, canonical) &&
		c.pendingPersistence == nil && c.configurationOwner == nil
	transaction := ""
	if record != nil {
		transaction = record.plan.TransactionID
	}
	c.access.Unlock()
	if !owned || id.Incarnation != before.Incarnation || id.Revision != before.Revision+1 || runtimeTestProducer(t, f) != p {
		t.Fatal("root watcher lost its original proof, canonical bytes or persistence owner")
	}
	receipt, err := f.box.GetRuntimeConfigStatus(runtimeSourceProducerActor, id.Incarnation, transaction)
	if err != nil || receipt.LookupState != "FOUND" || receipt.Active != id || receipt.Operation == nil ||
		!receipt.Operation.Durable || receipt.DurableAppliedDigest != before.EffectiveDigest ||
		receipt.DurableDesiredStateDigest != "" || receipt.DurableDesiredStateRevision != "" || receipt.DurableOwnerReloadAcknowledged {
		t.Fatal("root resource refresh manufactured desired-state evidence", receipt, err)
	}
	// Content refresh does not grant authority to edit certificate options.
	edited := r3SourceRootConfig(t, canonical, filepath.Join(t.TempDir(), "replacement.pem"))
	plan, err := f.box.PlanRuntimeConfigWithClientImpactPolicy(context.Background(), "actor-a", id, edited, nil, RuntimeClientImpactPolicyExplicit)
	if err != nil || plan.Applicable || !slices.ContainsFunc(plan.Errors, func(problem RuntimePlanError) bool {
		return problem.Path == "certificate.certificate_path" && problem.Code == "RESTART_REQUIRED"
	}) {
		t.Fatal("initial root adapter relaxed the certificate edit boundary", plan, err)
	}
}

// Hold only the background worker activation so Plan -> Apply fault ordering is
// deterministic. The actual resource, watches, snapshots and public transaction
// methods remain production objects; no executable Plan field is modified.
func r3SourceHoldWorkerActivation(t *testing.T, f *runtimeTestFixture) {
	t.Helper()
	found := false
	for _, resource := range f.box.runtime.initialPrepared.resources {
		if p := resource.sourceProducer; p != nil {
			p.activateOnce.Do(func() {})
			found = true
		}
	}
	if !found {
		t.Fatal("initial real producer not constructed")
	}
}

func TestRuntimeSourceProducerDriftAndStopFailBeforeCandidateConstruction(t *testing.T) {
	for _, fault := range []string{"root-drift", "source-drift", "producer-stop", "request-cancel", "wrong-actor"} {
		t.Run(fault, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sites.json")
			r3SourceWrite(t, path, runtimeTestSourceBytes("first.example"))
			rootPath := filepath.Join(t.TempDir(), "roots.pem")
			r3SourceWrite(t, rootPath, r3SourceRootPEM(t, 1))
			config := r3SourceRootConfig(t, r3SourceCanaryConfig(t, runtimeTestLocalConfig(path)), rootPath)
			f := r3SourceFixture(t, config, nil, nil, false, func(f *runtimeTestFixture) { r3SourceHoldWorkerActivation(t, f) })
			p := runtimeTestProducer(t, f)
			before := f.identity()
			r3SourceWrite(t, path, runtimeTestSourceBytes("second.example"))
			plan, err := p.planSourceRefresh(context.Background(), before, r3SourceCanonical(f))
			if err != nil || !plan.Applicable || plan.NoOp {
				t.Fatal("not a real executable source-only plan", plan, err)
			}
			ctx := context.Background()
			actor := runtimeSourceProducerActor
			switch fault {
			case "root-drift":
				revision := p.rootStore.RuntimeRevision()
				r3SourceWrite(t, rootPath, r3SourceRootPEM(t, 2))
				waitRetryState(t, f.box.runtime, func() bool { return p.rootStore.RuntimeRevision() > revision })
			case "source-drift":
				r3SourceWrite(t, path, runtimeTestSourceBytes("third.example"))
			case "producer-stop":
				p.stop()
			case "request-cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "wrong-actor":
				actor = "actor-a"
			}
			f.box.runtime.access.Lock()
			sequence := f.box.runtime.resourceSequence
			f.box.runtime.access.Unlock()
			op, err := f.box.ApplyRuntimeConfig(ctx, actor, r3SourceRequest(plan))
			if err == nil && op.Active != before {
				t.Fatal("rejected source changed graph", op)
			}
			if f.identity() != before || f.count("a") != 1 || f.count("b") != 1 {
				t.Fatal("rejected source constructed/replaced original consumers", op, err)
			}
			f.box.runtime.access.Lock()
			unchanged := f.box.runtime.resourceSequence == sequence
			f.box.runtime.access.Unlock()
			if !unchanged {
				t.Fatal("root/source/Stop failure allocated a candidate owner before its proof")
			}
		})
	}
}

func TestRuntimeSourceProducerProofCannotBeInjectedIntoPublicPlanContext(t *testing.T) {
	f := r3SourceFixture(t, runtimeTestConfig(1080, "public.example"), nil, nil, false)
	plan, request := f.plan(t, runtimeTestConfig(1081, "public.example"))
	ctx := context.WithValue(context.Background(), runtimeSourceApplyProofKey{}, &runtimeSourceApplyProof{})
	op, err := f.box.ApplyRuntimeConfig(ctx, "actor-a", request)
	if err != nil || op.Active.Revision != plan.Expected.Revision+1 {
		t.Fatal("public plan used a context-injected source capability", op, err)
	}
}

func r4RegenerationSourceFixture(t *testing.T, path string, calls *atomic.Int32) *runtimeTestFixture {
	t.Helper()
	return r3SourceFixture(t, r3SourceCanaryConfig(t, runtimeTestLocalConfig(path)), nil, nil, false, func(f *runtimeTestFixture) {
		err := f.box.BindRuntimePersistenceOptions(func(RuntimeIdentity, []byte) error {
			calls.Add(1)
			return &RuntimeOwnerAcknowledgementRequiredError{Mode: "app_authoritative_regeneration"}
		}, "app_authoritative_regeneration", false)
		if err != nil {
			t.Fatal(err)
		}
	})
}

func r4SourceAtRevision(t *testing.T, f *runtimeTestFixture, revision uint64) *runtimePlanRecord {
	t.Helper()
	c := f.box.runtime
	waitRetryState(t, c, func() bool { return c.active.Revision == revision && !c.preparing })
	c.access.Lock()
	defer c.access.Unlock()
	for _, r := range c.plans {
		if r.sourceProof != nil && r.operation != nil && r.operation.Active == c.active {
			return r
		}
	}
	t.Fatal("source publication lacks its original receipt")
	return nil
}

func TestRuntimeRegenerationSourceColdUnknownTwiceAndExternalNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.json")
	r3SourceWrite(t, path, runtimeTestSourceBytes("first.example"))
	var calls atomic.Int32
	f := r4RegenerationSourceFixture(t, path, &calls)
	for n, domain := range []string{"second.example", "third.example"} {
		r3SourceWrite(t, path, runtimeTestSourceBytes(domain))
		runtimeTestProducer(t, f).signal()
		r := r4SourceAtRevision(t, f, uint64(n+2))
		c := f.box.runtime
		c.access.Lock()
		ok := r.operation.State == "COMMITTED" && r.operation.PersistenceMode == runtimeSourceOnlyMode &&
			!r.operation.Durable && !r.operation.OwnerReloadAcknowledged && !r.persistenceTailEntered &&
			!r.awaitingOwnerAcknowledgement && c.pendingPersistence == nil && c.configurationOwner == nil &&
			c.durableIdentity == (RuntimeIdentity{}) && c.durableDigest == "" && c.durableDesiredDigest == "" && c.durableDesiredRevision == ""
		c.access.Unlock()
		if !ok || calls.Load() != 0 {
			t.Fatal("cold source refresh invented App durability or a new owner tail", r.operation, calls.Load())
		}
	}
	plan, request := runtimeClientPlan(t, f, r3SourceCanonical(f))
	if !plan.NoOp {
		t.Fatal("same canonical configuration was not NoOp", plan)
	}
	op, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || op.Durable || op.OwnerReloadAcknowledged {
		t.Fatal("NoOp invented cold source durability", op, err)
	}
	_, err = f.box.AcknowledgeRuntimePersistence(context.Background(), "actor-a", RuntimePersistenceAcknowledgement{
		ContractVersion: 1, TransactionID: op.TransactionID, Active: op.Active, PersistenceMode: "app_authoritative_regeneration",
		DesiredStateDigest: runtimeDigest([]byte("not an admitted D transaction")), DesiredStateRevision: "desired:unadmitted",
	})
	if err == nil || calls.Load() != 0 {
		t.Fatal("NoOp acquired an App acknowledgement tail", err)
	}
}

func TestRuntimeRegenerationSourcePreservesHistoricalGenuineBase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.json")
	r3SourceWrite(t, path, runtimeTestSourceBytes("first.example"))
	var calls atomic.Int32
	f := r4RegenerationSourceFixture(t, path, &calls)
	candidate := bytes.Replace(r3SourceCanonical(f), []byte("\"server_port\":1080"), []byte("\"server_port\":1081"), 1)
	_, request := runtimeClientPlan(t, f, candidate)
	op, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || op.Durable || !op.OwnerReloadAcknowledged {
		t.Fatal("ordinary provider reload lost its genuine App tail", op, err)
	}
	original := op
	ack := RuntimePersistenceAcknowledgement{
		ContractVersion: 1, TransactionID: op.TransactionID, Active: op.Active,
		PersistenceMode: "app_authoritative_regeneration", DesiredStateDigest: runtimeDigest([]byte("original durable desired state")),
		DesiredStateRevision: "desired:original",
	}
	op, err = f.box.AcknowledgeRuntimePersistence(context.Background(), "actor-a", ack)
	if err != nil || !op.Durable {
		t.Fatal(op, err)
	}
	for n, domain := range []string{"second.example", "third.example"} {
		r3SourceWrite(t, path, runtimeTestSourceBytes(domain))
		runtimeTestProducer(t, f).signal()
		r := r4SourceAtRevision(t, f, uint64(n+3))
		c := f.box.runtime
		c.access.Lock()
		ok := r.operation.State == "COMMITTED" && r.operation.Durable && !r.operation.OwnerReloadAcknowledged &&
			r.operation.PersistenceMode == runtimeSourceOnlyMode && !r.persistenceTailEntered && !r.awaitingOwnerAcknowledgement &&
			c.durableIdentity == c.active && c.durableDigest == original.Active.EffectiveDigest &&
			c.durableDesiredDigest == ack.DesiredStateDigest && c.durableDesiredRevision == ack.DesiredStateRevision &&
			c.durableOwnerReload && c.pendingPersistence == nil && c.configurationOwner == nil && c.sourceLineage.base.anchor == original.Active
		c.access.Unlock()
		if !ok || calls.Load() != 1 {
			t.Fatal("source refresh replaced historical D evidence or reloaded native owner", r.operation, calls.Load())
		}
	}
	plan, request := runtimeClientPlan(t, f, r3SourceCanonical(f))
	op, err = f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || !plan.NoOp || !op.Durable || op.DesiredStateDigest != ack.DesiredStateDigest {
		t.Fatal("same configuration lost historical base evidence", plan, op, err)
	}
}

func TestRuntimeRegenerationCleanRejectedIntentDoesNotRevokeSourceLineage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.json")
	r3SourceWrite(t, path, runtimeTestSourceBytes("first.example"))
	var calls atomic.Int32
	f := r4RegenerationSourceFixture(t, path, &calls)
	r3SourceWrite(t, path, runtimeTestSourceBytes("second.example"))
	runtimeTestProducer(t, f).signal()
	r4SourceAtRevision(t, f, 2)
	before := f.identity()
	candidate := bytes.Replace(r3SourceCanonical(f), []byte("\"server_port\":1080"), []byte("\"server_port\":1081"), 1)
	_, request := runtimeClientPlan(t, f, candidate)
	f.setConstructorHook(func(*runtimeTestSocks) error { return errors.New("clean construction rejection") })
	op, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil {
		t.Fatal(op, err)
	}
	c := f.box.runtime
	waitRetryState(t, c, func() bool {
		r := c.plans[request.TransactionID]
		return r.operation.State == "ABORTED_UNAPPLIED" && !c.preparing
	})
	f.setConstructorHook(nil)
	if f.identity() != before {
		t.Fatal("rejected intent changed active configuration")
	}
	r3SourceWrite(t, path, runtimeTestSourceBytes("third.example"))
	runtimeTestProducer(t, f).signal()
	r := r4SourceAtRevision(t, f, 3)
	if calls.Load() != 0 || r.operation.Durable {
		t.Fatal("clean source lineage was lost or upgraded", r.operation, calls.Load())
	}
}

func TestRuntimeRegenerationOriginalPendingTailRemainsOriginalDebt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.json")
	r3SourceWrite(t, path, runtimeTestSourceBytes("first.example"))
	var calls atomic.Int32
	f := r4RegenerationSourceFixture(t, path, &calls)
	candidate := bytes.Replace(r3SourceCanonical(f), []byte("\"server_port\":1080"), []byte("\"server_port\":1081"), 1)
	_, request := runtimeClientPlan(t, f, candidate)
	op, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || !op.OwnerReloadAcknowledged {
		t.Fatal(op, err)
	}
	r3SourceWrite(t, path, runtimeTestSourceBytes("second.example"))
	p := runtimeTestProducer(t, f)
	if _, retry := p.refresh(); !retry {
		t.Fatal("old genuine App tail did not retain source debt")
	}
	if plan, err := p.planSourceRefresh(context.Background(), f.identity(), r3SourceCanonical(f)); err == nil || plan.Applicable {
		t.Fatal("old entered tail reclassified as source-only", plan, err)
	}
	c := f.box.runtime
	c.access.Lock()
	r := c.plans[request.TransactionID]
	ok := c.pendingPersistence == r && c.configurationOwner == r && r.awaitingOwnerAcknowledgement && r.persistenceTailEntered && !r.operation.Durable
	c.access.Unlock()
	if !ok || calls.Load() != 1 {
		t.Fatal("original actor debt replaced", calls.Load())
	}
}

func TestRuntimeRegenerationSourceReusesRealJournalNamespaceAndDisabledRecognition(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sites.json")
	r3SourceWrite(t, path, runtimeTestSourceBytes("first.example"))
	f, options := runtimeFakeIPCleanupConstruction(t, filepath.Join(root, "cache.db"), nil)
	direct.RegisterInbound(service.FromContext[adapter.InboundRegistry](f.ctx).(*inbound.Registry))
	var local option.Options
	if err := json.UnmarshalContext(f.ctx, r3SourceCanaryConfig(t, runtimeTestLocalConfig(path)), &local); err != nil {
		t.Fatal(err)
	}
	options.Route, options.Outbounds, options.Inbounds = local.Route, local.Outbounds, local.Inbounds
	options.Context = adapter.ContextWithRuntimeRecoveryRoot(options.Context, root)
	physical := runtimeFakeIPCleanupBox(t, f, options)
	var calls atomic.Int32
	if err := f.box.BindRuntimePersistenceOptions(func(RuntimeIdentity, []byte) error {
		calls.Add(1)
		return &RuntimeOwnerAcknowledgementRequiredError{Mode: "app_authoritative_regeneration"}
	}, "app_authoritative_regeneration", false); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	address := runtimeFakeIPCleanupAllocate(t, f.box)
	answer, err := f.box.runtime.fakeIP.ProtectAnswer(&mdns.Msg{Answer: []mdns.RR{&mdns.A{
		Hdr: mdns.RR_Header{Name: "retained.example.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 3600}, A: net.IP(address.AsSlice()),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	answer.Delivered(time.Now())
	owner := f.box.runtime.fakeIPPersistence
	if owner == nil || !owner.ready {
		t.Fatal("actual journal owner not ready")
	}
	type catalogs struct{ backend, journal adapter.FakeIPRuntimeCatalog }
	read := func() catalogs {
		t.Helper()
		b, e := physical.FakeIPRuntimeCatalog(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		j, e := owner.journal.FakeIPRuntimeCatalog(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		return catalogs{b, j}
	}
	before := read()
	for n, domain := range []string{"second.example", "third.example"} {
		r3SourceWrite(t, path, runtimeTestSourceBytes(domain))
		runtimeTestProducer(t, f).signal()
		r := r4SourceAtRevision(t, f, uint64(n+2))
		after := read()
		if fmt.Sprint(after) != fmt.Sprint(before) || r.persistenceParticipant != nil || r.persistenceTailEntered || calls.Load() != 0 {
			t.Fatal("source-only refresh allocated/linked a namespace or borrowed native persistence", before, after, r.operation, calls.Load())
		}
		if domain, found := f.box.runtime.fakeIP.RecognitionStore().Lookup(address); !found || domain != "retained.example" {
			t.Fatal("unchanged selected namespace lost its issued answer", domain, found)
		}
	}
	// A genuine public removal still owns its new namespace/link and App ACK.
	// Only after its original tail finishes may a disabled source graph refresh.
	next := options.Options
	copyDNS := *next.DNS
	copyDNS.Servers = nil
	for _, server := range next.DNS.Servers {
		if server.Type != C.DNSTypeFakeIP {
			copyDNS.Servers = append(copyDNS.Servers, server)
		}
	}
	next.DNS = &copyDNS
	content, err := json.MarshalContext(f.ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	_, request := runtimeClientPlan(t, f, content)
	op, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || op.Durable || !op.OwnerReloadAcknowledged || calls.Load() != 1 {
		t.Fatal("public removal bypassed its original persistence tail", op, err)
	}
	op, err = f.box.AcknowledgeRuntimePersistence(context.Background(), "actor-a", RuntimePersistenceAcknowledgement{
		ContractVersion: 1, TransactionID: op.TransactionID, Active: op.Active, PersistenceMode: "app_authoritative_regeneration",
		DesiredStateDigest: runtimeDigest([]byte("disabled fakeip desired state")), DesiredStateRevision: "desired:disabled",
	})
	if err != nil || !op.Durable {
		t.Fatal("real removal participant did not finish", op, err)
	}
	before = read()
	r3SourceWrite(t, path, runtimeTestSourceBytes("fourth.example"))
	runtimeTestProducer(t, f).signal()
	r := r4SourceAtRevision(t, f, 5)
	after := read()
	if fmt.Sprint(after) != fmt.Sprint(before) || calls.Load() != 1 || r.persistenceParticipant != nil {
		t.Fatal("disabled refresh constructed another removal/namespace/native tail", before, after, r.operation)
	}
	if domain, found := f.box.runtime.fakeIP.RecognitionStore().Lookup(address); !found || domain != "retained.example" {
		t.Fatal("disabled graph refresh erased old answer recognition", domain, found)
	}
}
