package boxruntime

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func TestRuntimePlanPreconditionsRejectBeforeAnyConstruction(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	f.start(t)
	_, valid := f.plan(t, runtimeTestConfig(1081, "example.org"))
	_, competing := f.plan(t, runtimeTestConfig(1082, "example.org"))
	for name, mutate := range map[string]func(*RuntimeConfigApply){
		"contract":         func(v *RuntimeConfigApply) { v.ContractVersion++ },
		"incarnation":      func(v *RuntimeConfigApply) { v.Expected.Incarnation = "foreign" },
		"revision":         func(v *RuntimeConfigApply) { v.Expected.Revision++ },
		"effective digest": func(v *RuntimeConfigApply) { v.Expected.EffectiveDigest = "changed" },
		"control revision": func(v *RuntimeConfigApply) { v.Expected.ControlRevision++ },
		"candidate digest": func(v *RuntimeConfigApply) { v.CandidateDigest = "changed" },
		"accepted impacts": func(v *RuntimeConfigApply) { v.AcceptedImpactDigest = "changed" },
		"plan":             func(v *RuntimeConfigApply) { v.PlanID = "other" },
		"transaction":      func(v *RuntimeConfigApply) { v.TransactionID = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			mutate(&request)
			if _, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request); err == nil {
				t.Fatal("invalid bound plan accepted")
			}
			if f.count("a") != 1 || f.identity() != valid.Expected {
				t.Fatal("rejected request performed preparation or publication")
			}
		})
	}
	if _, err := f.box.applyRuntimeConfig(context.Background(), "actor-b", valid); err == nil {
		t.Fatal("plan actor binding ignored")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.box.applyRuntimeConfig(canceled, "actor-a", valid); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-admission cancellation = %v", err)
	}
	f.box.runtime.access.Lock()
	consumed := f.box.runtime.plans[valid.TransactionID].consumed
	f.box.runtime.access.Unlock()
	if consumed {
		t.Fatal("rejected requests consumed the still-valid one-to-one plan")
	}
	operation, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", valid)
	if err != nil || operation.Active.Revision != 2 {
		t.Fatalf("valid original request no longer executable: %+v %v", operation, err)
	}
	rejected, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", competing)
	if err != nil || rejected.State != "REJECTED_UNAPPLIED" || rejected.Before != competing.Expected ||
		rejected.Active != competing.Expected || len(rejected.Errors) != 1 || rejected.Errors[0].Code != "PLAN_PRECONDITION_CHANGED" {
		t.Fatalf("stale Apply did not return an unapplied receipt: %+v %v", rejected, err)
	}
	status, err := f.box.GetRuntimeConfigStatus("actor-a", competing.Expected.Incarnation, competing.TransactionID)
	if err != nil || status.Active != operation.Active || status.LookupState != "FOUND" || status.Operation == nil ||
		status.Operation.State != rejected.State || status.Operation.TransactionID != competing.TransactionID {
		t.Fatalf("stale Apply receipt could not be reconciled: %+v %v", status, err)
	}
	competing.CandidateDigest = "changed"
	if _, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", competing); err == nil {
		t.Fatal("consumed rejection ticket accepted a different request")
	}
	if f.identity() != operation.Active {
		t.Fatal("the rejected ticket changed the published identity")
	}
}

func TestRuntimePlansAreBoundedExpiringDetachedAndNeverReuseIdentifiers(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	f.start(t)
	now := time.Unix(1700000000, 0)
	f.box.runtime.access.Lock()
	f.box.runtime.now = func() time.Time { return now }
	f.box.runtime.access.Unlock()
	first, firstRequest := f.plan(t, runtimeTestConfig(1081, "example.org"))
	if first.ExpiresAtUnixMilli != now.Add(runtimePlanLifetime).UnixMilli() || first.PlanID == first.TransactionID {
		t.Fatal("plan lifetime or one-to-one identifiers were not minted")
	}
	identities := map[string]bool{first.PlanID: true, first.TransactionID: true}
	for i := 1; i < runtimePlanLimit; i++ {
		plan, _ := f.plan(t, runtimeTestConfig(1081, "example.org"))
		if identities[plan.PlanID] || identities[plan.TransactionID] {
			t.Fatal("live plan identifier reused")
		}
		identities[plan.PlanID] = true
		identities[plan.TransactionID] = true
	}
	if _, err := f.box.planRuntimeConfig(context.Background(), "actor-a", f.identity(), runtimeTestConfig(1081, "example.org")); err == nil {
		t.Fatal("unbounded plan admission")
	}
	if f.count("a") != 1 || f.count("b") != 1 {
		t.Fatal("planning constructed runtime components")
	}
	f.box.runtime.access.Lock()
	now = now.Add(runtimePlanLifetime)
	f.box.runtime.access.Unlock()
	if _, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", firstRequest); err == nil {
		t.Fatal("plan accepted at its exclusive expiry boundary")
	}
	next, _ := f.plan(t, runtimeTestConfig(1081, "example.org"))
	if identities[next.PlanID] || identities[next.TransactionID] {
		t.Fatal("expired plan identity reused")
	}
	f.box.runtime.access.Lock()
	count := len(f.box.runtime.plans)
	charge := f.box.runtime.planStorage
	recordCharge := f.box.runtime.plans[next.TransactionID].storageCharge
	f.box.runtime.access.Unlock()
	if count != 1 || charge != recordCharge || charge <= 0 {
		t.Fatalf("expired plans not released from bounded accounting: count %d charge %d record %d", count, charge, recordCharge)
	}
	if _, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", firstRequest); err == nil {
		t.Fatal("pruned transaction became executable again")
	}
}

func TestRuntimePlanInputAndSequenceBudgetsDoNotChangeActiveGraph(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	f.start(t)
	before := f.identity()
	for _, input := range [][]byte{nil, make([]byte, runtimeConfigByteLimit+1)} {
		if _, err := f.box.planRuntimeConfig(context.Background(), "actor-a", before, input); err == nil {
			t.Fatal("input budget accepted")
		}
	}
	invalid, err := f.box.planRuntimeConfig(context.Background(), "actor-a", before, []byte(`{"outbounds":[{"type":"unknown","password":"must-not-appear"}]}`))
	if err != nil || invalid.Applicable || len(invalid.Errors) != 1 || invalid.Errors[0].Code != "INVALID_CONFIG" || invalid.Errors[0].Message != "configuration failed schema validation" {
		t.Fatalf("invalid config was not safely diagnosed: %+v %v", invalid, err)
	}
	f.box.runtime.access.Lock()
	f.box.runtime.sequence = math.MaxUint64
	f.box.runtime.access.Unlock()
	if _, err := f.box.planRuntimeConfig(context.Background(), "actor-a", before, runtimeTestConfig(1081, "example.org")); err == nil {
		t.Fatal("transaction sequence wrapped")
	}
	if f.identity() != before || f.count("a") != 1 {
		t.Fatal("planning failure changed active resources")
	}
}

func TestRuntimePublicCapabilityRequiresStartedGraphAndPreservesReplay(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	initial := f.box.RuntimeCapabilities()
	if initial.Enabled || initial.Identity.Incarnation == "" || initial.ImplementationManifestDigest == "" {
		t.Fatal("pre-start identity/manifest must exist without admitting mutations")
	}
	if _, err := f.box.PlanRuntimeConfig(context.Background(), "actor-a", f.identity(), runtimeTestConfig(1081, "example.org")); err == nil {
		t.Fatal("public Plan admitted an unstarted graph")
	}
	f.start(t)
	before := f.identity()
	capability := f.box.RuntimeCapabilities()
	if !capability.Enabled || capability.FullConfiguration || capability.ImplementationManifestDigest != initial.ImplementationManifestDigest {
		t.Fatal("started daily capability or stable implementation manifest is incorrect")
	}
	plan, err := f.box.PlanRuntimeConfig(context.Background(), "actor-a", before, runtimeTestConfig(1081, "example.org"))
	if err != nil || !plan.Applicable {
		t.Fatalf("public Plan: %+v %v", plan, err)
	}
	request := RuntimeConfigApply{ContractVersion: RuntimeConfigContractVersion, PlanID: plan.PlanID, TransactionID: plan.TransactionID, Expected: plan.Expected, CandidateDigest: plan.CandidateDigest, AcceptedImpactDigest: plan.ImpactDigest}
	// Model the real startup window after graph publication but before all
	// stable API/listener Started callbacks have finished.
	f.box.runtime.access.Lock()
	f.box.runtime.initialPhase = 1
	f.box.runtime.access.Unlock()
	if f.box.RuntimeCapabilities().Enabled {
		t.Fatal("partially started graph advertised ready")
	}
	if _, err := f.box.PlanRuntimeConfig(context.Background(), "actor-a", before, runtimeTestConfig(1081, "example.org")); err == nil {
		t.Fatal("published-but-unready graph admitted Plan")
	}
	if _, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request); err == nil {
		t.Fatal("published-but-unready graph admitted Apply")
	}
	f.box.runtime.access.Lock()
	f.box.runtime.initialPhase = 2
	f.box.runtime.access.Unlock()
	operation, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || operation.Active.Revision != before.Revision+1 || operation.State != "COMMITTED_DURABILITY_PENDING" || operation.Durable {
		t.Fatalf("public Apply without owner must truthfully retain durability debt: %+v %v", operation, err)
	}
	if _, err := f.box.PlanRuntimeConfig(context.Background(), "actor-a", before, runtimeTestConfig(1082, "example.org")); err == nil {
		t.Fatal("stale public Plan admitted")
	}
	count := f.count("a")
	f.box.runtime.access.Lock()
	f.box.runtime.preparing = true
	f.box.runtime.access.Unlock()
	replay, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	f.box.runtime.access.Lock()
	f.box.runtime.preparing = false
	f.box.runtime.access.Unlock()
	if err != nil || replay.Active != operation.Active || f.count("a") != count {
		t.Fatal("public replay reconstructed the graph")
	}
	if _, err := f.box.ApplyRuntimeConfig(context.Background(), "another-owner", request); err == nil {
		t.Fatal("foreign actor acquired a receipt")
	}
}

func TestRuntimeCapacityDiagnosticCountsOnlyUnconfirmedRetirements(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	f.start(t)
	c := f.box.runtime
	c.access.Lock()
	for seq := uint64(1); len(c.catalog) < runtimeResourceLimit; seq++ {
		id := adapter.RuntimeResourceID{Incarnation: "capacity-diagnostic", Sequence: seq}
		owner, err := runtimegraph.NewResourceOwner(context.Background(), id, nil, func() error { return nil })
		if err != nil {
			c.access.Unlock()
			t.Fatal(err)
		}
		c.catalog[id] = &runtimeResource{id: id, owner: owner}
	}
	// Failed and rejected receipts carry no retirement state; only unconfirmed
	// retirements of published generations are charged as retiring.
	for index, state := range []RuntimeConfigOperation{
		{State: "ABORTED_UNAPPLIED"},
		{State: "REJECTED_UNAPPLIED"},
		{RetirementState: "DRAINED"},
		{RetirementState: "PENDING"},
		{RetirementState: "DRAINING"},
		{RetirementState: "UNKNOWN"},
	} {
		c.plans[fmt.Sprint("capacity-diagnostic-", index)] = &runtimePlanRecord{operation: &state}
	}
	c.access.Unlock()
	var options option.Options
	if err := json.UnmarshalContext(f.ctx, runtimeTestConfig(1081, "example.org"), &options); err != nil {
		t.Fatal(err)
	}
	identity := f.identity()
	identity.Revision++
	prepared, err := f.box.constructRuntimeGraph(context.Background(), identity, options)
	if prepared != nil {
		prepared.abort()
	}
	if err == nil || !strings.Contains(err.Error(), " retiring=3") {
		t.Fatalf("unexpected capacity diagnostic: %v", err)
	}
}
