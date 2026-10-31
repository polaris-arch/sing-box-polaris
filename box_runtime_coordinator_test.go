package box

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/adapter"

	mdns "github.com/miekg/dns"
)

func TestRuntimeBoxInitialPublicationWaitsForActualStartedStage(t *testing.T) {
	barrier := newRuntimeTestBarrier()
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), func(outbound *runtimeTestSocks) error {
		if outbound.Tag() == "a" {
			outbound.startHook = func(stage adapter.StartStage) error {
				if stage == adapter.StartStateStarted {
					barrier.block()
				}
				return nil
			}
		}
		return nil
	})
	t.Cleanup(barrier.open)
	if identity := f.identity(); identity.Revision != 0 || identity.EffectiveDigest != "" {
		t.Fatalf("constructor published prematurely: %+v", identity)
	}
	gateway, ok := adapter.RuntimeDNSIngressFromContext(f.box.runtime.ctx)
	if !ok {
		t.Fatal("real initial constructor did not bind stable DNS ingress")
	}
	query := new(mdns.Msg)
	query.SetQuestion("example.org.", mdns.TypeA)
	assertUnready := func() {
		t.Helper()
		if lease, err := f.box.runtime.store.Acquire(); err == nil {
			lease.Release()
			t.Fatal("half-started graph admitted")
		}
		if _, err := gateway.Exchange(context.Background(), query, adapter.DNSQueryOptions{}); err == nil {
			t.Fatal("early DNS query entered an unpublished leaf")
		}
		calls := 0
		gateway.ExchangeAsync(context.Background(), query, adapter.DNSQueryOptions{}, func(response *mdns.Msg, err error) {
			calls++
			if response != nil || err == nil {
				t.Error("early async query did not report unavailable")
			}
		})
		if calls != 1 {
			t.Fatalf("early async rejection callback count = %d", calls)
		}
	}
	assertUnready()
	if err := f.box.PreStart(); err != nil {
		t.Fatal(err)
	}
	assertUnready()
	started := make(chan error, 1)
	go func() { started <- f.box.Start() }()
	runtimeTestWait(t, barrier.entered, "actual initial Started lifecycle")
	assertUnready()
	barrier.open()
	select {
	case err := <-started:
		if err != nil {
			t.Fatal(err)
		}
	case <-runtimeTestContext(t).Done():
		t.Fatal("initial Start did not finish")
	}
	lease, view := f.acquire(t)
	if view.Identity().Revision != 1 || f.identity().Revision != 1 {
		t.Fatal("initial publication did not create revision one")
	}
	lease.Release()
	for _, tag := range []string{"a", "b"} {
		stages, closes := f.object(t, tag, 0).snapshot()
		if !reflect.DeepEqual(stages, adapter.ListStartStages) || closes != 0 {
			t.Fatalf("%s lifecycle = %v, closes %d", tag, stages, closes)
		}
	}
	capability := f.box.RuntimeCapabilities()
	if !capability.Enabled || capability.FullConfiguration {
		t.Fatal("started daily runtime capability or bounded schema declaration is incorrect")
	}
}

func TestRuntimeApplyReusesExactUnchangedResourcesAndRetiresAfterContinuation(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	f.start(t)
	oldLease, oldView := f.acquire(t)
	oldA := f.object(t, "a", 0)
	borrowedB := f.object(t, "b", 0)
	oldResource := runtimeTestResource(t, f, oldView.componentIDs["outbound:a"])
	_, request := f.plan(t, runtimeTestConfig(1081, "example.org"))
	operation, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil {
		t.Fatal(err)
	}
	if operation.State != "COMMITTED_DURABILITY_PENDING" || operation.Active.Revision != 2 {
		t.Fatalf("unexpected commit: %+v", operation)
	}
	newLease, newView := f.acquire(t)
	if oldView == newView {
		t.Fatal("new revision reused a mutable graph view")
	}
	for _, name := range []string{"outbound:b", "dns-transport:resolver", "rule-set:sites", "dns-router"} {
		if oldView.componentIDs[name] != newView.componentIDs[name] {
			t.Errorf("unchanged %s was not borrowed by identity", name)
		}
	}
	for _, name := range []string{"outbound:a", "outbound:select", "route-router"} {
		if oldView.componentIDs[name] == newView.componentIDs[name] {
			t.Errorf("changed closure %s was borrowed", name)
		}
	}
	actualB, _ := newView.OutboundManager().Outbound("b")
	if actualB != borrowedB || f.count("b") != 1 {
		t.Fatal("borrowed outbound was reconstructed")
	}
	if stages, closes := borrowedB.snapshot(); !reflect.DeepEqual(stages, adapter.ListStartStages) || closes != 0 {
		t.Fatal("borrowed member restarted or closed")
	}
	if newView.DNSRouter() != oldView.DNSRouter() {
		t.Fatal("unchanged receiving DNS leaf identity was lost")
	}
	inventory := newView.OutboundManager().Outbounds()
	inventory[0] = nil
	if newView.OutboundManager().Outbounds()[0] == nil {
		t.Fatal("candidate inventory aliases a caller slice")
	}
	runtimeTestWait(t, oldResource.owner.Retiring(), "old-only resource seal")
	if _, err := oldResource.owner.Acquire(); err == nil {
		t.Fatal("retired owner admitted a new root")
	}
	if oldA.ctx.Err() != nil {
		t.Fatal("retirement canceled admitted foreground operations")
	}
	continuation, err := oldLease.Fork()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(continuation.Release)
	selected, _ := continuation.View().OutboundManager().Outbound("a")
	if selected != oldA {
		t.Fatal("old flow continuation changed its outbound")
	}
	oldLease.Release()
	select {
	case <-oldA.closed:
		t.Fatal("cleanup ran while an old continuation was live")
	default:
	}
	resourceContinuation, err := continuation.RetainResource(oldView.componentIDs["outbound:a"])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resourceContinuation.Release)
	continuation.Release()
	select {
	case <-oldA.closed:
		t.Fatal("cleanup ignored a resource continuation")
	default:
	}
	resourceContinuation.Release()
	if err := oldResource.owner.WaitClosed(runtimeTestContext(t)); err != nil {
		t.Fatal(err)
	}
	if _, count := oldA.snapshot(); count != 1 {
		t.Fatalf("old member cleanup count = %d", count)
	}
	if oldA.ctx.Err() == nil || borrowedB.ctx.Err() != nil {
		t.Fatal("cleanup cancellation crossed the resource boundary")
	}
	if _, err := resourceContinuation.Fork(); err == nil {
		t.Fatal("released resource token resurrected a drained owner")
	}
	newLease.Release()
}

func TestRuntimePrepareFailurePreservesCurrentAndAbortKeepsBorrowedMembers(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	f.start(t)
	oldLease, oldView := f.acquire(t)
	before := f.identity()
	barrier := newRuntimeTestBarrier()
	t.Cleanup(barrier.open)
	f.setConstructorHook(func(outbound *runtimeTestSocks) error {
		if outbound.Tag() == "a" {
			outbound.closeHook = func() error { barrier.block(); return nil }
			return errors.New("injected error after the real SOCKS constructor acquired its resources")
		}
		return nil
	})
	_, request := f.plan(t, runtimeTestConfig(1081, "example.org"))
	operation, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil {
		t.Fatal(err)
	}
	if operation.State != "ABORTING_UNAPPLIED" || operation.Active != before {
		t.Fatalf("failure did not report uncommitted cleanup: %+v", operation)
	}
	runtimeTestWait(t, barrier.entered, "candidate abort cleanup")
	if f.identity() != before {
		t.Fatal("failed preparation changed active identity")
	}
	lease, view := f.acquire(t)
	if view != oldView {
		t.Fatal("failed preparation replaced current view")
	}
	lease.Release()
	if f.count("a") != 2 || f.count("b") != 1 {
		t.Fatal("failure did not preserve mixed new/borrowed construction")
	}
	failed := f.object(t, "a", 1)
	source, ok := adapter.RuntimeResourceSourceFromContext(failed.ctx)
	if !ok {
		t.Fatal("constructor was not bound to its real resource owner")
	}
	owner := runtimeTestResource(t, f, source.ID())
	if failed.ctx.Err() == nil || f.object(t, "a", 0).ctx.Err() != nil || f.object(t, "b", 0).ctx.Err() != nil {
		t.Fatal("abort cancellation escaped candidate ownership")
	}
	select {
	case <-owner.owner.Closed():
		t.Fatal("owner claimed cleanup complete before callback returned")
	default:
	}
	retry, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || retry.State != "ABORTING_UNAPPLIED" || f.count("a") != 2 {
		t.Fatal("exact retry repeated failed preparation")
	}
	barrier.open()
	if err := owner.owner.WaitClosed(runtimeTestContext(t)); err != nil {
		t.Fatal(err)
	}
	if _, closes := failed.snapshot(); closes != 1 {
		t.Fatal("failed constructor was not closed exactly once")
	}
	for _, tag := range []string{"a", "b"} {
		if stages, closes := f.object(t, tag, 0).snapshot(); !reflect.DeepEqual(stages, adapter.ListStartStages) || closes != 0 {
			t.Fatalf("abort touched old %s lifecycle", tag)
		}
	}
	oldLease.Release()
}

func TestRuntimePreparationCancellationIsPrivateAndExactRetryDoesNotRestart(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	f.start(t)
	before := f.identity()
	barrier := newRuntimeTestBarrier()
	t.Cleanup(barrier.open)
	f.setConstructorHook(func(outbound *runtimeTestSocks) error {
		if outbound.Tag() == "a" {
			outbound.startHook = func(stage adapter.StartStage) error {
				if stage == adapter.StartStateStarted {
					barrier.block()
				}
				return nil
			}
		}
		return nil
	})
	_, request := f.plan(t, runtimeTestConfig(1081, "example.org"))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := runtimeTestApplyAsync(f, ctx, request)
	runtimeTestWait(t, barrier.entered, "candidate Started stage")
	inFlight, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || inFlight.State != "PREPARING" || f.count("a") != 2 {
		t.Fatalf("in-flight retry was not observational: %+v %v", inFlight, err)
	}
	changed := request
	changed.AcceptedImpactDigest = "different"
	if _, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", changed); err == nil {
		t.Fatal("reused transaction accepted a changed exact fingerprint")
	}
	if _, err := f.box.applyRuntimeConfig(context.Background(), "actor-b", request); err == nil {
		t.Fatal("transaction crossed authenticated actor scope")
	}
	cancel()
	barrier.open()
	operation := runtimeTestReceiveApply(t, result)
	if operation.State != "ABORTING_UNAPPLIED" || f.identity() != before {
		t.Fatal("canceled candidate was published")
	}
	failed := f.object(t, "a", 1)
	source, _ := adapter.RuntimeResourceSourceFromContext(failed.ctx)
	if err := runtimeTestResource(t, f, source.ID()).owner.WaitClosed(runtimeTestContext(t)); err != nil {
		t.Fatal(err)
	}
	if f.object(t, "a", 0).ctx.Err() != nil {
		t.Fatal("request cancellation poisoned the current graph")
	}
	retry, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || (retry.State != "ABORTING_UNAPPLIED" && retry.State != "ABORTED_UNAPPLIED") || f.count("a") != 2 {
		t.Fatalf("canceled transaction restarted: %+v %v", retry, err)
	}
}

func TestRuntimeManualSelectionDuringFinalStageRejectsStaleCandidate(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	f.start(t)
	oldLease, oldView := f.acquire(t)
	before := f.identity()
	barrier := newRuntimeTestBarrier()
	t.Cleanup(barrier.open)
	f.setConstructorHook(func(outbound *runtimeTestSocks) error {
		if outbound.Tag() == "a" {
			outbound.startHook = func(stage adapter.StartStage) error {
				if stage == adapter.StartStateStarted {
					barrier.block()
				}
				return nil
			}
		}
		return nil
	})
	_, request := f.plan(t, runtimeTestConfig(1081, "example.org"))
	result := runtimeTestApplyAsync(f, context.Background(), request)
	runtimeTestWait(t, barrier.entered, "last candidate outbound lifecycle stage")
	if !f.box.runtime.SelectRuntimeOutbound(oldView.componentIDs["outbound:select"], "select", "b") {
		t.Fatal("current manual selector update rejected")
	}
	selected := f.identity()
	if selected.Revision != before.Revision || selected.ControlRevision != before.ControlRevision+1 {
		t.Fatal("manual selection did not independently advance control revision")
	}
	barrier.open()
	operation := runtimeTestReceiveApply(t, result)
	observedIdentity := f.identity()
	t.Logf("manual choice: returned-state=%s selected=%+v current=%+v before=%+v operation-active=%+v errors=%+v", operation.State, selected, observedIdentity, operation.Before, operation.Active, operation.Errors)
	if observedIdentity != selected || observedIdentity.Revision != before.Revision || observedIdentity.ControlRevision != before.ControlRevision+1 {
		t.Fatalf("candidate changed concurrent manual identity: selected=%+v current=%+v operation=%+v", selected, observedIdentity, operation)
	}
	// Apply observes an asynchronous abort. Like the reference/source-producer
	// contracts, its returned snapshot may already be terminal. This is not a
	// relaxation of identity, graph publication or user-selection safety.
	if operation.State != "ABORTING_UNAPPLIED" && operation.State != "ABORTED_UNAPPLIED" {
		t.Fatalf("stale candidate did not abort: state=%s errors=%+v", operation.State, operation.Errors)
	}
	group, _ := oldView.outbounds.Outbound("select")
	if group.(adapter.OutboundGroup).Selected("tcp").Tag() != "b" {
		t.Fatalf("manual choice was lost: selected=%s identity=%+v", group.(adapter.OutboundGroup).Selected("tcp").Tag(), f.identity())
	}
	status, err := f.box.GetRuntimeConfigStatus("actor-a", selected.Incarnation, request.TransactionID)
	if err != nil || status.Active != selected || status.Operation == nil || (status.Operation.State != "ABORTING_UNAPPLIED" && status.Operation.State != "ABORTED_UNAPPLIED") {
		t.Fatalf("stale candidate reconciliation lost manual identity: status=%+v error=%v", status, err)
	}
	oldLease.Release()
	// A new plan at the new control revision can commit and migrate the choice.
	_, fresh := f.plan(t, runtimeTestConfig(1082, "example.org"))
	committed, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", fresh)
	if err != nil || committed.Active.Revision != before.Revision+1 {
		t.Fatalf("fresh plan failed: %+v %v", committed, err)
	}
	newLease, newView := f.acquire(t)
	newGroup, _ := newView.outbounds.Outbound("select")
	if newGroup.(adapter.OutboundGroup).Selected("tcp").Tag() != "b" {
		t.Fatal("candidate failed to migrate current selection")
	}
	current := f.identity()
	if f.box.runtime.SelectRuntimeOutbound(oldView.componentIDs["outbound:select"], "select", "a") {
		t.Fatal("stale resource handle changed the replacement selector")
	}
	if f.identity() != current {
		t.Fatal("rejected stale control changed a revision")
	}
	newLease.Release()
}

func TestRuntimePersistenceFailureCannotRollbackOrCancelPublishedGraph(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	barrier := newRuntimeTestBarrier()
	t.Cleanup(barrier.open)
	persistCalls := 0
	var persistedIdentity RuntimeIdentity
	if err := f.box.BindRuntimePersistence(func(identity RuntimeIdentity, content []byte) error {
		persistCalls++
		persistedIdentity = identity
		if len(content) != 0 {
			content[0] = '!'
		} // Callback receives a detached snapshot.
		barrier.block()
		return errors.New("injected durable-store failure")
	}); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	oldLease, _ := f.acquire(t)
	_, request := f.plan(t, runtimeTestConfig(1081, "example.org"))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := runtimeTestApplyAsync(f, ctx, request)
	runtimeTestWait(t, barrier.entered, "post-publication persistence")
	if f.identity().Revision != 2 || persistedIdentity != f.identity() {
		t.Fatal("durability ran before publication")
	}
	currentLease, _ := f.acquire(t)
	if currentLease.View().Identity().Revision != 2 {
		t.Fatal("new ingress cannot see published revision during persistence")
	}
	cancel()
	if f.object(t, "a", 1).ctx.Err() != nil {
		t.Fatal("postcommit request cancellation reached active resource context")
	}
	retry, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || retry.State != "COMMITTED_DURABILITY_PENDING" || persistCalls != 1 {
		t.Fatal("retry repeated preparation or persistence")
	}
	barrier.open()
	operation := runtimeTestReceiveApply(t, result)
	if operation.State != "COMMITTED_DURABILITY_PENDING" || operation.Durable || operation.Active.Revision != 2 || len(operation.Errors) != 1 || operation.Errors[0].Code != "PERSISTENCE_FAILED" {
		t.Fatalf("persistence failure misreported commit: %+v", operation)
	}
	f.box.runtime.access.Lock()
	canonical := append([]byte(nil), f.box.runtime.canonical...)
	f.box.runtime.access.Unlock()
	if bytes.HasPrefix(canonical, []byte("!")) || runtimeDigest(canonical) != operation.Active.EffectiveDigest {
		t.Fatal("persistence callback mutated active snapshot")
	}
	status, err := f.box.GetRuntimeConfigStatus("actor-a", operation.Active.Incarnation, request.TransactionID)
	if err != nil || status.LookupState != "FOUND" || status.Active != operation.Active || status.DurableAppliedDigest != "" {
		t.Fatalf("durability status hid uncertainty: %+v %v", status, err)
	}
	status.Operation.Errors[0].Code = "caller mutation"
	if len(status.Operation.Impacts) != 0 {
		status.Operation.Impacts[0].AffectedSessionClasses[0] = "caller mutation"
	}
	again, err := f.box.GetRuntimeConfigStatus("actor-a", operation.Active.Incarnation, request.TransactionID)
	if err != nil || again.Operation.Errors[0].Code != "PERSISTENCE_FAILED" {
		t.Fatal("status aliases retained receipt")
	}
	if len(again.Operation.Impacts) != 0 && again.Operation.Impacts[0].AffectedSessionClasses[0] == "caller mutation" {
		t.Fatal("nested impact slice aliases receipt")
	}
	foreign, err := f.box.GetRuntimeConfigStatus("actor-b", operation.Active.Incarnation, request.TransactionID)
	if err != nil || foreign.Operation != nil || foreign.LookupState != "UNKNOWN_OR_EXPIRED" {
		t.Fatal("status leaked another actor's receipt")
	}
	wrong, err := f.box.GetRuntimeConfigStatus("actor-a", "different-incarnation", request.TransactionID)
	if err != nil || wrong.Operation != nil || wrong.LookupState != "WRONG_INCARNATION" {
		t.Fatal("status confused process incarnations")
	}
	oldLease.Release()
	currentLease.Release()
}

func TestRuntimeShutdownObservationCancellationDoesNotFinishCleanup(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	f.start(t)
	lease, view := f.acquire(t)
	resource := runtimeTestResource(t, f, view.componentIDs["outbound:a"])
	old := f.object(t, "a", 0)
	barrier := newRuntimeTestBarrier()
	t.Cleanup(barrier.open)
	old.access.Lock()
	old.closeHook = func() error { barrier.block(); return nil }
	old.access.Unlock()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.box.closeRuntimeResourcesContext(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled observer = %v", err)
	}
	if next, err := f.box.runtime.store.Acquire(); err == nil {
		next.Release()
		t.Fatal("shutdown left new admission open")
	}
	select {
	case <-f.box.runtime.shutdownDone:
		t.Fatal("shutdown ignored retained graph continuation")
	default:
	}
	lease.Release()
	runtimeTestWait(t, barrier.entered, "real resource cleanup")
	if err := f.box.closeRuntimeResourcesContext(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("second observer changed the uncertain outcome")
	}
	select {
	case <-resource.owner.Closed():
		t.Fatal("observation cancellation forged owner cleanup completion")
	default:
	}
	select {
	case <-f.box.runtime.shutdownDone:
		t.Fatal("blocked callback was reported drained")
	default:
	}
	barrier.open()
	if err := f.box.closeRuntimeResourcesContext(runtimeTestContext(t)); err != nil {
		t.Fatal(err)
	}
	if err := resource.owner.WaitClosed(runtimeTestContext(t)); err != nil {
		t.Fatal(err)
	}
	if _, count := old.snapshot(); count != 1 {
		t.Fatalf("concurrent observers repeated cleanup %d times", count)
	}
}

func TestRuntimeInitialStartFailureNeverPublishesAndCleansRealConstructors(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), func(outbound *runtimeTestSocks) error {
		if outbound.Tag() == "a" {
			outbound.startHook = func(stage adapter.StartStage) error {
				if stage == adapter.StartStateStarted {
					return errors.New("injected final initial lifecycle failure")
				}
				return nil
			}
		}
		return nil
	})
	if err := f.box.Start(); err == nil {
		t.Fatal("failed initial lifecycle reported success")
	}
	if f.identity().Revision != 0 {
		t.Fatal("failed startup published an admission revision")
	}
	if lease, err := f.box.runtime.store.Acquire(); err == nil {
		lease.Release()
		t.Fatal("failed startup left admission open")
	}
	for _, tag := range []string{"a", "b"} {
		actual := f.object(t, tag, 0)
		runtimeTestWait(t, actual.closed, "initial constructor cleanup")
		if _, count := actual.snapshot(); count != 1 {
			t.Fatalf("initial %s constructor cleanup count = %d", tag, count)
		}
	}
}

func TestRuntimeInlineSourceReplacementChangesOnlyCapturedClosure(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	f.start(t)
	oldLease, before := f.acquire(t)
	_, request := f.plan(t, runtimeTestConfig(1080, "changed.example"))
	operation, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || operation.Active.Revision != 2 {
		t.Fatalf("inline-source candidate failed: %+v %v", operation, err)
	}
	newLease, after := f.acquire(t)
	for _, name := range []string{"rule-set:sites", "dns-router", "route-router"} {
		if before.componentIDs[name] == after.componentIDs[name] {
			t.Errorf("captured inline-source closure did not replace %s", name)
		}
	}
	for _, name := range []string{"dns-transport:resolver", "outbound:a", "outbound:b", "outbound:select"} {
		if before.componentIDs[name] != after.componentIDs[name] {
			t.Errorf("source change unnecessarily replaced %s", name)
		}
	}
	if f.count("a") != 1 || f.count("b") != 1 {
		t.Fatal("inline replacement reconstructed unrelated actual outbounds")
	}
	oldLease.Release()
	newLease.Release()
}

func TestRuntimeDurableCommitAndExactCompletedRetryDoNotRepeatEffects(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	persistCalls := 0
	if err := f.box.BindRuntimePersistence(func(identity RuntimeIdentity, content []byte) error {
		persistCalls++
		if identity != f.identity() || runtimeDigest(content) != identity.EffectiveDigest {
			return errors.New("persistence did not receive the committed effective snapshot")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	candidate := runtimeTestConfig(1081, "example.org")
	plan, request := f.plan(t, candidate)
	for i := range candidate {
		candidate[i] = '!'
	}
	plan.CandidateDigest = "caller mutation"
	if len(plan.Impacts) != 0 {
		plan.Impacts[0].AffectedSessionClasses[0] = "caller mutation"
	}
	operation, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || operation.State != "COMMITTED" || !operation.Durable {
		t.Fatalf("durable commit failed: %+v %v", operation, err)
	}
	identity := f.identity()
	retry, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || retry.Active != identity || retry.State != "COMMITTED" || !retry.Durable || persistCalls != 1 || f.count("a") != 2 {
		t.Fatalf("completed retry repeated transaction: %+v %v", retry, err)
	}
	status, err := f.box.GetRuntimeConfigStatus("actor-a", identity.Incarnation, request.TransactionID)
	if err != nil || status.DurableAppliedDigest != identity.EffectiveDigest {
		t.Fatal("committed durable digest missing from status")
	}
	if len(status.Operation.Impacts) != 0 && status.Operation.Impacts[0].AffectedSessionClasses[0] == "caller mutation" {
		t.Fatal("plan response mutated its retained receipt")
	}
	if err := f.box.BindRuntimePersistence(nil); err == nil {
		t.Fatal("live persistence binding was mutable")
	}
}

func TestRuntimeInitialConstructorFailureReturnsActualCleanupReport(t *testing.T) {
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "example.org"), func(outbound *runtimeTestSocks) error {
		if outbound.Tag() == "b" {
			return errors.New("failure after the second real SOCKS constructor")
		}
		return nil
	})
	instance, err, report := NewWithConstructionReport(options)
	if instance != nil || err == nil || !report.Attempted || report.CleanupError != nil {
		t.Fatalf("initial construction report = %p %v %+v", instance, err, report)
	}
	for _, tag := range []string{"a", "b"} {
		actual := f.object(t, tag, 0)
		select {
		case <-actual.closed:
		default:
			t.Fatalf("constructor report preceded %s cleanup", tag)
		}
		stages, count := actual.snapshot()
		if len(stages) != 0 || count != 1 || actual.ctx.Err() == nil {
			t.Fatalf("failed initial %s lifecycle = %v, cleanup = %d", tag, stages, count)
		}
	}
}
