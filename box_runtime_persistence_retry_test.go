package box

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func retryFixture(t *testing.T, mode string, safe bool, persist func(RuntimeIdentity, []byte) error) (*runtimeTestFixture, RuntimePersistenceRetry, RuntimeConfigApply) {
	t.Helper()
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "before.example"), nil)
	if err := f.box.BindRuntimePersistenceOptions(persist, mode, safe); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	_, apply := f.plan(t, runtimeTestConfig(1080, "after.example"))
	op, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", apply)
	if err != nil {
		t.Fatal(err)
	}
	return f, RuntimePersistenceRetry{ContractVersion: 1, TransactionID: op.TransactionID, Active: op.Active, PersistenceMode: mode}, apply
}

func TestRuntimePersistenceRetryOriginalTailOnly(t *testing.T) {
	calls := 0
	var snapshot []byte
	f, request, apply := retryFixture(t, "exact_configuration_file", true, func(id RuntimeIdentity, content []byte) error {
		calls++
		if runtimeDigest(content) != id.EffectiveDigest {
			t.Error("identity/content mismatch")
		}
		if calls == 1 {
			snapshot = append([]byte(nil), content...)
			return errors.New("rename succeeded, sync uncertain")
		}
		if string(snapshot) != string(content) {
			t.Error("retry changed bytes")
		}
		return nil
	})
	if _, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", apply); err != nil || calls != 1 {
		t.Fatal("Apply replay performed persistence", err)
	}
	for _, mutate := range []func(*RuntimePersistenceRetry){
		func(r *RuntimePersistenceRetry) { r.ContractVersion++ },
		func(r *RuntimePersistenceRetry) { r.TransactionID = "other" },
		func(r *RuntimePersistenceRetry) { r.Active.EffectiveDigest = "other" },
		func(r *RuntimePersistenceRetry) { r.Active.Incarnation = "other" },
		func(r *RuntimePersistenceRetry) { r.Active.Revision++ },
		func(r *RuntimePersistenceRetry) { r.Active.ControlRevision++ },
		func(r *RuntimePersistenceRetry) { r.PersistenceMode = "owner_acknowledged" },
	} {
		bad := request
		mutate(&bad)
		if _, err := f.box.retryRuntimePersistence(context.Background(), "actor-a", bad); err == nil {
			t.Fatal("stale identity accepted")
		}
	}
	if _, err := f.box.retryRuntimePersistence(context.Background(), "other", request); err == nil || calls != 1 {
		t.Fatal("wrong actor performed effects")
	}
	op, err := f.box.retryRuntimePersistence(context.Background(), "actor-a", request)
	if err != nil || !op.Durable || op.Active != request.Active || calls != 2 {
		t.Fatal("original retry failed", op, err)
	}
	if _, err = f.box.retryRuntimePersistence(context.Background(), "actor-a", request); err != nil || calls != 2 {
		t.Fatal("durable retry replayed callback", err)
	}
}

func TestRuntimePersistenceRetryRequiresExplicitRepeatSafety(t *testing.T) {
	calls := 0
	f, request, _ := retryFixture(t, "exact_configuration_file", false, func(RuntimeIdentity, []byte) error { calls++; return errors.New("partial effect") })
	if _, err := f.box.retryRuntimePersistence(context.Background(), "actor-a", request); err == nil || calls != 1 {
		t.Fatal("generic callback replayed")
	}
	if f.box.runtime.pendingPersistence != nil {
		t.Fatal("unsupported callback pinned indefinitely")
	}
}

func TestRuntimePersistenceRetryReloadReceiptDoesNotRepeatCallback(t *testing.T) {
	calls := 0
	f, request, _ := retryFixture(t, "app_authoritative_regeneration", true, func(RuntimeIdentity, []byte) error {
		calls++
		if calls == 1 {
			return errors.New("reload failed")
		}
		return &RuntimeOwnerAcknowledgementRequiredError{Mode: "app_authoritative_regeneration"}
	})
	op, err := f.box.retryRuntimePersistence(context.Background(), "actor-a", request)
	if err != nil || op.Durable || !op.OwnerReloadAcknowledged {
		t.Fatal("reload was confused with durable desired state", err)
	}
	if _, err = f.box.retryRuntimePersistence(context.Background(), "actor-a", request); err != nil || calls != 2 {
		t.Fatal("reload receipt repeated callback", err)
	}
	c := f.box.runtime
	c.access.Lock()
	c.plans[request.TransactionID].receiptExpires = 1
	c.access.Unlock()
	ack := RuntimePersistenceAcknowledgement{ContractVersion: 1, TransactionID: request.TransactionID, Active: request.Active, PersistenceMode: request.PersistenceMode, DesiredStateDigest: runtimeDigest([]byte("D")), DesiredStateRevision: "2"}
	op, err = f.box.acknowledgeRuntimePersistence(context.Background(), "actor-a", ack)
	if err != nil || !op.Durable || len(op.Errors) != 0 {
		t.Fatal("pinned owner acknowledgement failed", err)
	}
	if c.pendingPersistence != nil {
		t.Fatal("settled owner remains pinned")
	}
}

func TestRuntimePersistenceRetryPinsOnlyCurrentOriginalOwner(t *testing.T) {
	f, request, _ := retryFixture(t, "exact_configuration_file", true, func(RuntimeIdentity, []byte) error { return errors.New("offline") })
	c := f.box.runtime
	waitRetryState(t, c, func() bool { return !c.plans[request.TransactionID].inFlight })
	c.access.Lock()
	original := c.plans[request.TransactionID]
	original.receiptExpires = 1
	chargeBefore := c.planStorage
	originalCharge := original.storageCharge
	c.access.Unlock()
	_, alias := f.plan(t, runtimeTestConfig(1080, "after.example"))
	if _, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", alias); err != nil {
		t.Fatal(err)
	}
	bad := request
	bad.TransactionID = alias.TransactionID
	if _, err := f.box.retryRuntimePersistence(context.Background(), "actor-a", bad); err == nil {
		t.Fatal("no-op acquired original tail")
	}
	c.access.Lock()
	retained := c.plans[request.TransactionID] == original && c.pendingPersistence == original && original.storageCharge == originalCharge && c.planStorage >= chargeBefore
	c.access.Unlock()
	if !retained {
		t.Fatal("original owner evicted")
	}
	_, replacement := f.plan(t, runtimeTestConfig(1080, "new.example"))
	if _, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", replacement); err != nil {
		t.Fatal(err)
	}
	if _, err := f.box.retryRuntimePersistence(context.Background(), "actor-a", request); err == nil {
		t.Fatal("superseded original replayed")
	}
	c.access.Lock()
	invalid := original.operation.Durable || c.pendingPersistence == original
	c.access.Unlock()
	if invalid {
		t.Fatal("superseded receipt falsely settled or pinned")
	}
}

func TestRuntimePersistenceRetryReentryAndCloseJoin(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var f *runtimeTestFixture
	var request RuntimePersistenceRetry
	f, request, _ = retryFixture(t, "exact_configuration_file", true, func(RuntimeIdentity, []byte) error {
		if calls.Add(1) == 1 {
			return errors.New("offline")
		}
		if _, err := f.box.retryRuntimePersistence(context.Background(), "actor-a", request); err == nil {
			t.Error("reentrant retry accepted")
		}
		close(entered)
		<-release
		return nil
	})
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { defer close(done); _, _ = f.box.retryRuntimePersistence(ctx, "actor-a", request) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("retry admission watchdog")
	}
	cancel()
	if _, err := f.box.retryRuntimePersistence(context.Background(), "actor-a", request); err == nil {
		t.Fatal("concurrent retry accepted")
	}
	closed := make(chan struct{})
	go func() { _ = f.box.Close(); close(closed) }()
	waitRetryState(t, f.box.runtime, func() bool { return f.box.runtime.stopped })
	f.box.runtime.access.Lock()
	owned := f.box.runtime.preparing && f.box.runtime.plans[request.TransactionID].retryInFlight
	f.box.runtime.access.Unlock()
	if !owned {
		t.Fatal("Close lost admitted retry ownership")
	}
	select {
	case <-done:
		t.Fatal("cancellation detached callback")
	case <-closed:
		t.Fatal("Close detached callback")
	default:
	}
	unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("retry unwind watchdog")
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close join watchdog")
	}
	if f.box.runtime.pendingPersistence != nil {
		t.Fatal("Close retained repair pin")
	}
}

func TestRuntimePersistenceRetryPanicRemainsBounded(t *testing.T) {
	f, request, _ := retryFixture(t, "exact_configuration_file", true, func(RuntimeIdentity, []byte) error { panic("partial effect") })
	for range 3 {
		op, err := f.box.retryRuntimePersistence(context.Background(), "actor-a", request)
		if err != nil || op.Durable || len(op.Errors) != 1 || op.Errors[0].Code != "PERSISTENCE_FAILED" {
			t.Fatal("panic lost bounded pending receipt", err)
		}
	}
}

func TestRuntimePersistenceRetryControlsInvalidateWithoutBlocking(t *testing.T) {
	calls := 0
	f, request, _ := retryFixture(t, "exact_configuration_file", true, func(RuntimeIdentity, []byte) error { calls++; return errors.New("offline") })
	lease, view := f.acquire(t)
	id := view.componentIDs["outbound:select"]
	if !f.box.runtime.SelectRuntimeOutbound(id, "select", "a") {
		t.Fatal("same selector rejected")
	}
	if f.box.runtime.pendingPersistence == nil {
		t.Fatal("unchanged selection invalidated owner")
	}
	if !f.box.runtime.SelectRuntimeOutbound(id, "select", "b") {
		t.Fatal("pending durability blocked control")
	}
	lease.Release()
	if f.box.runtime.pendingPersistence != nil {
		t.Fatal("changed control retained stale owner")
	}
	if _, err := f.box.retryRuntimePersistence(context.Background(), "actor-a", request); err == nil || calls != 1 {
		t.Fatal("control conflict replayed old tail")
	}
}

func TestRuntimePersistenceRetryParticipantFailureStaysPending(t *testing.T) {
	calls := 0
	f, request, _ := retryFixture(t, "exact_configuration_file", true, func(RuntimeIdentity, []byte) error { calls++; return errors.New("offline") })
	var events []string
	participant := &runtimePersistenceFixture{calls: &events, waitErr: errors.New("sticky namespace writer failure")}
	c := f.box.runtime
	c.access.Lock()
	c.plans[request.TransactionID].persistenceParticipant = participant
	c.access.Unlock()
	op, err := f.box.retryRuntimePersistence(context.Background(), "actor-a", request)
	if err != nil || op.Durable || calls != 1 || len(events) != 1 || events[0] != "wait" {
		t.Fatal("namespace failure bypassed", err)
	}
}

// The predicate runs under the coordinator guard; the timer only bounds test
// observation, never substitutes for completion of an admitted operation.
func waitRetryState(t *testing.T, c *runtimeCoordinator, predicate func() bool) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		c.access.Lock()
		ready := predicate()
		c.access.Unlock()
		if ready {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("retry state observation watchdog")
		case <-tick.C:
		}
	}
}
