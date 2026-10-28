package box

import (
	"context"
	"errors"
	"testing"
)

func runtimeOwnerAckFixture(t *testing.T, callbackError error) (*runtimeTestFixture, RuntimeConfigOperation, RuntimePersistenceAcknowledgement) {
	t.Helper()
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "before.example"), nil)
	if err := f.box.BindRuntimePersistenceMode(func(RuntimeIdentity, []byte) error { return callbackError }, "app_authoritative_regeneration"); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	_, request := f.plan(t, runtimeTestConfig(1080, "after.example"))
	operation, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil {
		t.Fatal(err)
	}
	ack := RuntimePersistenceAcknowledgement{ContractVersion: 1, TransactionID: request.TransactionID, Active: operation.Active, PersistenceMode: "app_authoritative_regeneration", DesiredStateDigest: runtimeDigest([]byte("durable desired state")), DesiredStateRevision: "desired:2"}
	return f, operation, ack
}

func TestRuntimeOwnerAcknowledgementIsBoundAndReplaySafe(t *testing.T) {
	f, pending, ack := runtimeOwnerAckFixture(t, &RuntimeOwnerAcknowledgementRequiredError{Mode: "app_authoritative_regeneration"})
	if pending.Durable || !pending.OwnerReloadAcknowledged {
		t.Fatal("provider reload was confused with owner durability")
	}
	if _, err := f.box.acknowledgeRuntimePersistence(context.Background(), "other-actor", ack); err == nil {
		t.Fatal("wrong actor acknowledged owner state")
	}
	wrong := ack
	wrong.Active.Incarnation = "other-incarnation"
	if _, err := f.box.acknowledgeRuntimePersistence(context.Background(), "actor-a", wrong); err == nil {
		t.Fatal("wrong incarnation accepted")
	}
	committed, err := f.box.acknowledgeRuntimePersistence(context.Background(), "actor-a", ack)
	if err != nil {
		t.Fatal(err)
	}
	if !committed.Durable || committed.DesiredStateDigest != ack.DesiredStateDigest || committed.PersistenceMode != "app_authoritative_regeneration" {
		t.Fatal("owner evidence not reflected")
	}
	replay, err := f.box.acknowledgeRuntimePersistence(context.Background(), "actor-a", ack)
	if err != nil || !replay.Durable {
		t.Fatal("exact acknowledgement replay failed")
	}
	wrong = ack
	wrong.DesiredStateRevision = "desired:3"
	if _, err := f.box.acknowledgeRuntimePersistence(context.Background(), "actor-a", wrong); err == nil {
		t.Fatal("conflicting replay accepted")
	}
}

func TestRuntimeProviderFailureCannotBeAcknowledgedByOwner(t *testing.T) {
	f, pending, ack := runtimeOwnerAckFixture(t, errors.New("provider reload failed"))
	if pending.OwnerReloadAcknowledged {
		t.Fatal("provider failure emitted reload receipt")
	}
	if _, err := f.box.acknowledgeRuntimePersistence(context.Background(), "actor-a", ack); err == nil {
		t.Fatal("owner bypassed failed provider callback")
	}
}

func TestRuntimeOlderPendingReceiptCannotAcknowledgeNewerGraph(t *testing.T) {
	f, _, ack := runtimeOwnerAckFixture(t, &RuntimeOwnerAcknowledgementRequiredError{Mode: "app_authoritative_regeneration"})
	_, request := f.plan(t, runtimeTestConfig(1080, "latest-desired.example"))
	latest, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.box.acknowledgeRuntimePersistence(context.Background(), "actor-a", ack); err == nil {
		t.Fatal("obsolete transaction acknowledged")
	}
	if f.identity() != latest.Active {
		t.Fatal("obsolete acknowledgement changed runtime")
	}
	f.box.runtime.access.Lock()
	old := cloneRuntimeOperation(*f.box.runtime.plans[ack.TransactionID].operation)
	f.box.runtime.access.Unlock()
	if old.Durable || old.State != "COMMITTED_DURABILITY_PENDING" {
		t.Fatal("corrective commit fabricated old acknowledgement")
	}
}

func TestRuntimeRegenerationModeRequiresTypedProviderReceipt(t *testing.T) {
	f, pending, ack := runtimeOwnerAckFixture(t, nil)
	if pending.Durable || pending.OwnerReloadAcknowledged {
		t.Fatal("nil callback silently certified regeneration authority")
	}
	if _, err := f.box.acknowledgeRuntimePersistence(context.Background(), "actor-a", ack); err == nil {
		t.Fatal("missing typed reload receipt accepted")
	}
}
