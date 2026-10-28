package listener

import (
	"context"
	"testing"
)

func TestPreparedListenerPublicationOpensOnlyValidatedGate(t *testing.T) {
	a := newAdmissionFixture()
	socket := newAcceptorFixture()
	candidate := listenerFixture(a, socket, "prepared")
	transaction, err := ReserveListenerSet(nil, []*Listener{candidate}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	publication, err := transaction.PreparePublication()
	if err != nil {
		t.Fatal(err)
	}
	if candidate.runtime.gateway.open {
		t.Fatal("prepublication opened admission")
	}
	publication.Publish()
	publication.Finish()
	waitFixture(t, socket.accepted)
	if err := candidate.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
}

func TestPreparedListenerPublicationAbortLeavesCandidateInvisible(t *testing.T) {
	a := newAdmissionFixture()
	socket := newAcceptorFixture()
	candidate := listenerFixture(a, socket, "prepared")
	transaction, err := ReserveListenerSet(nil, []*Listener{candidate}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	publication, err := transaction.PreparePublication()
	if err != nil {
		t.Fatal(err)
	}
	publication.Finish()
	select {
	case <-socket.accepted:
		t.Fatal("aborted publication accepted traffic")
	default:
	}
	if restoration := transaction.Compensate(); !restoration.Restored {
		t.Fatal(restoration.Error)
	}
}

func TestRemovedIngressReleasesUntransferredSocket(t *testing.T) {
	a := newAdmissionFixture()
	socket := newAcceptorFixture()
	old := listenerFixture(a, socket, "prepared")
	if err := old.ArmIngress(); err != nil {
		t.Fatal(err)
	}
	if err := old.Activate(); err != nil {
		t.Fatal(err)
	}
	waitFixture(t, socket.accepted)
	transaction, err := ReserveListenerSet([]*Listener{old}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	socket.mu.Lock()
	closed := socket.closed
	socket.mu.Unlock()
	if !closed {
		t.Fatal("retired ingress retained an invisible address reservation")
	}
	publication, err := transaction.PreparePublication()
	if err != nil {
		t.Fatal(err)
	}
	publication.Publish()
	publication.Finish()
	if err := old.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
}
