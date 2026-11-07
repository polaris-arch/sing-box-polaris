package listener

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
)

// The underlying callback deliberately offers a later nil result. Close custody
// must remember the first result instead of retrying until the debt disappears.
type closeResultFixture struct {
	*acceptorFixture
	calls      atomic.Int64
	failure    error
	panicClose bool
}

func (s *closeResultFixture) Close() error {
	if s.calls.Add(1) != 1 {
		return nil
	}
	if s.panicClose {
		panic("injected member close panic")
	}
	if s.failure != nil {
		return s.failure
	}
	return s.acceptorFixture.Close()
}

func heldListenerFixture(a *admissionFixture, socket net.Listener) *Listener {
	l := listenerFixture(a, nil, "prepared")
	spec := runtimeTCPBindSpec{network: "tcp6", address: netip.MustParseAddr("::"), port: 12345, v6only: true, exclusive: true, narrowExclusive: true}
	fixtureTCPExpected(l, spec)
	fixtureAddTCP(l, socket, spec)
	return l
}

func stageHeldRemovalFixture(t *testing.T, old *Listener, socket *acceptorFixture) *ListenerSetTransaction {
	t.Helper()
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
	reservedTicket := transaction.Retirement()
	if reservedTicket == nil {
		t.Fatal("Reserve did not preallocate retirement ticket")
	}
	if err := reservedTicket.RetirePrevious(); !errors.Is(err, ErrRuntimeTransition) {
		t.Fatal("unstaged ticket consumed or retired old ingress:", err)
	}
	if err := transaction.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if transaction.Retirement() != reservedTicket {
		t.Fatal("Stage replaced the preallocated ticket")
	}
	socket.mu.Lock()
	closed := socket.closed
	socket.mu.Unlock()
	if closed {
		t.Fatal("Stage closed held exclusive ingress before publication")
	}
	return transaction
}

func TestHeldRetirementPreallocatedPublicationPureAndExplicitClose(t *testing.T) {
	a := newAdmissionFixture()
	socket := newAcceptorFixture()
	socket.closeEntered, socket.closeAllow = make(chan struct{}), make(chan struct{})
	old := heldListenerFixture(a, socket)
	transaction := stageHeldRemovalFixture(t, old, socket)
	ticket := transaction.Retirement()
	if ticket == nil || transaction.Retirement() != ticket {
		t.Fatal("retirement ticket was not preallocated and stable")
	}
	if err := ticket.RetirePrevious(); !errors.Is(err, ErrRuntimeTransition) {
		t.Fatal("premature retirement did not reject without consuming once:", err)
	}
	publication, err := transaction.PreparePublication()
	if err != nil {
		t.Fatal(err)
	}
	published := make(chan struct{})
	var beforeFinish error
	go func() {
		publication.Publish()
		beforeFinish = ticket.RetirePrevious()
		publication.Finish()
		close(published)
	}()
	waitFixture(t, published)
	if !errors.Is(beforeFinish, ErrRuntimeTransition) {
		t.Fatal("published ticket retired while Finish fences still held:", beforeFinish)
	}
	pendingFixture(t, socket.closeEntered)
	if transaction.Retirement() != ticket {
		t.Fatal("Finish lost the preallocated ticket")
	}
	retired := make(chan error, 1)
	go func() { retired <- ticket.RetirePrevious() }()
	waitFixture(t, socket.closeEntered)
	// Close is blocked: acquiring all listener-side fences proves H owns none.
	unlocked := make(chan struct{})
	go func() {
		transaction.mu.Lock()
		transaction.mu.Unlock() //nolint:staticcheck // Deliberate lock-acquisition witness while the actual close is blocked.
		old.runtime.mu.Lock()
		old.runtime.mu.Unlock() //nolint:staticcheck // Deliberate lock-acquisition witness while the actual close is blocked.
		old.runtime.gateway.mu.Lock()
		old.runtime.gateway.mu.Unlock() //nolint:staticcheck // Deliberate lock-acquisition witness while the actual close is blocked.
		close(unlocked)
	}()
	waitFixture(t, unlocked)
	select {
	case err := <-retired:
		t.Fatal("retirement returned before actual close:", err)
	default:
	}
	close(socket.closeAllow)
	select {
	case err := <-retired:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("retirement close did not join")
	}
	if err := ticket.RetirePrevious(); err != nil {
		t.Fatal(err)
	}
}

func TestUnpublishedCompensatedTicketNeverClosesHeldMember(t *testing.T) {
	socket := newAcceptorFixture()
	old := heldListenerFixture(newAdmissionFixture(), socket)
	transaction := stageHeldRemovalFixture(t, old, socket)
	ticket := transaction.Retirement()
	publication, err := transaction.PreparePublication()
	if err != nil {
		t.Fatal(err)
	}
	publication.Finish()
	if restoration := transaction.Compensate(); !restoration.Restored || restoration.LocalReconnect || restoration.Error != nil {
		t.Fatalf("held abort lost original descriptor: %+v", restoration)
	}
	if err := ticket.RetirePrevious(); !errors.Is(err, ErrRuntimeTransition) {
		t.Fatal("compensated ticket was executable:", err)
	}
	if !fixtureOwnsTCP(old, socket) {
		t.Fatal("abort did not restore same held descriptor")
	}
	socket.mu.Lock()
	closed := socket.closed
	socket.mu.Unlock()
	if closed {
		t.Fatal("compensated ticket closed original held descriptor")
	}
	if err := old.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentRetirementAndRuntimeCloseShareFirstResult(t *testing.T) {
	base := newAcceptorFixture()
	socket := &closeResultFixture{acceptorFixture: base, failure: net.ErrClosed}
	old := heldListenerFixture(newAdmissionFixture(), socket)
	transaction := stageHeldRemovalFixture(t, old, base)
	publication, err := transaction.PreparePublication()
	if err != nil {
		t.Fatal(err)
	}
	publication.Publish()
	publication.Finish()
	results := make(chan error, 4)
	start := make(chan struct{})
	for range 3 {
		go func() { <-start; results <- transaction.Retirement().RetirePrevious() }()
	}
	go func() { <-start; results <- old.RuntimeCloseAndWait() }()
	close(start)
	var first error
	for range 4 {
		select {
		case err := <-results:
			if err == nil {
				t.Fatal("unknown close result washed to nil")
			}
			if first == nil {
				first = err
			} else if err.Error() != first.Error() {
				t.Fatal("concurrent close callers lost the first result")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent closeDone waiter hung")
		}
	}
	if socket.calls.Load() != 1 || !fixtureOwnsTCP(old, socket) {
		t.Fatal("unknown member retried or lost its retained claim")
	}
	if err := old.RuntimeCloseAndWait(); err == nil || err.Error() != first.Error() {
		t.Fatal("later scope close lost sticky debt:", err)
	}
}

func TestGroupedCloseFailureAndPanicPreserveOwnerDebt(t *testing.T) {
	for _, panicClose := range []bool{false, true} {
		name := "error"
		if panicClose {
			name = "panic"
		}
		t.Run(name, func(t *testing.T) {
			good := &closeResultFixture{acceptorFixture: newAcceptorFixture()}
			bad := &closeResultFixture{acceptorFixture: newAcceptorFixture(), failure: net.ErrClosed, panicClose: panicClose}
			l := listenerFixture(newAdmissionFixture(), nil, "prepared")
			fixtureAddTCP(l, bad, runtimeTCPBindSpec{network: "tcp6", address: netip.MustParseAddr("::"), port: 12345, v6only: true, exclusive: true, narrowExclusive: true})
			fixtureAddTCP(l, good, runtimeTCPBindSpec{network: "tcp4", address: netip.MustParseAddr("0.0.0.0"), port: 12345})
			fixtureTCPExpected(l, l.runtime.tcp.members[0].spec, l.runtime.tcp.members[1].spec)
			result := make(chan error, 1)
			go func() { result <- l.RuntimeCloseAndWait() }()
			var first error
			select {
			case first = <-result:
			case <-time.After(5 * time.Second):
				t.Fatal("member panic abandoned closeDone")
			}
			if first == nil {
				t.Fatal("partial unknown member reported successful retirement")
			}
			if good.calls.Load() != 1 || bad.calls.Load() != 1 || !fixtureOwnsTCP(l, bad) {
				t.Fatal("partial close skipped sibling or dropped uncertain claim")
			}
			if later := l.RuntimeCloseAndWait(); later != first {
				t.Fatal("later close changed the cached first result")
			}
			scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
			scope.Add(l.RuntimeCloseAndWait)
			dependency, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "listeners", Sequence: 2}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			lease, err := dependency.Acquire()
			if err != nil {
				t.Fatal(err)
			}
			owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "listeners", Sequence: 3}, []adapter.RuntimeResourceLease{lease}, scope.Close)
			if err != nil {
				t.Fatal(err)
			}
			lease.Release()
			dependency.Seal()
			owner.Seal()
			waitFixture(t, owner.Closed())
			if err := owner.WaitClosed(context.Background()); err == nil {
				t.Fatal("Scope filtered concrete listener debt and owner falsely drained")
			}
			pendingFixture(t, dependency.Closed())
			if !fixtureOwnsTCP(l, bad) || good.calls.Load() != 1 || bad.calls.Load() != 1 {
				t.Fatal("scope cleanup retried or erased retained physical claim")
			}
		})
	}
}

func TestTicketContinuesIndependentOldListenersAfterMemberPanic(t *testing.T) {
	badBase, goodBase := newAcceptorFixture(), newAcceptorFixture()
	bad := &closeResultFixture{acceptorFixture: badBase, panicClose: true}
	good := &closeResultFixture{acceptorFixture: goodBase}
	oldBad, oldGood := heldListenerFixture(newAdmissionFixture(), bad), heldListenerFixture(newAdmissionFixture(), good)
	oldGood.listenOptions.ListenPort = 12346
	oldGood.runtime.tcp.members[0].spec.port = 12346
	oldGood.runtime.tcp.specs[0].port = 12346
	for _, old := range []*Listener{oldBad, oldGood} {
		if err := old.ArmIngress(); err != nil {
			t.Fatal(err)
		}
		if err := old.Activate(); err != nil {
			t.Fatal(err)
		}
	}
	waitFixture(t, badBase.accepted)
	waitFixture(t, goodBase.accepted)
	transaction, err := ReserveListenerSet([]*Listener{oldBad, oldGood}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = transaction.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	publication, err := transaction.PreparePublication()
	if err != nil {
		t.Fatal(err)
	}
	publication.Publish()
	publication.Finish()
	result := make(chan error, 1)
	go func() { result <- transaction.Retirement().RetirePrevious() }()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("member panic lost physical retirement debt")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("member panic abandoned ticket completion")
	}
	if bad.calls.Load() != 1 || good.calls.Load() != 1 || !fixtureOwnsTCP(oldBad, bad) {
		t.Fatal("ticket panic skipped independent old listener or erased bad claim")
	}
	if err = transaction.Retirement().RetirePrevious(); err == nil {
		t.Fatal("duplicate ticket erased panic debt")
	}
	if bad.calls.Load() != 1 || good.calls.Load() != 1 {
		t.Fatal("duplicate ticket reclosed logical old listeners")
	}
}

func TestListenerSetCommitRetiresHeldIngress(t *testing.T) {
	base := newAcceptorFixture()
	socket := &closeResultFixture{acceptorFixture: base}
	old := heldListenerFixture(newAdmissionFixture(), socket)
	transaction := stageHeldRemovalFixture(t, old, base)
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	if socket.calls.Load() != 1 {
		t.Fatal("ordinary set Commit left held ingress unretired")
	}
	if err := transaction.Retirement().RetirePrevious(); err != nil {
		t.Fatal(err)
	}
	if socket.calls.Load() != 1 {
		t.Fatal("Commit and ticket duplicated old close")
	}
}

func TestStandaloneReplacementCommitRetiresHeldIngress(t *testing.T) {
	base := newAcceptorFixture()
	socket := &closeResultFixture{acceptorFixture: base}
	old := heldListenerFixture(newAdmissionFixture(), socket)
	if err := old.ArmIngress(); err != nil {
		t.Fatal(err)
	}
	if err := old.Activate(); err != nil {
		t.Fatal(err)
	}
	waitFixture(t, base.accepted)
	nextSocket := newAcceptorFixture()
	next := listenerFixture(newAdmissionFixture(), nextSocket, "prepared")
	next.listenOptions.ListenPort = 12346
	next.runtime.tcp.members[0].spec.port = 12346
	next.runtime.tcp.specs[0].port = 12346
	replacement, err := ReserveReplacement(old, next, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = replacement.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if socket.calls.Load() != 0 {
		t.Fatal("standalone Stage destroyed held old ingress")
	}
	if err = replacement.Commit(); err != nil {
		t.Fatal(err)
	}
	if socket.calls.Load() != 1 {
		t.Fatal("standalone Commit omitted explicit held retirement")
	}
	if err = next.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
}

func TestNilRetirementTicketIsNoop(t *testing.T) {
	var ticket *ListenerRetirement
	if err := ticket.RetirePrevious(); err != nil {
		t.Fatal(err)
	}
}

func TestStandaloneIndependentOrdinaryTCPPreservesNoReconnectUntilCommit(t *testing.T) {
	oldBase, nextBase := newAcceptorFixture(), newAcceptorFixture()
	oldSocket := &closeResultFixture{acceptorFixture: oldBase}
	old := listenerFixture(newAdmissionFixture(), nil, "prepared")
	fixtureAddTCP(old, oldSocket, old.runtime.tcp.specs[0])
	next := listenerFixture(newAdmissionFixture(), nextBase, "prepared")
	next.listenOptions.ListenPort = 12346
	next.runtime.tcp.members[0].spec.port = 12346
	next.runtime.tcp.specs[0].port = 12346
	if err := old.ArmIngress(); err != nil {
		t.Fatal(err)
	}
	if err := old.Activate(); err != nil {
		t.Fatal(err)
	}
	waitFixture(t, oldBase.accepted)
	replacement, err := ReserveReplacement(old, next, false)
	if err != nil {
		t.Fatal(err)
	}
	if impact := replacement.Impact(); impact.Mode != ReplacementIndependent || impact.LocalReconnect || impact.UDPAssociationsInterrupted {
		t.Fatalf("standalone independent TCP impact changed: %+v", impact)
	}
	if err = replacement.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if oldSocket.calls.Load() != 0 || !fixtureOwnsTCP(old, oldSocket) {
		t.Fatal("independent standalone Stage destroyed old TCP rollback custody")
	}
	if err = replacement.Commit(); err != nil {
		t.Fatal(err)
	}
	if oldSocket.calls.Load() != 1 {
		t.Fatal("independent standalone Commit did not retire old listening ingress")
	}
	if err = next.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
}

func TestCommitGateFailureLeavesHeldOldCompensatable(t *testing.T) {
	for _, standalone := range []bool{false, true} {
		name := "set"
		if standalone {
			name = "standalone"
		}
		t.Run(name, func(t *testing.T) {
			oldBase, nextBase := newAcceptorFixture(), newAcceptorFixture()
			oldSocket := &closeResultFixture{acceptorFixture: oldBase}
			old := heldListenerFixture(newAdmissionFixture(), oldSocket)
			next := listenerFixture(newAdmissionFixture(), nextBase, "prepared")
			next.listenOptions.ListenPort = 12346
			next.runtime.tcp.members[0].spec.port = 12346
			next.runtime.tcp.specs[0].port = 12346
			if err := old.ArmIngress(); err != nil {
				t.Fatal(err)
			}
			if err := old.Activate(); err != nil {
				t.Fatal(err)
			}
			waitFixture(t, oldBase.accepted)
			var stage func(context.Context) error
			var commit func() error
			var compensate func() Restoration
			if standalone {
				replacement, err := ReserveReplacement(old, next, false)
				if err != nil {
					t.Fatal(err)
				}
				stage, commit, compensate = replacement.Stage, replacement.Commit, replacement.Compensate
			} else {
				transaction, err := ReserveListenerSet([]*Listener{old}, []*Listener{next}, false)
				if err != nil {
					t.Fatal(err)
				}
				stage, commit, compensate = transaction.Stage, transaction.Commit, transaction.Compensate
			}
			if err := stage(context.Background()); err != nil {
				t.Fatal(err)
			}
			next.runtime.gateway.mu.Lock()
			next.runtime.gateway.sealed = true
			next.runtime.gateway.mu.Unlock()
			if err := commit(); err == nil {
				t.Fatal("invalid prepublication candidate gate was committed")
			}
			if oldSocket.calls.Load() != 0 || !fixtureOwnsTCP(old, oldSocket) {
				t.Fatal("failed Commit retired original held ingress")
			}
			if result := compensate(); !result.Restored || result.LocalReconnect || result.Error != nil {
				t.Fatalf("prepublication Commit failure became irreversible: %+v", result)
			}
			if old.RuntimeStatus().Phase != "active" || !fixtureOwnsTCP(old, oldSocket) || oldSocket.calls.Load() != 0 {
				t.Fatal("Commit rejection did not restore original ingress")
			}
			if err := old.RuntimeCloseAndWait(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
