package listener

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type queuedAcceptorFixture struct {
	*acceptorFixture
	conns chan net.Conn
	calls atomic.Int64
}

func newQueuedAcceptorFixture() *queuedAcceptorFixture {
	return &queuedAcceptorFixture{acceptorFixture: newAcceptorFixture(), conns: make(chan net.Conn, 1)}
}

func (s *queuedAcceptorFixture) Accept() (net.Conn, error) {
	s.calls.Add(1)
	s.accepted <- struct{}{}
	s.mu.Lock()
	wake, closed, deadline := s.wake, s.closed, s.deadline
	s.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	if deadline {
		return nil, timeoutFixture{}
	}
	select {
	case conn := <-s.conns:
		return conn, nil
	case <-wake:
		return nil, timeoutFixture{}
	}
}

func pairSpecsFixture(port uint16) (runtimeTCPBindSpec, runtimeTCPBindSpec) {
	return runtimeTCPBindSpec{network: "tcp4", address: netip.MustParseAddr("0.0.0.0"), port: port}, runtimeTCPBindSpec{network: "tcp6", address: netip.MustParseAddr("::"), port: port, v6only: true, exclusive: true, narrowExclusive: true}
}

func pairListenerFixture(a *admissionFixture, four, six net.Listener, port uint16, phase string) *Listener {
	l := listenerFixture(a, nil, phase)
	l.listenOptions.ListenPort = port
	spec4, spec6 := pairSpecsFixture(port)
	fixtureTCPExpected(l, spec4, spec6)
	if four != nil {
		fixtureAddTCP(l, four, spec4)
	}
	if six != nil {
		fixtureAddTCP(l, six, spec6)
	}
	return l
}

func fixtureHasMember(l *Listener, wanted *runtimeTCPMember) bool {
	return slices.Contains(l.runtimeTCPMembers(), wanted)
}

func TestTwoMemberPortSwapTransfersAndReversesPhysicalPointers(t *testing.T) {
	a := newAdmissionFixture()
	a4, a6, b4, b6 := newAcceptorFixture(), newAcceptorFixture(), newAcceptorFixture(), newAcceptorFixture()
	oldA := pairListenerFixture(a, a4, a6, 12345, "prepared")
	oldB := pairListenerFixture(a, b4, b6, 12346, "prepared")
	membersA, membersB := oldA.runtimeTCPMembers(), oldB.runtimeTCPMembers()
	for _, old := range []*Listener{oldA, oldB} {
		if err := old.ArmIngress(); err != nil {
			t.Fatal(err)
		}
		if err := old.Activate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, socket := range []*acceptorFixture{a4, a6, b4, b6} {
		waitFixture(t, socket.accepted)
	}
	nextB, nextA := pairListenerFixture(a, nil, nil, 12346, "inert"), pairListenerFixture(a, nil, nil, 12345, "inert")
	// The family order is also reversed; neither old-list nor member index is identity.
	for _, next := range []*Listener{nextB, nextA} {
		next.runtime.tcp.specs[0], next.runtime.tcp.specs[1] = next.runtime.tcp.specs[1], next.runtime.tcp.specs[0]
	}
	transaction, err := ReserveListenerSet([]*Listener{oldA, oldB}, []*Listener{nextB, nextA}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = transaction.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, member := range membersA {
		if !fixtureHasMember(nextA, member) {
			t.Fatal("A physical member/custody cell matched by array position")
		}
	}
	for _, member := range membersB {
		if !fixtureHasMember(nextB, member) {
			t.Fatal("B physical member/custody cell matched by array position")
		}
	}
	if result := transaction.Compensate(); !result.Restored || result.LocalReconnect || result.Error != nil {
		t.Fatalf("exact transfer rollback: %+v", result)
	}
	for _, member := range membersA {
		if !fixtureHasMember(oldA, member) {
			t.Fatal("A reverse transfer cloned or lost custody cell")
		}
	}
	for _, member := range membersB {
		if !fixtureHasMember(oldB, member) {
			t.Fatal("B reverse transfer cloned or lost custody cell")
		}
	}
	for _, old := range []*Listener{oldA, oldB} {
		if err := old.RuntimeCloseAndWait(); err != nil {
			t.Fatal(err)
		}
	}
}

// Handler return and its invocation-lease defers are separate events. Observe
// actual releases rather than assuming a channel sent by the handler joins them.
func waitSourceReferencesFixture(t *testing.T, source *admissionFixture, graph, resource int64) {
	t.Helper()
	watchdog := time.NewTimer(5 * time.Second)
	defer watchdog.Stop()
	for source.graphRefs.Load() != graph || source.resourceRefs.Load() != resource {
		select {
		case <-source.released:
		case <-watchdog.C:
			t.Fatal("source lease release barrier")
		}
	}
}

func TestTransferredMembersKeepOldCarriersAndAdmitWithCandidateSource(t *testing.T) {
	oldSource, nextSource := newAdmissionFixture(), newAdmissionFixture()
	nextSource.id.Sequence = 2
	four, six := newQueuedAcceptorFixture(), newQueuedAcceptorFixture()
	old := pairListenerFixture(oldSource, four, six, 12345, "prepared")
	oldHandler := retainedHandlerFixture{ready: make(chan net.Conn, 1), returned: make(chan struct{})}
	old.connHandler = oldHandler
	if err := old.ArmIngress(); err != nil {
		t.Fatal(err)
	}
	if four.calls.Load() != 0 || six.calls.Load() != 0 {
		t.Fatal("armed group called Accept before publication")
	}
	if err := old.Activate(); err != nil {
		t.Fatal(err)
	}
	waitFixture(t, four.accepted)
	waitFixture(t, six.accepted)
	if four.calls.Load() != 1 || six.calls.Load() != 1 {
		t.Fatal("group did not bound ingress to one blocked worker per physical member")
	}
	physicalOld := &connFixture{}
	six.conns <- physicalOld
	waitFixture(t, oldHandler.returned)
	carrierOld := <-oldHandler.ready
	waitSourceReferencesFixture(t, oldSource, 1, 1)
	waitFixture(t, six.accepted)
	next := pairListenerFixture(nextSource, nil, nil, 12345, "inert")
	nextHandler := retainedHandlerFixture{ready: make(chan net.Conn, 1), returned: make(chan struct{})}
	next.connHandler = nextHandler
	transaction, err := ReserveListenerSet([]*Listener{old}, []*Listener{next}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = transaction.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if oldSource.graphRefs.Load() != 1 || oldSource.resourceRefs.Load() != 1 || physicalOld.closed.Load() {
		t.Fatal("transfer moved or closed old accepted ownership")
	}
	publication, err := transaction.PreparePublication()
	if err != nil {
		t.Fatal(err)
	}
	publication.Publish()
	publication.Finish()
	waitFixture(t, four.accepted)
	waitFixture(t, six.accepted)
	physicalNext := &connFixture{}
	four.conns <- physicalNext
	waitFixture(t, nextHandler.returned)
	carrierNext := <-nextHandler.ready
	waitSourceReferencesFixture(t, nextSource, 1, 1)
	if nextSource.graphRefs.Load() != 1 || nextSource.resourceRefs.Load() != 1 || oldSource.resourceRefs.Load() != 1 {
		t.Fatal("fresh accept captured wrong source or migrated old carrier")
	}
	if err = transaction.Retirement().RetirePrevious(); err != nil {
		t.Fatal(err)
	}
	if err = old.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
	if physicalOld.closed.Load() || physicalNext.closed.Load() {
		t.Fatal("old retirement closed established carrier")
	}
	if err = next.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
	_ = carrierOld.Close()
	_ = carrierNext.Close()
	waitSourceReferencesFixture(t, oldSource, 0, 0)
	waitSourceReferencesFixture(t, nextSource, 0, 0)
	if oldSource.graphRefs.Load() != 0 || oldSource.resourceRefs.Load() != 0 || nextSource.graphRefs.Load() != 0 || nextSource.resourceRefs.Load() != 0 {
		t.Fatal("carrier terminal ownership did not release original sources")
	}
}

type deadlineFailureFixture struct {
	*closeResultFixture
	resetErr error
	pauseErr error
}

func (s *deadlineFailureFixture) SetDeadline(value time.Time) error {
	if value.IsZero() && s.resetErr != nil {
		return s.resetErr
	}
	if !value.IsZero() && s.pauseErr != nil {
		return s.pauseErr
	}
	return s.acceptorFixture.SetDeadline(value)
}

func TestHeldExclusiveDeadlineFailureNeverFallsBackToClose(t *testing.T) {
	base := newAcceptorFixture()
	socket := &deadlineFailureFixture{closeResultFixture: &closeResultFixture{acceptorFixture: base}, pauseErr: errors.New("held deadline rejected")}
	l := heldListenerFixture(newAdmissionFixture(), socket)
	if err := l.ArmIngress(); err != nil {
		t.Fatal(err)
	}
	if err := l.Activate(); err != nil {
		t.Fatal(err)
	}
	waitFixture(t, base.accepted)
	if err := l.PauseIngressForRebind(); err == nil {
		t.Fatal("held deadline failure was hidden")
	}
	if socket.calls.Load() != 0 || !fixtureOwnsTCP(l, socket) {
		t.Fatal("held6 deadline failure closed or dropped physical claim")
	}
	if err := l.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
}

func TestSiblingArmResetFailureStartsNoPartialWorker(t *testing.T) {
	four := newAcceptorFixture()
	baseSix := newAcceptorFixture()
	six := &deadlineFailureFixture{closeResultFixture: &closeResultFixture{acceptorFixture: baseSix}, resetErr: errors.New("second member reset rejected")}
	l := pairListenerFixture(newAdmissionFixture(), four, six, 12345, "prepared")
	members := l.runtimeTCPMembers()
	if err := l.ArmIngress(); err == nil {
		t.Fatal("sibling reset failure was hidden")
	}
	pendingFixture(t, four.accepted)
	pendingFixture(t, baseSix.accepted)
	if l.RuntimeStatus().Phase == "armed" {
		t.Fatal("partially reset group reported armed")
	}
	for _, member := range members {
		if !fixtureHasMember(l, member) {
			t.Fatal("Arm failure lost actual member custody")
		}
	}
	if err := l.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimePartialPreparationOwnsAllMembersBeforeFailure(t *testing.T) {
	for _, readbackFailure := range []bool{false, true} {
		name := "second-bind"
		if readbackFailure {
			name = "post-bind-readback"
		}
		t.Run(name, func(t *testing.T) {
			first := &closeResultFixture{acceptorFixture: newAcceptorFixture()}
			second := &closeResultFixture{acceptorFixture: newAcceptorFixture()}
			l := pairListenerFixture(newAdmissionFixture(), nil, nil, 12345, "inert")
			spec4, spec6 := pairSpecsFixture(12345)
			injected := errors.New("candidate native stage rejected")
			l.runtime.prepareSockets = func() error {
				fixtureAddTCP(l, first, spec4)
				if !fixtureOwnsTCP(l, first) {
					t.Fatal("first bind was invisible to compensation before sibling bind")
				}
				if readbackFailure {
					fixtureAddTCP(l, second, spec6)
					if !fixtureOwnsTCP(l, second) {
						t.Fatal("second bind invisible before readback")
					}
				}
				return injected
			}
			if err := l.Prepare(); err == nil {
				t.Fatal("partial preparation failure lost")
			}
			if first.calls.Load() != 1 {
				t.Fatal("partial first member was not closed exactly once")
			}
			wantSecond := int64(0)
			if readbackFailure {
				wantSecond = 1
			}
			if second.calls.Load() != wantSecond {
				t.Fatal("post-bind readback acquired member escaped joined cleanup")
			}
			if err := l.RuntimeCloseAndWait(); err != nil {
				t.Fatal(err)
			}
			if first.calls.Load() != 1 || second.calls.Load() != wantSecond {
				t.Fatal("repeated cleanup reclosed an acquired member")
			}
		})
	}
}

func TestExclusivePolicyMismatchRefusesBeforeOldEffects(t *testing.T) {
	for _, change := range []string{"routing-mark", "api-exclusive"} {
		t.Run(change, func(t *testing.T) {
			four, six := newAcceptorFixture(), newAcceptorFixture()
			old := pairListenerFixture(newAdmissionFixture(), four, six, 12345, "prepared")
			if err := old.ArmIngress(); err != nil {
				t.Fatal(err)
			}
			if err := old.Activate(); err != nil {
				t.Fatal(err)
			}
			waitFixture(t, four.accepted)
			waitFixture(t, six.accepted)
			next := pairListenerFixture(newAdmissionFixture(), nil, nil, 12345, "inert")
			if change == "routing-mark" {
				next.listenOptions.RoutingMark = 17
			} else {
				next.exclusive = true
			}
			bound := false
			next.runtime.prepareSockets = func() error { bound = true; return errors.New("must not bind") }
			_, err := ReserveListenerSet([]*Listener{old}, []*Listener{next}, true)
			if err == nil {
				t.Fatal("incompatible same-endpoint narrow exclusive policy admitted")
			}
			if _, ok := errors.AsType[*PhysicalHandoffError](err); !ok {
				t.Fatal("structural exclusive refusal lost typed physical handoff contract:", err)
			}
			var bindError *net.OpError
			if errors.As(err, &bindError) || bound {
				t.Fatal("structural refusal masqueraded as actual bind failure")
			}
			if old.RuntimeStatus().Phase != "active" || !old.runtime.gateway.open {
				t.Fatal("structural refusal mutated old admission")
			}
			for _, socket := range []*acceptorFixture{four, six} {
				socket.mu.Lock()
				closed, deadline := socket.closed, socket.deadline
				socket.mu.Unlock()
				if closed || deadline {
					t.Fatal("structural refusal paused or closed old member")
				}
			}
			if err := old.RuntimeCloseAndWait(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type rawAcceptGapFixture struct {
	*acceptorFixture
	entered       chan struct{}
	allow         chan struct{}
	interrupted   chan struct{}
	interruptOnce sync.Once
	physical      *connFixture
}

func (s *rawAcceptGapFixture) Accept() (net.Conn, error) {
	close(s.entered)
	<-s.allow
	return s.physical, nil
}

func (s *rawAcceptGapFixture) SetDeadline(value time.Time) error {
	if !value.IsZero() {
		s.interruptOnce.Do(func() { close(s.interrupted) })
	}
	return s.acceptorFixture.SetDeadline(value)
}

func TestGroupPauseJoinsEveryRawAcceptAdmissionGap(t *testing.T) {
	newGap := func() *rawAcceptGapFixture {
		return &rawAcceptGapFixture{acceptorFixture: newAcceptorFixture(), entered: make(chan struct{}), allow: make(chan struct{}), interrupted: make(chan struct{}), physical: &connFixture{}}
	}
	four, six := newGap(), newGap()
	source := newAdmissionFixture()
	l := pairListenerFixture(source, four, six, 12345, "prepared")
	if err := l.ArmIngress(); err != nil {
		t.Fatal(err)
	}
	pendingFixture(t, four.entered)
	pendingFixture(t, six.entered)
	if err := l.Activate(); err != nil {
		t.Fatal(err)
	}
	waitFixture(t, four.entered)
	waitFixture(t, six.entered)
	paused := make(chan error, 1)
	go func() { paused <- l.PauseIngress() }()
	waitFixture(t, four.interrupted)
	waitFixture(t, six.interrupted)
	select {
	case err := <-paused:
		t.Fatal("pause returned while raw accepts could still admit:", err)
	default:
	}
	close(four.allow)
	// The second gap alone must still hold the complete group join.
	select {
	case err := <-paused:
		t.Fatal("pause joined only first family:", err)
	default:
	}
	close(six.allow)
	select {
	case err := <-paused:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("group pause failed to join raw accept gaps")
	}
	if !four.physical.closed.Load() || !six.physical.closed.Load() || source.graphRefs.Load() != 0 || source.resourceRefs.Load() != 0 {
		t.Fatal("paused raw accepts escaped carrier/admission cleanup")
	}
	if err := l.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
}

func TestMissingOnlyRestoreKeepsHeldSixAndRebindsOnlyFour(t *testing.T) {
	four, six := newAcceptorFixture(), newAcceptorFixture()
	old := pairListenerFixture(newAdmissionFixture(), four, six, 12345, "prepared")
	originalSix := old.runtimeTCPMembers()[1]
	if err := old.ArmIngress(); err != nil {
		t.Fatal(err)
	}
	if err := old.Activate(); err != nil {
		t.Fatal(err)
	}
	waitFixture(t, four.accepted)
	waitFixture(t, six.accepted)
	next := listenerFixture(newAdmissionFixture(), nil, "inert")
	next.runtime.tcp.specs[0].address = netip.MustParseAddr("127.0.0.1")
	next.runtime.prepareSockets = func() error { return errors.New("candidate loopback bind rejected") }
	restoreCalls := 0
	old.runtime.prepareSockets = func() error {
		restoreCalls++
		if !fixtureHasMember(old, originalSix) || len(old.runtimeTCPMembers()) != 1 {
			t.Fatal("held6 not retained as sole member before missing-only restore")
		}
		spec4, _ := pairSpecsFixture(12345)
		fixtureAddTCP(old, newAcceptorFixture(), spec4)
		return nil
	}
	transaction, err := ReserveListenerSet([]*Listener{old}, []*Listener{next}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = transaction.Stage(context.Background()); err == nil {
		t.Fatal("candidate failure lost")
	}
	if result := transaction.Compensate(); !result.Restored || !result.LocalReconnect || result.Error != nil {
		t.Fatalf("missing-only restoration: %+v", result)
	}
	if restoreCalls != 1 || !fixtureHasMember(old, originalSix) || !fixtureOwnsTCP(old, six) || fixtureOwnsTCP(old, four) {
		t.Fatal("restore rebound held6 or reused closed ordinary4")
	}
	six.mu.Lock()
	closed := six.closed
	six.mu.Unlock()
	if closed {
		t.Fatal("missing-only restore closed original held6")
	}
	if err = old.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
}

type failedGapCloseFixture struct {
	*rawAcceptGapFixture
	closeEntered chan struct{}
}

func (s *failedGapCloseFixture) Close() error { close(s.closeEntered); return net.ErrClosed }

func TestFailedCloseStillJoinsStartedIngressWorker(t *testing.T) {
	gap := &rawAcceptGapFixture{acceptorFixture: newAcceptorFixture(), entered: make(chan struct{}), allow: make(chan struct{}), interrupted: make(chan struct{}), physical: &connFixture{}}
	socket := &failedGapCloseFixture{rawAcceptGapFixture: gap, closeEntered: make(chan struct{})}
	l := heldListenerFixture(newAdmissionFixture(), socket)
	if err := l.ArmIngress(); err != nil {
		t.Fatal(err)
	}
	if err := l.Activate(); err != nil {
		t.Fatal(err)
	}
	waitFixture(t, gap.entered)
	finished := make(chan error, 1)
	go func() { finished <- l.RuntimeCloseAndWait() }()
	waitFixture(t, socket.closeEntered)
	select {
	case err := <-finished:
		t.Fatal("close debt completed before started ingress joined:", err)
	default:
	}
	close(gap.allow)
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("failed close lost sticky debt")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("failed close did not finalize after ingress joined")
	}
	if !gap.physical.closed.Load() || !fixtureOwnsTCP(l, socket) {
		t.Fatal("failed close lost raw carrier or uncertain physical claim")
	}
}

func TestGroupedRuntimeDoesNotMirrorLegacyRawTransport(t *testing.T) {
	four, six := newAcceptorFixture(), newAcceptorFixture()
	l := pairListenerFixture(newAdmissionFixture(), four, six, 12345, "prepared")
	if l.tcpListener != nil || l.TCPListener() != nil {
		t.Fatal("runtime grouped custody escaped through legacy raw transport")
	}
	if socket, err := l.ListenTCP(); socket != nil || !errors.Is(err, ErrRuntimeRawTransport) {
		t.Fatal("runtime raw ListenTCP bypassed staged member inventory")
	}
	if len(l.runtimeTCPMembers()) != 2 {
		t.Fatal("raw accessor changed runtime custody")
	}
	if err := l.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
}

func TestPartialTransferCompensationReturnsSixBeforeNewFourCleanup(t *testing.T) {
	oldFourBase, oldSixBase := newAcceptorFixture(), newAcceptorFixture()
	oldFour := &closeResultFixture{acceptorFixture: oldFourBase}
	oldSix := &closeResultFixture{acceptorFixture: oldSixBase}
	old := pairListenerFixture(newAdmissionFixture(), oldFour, oldSix, 12345, "prepared")
	originalSix := old.runtimeTCPMembers()[1]
	if err := old.ArmIngress(); err != nil {
		t.Fatal(err)
	}
	if err := old.Activate(); err != nil {
		t.Fatal(err)
	}
	waitFixture(t, oldFourBase.accepted)
	waitFixture(t, oldSixBase.accepted)
	nextFour := &closeResultFixture{acceptorFixture: newAcceptorFixture()}
	next := pairListenerFixture(newAdmissionFixture(), nil, nil, 12345, "inert")
	next.runtime.tcp.specs[0].address = netip.MustParseAddr("127.0.0.1")
	next.runtime.prepareSockets = func() error {
		if !fixtureHasMember(next, originalSix) {
			t.Fatal("exact six did not move before acquiring missing four")
		}
		fixtureAddTCP(next, nextFour, next.runtime.tcp.specs[0])
		return nil
	}
	old.runtime.prepareSockets = func() error {
		if !fixtureHasMember(old, originalSix) || len(old.runtimeTCPMembers()) != 1 {
			t.Fatal("reverse transfer did not precede old missing-only bind")
		}
		four, _ := pairSpecsFixture(12345)
		fixtureAddTCP(old, newAcceptorFixture(), four)
		return nil
	}
	transaction, err := ReserveListenerSet([]*Listener{old}, []*Listener{next}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = transaction.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result := transaction.Compensate(); !result.Restored || !result.LocalReconnect || result.Error != nil {
		t.Fatalf("partial transfer compensation: %+v", result)
	}
	if oldFour.calls.Load() != 1 || nextFour.calls.Load() != 1 || oldSix.calls.Load() != 0 || !fixtureHasMember(old, originalSix) {
		t.Fatal("candidate cleanup closed returned six or omitted acquired four")
	}
	if err = old.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
	if oldSix.calls.Load() != 1 || nextFour.calls.Load() != 1 {
		t.Fatal("restored six custody or candidate close-once changed")
	}
}

func TestTCPMemberTransferSurvivesDeclaredUDPSplitAndMerge(t *testing.T) {
	for _, direction := range []string{"split", "merge"} {
		t.Run(direction, func(t *testing.T) {
			four, six := newAcceptorFixture(), newAcceptorFixture()
			old := pairListenerFixture(newAdmissionFixture(), four, six, 12345, "prepared")
			next := pairListenerFixture(newAdmissionFixture(), nil, nil, 12345, "inert")
			endpoint := packetTransportFixture()
			defer endpoint.Close()
			udpListener := old
			if direction == "merge" {
				udpListener = next
			}
			udpListener.network = append(udpListener.network, "udp")
			udpListener.packetHandler = endpoint
			// The existing binding fixture owns no physical UDP socket. Its declaration
			// must neither forbid exact TCP transfer nor invent interrupted associations.
			next.runtime.prepareSockets = func() error { return nil }
			members := old.runtimeTCPMembers()
			if err := old.ArmIngress(); err != nil {
				t.Fatal(err)
			}
			if err := old.Activate(); err != nil {
				t.Fatal(err)
			}
			waitFixture(t, four.accepted)
			waitFixture(t, six.accepted)
			transaction, err := ReserveListenerSet([]*Listener{old}, []*Listener{next}, false)
			if err != nil {
				t.Fatal("declared UDP blocked exact narrow6 transfer:", err)
			}
			impact := transaction.Impact()
			if impact.LocalReconnect || impact.UDPAssociationsInterrupted {
				t.Fatal("unbound UDP declaration invented physical interruption impact")
			}
			if err = transaction.Stage(context.Background()); err != nil {
				t.Fatal(err)
			}
			for _, member := range members {
				if !fixtureHasMember(next, member) {
					t.Fatal("UDP network shape prevented physical TCP member transfer")
				}
			}
			if result := transaction.Compensate(); !result.Restored || result.LocalReconnect || result.UDPAssociationsInterrupted || result.Error != nil {
				t.Fatalf("declared UDP transfer compensation: %+v", result)
			}
			for _, member := range members {
				if !fixtureHasMember(old, member) {
					t.Fatal("UDP split/merge reverse lost same TCP custody cell")
				}
			}
			if err = old.RuntimeCloseAndWait(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
