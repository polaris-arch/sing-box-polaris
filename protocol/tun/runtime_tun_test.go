package tun

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
)

func runtimeTunFixture(open func(*runtimeTunPhysical) error) *Inbound {
	owner := &Inbound{ctx: context.Background(), logger: log.NewNOPFactory().Logger()}
	owner.runtime = &runtimeTunState{owner: owner, closed: make(chan struct{}), openPhysical: open}
	return owner
}

func TestRuntimeTunStageDoesNotOpenPacketAdmission(t *testing.T) {
	owner := runtimeTunFixture(func(*runtimeTunPhysical) error { return nil })
	defer owner.RuntimeCloseAndWait()
	if err := owner.RuntimeStagePhysical(context.Background()); err != nil {
		t.Fatal(err)
	}
	owner.runtime.mu.Lock()
	physical := owner.runtime.physical
	owner.runtime.mu.Unlock()
	if physical.gate.Load() {
		t.Fatal("private stage opened packet admission")
	}
	publication, err := PrepareRuntimeTunPublication([]*Inbound{owner})
	if err != nil {
		t.Fatal(err)
	}
	publication.Publish()
	if !physical.gate.Load() {
		t.Fatal("publication failed to open prepared gate")
	}
	if err := owner.RuntimeSuspendPhysical(context.Background()); err != nil {
		t.Fatal(err)
	}
	if physical.gate.Load() {
		t.Fatal("suspended device still admits")
	}
}

func TestRuntimeTunCanceledWaitRetainsRunningConstruction(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	owner := runtimeTunFixture(func(*runtimeTunPhysical) error { close(entered); <-release; return nil })
	t.Cleanup(func() { finish(); _ = owner.RuntimeCloseAndWait() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- owner.RuntimeStagePhysical(ctx) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("constructor entry watchdog")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancel observation watchdog")
	}
	owner.runtime.mu.Lock()
	physical := owner.runtime.physical
	operation := owner.runtime.operation
	owner.runtime.mu.Unlock()
	select {
	case <-physical.done:
		t.Fatal("observer cancellation destroyed in-flight construction")
	default:
	}
	if _, err := PrepareRuntimeTunPublication([]*Inbound{owner}); err == nil {
		t.Fatal("published incomplete constructor")
	}
	if err := owner.RuntimeSuspendPhysical(context.Background()); err == nil {
		t.Fatal("overlapping physical operation admitted")
	}
	finish()
	select {
	case <-operation.done:
	case <-time.After(5 * time.Second):
		t.Fatal("constructor terminal watchdog")
	}
}

func TestRuntimeTunFailedCandidateRestoresOldDeviceWithoutRestoringSessions(t *testing.T) {
	old := runtimeTunFixture(func(*runtimeTunPhysical) error { return nil })
	next := runtimeTunFixture(func(*runtimeTunPhysical) error { return errors.New("bind failure") })
	defer old.RuntimeCloseAndWait()
	defer next.RuntimeCloseAndWait()
	if err := old.RuntimeStagePhysical(context.Background()); err != nil {
		t.Fatal(err)
	}
	initial, err := PrepareRuntimeTunPublication([]*Inbound{old})
	if err != nil {
		t.Fatal(err)
	}
	initial.Publish()
	transaction := NewRuntimeSetTransaction([]*Inbound{old}, []*Inbound{next})
	if err := transaction.Stage(context.Background()); err == nil {
		t.Fatal("expected candidate bind failure")
	}
	if err := transaction.Compensate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !transaction.AffectedSessionsReset() {
		t.Fatal("lost session interruption evidence")
	}
	old.runtime.mu.Lock()
	physical := old.runtime.physical
	old.runtime.mu.Unlock()
	if !physical.gate.Load() {
		t.Fatal("restored old physical endpoint remains closed")
	}
}

func TestRuntimeTunConstructorPanicCannotCertifyCleanup(t *testing.T) {
	owner := runtimeTunFixture(func(*runtimeTunPhysical) error { panic("constructor") })
	if err := owner.RuntimeStagePhysical(context.Background()); err == nil {
		t.Fatal("panic was not retained")
	}
	if err := owner.RuntimeCloseAndWait(); err == nil {
		t.Fatal("panic uncertainty was erased by empty cleanup")
	}
}
