package tun

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	nativeTun "github.com/sagernet/sing-tun"
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

func TestRuntimeTunFailedStageCannotPreparePublication(t *testing.T) {
	old := runtimeTunFixture(func(*runtimeTunPhysical) error { return nil })
	next := runtimeTunFixture(func(*runtimeTunPhysical) error { return errors.New("candidate stage failed") })
	defer old.RuntimeCloseAndWait()
	defer next.RuntimeCloseAndWait()
	if err := old.RuntimeStagePhysical(context.Background()); err != nil {
		t.Fatal(err)
	}
	transaction := NewRuntimeSetTransaction([]*Inbound{old}, []*Inbound{next})
	if err := transaction.Stage(context.Background()); err == nil {
		t.Fatal("failure fixture not reached")
	}
	if _, err := transaction.PreparePublication(); err == nil {
		t.Fatal("failed stage created a publication participant")
	}
	if err := transaction.Compensate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !transaction.AffectedSessionsReset() {
		t.Fatal("resource restoration erased actual session reset")
	}
}

func TestRuntimeTunDuplicateInventoryCannotSuspendOldOwner(t *testing.T) {
	opens := 0
	old := runtimeTunFixture(func(*runtimeTunPhysical) error { opens++; return nil })
	defer old.RuntimeCloseAndWait()
	if err := old.RuntimeStagePhysical(context.Background()); err != nil {
		t.Fatal(err)
	}
	publication, err := PrepareRuntimeTunPublication([]*Inbound{old})
	if err != nil {
		t.Fatal(err)
	}
	publication.Publish()
	physical := old.runtime.physical
	transaction := NewRuntimeSetTransaction([]*Inbound{old}, []*Inbound{old})
	if err := transaction.Stage(context.Background()); err == nil {
		t.Fatal("same owner admitted as previous and next")
	}
	if err := transaction.Compensate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if opens != 1 || !physical.gate.Load() || transaction.AffectedSessionsReset() {
		t.Fatal("invalid inventory touched old resource")
	}
}

type runtimeTunNativeProviderFixture struct{ adapter.PlatformInterface }

func (runtimeTunNativeProviderFixture) UsePlatformInterface() bool { return true }

func TestRuntimeTunNativeFDProviderCannotBeInferredFromCoreDuplicate(t *testing.T) {
	old := runtimeTunFixture(func(*runtimeTunPhysical) error { return nil })
	next := runtimeTunFixture(func(*runtimeTunPhysical) error { t.Error("native candidate opened"); return nil })
	defer old.RuntimeCloseAndWait()
	defer next.RuntimeCloseAndWait()
	old.platformInterface = runtimeTunNativeProviderFixture{}
	next.platformInterface = runtimeTunNativeProviderFixture{}
	transaction := NewRuntimeSetTransaction([]*Inbound{old}, []*Inbound{next})
	if err := transaction.Stage(context.Background()); err == nil || transaction.AffectedSessionsReset() {
		t.Fatal("native provider boundary was treated as Core-owned migration", err)
	}
}

func TestRuntimeTunCancellationAfterFinalPhysicalStageIsNotPublishable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	next := runtimeTunFixture(func(*runtimeTunPhysical) error { cancel(); return nil })
	defer next.RuntimeCloseAndWait()
	transaction := NewRuntimeSetTransaction(nil, []*Inbound{next})
	if err := transaction.Stage(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("late cancellation not observed", err)
	}
	if _, err := transaction.PreparePublication(); err == nil {
		t.Fatal("canceled stage published")
	}
	if err := transaction.Compensate(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// This fixture has separate native original and Core duplicate custody. It
// exercises the production RuntimeSet path without opening a host interface.
type runtimeNativeBridgeFixture struct {
	adapter.PlatformInterface
	sessions  []*runtimeNativeSessionFixture
	nextFD    int
	failOpen  bool
	failAbort bool
	events    []string
}

func (*runtimeNativeBridgeFixture) UsePlatformInterface() bool { return true }
func (*runtimeNativeBridgeFixture) RuntimeTunVersion() int     { return 1 }
func (b *runtimeNativeBridgeFixture) NewRuntimeTunSession(_ *nativeTun.Options, _ option.TunPlatformOptions, previous adapter.RuntimeTunSession, receipt *adapter.RuntimeTunReceipt) (adapter.RuntimeTunSession, error) {
	var old *runtimeNativeSessionFixture
	if previous != nil {
		old = previous.(*runtimeNativeSessionFixture)
	}
	session := &runtimeNativeSessionFixture{bridge: b, previous: old, receipt: receipt, failOpen: b.failOpen, failAbort: b.failAbort}
	b.sessions = append(b.sessions, session)
	return session, nil
}

type runtimeNativeSessionFixture struct {
	bridge                     *runtimeNativeBridgeFixture
	previous                   *runtimeNativeSessionFixture
	receipt                    *adapter.RuntimeTunReceipt
	fd                         int
	lastOpenedFD               int
	duplicates                 int
	failOpen, failAbort        bool
	prepared, aborted, retired bool
}

func (s *runtimeNativeSessionFixture) OwnerID() string { return s.receipt.OwnerID() }
func (s *runtimeNativeSessionFixture) Prepare() error {
	if s.previous != nil && (s.previous.duplicates != 0 || s.previous.receipt.Published()) {
		return errors.New("old Core reader has not joined")
	}
	s.bridge.events = append(s.bridge.events, "prepare")
	s.bridge.nextFD++
	s.fd = s.bridge.nextFD
	s.prepared = true
	return nil
}
func (s *runtimeNativeSessionFixture) Validate() error {
	if !s.prepared || s.aborted || s.retired {
		return errors.New("session not current")
	}
	return nil
}
func (s *runtimeNativeSessionFixture) OpenInterface(*nativeTun.Options) (nativeTun.Tun, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if s.failOpen {
		return nil, errors.New("Core duplicate/stack failure after native prepare")
	}
	s.lastOpenedFD = s.fd
	s.duplicates++
	s.bridge.events = append(s.bridge.events, "duplicate")
	return &runtimeNativeDeviceFixture{session: s}, nil
}
func (s *runtimeNativeSessionFixture) Abort() error {
	if s.duplicates != 0 {
		return errors.New("candidate Core readers not joined")
	}
	s.bridge.events = append(s.bridge.events, "abort")
	if s.failAbort {
		return errors.New("NE timeout remains quarantined")
	}
	s.aborted = true
	if s.previous != nil {
		s.bridge.nextFD++
		s.previous.fd = s.bridge.nextFD
	}
	return nil
}
func (s *runtimeNativeSessionFixture) Retire() error {
	if s.duplicates != 0 {
		return errors.New("retired before Core join")
	}
	s.bridge.events = append(s.bridge.events, "retire")
	s.retired = true
	return nil
}

type runtimeNativeDeviceFixture struct {
	session *runtimeNativeSessionFixture
	closed  bool
}

func (*runtimeNativeDeviceFixture) Read([]byte) (int, error)                   { return 0, errors.New("fixture") }
func (*runtimeNativeDeviceFixture) Write(p []byte) (int, error)                { return len(p), nil }
func (*runtimeNativeDeviceFixture) Name() (string, error)                      { return "native-fixture", nil }
func (*runtimeNativeDeviceFixture) Start() error                               { return nil }
func (*runtimeNativeDeviceFixture) UpdateRouteOptions(nativeTun.Options) error { return nil }
func (d *runtimeNativeDeviceFixture) Close() error {
	if !d.closed {
		d.closed = true
		d.session.duplicates--
		d.session.bridge.events = append(d.session.bridge.events, "close-duplicate")
	}
	return nil
}
func runtimeNativeOwnerFixture(bridge *runtimeNativeBridgeFixture) *Inbound {
	var owner *Inbound
	owner = runtimeTunFixture(func(physical *runtimeTunPhysical) error {
		device, err := owner.openRuntimeNativeInterface(&nativeTun.Options{MTU: 1500}, option.TunPlatformOptions{})
		if err != nil {
			return err
		}
		physical.scope.Add(device.Close)
		return nil
	})
	owner.platformInterface = bridge
	owner.tag = "tun-in"
	return owner
}
func publishRuntimeNativeFixture(t *testing.T, owner *Inbound) {
	t.Helper()
	if err := owner.RuntimeStagePhysical(context.Background()); err != nil {
		t.Fatal(err)
	}
	publication, err := PrepareRuntimeTunPublication([]*Inbound{owner})
	if err != nil {
		t.Fatal(err)
	}
	publication.Publish()
}
func TestRuntimeNativeFailedCandidateReopensRestoredActualDescriptor(t *testing.T) {
	bridge := &runtimeNativeBridgeFixture{}
	old := runtimeNativeOwnerFixture(bridge)
	defer old.RuntimeCloseAndWait()
	publishRuntimeNativeFixture(t, old)
	original := bridge.sessions[0]
	oldFD := original.fd
	bridge.failOpen = true
	next := runtimeNativeOwnerFixture(bridge)
	defer next.RuntimeCloseAndWait()
	transaction := NewRuntimeSetTransaction([]*Inbound{old}, []*Inbound{next})
	if err := transaction.Stage(context.Background()); err == nil {
		t.Fatal("candidate failure not injected")
	}
	if err := transaction.Compensate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(bridge.sessions) != 2 || original.fd == oldFD || original.lastOpenedFD != original.fd || !original.receipt.Published() || original.duplicates != 1 || !bridge.sessions[1].aborted {
		t.Fatal("restoration did not rebuild from the updated original session")
	}
	if !transaction.AffectedSessionsReset() || !old.runtime.physical.gate.Load() {
		t.Fatal("restoration lost reset/publication facts")
	}
	if err := next.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
	if original.retired {
		t.Fatal("candidate cleanup retired the restored old native owner")
	}
}
func TestRuntimeNativePublicationAndRetirementKeepSeparateOriginalCustody(t *testing.T) {
	bridge := &runtimeNativeBridgeFixture{}
	old := runtimeNativeOwnerFixture(bridge)
	defer old.RuntimeCloseAndWait()
	publishRuntimeNativeFixture(t, old)
	next := runtimeNativeOwnerFixture(bridge)
	defer next.RuntimeCloseAndWait()
	transaction := NewRuntimeSetTransaction([]*Inbound{old}, []*Inbound{next})
	if err := transaction.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	candidate := bridge.sessions[1]
	if candidate.receipt.Published() || bridge.sessions[0].receipt.Published() || bridge.sessions[0].retired {
		t.Fatal("private stage published or retired native custody")
	}
	publication, err := transaction.PreparePublication()
	if err != nil {
		t.Fatal(err)
	}
	publication.Publish()
	if !candidate.receipt.Published() {
		t.Fatal("Core publication receipt not set")
	}
	if err := old.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
	if !bridge.sessions[0].retired || candidate.retired || candidate.duplicates != 1 {
		t.Fatal("old retirement touched new original")
	}
	if err := next.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
	if !candidate.retired || candidate.duplicates != 0 {
		t.Fatal("Stop failed to join and retire exact published owner")
	}
}
func TestRuntimeNativeUnknownAbortCannotReopenOldOrPublishCandidate(t *testing.T) {
	bridge := &runtimeNativeBridgeFixture{}
	old := runtimeNativeOwnerFixture(bridge)
	defer old.RuntimeCloseAndWait()
	publishRuntimeNativeFixture(t, old)
	bridge.failOpen = true
	bridge.failAbort = true
	next := runtimeNativeOwnerFixture(bridge)
	defer next.RuntimeCloseAndWait()
	transaction := NewRuntimeSetTransaction([]*Inbound{old}, []*Inbound{next})
	if err := transaction.Stage(context.Background()); err == nil {
		t.Fatal("failure not injected")
	}
	if err := transaction.Compensate(context.Background()); err == nil {
		t.Fatal("unknown abort treated as restored")
	}
	if bridge.sessions[0].duplicates != 0 || old.runtime.physical.gate.Load() {
		t.Fatal("old device reopened while native owner unknown")
	}
	if _, err := transaction.PreparePublication(); err == nil {
		t.Fatal("unknown candidate published")
	}
	if err := next.RuntimeCloseAndWait(); err == nil {
		t.Fatal("cleanup erased native uncertainty")
	}
}
