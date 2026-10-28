package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

type runtimeNoAcquisitionFixture struct{}

func (runtimeNoAcquisitionFixture) Error() string                       { return "unused original reservation" }
func (runtimeNoAcquisitionFixture) RuntimeTailscaleNoAcquisition() bool { return true }
func terminalRuntimeChild(entered bool, construction, closeErr error) *runtimeTailscaleChild {
	done := make(chan struct{})
	close(done)
	run := &tailscaleRetirementRun{expected: []string{"original"}, closeFinished: done, binding: adapter.TailscaleStoreRunBinding{RunNonce: "original", ConfigDigest: "captured"}}
	return &runtimeTailscaleChild{ctx: context.Background(), run: run, entered: entered, request: adapter.RuntimeTailscaleChildRequest{ConstructionDone: done, CloseDone: done, ConstructionResult: func() error { return construction }, CloseResult: func() error { return closeErr }, StoreScopes: func() []adapter.TailscaleStoreNode { return nil }, DirectoryScopes: func() []adapter.TailscaleDirectoryNode { return nil }}}
}

func TestRuntimeUnusedOriginalBirthHasExactNoAcquisitionEvidence(t *testing.T) {
	child := terminalRuntimeChild(false, runtimeNoAcquisitionFixture{}, nil)
	child.observeActualClose()
	if !child.run.reclaimableEmptyRun() {
		t.Fatal("actual unused reservation did not become reclaimable")
	}
	if len(child.run.expected) != 1 || child.run.binding.RunNonce != "original" {
		t.Fatal("original census identity was rewritten")
	}
}

func TestRuntimePrepareEnteredCannotUseNoAcquisitionMarker(t *testing.T) {
	child := terminalRuntimeChild(true, runtimeNoAcquisitionFixture{}, nil)
	child.observeActualClose()
	if child.run.reclaimableEmptyRun() || child.run.snapshot().CensusComplete {
		t.Fatal("entered acquisition erased unknown original evidence")
	}
}

func TestRuntimeFailedCloseCannotCertifyEmptyBirth(t *testing.T) {
	child := terminalRuntimeChild(false, runtimeNoAcquisitionFixture{}, errors.New("cleanup unknown"))
	child.observeActualClose()
	if child.run.reclaimableEmptyRun() || child.run.snapshot().CensusComplete {
		t.Fatal("failed original close promoted unused reservation")
	}
}

func TestRuntimeCommittedChildAbortIsNoOp(t *testing.T) {
	plan := &preparationFixtureResources{ctx: context.Background()}
	child := terminalRuntimeChild(true, nil, nil)
	child.committed = true
	child.plan = &runtimePlanFixture{preparationFixtureResources: plan}
	if err := child.Abort(); err != nil || plan.aborted {
		t.Fatal("committed physical owner was aborted", err)
	}
}

type runtimePlanFixture struct{ *preparationFixtureResources }

func (*runtimePlanFixture) Acquire(context.Context) error { return nil }
func TestRuntimeAbortCannotCloseLiveConstructorBinding(t *testing.T) {
	child := terminalRuntimeChild(true, nil, nil)
	child.request.ConstructionDone = make(chan struct{})
	plan := &preparationFixtureResources{ctx: context.Background()}
	child.plan = &runtimePlanFixture{plan}
	if err := child.Abort(); err == nil || plan.aborted {
		t.Fatal("live constructor lease aborted")
	}
}

func TestRuntimeRegistryAdmissionRetainsUnknownAndPrunesOnlyActualUnused(t *testing.T) {
	unused := terminalRuntimeChild(false, runtimeNoAcquisitionFixture{}, nil)
	unused.observeActualClose()
	unknown := terminalRuntimeChild(true, runtimeNoAcquisitionFixture{}, nil)
	unknown.observeActualClose()
	host := &StartedService{tailscaleRetirementRuns: []*tailscaleRetirementRun{unused.run, unknown.run}}
	next := &tailscaleRetirementRun{}
	if err := host.appendTailscaleRetirementRun(next); err != nil {
		t.Fatal(err)
	}
	runs := host.snapshotTailscaleRetirementRuns()
	if len(runs) != 2 || runs[0] != unknown.run || runs[1] != next {
		t.Fatal("admission changed uncertain original census")
	}
}

func TestRuntimeCloseObserverPanicKeepsUnknownEvidence(t *testing.T) {
	child := terminalRuntimeChild(true, nil, nil)
	child.request.CloseResult = func() error { panic("native result unknown") }
	child.observeActualClose()
	if child.run.snapshot().CensusComplete || child.run.reclaimableEmptyRun() {
		t.Fatal("panic certified retirement")
	}
}
