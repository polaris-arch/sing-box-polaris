package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
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

type nativeTailscaleClaimsFixture struct {
	runtimeURLTestPlatform
	mu        sync.Mutex
	owners    map[string]adapter.RuntimeTailscaleWriterScope
	releases  []bool
	uncertain bool
	onClaim   func()
	onRelease func()
}

func (*nativeTailscaleClaimsFixture) RequiresRuntimeTailscaleWriter() bool { return true }

func (p *nativeTailscaleClaimsFixture) ValidateRuntimeTailscaleWriter(_ string, directories adapter.RuntimeTailscaleDirectories) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, exists := p.owners[directories.State]
	return !exists
}

func (p *nativeTailscaleClaimsFixture) ClaimRuntimeTailscaleWriter(scope adapter.RuntimeTailscaleWriterScope) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.owners[scope.Directories.State]; exists {
		return false, nil
	}
	p.owners[scope.Directories.State] = scope
	if p.onClaim != nil {
		p.onClaim()
	}
	if p.uncertain {
		return false, errors.New("original claim acknowledgement was lost")
	}
	return true, nil
}

func (p *nativeTailscaleClaimsFixture) ReleaseRuntimeTailscaleWriter(scope adapter.RuntimeTailscaleWriterScope, acquired bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.owners[scope.Directories.State] != scope {
		return errors.New("release did not match the original native scope")
	}
	if p.onRelease != nil {
		p.onRelease()
	}
	delete(p.owners, scope.Directories.State)
	p.releases = append(p.releases, acquired)
	return nil
}

type nativeTailscaleChildFixture struct {
	*runtimeTailscaleChild
	constructionDone, closeDone chan struct{}
	constructionErr, closeErr   error
	checkedWriter, finished     bool
}

var fixtureAcceptedTailscaleDigest = strings.Repeat("a", 64)

func registerNativeTailscaleFixture(t *testing.T, host *StartedService, dirs adapter.RuntimeTailscaleDirectories) *nativeTailscaleChildFixture {
	t.Helper()
	return registerNativeTailscaleFixtureInContext(t, host.runtimeTailscaleContext(standaloneTailscaleContext(), nil), dirs)
}

func registerNativeTailscaleFixtureInContext(t *testing.T, ctx context.Context, dirs adapter.RuntimeTailscaleDirectories) *nativeTailscaleChildFixture {
	t.Helper()
	fixture := &nativeTailscaleChildFixture{constructionDone: make(chan struct{}), closeDone: make(chan struct{})}
	request := adapter.RuntimeTailscaleChildRequest{
		ResourceID: standaloneTailscaleSource{}.ID(), Generation: 1, Tag: "child",
		StateDirectory: "fixture-state", TaildropDirectory: "fixture-taildrop", NativeWriter: &dirs,
		ConstructionDone: fixture.constructionDone, CloseDone: fixture.closeDone,
		ConstructionResult: func() error { return fixture.constructionErr },
		CloseResult:        func() error { return fixture.closeErr },
		StoreScopes: func() []adapter.TailscaleStoreNode {
			if !fixture.checkedWriter {
				return nil
			}
			scope := fixture.nativeScope
			return []adapter.TailscaleStoreNode{{
				Tag: scope.Tag, RunNonce: scope.Binding.RunNonce, ConfigDigest: scope.Binding.ConfigDigest,
				StateFile: filepath.Join(scope.Directories.State, "tailscaled.state"), WriterState: "NoStoreConstruction",
			}}
		},
		DirectoryScopes: func() []adapter.TailscaleDirectoryNode {
			if !fixture.checkedWriter {
				return nil
			}
			scope := fixture.nativeScope
			return []adapter.TailscaleDirectoryNode{{
				Tag: scope.Tag, RunNonce: scope.Binding.RunNonce, ConfigDigest: scope.Binding.ConfigDigest,
				StateDirectory: scope.Directories.State, CensusVersion: 1, WriterState: "Unknown",
			}}
		},
	}
	ctx = adapter.ContextWithRuntimeResourceSource(ctx, standaloneTailscaleSource{})
	ctx = adapter.ContextWithRuntimeTailscaleConfiguration(ctx, []byte(standaloneTailscaleConfig))
	ctx = adapter.ContextWithRuntimeTailscalePlanDigest(ctx, fixtureAcceptedTailscaleDigest)
	registration, err := adapter.RegisterRuntimeTailscaleChild(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.runtimeTailscaleChild = registration.(*runtimeTailscaleChild)
	t.Cleanup(func() {
		if !fixture.finished {
			fixture.finish(t, errors.New("fixture stopped before construction"), nil, false)
		}
	})
	return fixture
}

func (fixture *nativeTailscaleChildFixture) signalClose(t *testing.T, constructionErr, closeErr error, checkedWriter bool) {
	t.Helper()
	fixture.finished = true
	fixture.constructionErr, fixture.closeErr, fixture.checkedWriter = constructionErr, closeErr, checkedWriter
	close(fixture.constructionDone)
	if checkedWriter {
		if err := fixture.Constructed(); err != nil {
			t.Error(err)
		}
	}
	close(fixture.closeDone)
}

func (fixture *nativeTailscaleChildFixture) finish(t *testing.T, constructionErr, closeErr error, checkedWriter bool) {
	t.Helper()
	fixture.signalClose(t, constructionErr, closeErr, checkedWriter)
	select {
	case <-fixture.nativeCloseDone:
	case <-time.After(5 * time.Second):
		t.Fatal("original native close observer did not complete")
	}
}

func TestRuntimeTailscaleNativeStrictReloadRetainsOriginalWarmParent(t *testing.T) {
	for _, claimed := range []bool{true, false} {
		name := "held original native writer"
		if !claimed {
			name = "never entered native preparation"
		}
		t.Run(name, func(t *testing.T) {
			host, _ := retirementPureHost(t)
			platform := &nativeTailscaleClaimsFixture{owners: make(map[string]adapter.RuntimeTailscaleWriterScope)}
			host.ctx = service.ContextWith[adapter.PlatformInterface](host.ctx, platform)
			host.ctx = service.ContextWith[option.EndpointOptionsRegistry](host.ctx,
				service.FromContext[option.EndpointOptionsRegistry](standaloneTailscaleContext()))
			const coldConfig = `{"log":{"disabled":true}}`
			if err := host.StartOrReloadService(context.Background(), coldConfig, nil); err != nil {
				t.Fatal(err)
			}
			parent := host.instance.tailscaleRetirement
			before := parent.snapshot()
			if len(before.Nodes) != 0 || before.CensusComplete {
				t.Fatal("cold parent census already has an endpoint or terminal")
			}
			root := t.TempDir()
			child := registerNativeTailscaleFixtureInContext(t, host.instance.ctx, adapter.RuntimeTailscaleDirectories{
				State: filepath.Join(root, "state"), Taildrop: filepath.Join(root, "taildrop"),
			})
			if claimed {
				if err := child.Prepare(context.Background()); err != nil {
					t.Fatal(err)
				}
				child.finish(t, nil, nil, true)
			} else {
				child.finish(t, runtimeNoAcquisitionFixture{}, nil, false)
			}
			if err := child.WaitOriginalNativeClose(); err != nil {
				t.Fatal(err)
			}
			if err := host.StartOrReloadService(context.Background(), coldConfig, nil); err != nil {
				t.Fatal(err)
			}
			runs := host.snapshotTailscaleRetirementRuns()
			replacement := host.instance.tailscaleRetirement
			if !claimed {
				if len(runs) != 1 || runs[0] != replacement {
					t.Fatal("unclaimed child kept ordinary empty history")
				}
				return
			}
			if len(runs) != 3 || runs[0] != parent || runs[1] != child.run || runs[2] != replacement {
				t.Fatal("strict reload lost or reordered the original native parent and child")
			}
			after := parent.snapshot()
			if after.RunNonce != before.RunNonce || after.ConfigDigest != before.ConfigDigest ||
				!after.CensusComplete || after.Terminal != "NoStoreConstruction" || len(after.Nodes) != 0 {
				t.Fatalf("empty original cold census was not terminal: %+v", after)
			}
			if warm := child.run.snapshot(); !warm.CensusComplete || len(warm.Nodes) != 1 ||
				warm.RunNonce != child.nativeScope.Binding.RunNonce || warm.ConfigDigest != fixtureAcceptedTailscaleDigest {
				t.Fatalf("warm child lost its original native binding: %+v", warm)
			}
		})
	}
}

func TestRuntimeTailscaleNativePlanChecksCapacityWithoutPruning(t *testing.T) {
	host := &StartedService{tailscaleRetirementRuns: make([]*tailscaleRetirementRun, maxTailscaleRetirementRuns)}
	for index := range host.tailscaleRetirementRuns {
		host.tailscaleRetirementRuns[index] = &tailscaleRetirementRun{}
	}
	if host.runtimeTailscaleChildHasCapacity() {
		t.Fatal("retained unknown births were excluded from Plan capacity")
	}
	unused := terminalRuntimeChild(false, runtimeNoAcquisitionFixture{}, nil)
	unused.observeActualClose()
	host.tailscaleRetirementRuns[0] = unused.run
	if !host.runtimeTailscaleChildHasCapacity() {
		t.Fatal("a certified unused birth will not fit the next physical reservation")
	}
	runs := host.snapshotTailscaleRetirementRuns()
	if len(runs) != maxTailscaleRetirementRuns || runs[0] != unused.run {
		t.Fatal("Plan pruned original runs")
	}
}

func TestRuntimeTailscaleNativeUnclassifiedCapacityReleasedOnlyByOriginalNoAcquisition(t *testing.T) {
	for _, test := range []struct {
		name     string
		closeErr error
	}{
		{name: "original unused"},
		{name: "unknown original close", closeErr: errors.New("close could not be checked")},
	} {
		t.Run(test.name, func(t *testing.T) {
			platform := &nativeTailscaleClaimsFixture{owners: make(map[string]adapter.RuntimeTailscaleWriterScope)}
			host := &StartedService{ctx: service.ContextWith[adapter.PlatformInterface](context.Background(), platform)}
			parent := completedEmptyRetirementRun(t)
			host.tailscaleRetirementRuns = append(host.tailscaleRetirementRuns, parent)
			for range maxTailscaleRetirementRuns - 2 {
				host.tailscaleRetirementRuns = append(host.tailscaleRetirementRuns, &tailscaleRetirementRun{})
			}
			root := t.TempDir()
			ctx := host.runtimeTailscaleContext(standaloneTailscaleContext(), parent)
			child := registerNativeTailscaleFixtureInContext(t, ctx, adapter.RuntimeTailscaleDirectories{State: filepath.Join(root, "state"), Taildrop: filepath.Join(root, "taildrop")})
			if host.runtimeTailscaleChildHasCapacity() || host.appendTailscaleRetirementRun(&tailscaleRetirementRun{}) == nil {
				t.Fatal("an unclassified child did not reserve the last original census slot")
			}
			if len(host.snapshotTailscaleRetirementRuns()) != maxTailscaleRetirementRuns-1 {
				t.Fatal("capacity reservation appeared in the export")
			}
			child.finish(t, runtimeNoAcquisitionFixture{}, test.closeErr, false)
			if err := child.WaitOriginalNativeClose(); (err != nil) != (test.closeErr != nil) {
				t.Fatalf("original close acknowledgement = %v", err)
			}
			if host.runtimeTailscaleChildHasCapacity() != (test.closeErr == nil) {
				t.Fatal("admission capacity did not follow exact no-acquisition evidence")
			}
			runs := host.snapshotTailscaleRetirementRuns()
			if test.closeErr != nil {
				if len(runs) != maxTailscaleRetirementRuns || runs[0] != parent || runs[len(runs)-1] != child.run || child.run.snapshot().CensusComplete {
					t.Fatal("unknown original close or its cold parent was omitted or promoted")
				}
			} else {
				if err := host.appendTailscaleRetirementRun(&tailscaleRetirementRun{}); err != nil {
					t.Fatal(err)
				}
				if host.snapshotTailscaleRetirementRuns()[0] == parent {
					t.Fatal("unacquired reservation permanently pinned its empty parent")
				}
			}
		})
	}
}

func TestRuntimeTailscaleNativeSameDirectoryConflictThenOriginalCloseReleases(t *testing.T) {
	root := t.TempDir()
	dirs := adapter.RuntimeTailscaleDirectories{State: filepath.Join(root, "state"), Taildrop: filepath.Join(root, "taildrop")}
	platform := &nativeTailscaleClaimsFixture{owners: make(map[string]adapter.RuntimeTailscaleWriterScope)}
	ctx := service.ContextWith[adapter.PlatformInterface](context.Background(), platform)
	main, other := &StartedService{ctx: ctx}, &StartedService{ctx: ctx}
	for range 2 {
		if !platform.ValidateRuntimeTailscaleWriter("child", dirs) || !main.runtimeTailscaleChildHasCapacity() || len(main.snapshotTailscaleRetirementRuns()) != 0 {
			t.Fatal("advisory validation reserved a writer or mutated the census")
		}
	}
	first := registerNativeTailscaleFixture(t, main, dirs)
	concurrent := registerNativeTailscaleFixture(t, other, dirs)
	if len(main.snapshotTailscaleRetirementRuns()) != 0 || len(other.snapshotTailscaleRetirementRuns()) != 0 {
		t.Fatal("registrar published an unclassified native reservation")
	}
	if err := first.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runs := main.snapshotTailscaleRetirementRuns(); len(runs) != 1 || runs[0] != first.run {
		t.Fatal("admitted writer was not recorded before native directory preparation")
	}
	claimedScope := platform.owners[dirs.State]
	if claimedScope.Binding.ConfigDigest != fixtureAcceptedTailscaleDigest ||
		first.run.binding != claimedScope.Binding || service.PtrFromContext[adapter.TailscaleStoreRunBinding](first.Context()).ConfigDigest != fixtureAcceptedTailscaleDigest {
		t.Fatal("native scope and original Store use different canonical Plan bindings")
	}
	denied := concurrent.Prepare(context.Background())
	if denied == nil || concurrent.directoryEntered {
		t.Fatal("second owner entered directory preparation")
	}
	concurrent.finish(t, denied, nil, false)
	if concurrent.WaitOriginalNativeClose() != nil || len(other.snapshotTailscaleRetirementRuns()) != 0 {
		t.Fatal("rejected claim added an unadmitted row to the original writer history")
	}
	if first.nativeScope.Binding.RunNonce == concurrent.nativeScope.Binding.RunNonce || !first.claimed {
		t.Fatal("main and other child did not have distinct original claims")
	}
	first.finish(t, nil, nil, true)
	if err := first.WaitOriginalNativeClose(); err != nil || len(platform.releases) != 1 || !platform.releases[0] {
		t.Fatal("checked original writer Close was not acknowledged")
	}
	retry := registerNativeTailscaleFixture(t, other, dirs)
	if err := retry.Prepare(context.Background()); err != nil || !retry.claimed {
		t.Fatal("fresh child could not claim released path", err)
	}
}

func TestRuntimeTailscaleNativeCloseWaitIsStickyWhenOriginalReleaseStalls(t *testing.T) {
	releaseEntered, allowRelease := make(chan bool, 1), make(chan struct{})
	defer close(allowRelease)
	platform := &nativeTailscaleClaimsFixture{owners: make(map[string]adapter.RuntimeTailscaleWriterScope)}
	host := &StartedService{ctx: service.ContextWith[adapter.PlatformInterface](context.Background(), platform)}
	root := t.TempDir()
	child := registerNativeTailscaleFixture(t, host, adapter.RuntimeTailscaleDirectories{State: filepath.Join(root, "state"), Taildrop: filepath.Join(root, "taildrop")})
	platform.onRelease = func() {
		unlocked := child.op.TryLock()
		if unlocked {
			child.op.Unlock()
		}
		releaseEntered <- unlocked
		<-allowRelease
	}
	if err := child.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	child.signalClose(t, nil, nil, true)
	select {
	case unlocked := <-releaseEntered:
		if !unlocked {
			t.Fatal("native callback ran under the original child operation lock")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("original writer release never started")
	}
	if err := child.waitOriginalNativeClose(5 * time.Millisecond); !errors.Is(err, errRuntimeTailscaleNativeCloseUnknown) {
		t.Fatalf("unfinished native release was acknowledged: %v", err)
	}
	select {
	case <-child.nativeCloseDone:
		t.Fatal("stalled native release published completion")
	default:
	}
	// Let the old callback complete independently after the observed timeout.
	allowRelease <- struct{}{}
	select {
	case <-child.nativeCloseDone:
	case <-time.After(5 * time.Second):
		t.Fatal("old release did not complete")
	}
	if child.nativeCloseResult != nil || !errors.Is(child.WaitOriginalNativeClose(), errRuntimeTailscaleNativeCloseUnknown) {
		t.Fatal("late original release rewrote the returned Close acknowledgement")
	}
}

func TestRuntimeTailscaleNativeReleaseRequiresOriginalNoAcquisitionOrCheckedClose(t *testing.T) {
	for _, test := range []struct {
		name             string
		cancelAfterClaim bool
		uncertainClaim   bool
		closeErr         error
		checkedWriter    bool
		wantRelease      bool
	}{
		{name: "canceled before acquisition", cancelAfterClaim: true, wantRelease: true},
		{name: "unknown native admission", uncertainClaim: true},
		{name: "failed original close", closeErr: errors.New("unknown close"), checkedWriter: true},
		{name: "missing writer census"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			platform := &nativeTailscaleClaimsFixture{owners: make(map[string]adapter.RuntimeTailscaleWriterScope), uncertain: test.uncertainClaim}
			if test.cancelAfterClaim {
				platform.onClaim = cancel
			}
			host := &StartedService{ctx: service.ContextWith[adapter.PlatformInterface](context.Background(), platform)}
			root := t.TempDir()
			child := registerNativeTailscaleFixture(t, host, adapter.RuntimeTailscaleDirectories{State: filepath.Join(root, "state"), Taildrop: filepath.Join(root, "taildrop")})
			err := child.Prepare(ctx)
			if (err != nil) != (test.cancelAfterClaim || test.uncertainClaim) {
				t.Fatalf("unexpected preparation result: %v", err)
			}
			child.finish(t, err, test.closeErr, test.checkedWriter)
			if allowed := platform.ValidateRuntimeTailscaleWriter("child", child.nativeScope.Directories); allowed != test.wantRelease {
				t.Fatalf("scope availability after original Close = %v", allowed)
			}
			if test.wantRelease && (len(platform.releases) != 1 || platform.releases[0]) {
				t.Fatal("never-entered preparation was reported as physical acquisition")
			}
			proof := child.run.snapshot()
			if test.wantRelease && (proof.Terminal != "NoStoreConstruction" || !proof.CensusComplete || len(proof.Nodes) != 0) {
				t.Fatal("original claimed run lacks its checked empty constructor proof")
			}
			if test.uncertainClaim && (proof.Terminal != "Unknown" || proof.CensusComplete) {
				t.Fatal("unknown native claim was recast as no acquisition")
			}
			if err := host.appendTailscaleRetirementRun(&tailscaleRetirementRun{}); err != nil {
				t.Fatal(err)
			}
			if runs := host.snapshotTailscaleRetirementRuns(); len(runs) != 2 || runs[0] != child.run {
				t.Fatal("claimed or uncertain original run was omitted or pruned")
			}
		})
	}
}
