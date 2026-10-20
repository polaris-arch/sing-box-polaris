package runtimegraph

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

type typedTestView struct {
	adapter.RuntimeView
	identity adapter.RuntimeRevision
	router adapter.Router
	dns adapter.DNSRouter
	outbound adapter.OutboundManager
}
func (v *typedTestView) Identity() adapter.RuntimeRevision { return v.identity }
func (v *typedTestView) Router() adapter.Router { return v.router }
func (v *typedTestView) DNSRouter() adapter.DNSRouter { return v.dns }
func (v *typedTestView) OutboundManager() adapter.OutboundManager { return v.outbound }
type typedTestRouter struct { adapter.Router; revision uint64 }
type typedTestDNSRouter struct { adapter.DNSRouter; revision uint64 }
type typedTestOutboundManager struct { adapter.OutboundManager; revision uint64 }

func testGraph(t *testing.T, revision uint64, members ...adapter.RuntimeResourceLease) *Graph {
	t.Helper()
	view := &typedTestView{
		identity: adapter.RuntimeRevision{Incarnation: "test-run", Revision: revision},
		router: &typedTestRouter{revision: revision},
		dns: &typedTestDNSRouter{revision: revision},
		outbound: &typedTestOutboundManager{revision: revision},
	}
	graph, err := NewGraph(view, members)
	if err != nil { t.Fatal(err) }
	return graph
}
func testStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore("test-run")
	if err != nil { t.Fatal(err) }
	t.Cleanup(store.Seal)
	return store
}
func publishTestGraph(t *testing.T, store *Store, expected uint64, graph *Graph) *Graph {
	t.Helper()
	old, err := store.Publish(adapter.RuntimeRevision{Incarnation: "test-run", Revision: expected}, graph)
	if err != nil { t.Fatal(err) }
	return old
}
func testOwner(t *testing.T, sequence uint64, deps []adapter.RuntimeResourceLease, closeFn func() error) (*ResourceOwner, adapter.RuntimeResourceLease) {
	t.Helper()
	owner, err := NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "test-run", Sequence: sequence}, deps, closeFn)
	if err != nil { t.Fatal(err) }
	lease, err := owner.Acquire()
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { owner.Seal(); lease.Release() })
	return owner, lease
}

func TestTypedGraphPublishOldOrNew(t *testing.T) {
	store := testStore(t)
	if _, err := store.Acquire(); !errors.Is(err, ErrAdmissionNotReady) { t.Fatalf("unready admission: %v", err) }
	publishTestGraph(t, store, 0, testGraph(t, 1))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 32; j++ {
				lease, err := store.Acquire()
				if err != nil { t.Error(err); return }
				view := lease.View()
				revision := view.Identity().Revision
				if view.Router().(*typedTestRouter).revision != revision || view.DNSRouter().(*typedTestDNSRouter).revision != revision || view.OutboundManager().(*typedTestOutboundManager).revision != revision {
					t.Error("mixed graph bindings")
				}
				lease.Release()
			}
		}()
	}
	close(start)
	publishTestGraph(t, store, 1, testGraph(t, 2))
	wg.Wait()
	store.Seal()
	await(t, store.Drained())
	if _, err := store.Acquire(); !errors.Is(err, ErrAdmissionSealed) { t.Fatal(err) }
}

func TestGraphForkAfterRetireBeforeSourceRelease(t *testing.T) {
	store := testStore(t)
	old := testGraph(t, 1)
	publishTestGraph(t, store, 0, old)
	source, err := store.Acquire()
	if err != nil { t.Fatal(err) }
	publishTestGraph(t, store, 1, testGraph(t, 2))
	fork, err := source.Fork()
	if err != nil { t.Fatal(err) }
	source.Release()
	if _, err := source.Fork(); !errors.Is(err, ErrLeaseReleased) { t.Fatal(err) }
	select { case <-old.Drained(): t.Fatal("live continuation drained"); default: }
	fork.Release()
	await(t, old.Drained())
	if _, err := fork.Fork(); !errors.Is(err, ErrLeaseReleased) { t.Fatal(err) }
}

func TestGraphForkReleaseOneMutex(t *testing.T) {
	for iteration := 0; iteration < 64; iteration++ {
		g := newGeneration(1)
		a := mustAdmission(t, g)
		lease := mustGenerationLease(t, a)
		a.seal()
		g.mu.Lock()
		start := make(chan struct{})
		result := make(chan adapter.RuntimeLease, 1)
		errorsCh := make(chan error, 1)
		released := make(chan struct{})
		go func() { <-start; fork, err := lease.Fork(); result <- fork; errorsCh <- err }()
		go func() { <-start; lease.Release(); close(released) }()
		close(start)
		g.mu.Unlock()
		fork, err := <-result, <-errorsCh
		await(t, released)
		if err == nil { fork.Release() } else if !errors.Is(err, ErrLeaseReleased) { t.Fatal(err) }
		await(t, g.drained)
		assertGeneration(t, g, 0, true, true)
	}
}

func TestResourceForkAfterSeal(t *testing.T) {
	owner, source := testOwner(t, 1, nil, nil)
	owner.Seal()
	await(t, owner.Retiring())
	if _, err := owner.Acquire(); !errors.Is(err, ErrResourceSealed) { t.Fatal(err) }
	fork, err := source.Fork()
	if err != nil { t.Fatal(err) }
	source.Release()
	if _, err := source.Fork(); !errors.Is(err, ErrLeaseReleased) { t.Fatal(err) }
	owner.owner.mu.Lock()
	refs := owner.owner.refs
	owner.owner.refs = ^uint64(0)
	owner.owner.mu.Unlock()
	if _, err := fork.Fork(); err == nil { t.Fatal("overflow accepted") }
	owner.owner.mu.Lock(); owner.owner.refs = refs; owner.owner.mu.Unlock()
	fork.Release()
	await(t, owner.Closed())
	if _, err := owner.RetainExisting(); err == nil { t.Fatal("closed owner resurrected") }
}

func TestGraphZeroIsNotResourceClosed(t *testing.T) {
	entered, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(unblock) }) })
	owner, construction := testOwner(t, 1, nil, func() error { close(entered); <-unblock; return nil })
	store := testStore(t)
	graph := testGraph(t, 1, construction)
	publishTestGraph(t, store, 0, graph)
	lease, err := store.Acquire()
	if err != nil { t.Fatal(err) }
	attachment, err := lease.RetainResource(owner.ID())
	if err != nil { t.Fatal(err) }
	t.Cleanup(attachment.Release)
	construction.Release()
	lease.Release()
	owner.Seal()
	store.Seal()
	await(t, graph.Drained())
	select { case <-owner.Closed(): t.Fatal("attachment did not pin resource"); default: }
	select { case <-entered: t.Fatal("close started with live attachment"); default: }
	attachment.Release()
	await(t, entered)
	select { case <-owner.Closed(): t.Fatal("close callback still blocked"); default: }
	once.Do(func() { close(unblock) })
	await(t, owner.Closed())
}

func TestSharedResourceReusedAcrossGraphs(t *testing.T) {
	var closes atomic.Int32
	owner, construction := testOwner(t, 1, nil, func() error { closes.Add(1); return nil })
	store := testStore(t)
	first := testGraph(t, 1, construction)
	second := testGraph(t, 2, construction)
	construction.Release()
	publishTestGraph(t, store, 0, first)
	publishTestGraph(t, store, 1, second)
	await(t, first.Drained())
	select { case <-owner.Retiring(): t.Fatal("old graph sealed shared owner"); default: }
	lease, err := store.Acquire()
	if err != nil { t.Fatal(err) }
	resource, err := lease.RetainResource(owner.ID())
	if err != nil { t.Fatal(err) }
	lease.Release()
	owner.Seal()
	store.Seal()
	await(t, second.Drained())
	if closes.Load() != 0 { t.Fatal("retained resource closed") }
	resource.Release()
	await(t, owner.Closed())
	if closes.Load() != 1 { t.Fatal("resource not closed exactly once") }
}

func TestCohortDependencyCleanup(t *testing.T) {
	dependency, dependencyConstruction := testOwner(t, 1, nil, nil)
	entered, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(unblock) }) })
	cohort, construction := testOwner(t, 2, []adapter.RuntimeResourceLease{dependencyConstruction}, func() error {
		close(entered)
		<-unblock
		if dependency.Context().Err() != nil { return errors.New("dependency canceled before cohort cleanup") }
		return nil
	})
	dependencyConstruction.Release()
	dependency.Seal()
	cohort.Seal()
	construction.Release()
	await(t, entered)
	select { case <-dependency.Closed(): t.Fatal("dependency closed before actual dependent cleanup"); default: }
	once.Do(func() { close(unblock) })
	await(t, cohort.Closed())
	await(t, dependency.Closed())
	if err := cohort.WaitClosed(context.Background()); err != nil { t.Fatal(err) }
}

func TestCleanupUncertaintyRetainsDependencies(t *testing.T) {
	entered, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(unblock) }) })
	sentinel := errors.New("native cleanup uncertain")
	dependency, depLease := testOwner(t, 1, nil, nil)
	owner, lease := testOwner(t, 2, []adapter.RuntimeResourceLease{depLease}, func() error { close(entered); <-unblock; return sentinel })
	depLease.Release(); dependency.Seal(); owner.Seal(); lease.Release()
	await(t, entered)
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if err := owner.WaitClosed(ctx); !errors.Is(err, context.Canceled) { t.Fatal(err) }
	once.Do(func() { close(unblock) })
	await(t, owner.Closed())
	if owner.WaitClosed(context.Background()) != sentinel || owner.WaitClosed(context.Background()) != sentinel { t.Fatal("lost sticky cleanup error") }
	select { case <-dependency.Closed(): t.Fatal("uncertain cleanup released dependency"); default: }
	// Test-only release of the quarantine after its assertion; production does
	// not treat timeout or callback failure as clearance to do this.
	for _, reservation := range owner.owner.dependencies { reservation.release() }
	await(t, dependency.Closed())
}

func TestGraphMembershipValidation(t *testing.T) {
	dependency, depLease := testOwner(t, 1, nil, nil)
	owner, lease := testOwner(t, 2, []adapter.RuntimeResourceLease{depLease}, nil)
	view := &typedTestView{identity: adapter.RuntimeRevision{Incarnation: "test-run", Revision: 1}}
	for _, members := range [][]adapter.RuntimeResourceLease{{lease}, {lease, depLease, depLease}} {
		if graph, err := NewGraph(view, members); err == nil { _ = graph.Discard(); t.Fatal("incomplete or duplicate closure accepted") }
	}
	graph := testGraph(t, 1, depLease, lease)
	if err := graph.Discard(); err != nil { t.Fatal(err) }
	owner.Seal(); lease.Release(); await(t, owner.Closed())
	dependency.Seal(); depLease.Release(); await(t, dependency.Closed())
}

func TestForbiddenRuntimegraphImportDirections(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok { t.Fatal("cannot locate source") }
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	check := func(path string, forbidden []string) {
		t.Helper()
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil { t.Fatal(err) }
		for _, spec := range file.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil { t.Fatal(err) }
			if strings.Contains(path, "internal/runtimegraph") && imported == "github.com/sagernet/sing-box" { t.Errorf("%s imports Box", path) }
			for _, prefix := range forbidden {
				if imported == prefix || strings.HasPrefix(imported, prefix+"/") { t.Errorf("%s imports forbidden %s", path, imported) }
			}
		}
	}
	for _, directory := range []string{"adapter", "internal/runtimegraph"} {
		entries, err := os.ReadDir(filepath.Join(root, directory))
		if err != nil { t.Fatal(err) }
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") { continue }
			forbidden := []string{"github.com/sagernet/sing-box/internal/runtimegraph"}
			if directory == "internal/runtimegraph" { forbidden = []string{"github.com/sagernet/sing-box/route", "github.com/sagernet/sing-box/dns", "github.com/sagernet/sing-box/protocol", "github.com/sagernet/sing-box/daemon", "github.com/sagernet/sing-box/experimental/libbox"} }
			check(filepath.Join(root, directory, entry.Name()), forbidden)
		}
	}
}

func TestResourceForkReleaseOneMutex(t *testing.T) {
	for iteration := 0; iteration < 64; iteration++ {
		r := newResourceOwner(context.Background(), nil)
		lease := mustResourceLease(t, r)
		r.requestClose()
		r.mu.Lock()
		start := make(chan struct{})
		result := make(chan adapter.RuntimeResourceLease, 1)
		errorsCh := make(chan error, 1)
		released := make(chan struct{})
		go func() { <-start; fork, err := lease.Fork(); result <- fork; errorsCh <- err }()
		go func() { <-start; lease.Release(); close(released) }()
		close(start)
		r.mu.Unlock()
		fork, err := <-result, <-errorsCh
		await(t, released)
		if err == nil { fork.Release() } else if !errors.Is(err, ErrLeaseReleased) { t.Fatal(err) }
		await(t, r.closed)
		r.mu.Lock(); refs := r.refs; state := r.state; r.mu.Unlock()
		if refs != 0 || state != resourceClosed { t.Fatal("resource resurrected") }
	}
}

func TestRuntimeContextBorrowAndMask(t *testing.T) {
	store := testStore(t)
	graph := testGraph(t, 1)
	publishTestGraph(t, store, 0, graph)
	lease, err := store.Acquire()
	if err != nil { t.Fatal(err) }
	ctx := adapter.ContextWithRuntimeLease(context.Background(), lease)
	if got, ok := adapter.RuntimeLeaseFromContext(ctx); !ok || got != lease { t.Fatal("context did not borrow exact handle") }
	masked := adapter.ContextWithRuntimeLease(ctx, nil)
	if _, ok := adapter.RuntimeLeaseFromContext(masked); ok { t.Fatal("nil binding did not mask parent admission") }
	store.Seal(); lease.Release()
	await(t, graph.Drained())
	got, _ := adapter.RuntimeLeaseFromContext(ctx)
	if _, err := got.Fork(); !errors.Is(err, ErrLeaseReleased) { t.Fatal("copied context retained the graph") }
}

func TestGraphOverflowAndWrongIncarnation(t *testing.T) {
	store := testStore(t)
	graph := testGraph(t, 1)
	if _, err := store.Publish(adapter.RuntimeRevision{Incarnation: "other-run"}, graph); !errors.Is(err, ErrRevisionMismatch) { t.Fatal(err) }
	publishTestGraph(t, store, 0, graph)
	lease, err := store.Acquire()
	if err != nil { t.Fatal(err) }
	g := graph.generation
	g.mu.Lock(); refs := g.refs; g.refs = ^uint64(0); g.mu.Unlock()
	if _, err := lease.Fork(); err == nil { t.Fatal("graph overflow accepted") }
	g.mu.Lock(); g.refs = refs; g.mu.Unlock()
	lease.Release()
	store.Seal(); await(t, graph.Drained())
}

func TestSealedResourceCannotBecomeNewGraphMember(t *testing.T) {
	owner, source := testOwner(t, 1, nil, nil)
	owner.Seal()
	view := &typedTestView{identity: adapter.RuntimeRevision{Incarnation: "test-run", Revision: 1}}
	if graph, err := NewGraph(view, []adapter.RuntimeResourceLease{source}); !errors.Is(err, ErrResourceSealed) {
		if graph != nil { _ = graph.Discard() }
		t.Fatalf("sealed owner became new membership: %v", err)
	}
	continuation, err := source.Fork()
	if err != nil { t.Fatal(err) }
	source.Release(); continuation.Release(); await(t, owner.Closed())
}

func TestRejectedAdmissionReturnsNilInterface(t *testing.T) {
	store := testStore(t)
	if lease, err := store.Acquire(); err == nil || lease != nil { t.Fatalf("unready: %v %v", lease, err) }
	owner, source := testOwner(t, 1, nil, nil)
	owner.Seal()
	if lease, err := owner.Acquire(); err == nil || lease != nil { t.Fatalf("sealed: %v %v", lease, err) }
	source.Release()
	if lease, err := source.Fork(); err == nil || lease != nil { t.Fatalf("released: %v %v", lease, err) }
	await(t, owner.Closed())
}
