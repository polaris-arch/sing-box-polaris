package route

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/process"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
)

type runtimeProcessFixture struct {
	closed   int
	closeErr error
	entered  chan struct{}
	proceed  chan struct{}
}

func (f *runtimeProcessFixture) FindProcessInfo(context.Context, string, netip.AddrPort, netip.AddrPort) (*adapter.ConnectionOwner, error) {
	if f.entered != nil {
		close(f.entered)
		<-f.proceed
	}
	return &adapter.ConnectionOwner{UserId: -1, ProcessPaths: []string{"fixture"}}, nil
}
func (*runtimeProcessFixture) ResetCache()    {}
func (f *runtimeProcessFixture) Close() error { f.closed++; return f.closeErr }

func TestRuntimeProcessFirstUsePrivateOwner(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	scope := adapter.NewScope(context.Background(), logger)
	initial := &Router{}
	leaf := &Router{logger: logger}
	leaf.BorrowRuntimePlatform(initial)
	fixture := &runtimeProcessFixture{}
	if err := leaf.initializeProcessSearcher(scope, func(process.Config) (process.Searcher, error) { return fixture, nil }); err != nil {
		t.Fatal(err)
	}
	if initial.processSearcher != nil || initial.processCache != nil {
		t.Fatal("private allocation mutated initial owner")
	}
	if leaf.processSearcher != fixture || leaf.processCache == nil {
		t.Fatal("private searcher/cache missing")
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if fixture.closed != 1 {
		t.Fatal("private cleanup missing")
	}
}

func TestRuntimeProcessBorrowedOwnerNotClosed(t *testing.T) {
	fixture := &runtimeProcessFixture{}
	initial := &Router{processSearcher: fixture}
	leaf := &Router{}
	leaf.BorrowRuntimePlatform(initial)
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	if err := leaf.initializeProcessSearcher(scope, func(process.Config) (process.Searcher, error) { t.Fatal("borrowed searcher replaced"); return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if fixture.closed != 0 {
		t.Fatal("borrower closed stable owner")
	}
}

func TestRuntimeProcessAllocationFailureDoesNotPublish(t *testing.T) {
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	defer scope.Close()
	leaf := &Router{runtimeLeaf: true}
	failure := errors.New("searcher allocation failed")
	err := leaf.initializeProcessSearcher(scope, func(process.Config) (process.Searcher, error) { return nil, failure })
	if !errors.Is(err, failure) || leaf.processSearcher != nil || leaf.processCache != nil {
		t.Fatal("failed allocation published")
	}
}

func TestRuntimeProcessQueryRetainsPrivateOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "private-process", Sequence: 1}, nil, scope.Close)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := owner.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	fixture := &runtimeProcessFixture{entered: make(chan struct{}), proceed: make(chan struct{})}
	leaf := &Router{}
	if err := leaf.initializeProcessSearcher(scope, func(process.Config) (process.Searcher, error) { return fixture, nil }); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer lease.Release()
		_, _ = leaf.findProcessInfoCached(adapter.ContextWithRuntimeResourceLease(ctx, lease), "tcp", netip.AddrPort{}, netip.AddrPort{})
	}()
	select {
	case <-fixture.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	owner.Seal()
	select {
	case <-owner.Closed():
		t.Fatal("private searcher closed during query")
	default:
	}
	close(fixture.proceed)
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := owner.WaitClosed(ctx); err != nil {
		t.Fatal(err)
	}
	if fixture.closed != 1 {
		t.Fatal("private searcher did not retire")
	}
}

func TestRuntimeProcessCleanupFailureRemainsVisible(t *testing.T) {
	failure := errors.New("searcher close failed")
	fixture := &runtimeProcessFixture{closeErr: failure}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	leaf := &Router{}
	if err := leaf.initializeProcessSearcher(scope, func(process.Config) (process.Searcher, error) { return fixture, nil }); err != nil {
		t.Fatal(err)
	}
	if err := scope.Close(); !errors.Is(err, failure) {
		t.Fatal("cleanup failure hidden", err)
	}
}
