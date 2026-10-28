package mux

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Pure ownership fixtures. Constructors and preparation must never bind sockets,
// acquire the published graph, or start receiving protocol traffic.
type ingressFixture struct {
	id             adapter.RuntimeResourceID
	graphs         atomic.Int64
	resources      atomic.Int64
	sourceAcquires atomic.Int64
	graphAcquires  atomic.Int64
	membership     bool
}
type ingressSource struct{ owner *ingressFixture }

func (s ingressSource) ID() adapter.RuntimeResourceID { return s.owner.id }
func (s ingressSource) Acquire() (adapter.RuntimeResourceLease, error) {
	s.owner.sourceAcquires.Add(1)
	return nil, errors.New("root source admission must not be used")
}

func (f *ingressFixture) Acquire() (adapter.RuntimeLease, error) {
	f.graphAcquires.Add(1)
	return nil, errors.New("constructor activated graph admission")
}

type ingressGraph struct {
	adapter.RuntimeLease
	owner    *ingressFixture
	mu       sync.Mutex
	released bool
}

func (g *ingressGraph) Fork() (adapter.RuntimeLease, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.released {
		return nil, net.ErrClosed
	}
	g.owner.graphs.Add(1)
	return &ingressGraph{owner: g.owner}, nil
}

func (g *ingressGraph) RetainResource(id adapter.RuntimeResourceID) (adapter.RuntimeResourceLease, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.released || !g.owner.membership || id != g.owner.id {
		return nil, net.ErrClosed
	}
	g.owner.resources.Add(1)
	return &ingressResource{owner: g.owner}, nil
}

func (g *ingressGraph) Release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.released {
		g.released = true
		g.owner.graphs.Add(-1)
	}
}

type ingressResource struct {
	owner    *ingressFixture
	mu       sync.Mutex
	released bool
}

func (r *ingressResource) ID() adapter.RuntimeResourceID { return r.owner.id }
func (*ingressResource) Retiring() <-chan struct{}       { return nil }
func (r *ingressResource) Fork() (adapter.RuntimeResourceLease, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released {
		return nil, net.ErrClosed
	}
	r.owner.resources.Add(1)
	return &ingressResource{owner: r.owner}, nil
}

func (r *ingressResource) Release() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.released {
		r.released = true
		r.owner.resources.Add(-1)
	}
}

func newIngressFixture() *ingressFixture {
	return &ingressFixture{id: adapter.RuntimeResourceID{Incarnation: "ingress", Sequence: 1}, membership: true}
}

func (f *ingressFixture) context() (context.Context, *ingressGraph) {
	f.graphs.Add(1)
	graph := &ingressGraph{owner: f}
	return adapter.ContextWithRuntimeLease(context.Background(), graph), graph
}

func ingressConstruction(f *ingressFixture) (context.Context, *adapter.Scope) {
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	ctx := adapter.ContextWithConstructionScope(scope.Context(), scope)
	ctx = adapter.ContextWithRuntimePreparation(ctx)
	ctx = adapter.ContextWithRuntimeResourceSource(ctx, ingressSource{f})
	ctx = listener.ContextWithRuntimeBinding(ctx, listener.RuntimeBinding{Admission: f})
	return ctx, scope
}

func ingressWait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("ownership barrier watchdog")
	}
}

func ingressPending(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
		t.Fatal("cleanup completed before the admitted callback")
	default:
	}
}

type muxCallbackFixture struct {
	entered chan struct{}
	proceed chan struct{}
}

func (h *muxCallbackFixture) NewConnectionEx(context.Context, net.Conn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
	close(h.entered)
	<-h.proceed
}

func (h *muxCallbackFixture) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
	close(h.entered)
	<-h.proceed
}

func TestRuntimeMultiplexInboundCallbackIsJoinedAndKeepsPhysicalLineage(t *testing.T) {
	f := newIngressFixture()
	construction, scope := ingressConstruction(f)
	callback := &muxCallbackFixture{entered: make(chan struct{}), proceed: make(chan struct{})}
	handler, _, err := newRuntimeServerHandler(construction, callback, log.NewNOPFactory().Logger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, graph := f.context()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	returned := make(chan struct{})
	go func() { handler.NewConnectionEx(ctx, a, M.Socksaddr{}, M.Socksaddr{}, nil); close(returned) }()
	ingressWait(t, callback.entered)
	graph.Release()
	boundary := handler.(*runtimeServerHandler)
	_ = boundary.callbacks.Close()
	closed := make(chan struct{})
	go func() { _ = boundary.callbacks.Wait(); close(closed) }()
	if _, _, err := boundary.enter(ctx); err == nil {
		t.Fatal("closed or released lineage reopened")
	}
	ingressPending(t, closed)
	close(callback.proceed)
	ingressWait(t, returned)
	ingressWait(t, closed)
	if f.graphs.Load() != 0 {
		t.Fatal("multiplex callback ownership leaked")
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
}
