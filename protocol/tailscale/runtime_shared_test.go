//go:build with_tailscale

package tailscale

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
)

type runtimeBindingTestSource struct {
	sequence uint64
	roots    atomic.Int32
}

func (s *runtimeBindingTestSource) ID() adapter.RuntimeResourceID {
	return adapter.RuntimeResourceID{Incarnation: "shared-ts", Sequence: s.sequence}
}

func (s *runtimeBindingTestSource) Acquire() (adapter.RuntimeResourceLease, error) {
	s.roots.Add(1)
	return nil, errors.New("internal binding must not acquire its logical resource")
}

func (s *runtimeBindingTestSource) RetainCapturedResource(adapter.RuntimeResourceID) (adapter.RuntimeResourceLease, error) {
	return nil, net.ErrClosed
}

func newRuntimeBindingFixture(t *testing.T, sequence uint64) *runtimeEndpointBinding {
	t.Helper()
	source := &runtimeBindingTestSource{sequence: sequence}
	scope := adapter.NewScope(context.Background(), nil)
	ctx := adapter.ContextWithConstructionScope(adapter.ContextWithRuntimeResourceSource(scope.Context(), source), scope)
	callbacks := outbound.NewRuntimeIOFence(nil)
	begin, err := outbound.RegisterRuntimeOwnedFence(ctx, callbacks)
	if err != nil {
		t.Fatal(err)
	}
	return &runtimeEndpointBinding{source: source, scope: scope, ctx: ctx, callbacks: callbacks, begin: begin, roots: true, quiescent: make(chan struct{}), closeDone: make(chan struct{})}
}

func TestSharedBindingRetirementPreservesContinuation(t *testing.T) {
	b := newRuntimeBindingFixture(t, 1)
	old, release, err := b.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b.retireRoot()
	if _, _, err = b.acquire(context.Background()); err == nil {
		t.Fatal("retired binding admitted fresh root")
	}
	continued, releaseContinuation, err := b.acquire(old)
	if err != nil {
		t.Fatalf("old continuation lost at retirement: %v", err)
	}
	_ = continued
	release()
	select {
	case <-b.quiescent:
		t.Fatal("binding completed while original continuation remained")
	default:
	}
	releaseContinuation()
	<-b.quiescent
	if err = b.closeAndWait(); err != nil {
		t.Fatal(err)
	}
	if b.source.(*runtimeBindingTestSource).roots.Load() != 0 {
		t.Fatal("binding acquired logical self lease")
	}
}

func TestReleasedBindingCannotFallbackToPublishedGeneration(t *testing.T) {
	old, next := newRuntimeBindingFixture(t, 1), newRuntimeBindingFixture(t, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &runtimeEndpointPhysical{ctx: ctx, attachments: map[*runtimeEndpointBinding]struct{}{old: {}, next: {}}, active: old}
	old.physical = p
	next.physical = p
	inherited, release, err := old.acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	release()
	p.active = next
	if _, _, _, err = p.bindingContext(inherited, false); err == nil {
		t.Fatal("released old capability fell through to current generation")
	}
	if err = old.closeAndWait(); err != nil {
		t.Fatal(err)
	}
	if err = next.closeAndWait(); err != nil {
		t.Fatal(err)
	}
}

func newRuntimePhysicalFixture() *runtimeEndpointPhysical {
	ctx, cancel := context.WithCancel(context.Background())
	return &runtimeEndpointPhysical{ctx: ctx, cancel: cancel, scope: adapter.NewScope(ctx, nil), callbacks: outbound.NewRuntimeIOFence(nil), carriers: outbound.NewRuntimeIOFenceSet(), attachments: make(map[*runtimeEndpointBinding]struct{}), constructionDone: make(chan struct{}), closeDone: make(chan struct{})}
}

func TestCandidateAbortDoesNotCloseSharedPhysical(t *testing.T) {
	p := newRuntimePhysicalFixture()
	old, next := newRuntimeBindingFixture(t, 1), newRuntimeBindingFixture(t, 2)
	if err := p.attach(old); err != nil {
		t.Fatal(err)
	}
	if err := p.attach(next); err != nil {
		t.Fatal(err)
	}
	p.active = old
	if err := p.detach(next); err != nil {
		t.Fatal(err)
	}
	if p.active != old || p.ctx.Err() != nil {
		t.Fatal("candidate abort changed active physical owner")
	}
	if err := next.closeAndWait(); err != nil {
		t.Fatal(err)
	}
	if err := p.detach(old); err != nil {
		t.Fatal(err)
	}
	if err := old.closeAndWait(); err != nil {
		t.Fatal(err)
	}
	late := newRuntimeBindingFixture(t, 3)
	if err := p.attach(late); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("last-detached owner resurrected: %v", err)
	}
	if err := late.closeAndWait(); err != nil {
		t.Fatal(err)
	}
}

func TestBindingCarrierWaitsActualCloseAndMethodReturn(t *testing.T) {
	b := newRuntimeBindingFixture(t, 1)
	_, release, err := b.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	closeEntered, closeReturn := make(chan struct{}), make(chan struct{})
	fence := outbound.NewRuntimeIOFence(func() error { close(closeEntered); <-closeReturn; return nil })
	methodLeave, err := fence.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	b.holdCarrier(fence, release)
	b.retireRoot()
	go func() { _ = fence.Close() }()
	<-closeEntered
	select {
	case <-b.quiescent:
		t.Fatal("binding completed before original Close returned")
	default:
	}
	close(closeReturn)
	select {
	case <-b.quiescent:
		t.Fatal("binding completed before admitted method returned")
	default:
	}
	methodLeave()
	<-b.quiescent
	if err = b.closeAndWait(); err != nil {
		t.Fatal(err)
	}
}

func TestNestedGenericContinuationPinsBindingFence(t *testing.T) {
	b := newRuntimeBindingFixture(t, 1)
	owned, release, err := b.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	nested, releaseNested, err := adapter.AcquireRuntimeOperation(owned, b.source)
	if err != nil {
		t.Fatal(err)
	}
	release()
	b.retireRoot()
	// This is a generic adapter Fork, not another binding.acquire invocation.
	continuation, releaseContinuation, err := adapter.AcquireRuntimeOperation(nested, b.source)
	if err != nil {
		t.Fatalf("generic old continuation lost: %v", err)
	}
	_ = continuation
	releaseNested()
	select {
	case <-b.quiescent:
		t.Fatal("binding ignored nested generic continuation")
	default:
	}
	releaseContinuation()
	<-b.quiescent
	if err = b.closeAndWait(); err != nil {
		t.Fatal(err)
	}
}

// This source fixture records the immutable pool policy without starting native
// Tailscale/network activity. Actual carrier return is covered separately above.
func TestBindingHTTPIdlePolicyIsFiniteAndImmutable(t *testing.T) {
	data, err := os.ReadFile("runtime_binding.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "IdleConnTimeout:90*time.Second") {
		t.Fatal("binding transport lost standard finite idle policy")
	}
	if !strings.Contains(string(data), "<-b.quiescent") {
		t.Fatal("idle timeout must not replace actual carrier completion")
	}
}

// The LocalClient callback and normal endpoint dialer share this exact custody
// path, while each still invokes its own original connection factory.
func TestBindingCustomDialRetainsExactGeneration(t *testing.T) {
	p := newRuntimePhysicalFixture()
	defer p.cancel()
	b := newRuntimeBindingFixture(t, 1)
	b.physical = p
	raw, peer := net.Pipe()
	defer peer.Close()
	conn, err := b.dialWith(context.Background(), func(ctx context.Context) (net.Conn, error) {
		if _, ok := adapter.RuntimeResourceLeaseFromContext(ctx, b.source.ID()); !ok {
			t.Fatal("original dial lost binding custody")
		}
		return raw, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	b.retireRoot()
	select {
	case <-b.quiescent:
		t.Fatal("live local carrier lost generation")
	default:
	}
	if _, err = b.dialWith(context.Background(), func(context.Context) (net.Conn, error) {
		t.Fatal("retired root invoked original dial")
		return nil, nil
	}); err == nil {
		t.Fatal("retired root accepted")
	}
	if err = conn.Close(); err != nil && !errors.Is(err, outbound.ErrRuntimeClosePending) {
		t.Fatal(err)
	}
	if err = b.closeAndWait(); err != nil {
		t.Fatal(err)
	}
	p.carriers.Stop()
	if err = p.carriers.Wait(); err != nil {
		t.Fatal(err)
	}
	if b.source.(*runtimeBindingTestSource).roots.Load() != 0 {
		t.Fatal("local carrier self-pinned logical source")
	}
}

func TestRuntimeReferenceWaitsForPendingResumeTail(t *testing.T) {
	endpoint := &Endpoint{resumeDone: make(chan struct{})}
	pending := endpoint.resumeDone
	returned := make(chan struct{})
	go func() { endpoint.waitRuntimeResumeCompletion(); close(returned) }()
	select {
	case <-returned:
		t.Fatal("pending native resume tail was not joined")
	default:
	}
	// Completion must be able to take the same lock; the join cannot hold it.
	endpoint.suspendAccess.Lock()
	endpoint.resumeDone = nil
	endpoint.suspendAccess.Unlock()
	close(pending)
	<-returned
	endpoint.waitRuntimeResumeCompletion()
}

type runtimeResumeTestLogger struct {
	log.ContextLogger
	entered chan struct{}
}

func (l *runtimeResumeTestLogger) Error(...any) { close(l.entered) }

func TestRuntimeReferenceCanceledResumeJoinsNativeTail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	logged := make(chan struct{})
	child := &Endpoint{ctx: ctx, logger: &runtimeResumeTestLogger{entered: logged}, resumeDone: make(chan struct{})}
	child.suspended.Store(true)
	pending := child.resumeDone
	physical := newRuntimePhysicalFixture()
	physical.child = child
	logical := &Endpoint{runtime: &runtimeEndpointState{physical: physical, binding: &runtimeEndpointBinding{}}}
	returned := make(chan struct{})
	go func() { logical.SetKeepIdleConnections(true); close(returned) }()
	<-logged // resume observed cancellation; its native completion is still pending.
	select {
	case <-returned:
		t.Fatal("canceled caller abandoned native resume tail")
	default:
	}
	child.suspendAccess.Lock()
	child.resumeDone = nil
	child.suspendAccess.Unlock()
	close(pending)
	<-returned
	physical.cancel()
}
