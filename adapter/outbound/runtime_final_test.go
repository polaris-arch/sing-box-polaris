package outbound

import (
	"context"
	"errors"
	"testing"
)

func TestRuntimeFinalNestedExternalCloseJoinsPending(t *testing.T) {
	raw := &lifecycleConn{closeEntered: make(chan struct{}), closeContinue: make(chan struct{})}
	var innerReleases, outerReleases int
	inner := WrapRuntimeConn(context.Background(), func() { innerReleases++ }, raw)
	outer := WrapRuntimeConn(context.Background(), func() { outerReleases++ }, inner)
	innerDone := make(chan error, 1)
	go func() { innerDone <- inner.Close() }()
	<-raw.closeEntered
	wait, ok := RuntimeConnectionCloseWaiter(outer)
	if !ok {
		t.Fatal("private waiter missing")
	}
	outerDone := make(chan error, 1)
	go func() { outerDone <- wait() }()
	select {
	case <-outerDone:
		t.Fatal("nested pending treated as failure/completion")
	default:
	}
	close(raw.closeContinue)
	if err := <-innerDone; err != nil {
		t.Fatal(err)
	}
	if err := <-outerDone; err != nil {
		t.Fatal(err)
	}
	if raw.closes.Load() != 1 || innerReleases != 1 || outerReleases != 1 {
		t.Fatal("nested close/release not exactly once")
	}
}

func TestRuntimeFinalOwnedWaiterJoinsMethodAndClose(t *testing.T) {
	raw := &lifecycleConn{}
	conn, fence := WrapRuntimeOwnedConn(raw)
	release, err := fence.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	wait, ok := RuntimeConnectionCloseWaiter(conn)
	if !ok {
		t.Fatal("private waiter missing")
	}
	done := make(chan error, 1)
	go func() { done <- wait() }()
	<-fence.state.closeSignal
	select {
	case <-done:
		t.Fatal("active method not joined")
	default:
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if raw.closes.Load() != 1 {
		t.Fatal("duplicate close")
	}
}

func TestRuntimeFinalUnknownWrapperHasNoPrivateWaiter(t *testing.T) {
	raw := &lifecycleConn{}
	conn, _ := WrapRuntimeOwnedConn(raw)
	if _, ok := RuntimeConnectionCloseWaiter(&lifecycleProtocolWrapper{Conn: conn}); ok {
		t.Fatal("unknown wrapper implicitly unwrapped")
	}
	if _, ok := RuntimeConnectionCloseWaiter(raw); ok {
		t.Fatal("raw conn gained private completion")
	}
	if !errors.Is(conn.Close(), ErrRuntimeClosePending) {
		t.Fatal("ordinary owned Close changed semantics")
	}
	wait, _ := RuntimeConnectionCloseWaiter(conn)
	if err := wait(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeFinalInboundCompletionPreservesAndDeduplicates(t *testing.T) {
	a := &lifecycleConn{closeEntered: make(chan struct{}), closeContinue: make(chan struct{})}
	b := &lifecycleConn{closeEntered: make(chan struct{}), closeContinue: make(chan struct{})}
	ca, _ := WrapRuntimeOwnedConn(a)
	cb, _ := WrapRuntimeOwnedConn(b)
	ctx := ContextWithRuntimeInboundClose(context.Background(), ca)
	ctx = ContextWithRuntimeInboundClose(ctx, ca)
	ctx = ContextWithRuntimeInboundClose(ctx, cb)
	targets := ctx.Value(runtimeInboundCloseContextKey{}).([]runtimeInboundCloseTarget)
	if len(targets) != 2 {
		t.Fatal("accepted carrier lost or duplicated")
	}
	wait, ok := RuntimeInboundCloseFromContext(ctx)
	if !ok {
		t.Fatal("completion missing")
	}
	done := make(chan error, 1)
	go func() { done <- wait() }()
	<-a.closeEntered
	<-b.closeEntered
	select {
	case <-done:
		t.Fatal("completion returned before both native closes")
	default:
	}
	close(a.closeContinue)
	close(b.closeContinue)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if a.closes.Load() != 1 || b.closes.Load() != 1 {
		t.Fatal("duplicate private close")
	}
	if _, ok = RuntimeInboundCloseFromContext(context.Background()); ok {
		t.Fatal("unknown context gained completion")
	}
}

func TestRuntimeFinalPrivateWaiterPanicIsUnknown(t *testing.T) {
	raw := &lifecycleConn{}
	conn := WrapRuntimeConn(context.Background(), func() { panic("private release secret marker") }, raw)
	ctx := ContextWithRuntimeInboundClose(context.Background(), conn)
	wait, ok := RuntimeInboundCloseFromContext(ctx)
	if !ok {
		t.Fatal("missing private control")
	}
	err := wait()
	if err == nil || err.Error() != "runtime private connection close wait panicked; completion unknown" {
		t.Fatalf("panic not fixed unknown: %v", err)
	}
}
