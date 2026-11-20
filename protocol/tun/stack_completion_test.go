package tun

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-tun"
)

type shutdownBarrierStack struct {
	tun.Stack
	entered   chan struct{}
	finish    chan struct{}
	closeErr  error
	detachErr error
	closed    bool
}

func (s *shutdownBarrierStack) Close() error { s.closed = true; return s.closeErr }
func (s *shutdownBarrierStack) WaitDetached(ctx context.Context) error {
	if !s.closed {
		panic("wait preceded Close")
	}
	close(s.entered)
	select {
	case <-s.finish:
		return s.detachErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestInboundShutdownWaitsForActualDetachAndKeepsFailure(t *testing.T) {
	failure := errors.New("detach quarantined")
	stack := &shutdownBarrierStack{entered: make(chan struct{}), finish: make(chan struct{}), detachErr: failure}
	shutdown := newStackShutdown(stack)
	inbound := &Inbound{stackShutdown: shutdown}
	result := make(chan error, 1)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(stack.finish) }) }
	var workers sync.WaitGroup
	t.Cleanup(func() { release(); workers.Wait() })
	workers.Go(func() { result <- shutdown.Close() })
	select {
	case <-stack.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("detach entry watchdog")
	}
	select {
	case <-result:
		t.Fatal("Close returned at callback entry")
	default:
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := inbound.WaitDetached(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("observer cancellation: %v", err)
	}
	select {
	case <-result:
		t.Fatal("observer canceled cleanup")
	default:
	}
	release()
	select {
	case err := <-result:
		if !errors.Is(err, failure) {
			t.Fatalf("lost failure: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup watchdog")
	}
	if err := inbound.WaitDetached(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("completion forgot failure: %v", err)
	}
	if err := shutdown.Close(); !errors.Is(err, failure) {
		t.Fatalf("repeated close forgot failure: %v", err)
	}
}

type noCompletionStack struct{ tun.Stack }

func (*noCompletionStack) Close() error { return nil }

func TestInboundShutdownMissingCompletionFailsClosed(t *testing.T) {
	shutdown := newStackShutdown(&noCompletionStack{})
	if err := shutdown.Close(); err == nil {
		t.Fatal("missing completion was accepted")
	}
	if err := shutdown.WaitDetached(context.Background()); err == nil {
		t.Fatal("missing completion lost its sticky error")
	}
}

func TestNativeCleanupAfterCompletedDetachPreservesCloseErrors(t *testing.T) {
	stackErr := errors.New("stack close failed")
	nativeErr := errors.New("native cleanup failed")
	stack := &shutdownBarrierStack{entered: make(chan struct{}), finish: make(chan struct{}), closeErr: stackErr}
	close(stack.finish)
	shutdown := newStackShutdown(stack)
	if err := shutdown.Close(); !errors.Is(err, stackErr) {
		t.Fatalf("stack close error lost: %v", err)
	}
	calls := 0
	err := shutdown.closeNative(context.Background(), func() error { calls++; return nativeErr })
	if calls != 1 || !errors.Is(err, stackErr) || !errors.Is(err, nativeErr) {
		t.Fatalf("completed detach skipped cleanup or lost errors: calls=%d err=%v", calls, err)
	}
}

func TestNativeCleanupDoesNotReleaseUnconfirmedDetach(t *testing.T) {
	failure := errors.New("detach failed")
	stack := &shutdownBarrierStack{entered: make(chan struct{}), finish: make(chan struct{}), detachErr: failure}
	close(stack.finish)
	shutdown := newStackShutdown(stack)
	_ = shutdown.Close()
	calls := 0
	err := shutdown.closeNative(context.Background(), func() error { calls++; return nil })
	if calls != 0 || !errors.Is(err, failure) {
		t.Fatalf("failed detach released native device: calls=%d err=%v", calls, err)
	}
	pending := newStackShutdown(&noCompletionStack{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := pending.closeNative(ctx, func() error { calls++; return nil }); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("pending detach released native device: calls=%d err=%v", calls, err)
	}
	_ = pending.Close()
	if err := pending.closeNative(context.Background(), func() error { calls++; return nil }); err == nil || calls != 0 {
		t.Fatalf("missing adapter released native device: calls=%d err=%v", calls, err)
	}
}
