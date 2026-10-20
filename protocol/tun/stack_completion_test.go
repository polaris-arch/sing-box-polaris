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
	workers.Add(1)
	go func() { defer workers.Done(); result <- shutdown.Close() }()
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
