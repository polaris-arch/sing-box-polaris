package device

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-tun"
)

type completionBarrierStack struct {
	deviceIPStack
	closed    chan struct{}
	entered   chan struct{}
	finish    chan struct{}
	once      sync.Once
	closeErr  error
	detachErr error
}

func (s *completionBarrierStack) Close() error {
	s.once.Do(func() { close(s.closed) })
	return s.closeErr
}

func (s *completionBarrierStack) WaitDetached(ctx context.Context) error {
	select {
	case <-s.closed:
	default:
		panic("wait preceded actual stack Close")
	}
	select {
	case s.entered <- struct{}{}:
	default:
	}
	select {
	case <-s.finish:
		return s.detachErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func awaitCompletionEvent(t *testing.T, event <-chan struct{}) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(5 * time.Second):
		t.Fatal("completion barrier watchdog")
	}
}

func TestDeviceWaitDetachedUsesActualStackAndStickyErrors(t *testing.T) {
	for _, system := range []bool{false, true} {
		t.Run(map[bool]string{false: "stack", true: "system-stack"}[system], func(t *testing.T) {
			closeFailure := errors.New("close failed")
			detachFailure := errors.New("detach quarantined")
			stack := &completionBarrierStack{closed: make(chan struct{}), entered: make(chan struct{}, 2), finish: make(chan struct{}), closeErr: closeFailure, detachErr: detachFailure}
			var finishOnce sync.Once
			finish := func() { finishOnce.Do(func() { close(stack.finish) }) }
			var device Device
			child := &stackDevice{stack: stack, memoryTun: tun.NewMemoryTun(tun.MemoryTunOptions{MTU: 1500}), closeDone: make(chan struct{})}
			device = child
			if system {
				device = &systemStackDevice{systemDevice: &systemDevice{}, stackDevice: child, closeDone: make(chan struct{})}
			}
			result := make(chan error, 1)
			var workers sync.WaitGroup
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(func() { finish(); cancel(); workers.Wait(); _ = device.Close() })
			if err := device.Close(); !errors.Is(err, closeFailure) {
				t.Fatalf("lost Close failure: %v", err)
			}
			if err := device.Close(); !errors.Is(err, closeFailure) {
				t.Fatalf("repeated Close erased failure: %v", err)
			}
			workers.Add(1)
			go func() { defer workers.Done(); result <- device.WaitDetached(ctx) }()
			awaitCompletionEvent(t, stack.entered)
			select {
			case <-result:
				t.Fatal("callback entry was mistaken for completion")
			default:
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("observer cancellation: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("observer watchdog")
			}
			// Cancellation is only observation. Actual completion still needs finish.
			workers.Add(1)
			go func() { defer workers.Done(); result <- device.WaitDetached(context.Background()) }()
			awaitCompletionEvent(t, stack.entered)
			select {
			case <-result:
				t.Fatal("canceled observer completed cleanup")
			default:
			}
			finish()
			select {
			case err := <-result:
				if !errors.Is(err, closeFailure) || !errors.Is(err, detachFailure) {
					t.Fatalf("lost sticky failures: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("completion watchdog")
			}
		})
	}
}

func TestCloseAndWaitDoesNotFlattenCloseIntoCompletion(t *testing.T) {
	failure := errors.New("detach quarantined")
	stack := &completionBarrierStack{closed: make(chan struct{}), entered: make(chan struct{}, 1), finish: make(chan struct{}), detachErr: failure}
	device := &stackDevice{stack: stack, memoryTun: tun.NewMemoryTun(tun.MemoryTunOptions{MTU: 1500}), closeDone: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(stack.finish) }) }
	var workers sync.WaitGroup
	t.Cleanup(func() { release(); workers.Wait(); _ = device.Close() })
	result := make(chan error, 1)
	workers.Add(1)
	go func() { defer workers.Done(); result <- CloseAndWait(device) }()
	awaitCompletionEvent(t, stack.entered)
	select {
	case <-result:
		t.Fatal("scope cleanup completed at stack Close return")
	default:
	}
	release()
	select {
	case err := <-result:
		if !errors.Is(err, failure) {
			t.Fatalf("lost completion failure: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("scope cleanup watchdog")
	}
}
