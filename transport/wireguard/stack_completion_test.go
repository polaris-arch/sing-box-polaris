package wireguard

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-tun"
	wgTun "github.com/sagernet/wireguard-go/tun"
)

type completionBarrierStack struct {
	deviceIPStack
	closed chan struct{}
	entered chan struct{}
	finish chan struct{}
	once sync.Once
	closeErr error
	detachErr error
}
func (s *completionBarrierStack) Close() error { s.once.Do(func() { close(s.closed) }); return s.closeErr }
func (s *completionBarrierStack) WaitDetached(ctx context.Context) error {
	select { case <-s.closed: default: panic("wait preceded actual stack Close") }
	select { case s.entered <- struct{}{}: default: }
	select { case <-s.finish: return s.detachErr; case <-ctx.Done(): return ctx.Err() }
}

func awaitCompletionEvent(t *testing.T, event <-chan struct{}) {
	t.Helper()
	select { case <-event: case <-time.After(5 * time.Second): t.Fatal("completion barrier watchdog") }
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
			router := &peerRouter{memoryTun: tun.NewMemoryTun(tun.MemoryTunOptions{MTU: 1500})}
			if system {
				device = &systemStackDevice{systemDevice: &systemDevice{events: make(chan wgTun.Event), closeDone: make(chan struct{})}, stack: stack, router: router, closeDone: make(chan struct{})}
			} else {
				device = &stackDevice{stack: stack, router: router, events: make(chan wgTun.Event), closed: make(chan struct{}), closeDone: make(chan struct{})}
			}
			result := make(chan error, 1)
			var workers sync.WaitGroup
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(func() { finish(); cancel(); workers.Wait(); _ = device.Close() })
			if err := device.Close(); !errors.Is(err, closeFailure) { t.Fatalf("lost Close failure: %v", err) }
			if err := device.Close(); !errors.Is(err, closeFailure) { t.Fatalf("repeated Close erased failure: %v", err) }
			workers.Add(1)
			go func() { defer workers.Done(); result <- device.WaitDetached(ctx) }()
			awaitCompletionEvent(t, stack.entered)
			select { case <-result: t.Fatal("callback entry was mistaken for completion"); default: }
			cancel()
			select { case err := <-result: if !errors.Is(err, context.Canceled) { t.Fatalf("observer cancellation: %v", err) }; case <-time.After(5 * time.Second): t.Fatal("observer watchdog") }
			// Cancellation is only observation. Actual completion still needs finish.
			workers.Add(1)
			go func() { defer workers.Done(); result <- device.WaitDetached(context.Background()) }()
			awaitCompletionEvent(t, stack.entered)
			select { case <-result: t.Fatal("canceled observer completed cleanup"); default: }
			finish()
			select {
			case err := <-result:
				if !errors.Is(err, closeFailure) || !errors.Is(err, detachFailure) { t.Fatalf("lost sticky failures: %v", err) }
			case <-time.After(5 * time.Second): t.Fatal("completion watchdog")
			}
		})
	}
}

type endpointCompletionDevice struct {
	Device
	endpoint *Endpoint
	entered chan struct{}
	finish chan struct{}
	failure error
}
func (d *endpointCompletionDevice) Close() error {
	// This would deadlock if Endpoint.Close still held stateAccess while calling
	// a device whose copied callback needed the same guard.
	d.endpoint.stateAccess.Lock()
	d.endpoint.stateAccess.Unlock()
	return nil
}
func (d *endpointCompletionDevice) WaitDetached(ctx context.Context) error {
	close(d.entered)
	select { case <-d.finish: return d.failure; case <-ctx.Done(): return ctx.Err() }
}

func TestEndpointClosePropagatesActualDeviceCompletion(t *testing.T) {
	failure := errors.New("device completion failed")
	endpoint := &Endpoint{closeDone: make(chan struct{})}
	device := &endpointCompletionDevice{endpoint: endpoint, entered: make(chan struct{}), finish: make(chan struct{}), failure: failure}
	endpoint.tunDevice = device
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(device.finish) }) }
	var workers sync.WaitGroup
	t.Cleanup(func() { release(); workers.Wait() })
	result := make(chan error, 1)
	workers.Add(1)
	go func() { defer workers.Done(); result <- endpoint.Close() }()
	awaitCompletionEvent(t, device.entered)
	select { case <-result: t.Fatal("endpoint completed before its device"); default: }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := endpoint.WaitDetached(ctx); !errors.Is(err, context.Canceled) { t.Fatalf("observer cancellation: %v", err) }
	release()
	select { case err := <-result: if !errors.Is(err, failure) { t.Fatalf("lost completion error: %v", err) }; case <-time.After(5 * time.Second): t.Fatal("endpoint close watchdog") }
	if err := endpoint.Close(); !errors.Is(err, failure) { t.Fatalf("repeated endpoint close erased failure: %v", err) }
	if err := endpoint.WaitDetached(context.Background()); !errors.Is(err, failure) { t.Fatalf("endpoint observer erased failure: %v", err) }
}

func TestPlainSystemDeviceEmptyCloseHasNoInventedFailure(t *testing.T) {
	device := &systemDevice{events: make(chan wgTun.Event), closeDone: make(chan struct{})}
	if err := device.Close(); err != nil { t.Fatalf("empty system device: %v", err) }
	if err := device.WaitDetached(context.Background()); err != nil { t.Fatalf("empty system device completion: %v", err) }
}
