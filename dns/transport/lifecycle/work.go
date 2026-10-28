// Package lifecycle joins work owned by a DNS component. It does not allocate
// runtime resource identities or replace the graph/resource reference counts.
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/sagernet/sing-box/adapter"
)

var ErrStopped = errors.New("DNS component stopped")

// Work's zero value is usable. Reserve precedes publication of every goroutine,
// callback and operation. Seal and Reserve share only this short admission lock;
// cancellation, I/O, user callbacks and joins never run under it.
type Work struct {
	access  sync.Mutex
	sealed  bool
	workers sync.WaitGroup
}

func (w *Work) Reserve() (func(), bool) {
	w.access.Lock()
	if w.sealed {
		w.access.Unlock()
		return nil, false
	}
	w.workers.Add(1)
	w.access.Unlock()
	var once sync.Once
	return func() { once.Do(w.workers.Done) }, true
}

func (w *Work) Seal()        { w.access.Lock(); w.sealed = true; w.access.Unlock() }
func (w *Work) Sealed() bool { w.access.Lock(); defer w.access.Unlock(); return w.sealed }
func (w *Work) Wait()        { w.workers.Wait() }
func (w *Work) Go(f func()) bool {
	done, ok := w.Reserve()
	if !ok {
		return false
	}
	go func() { defer done(); f() }()
	return true
}

// AfterFunc retains its work slot when stop returns false. The returned stop is
// nonjoining, so it is safe from the callback itself; Wait observes completion.
func (w *Work) AfterFunc(ctx context.Context, f func()) (func() bool, bool) {
	done, ok := w.Reserve()
	if !ok {
		return nil, false
	}
	stop := context.AfterFunc(ctx, func() { defer done(); f() })
	var once sync.Once
	var stopped bool
	return func() bool {
		once.Do(func() {
			stopped = stop()
			if stopped {
				done()
			}
		})
		return stopped
	}, true
}

// Operation captures both the graph continuation and the receiving resource.
// Call this separately for an invocation and for each escaping callback. Caller
// cancellation never releases it; only the actual final stack releases it.
func (w *Work) Operation(ctx context.Context, source adapter.RuntimeResourceSource) (context.Context, func(), error) {
	done, ok := w.Reserve()
	if !ok {
		return nil, nil, ErrStopped
	}
	ctx, release, err := adapter.AcquireRuntimeOperation(ctx, source)
	if err != nil {
		done()
		return nil, nil, err
	}
	var once sync.Once
	return ctx, func() { once.Do(func() { release(); done() }) }, nil
}

// LinkCancellation preserves caller ownership/values and joins the cancellation
// callback before release. Its callback only cancels a context, never user work.
func LinkCancellation(ctx, lifetime context.Context) (context.Context, func()) {
	linked, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	stop := context.AfterFunc(lifetime, func() { defer close(done); cancel() })
	if lifetime.Err() != nil {
		cancel()
	}
	return linked, func() {
		if !stop() {
			<-done
		}
		cancel()
	}
}

// ConstructionCleanup never cleans a standalone constructor accidentally.
// DeferConstructionCleanup may execute immediately for a closed scope. A
// constructor must reject that case even when the cleanup itself succeeded.
func ConstructionCleanup(ctx context.Context, cleanup func() error) (bool, error) {
	if !adapter.HasConstructionScope(ctx) {
		if err := ctx.Err(); err != nil {
			return false, errors.Join(err, cleanup())
		}
		return false, nil
	}
	var access sync.Mutex
	cleaned := false
	err := adapter.DeferConstructionCleanup(ctx, func() error {
		access.Lock()
		cleaned = true
		access.Unlock()
		return cleanup()
	})
	access.Lock()
	wasCleaned := cleaned
	access.Unlock()
	if err != nil {
		return true, err
	}
	if wasCleaned {
		return true, ErrStopped
	}
	if err := adapter.ConstructionScopeErr(ctx); err != nil {
		return true, err
	}
	if err := ctx.Err(); err != nil {
		return true, err
	}
	return true, nil
}

// Uncertain deliberately has no Unwrap. Scope.Close filters cancellation and
// closed errors; filtering an unproven native join would release dependencies.
func Uncertain(component string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s completion uncertain: %v", component, err)
}

// CleanupResult is for close workers launched off a caller stack. A panic is
// sticky uncertainty, exactly as it is at the resource owner's close boundary.
func CleanupResult(component string, cleanup func() error) (err error) {
	defer func() {
		if value := recover(); value != nil {
			err = fmt.Errorf("%s cleanup panic: %v", component, value)
		}
	}()
	return cleanup()
}
