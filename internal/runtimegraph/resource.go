package runtimegraph

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/sagernet/sing-box/adapter"
)

var errResourceSealed = errors.New("resource owner sealed")

type resourceState uint8

const (
	resourceOpen resourceState = iota
	resourceSealed
	resourceClosing
	resourceClosed
)

// resourceOwner owns one cleanup registration; borrowed handles only add
// references. Adapters must stop worker admission/control work separately,
// and hold a construction lease until all created subresources are registered.
// This does not repair Scope.Add or unblock workers that need close to exit.
type resourceOwner struct {
	mu        sync.Mutex
	state     resourceState
	refs      uint64
	ctx       context.Context
	cancel    context.CancelFunc
	closeFn   func() error
	closeOnce sync.Once
	closed    chan struct{}
	// closeErr is published by closing closed and read only after that signal.
	closeErr     error
	id           adapter.RuntimeResourceID
	retiring     chan struct{}
	dependencies []*resourceLease
}

// parent must be the live host owner, never a preparation/request context.
// Explicit exception: parent cancellation is final host shutdown and may
// cancel this context even with live leases. Ordinary retirement does not.
func newResourceOwner(parent context.Context, closeFn func() error) *resourceOwner {
	ctx, cancel := context.WithCancel(parent)
	return &resourceOwner{ctx: ctx, cancel: cancel, closeFn: closeFn, closed: make(chan struct{}), retiring: make(chan struct{})}
}

func (r *resourceOwner) context() context.Context { return r.ctx }

type resourceLease struct {
	owner    *resourceOwner
	released bool // protected by owner.mu, together with refs
}

func (r *resourceOwner) acquire() (*resourceLease, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != resourceOpen {
		return nil, errResourceSealed
	}
	if r.refs == ^uint64(0) {
		return nil, errors.New("resource reference overflow")
	}
	r.refs++
	return &resourceLease{owner: r}, nil
}

func (l *resourceLease) release() {
	r := l.owner
	r.mu.Lock()
	if l.released {
		r.mu.Unlock()
		return
	}
	l.released = true
	if r.refs == 0 {
		r.mu.Unlock()
		panic("runtimegraph: resource reference underflow")
	}
	r.refs--
	start := r.startCloseLocked()
	r.mu.Unlock()
	if start {
		go r.finishClose()
	}
}

// startCloseLocked reserves the sole close worker; ordinary releases allocate
// no worker. The worker is launched outside the mutex, never on a reader stack.
func (r *resourceOwner) startCloseLocked() bool {
	if r.state == resourceSealed && r.refs == 0 {
		r.state = resourceClosing
		return true
	}
	return false
}

// requestClose seals immediately and never joins cleanup. Reentrant calls
// from closeFn are safe. closeFn must not call waitClosed on its own owner.
func (r *resourceOwner) requestClose() {
	r.mu.Lock()
	if r.state == resourceOpen {
		r.state = resourceSealed
		close(r.retiring)
	}
	start := r.startCloseLocked()
	r.mu.Unlock()
	if start {
		go r.finishClose()
	}
}

func (r *resourceOwner) finishClose() {
	// Retain Box's close-once/sticky-result model, but do not make a lease
	// release join a possibly blocking callback through sync.Once.Do.
	r.closeOnce.Do(func() {
		r.cancel()
		r.closeErr = closeResourceRecovering(r.closeFn)
		// A failed cleanup stays quarantined with its dependency reservations.
		// A timeout/error is not evidence that native users have stopped.
		if r.closeErr == nil {
			for _, dependency := range r.dependencies {
				dependency.release()
			}
		}
		r.mu.Lock()
		r.state = resourceClosed
		r.mu.Unlock()
		close(r.closed)
	})
}

func closeResourceRecovering(closeFn func() error) (err error) {
	defer func() {
		if value := recover(); value != nil {
			err = fmt.Errorf("resource close panic: %v", value)
		}
	}()
	if closeFn != nil {
		return closeFn()
	}
	return nil
}

// waitClosed is the sole joining operation. Caller cancellation neither drops
// leases nor completes cleanup; a later wait can observe the sticky result.
func (r *resourceOwner) waitClosed(ctx context.Context) error {
	select {
	case <-r.closed:
		return r.closeErr
	default:
	}
	select {
	case <-r.closed:
		return r.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}
