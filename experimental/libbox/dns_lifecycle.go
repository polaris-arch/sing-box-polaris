package libbox

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// These primitives provide local bookkeeping, never proof of gomobile proxy
// reclamation or an operational Close result.
type dnsCancelRegistration struct {
	access   sync.Mutex
	callback func() error
	stop     func() bool
	finished chan struct{}
	once     sync.Once
	failure  error
	armed    bool
	stopped  bool
}

func newDNSCancelRegistration(ctx context.Context, callback func() error) *dnsCancelRegistration {
	r := makeDNSCancelRegistration(callback)
	r.arm(ctx)
	return r
}

func makeDNSCancelRegistration(callback func() error) *dnsCancelRegistration {
	return &dnsCancelRegistration{callback: callback, finished: make(chan struct{})}
}

// Publication on ExchangeContext and arming are separate: AfterFunc is never
// called under its response gate. Completion before arm prevents registration.
func (r *dnsCancelRegistration) arm(ctx context.Context) {
	// A pre-canceled context can launch invoke immediately. Publish stop under
	// the same lock it takes before consuming callback, with finished ready first.
	r.access.Lock()
	defer r.access.Unlock()
	if r.stopped || r.armed {
		return
	}
	r.armed = true
	r.stop = context.AfterFunc(ctx, r.invoke)
}

func (r *dnsCancelRegistration) invoke() {
	var failure error
	defer func() {
		if recovered := recover(); recovered != nil {
			failure = fmt.Errorf("DNS cancellation callback panicked: %v", recovered)
		}
		r.access.Lock()
		r.failure = failure
		r.access.Unlock()
		r.once.Do(func() { close(r.finished) })
	}()
	r.access.Lock()
	callback := r.callback
	r.callback, r.stop = nil, nil
	r.access.Unlock()
	if callback != nil {
		failure = callback()
	}
}

// stopAndDetach never waits, so it is safe inside the callback itself. A false
// AfterFunc stop result is not completion; only finished proves callback exit.
func (r *dnsCancelRegistration) stopAndDetach() <-chan struct{} {
	r.access.Lock()
	r.stopped = true
	stop := r.stop
	unarmed := !r.armed
	r.stop, r.callback = nil, nil
	r.access.Unlock()
	if unarmed || (stop != nil && stop()) {
		r.once.Do(func() { close(r.finished) })
	}
	return r.finished
}

func (r *dnsCancelRegistration) result() error {
	r.access.Lock()
	defer r.access.Unlock()
	return r.failure
}

var errDNSCallAdmissionClosed = errors.New("DNS call admission is closed")

type dnsCallGate struct {
	access  sync.Mutex
	sealed  bool
	calls   map[*dnsCallLease]struct{}
	failure error
}

type dnsCallSnapshot struct {
	sealed   bool
	inFlight int
	failure  error
}

type dnsCallLease struct {
	owner         *dnsCallGate
	ctx           context.Context
	cancel        context.CancelFunc
	cleanupCancel context.CancelFunc
	aborted       chan struct{}
	abortOnce     sync.Once
	once          sync.Once
}

// begin must run before launching the platform-call goroutine. Admission and
// seal use the same gate; no WaitGroup can race a later Add.
func (g *dnsCallGate) begin(ctx context.Context) (*dnsCallLease, error) {
	g.access.Lock()
	defer g.access.Unlock()
	return g.beginLocked(ctx)
}

func (g *dnsCallGate) beginLocked(ctx context.Context) (*dnsCallLease, error) {
	if g.sealed {
		return nil, errDNSCallAdmissionClosed
	}
	ctx, cancel := context.WithCancel(ctx)
	lease := &dnsCallLease{owner: g, ctx: ctx, cleanupCancel: cancel, aborted: make(chan struct{})}
	lease.cancel = func() {
		lease.abortOnce.Do(func() { close(lease.aborted) })
		cancel()
	}
	if g.calls == nil {
		g.calls = make(map[*dnsCallLease]struct{})
	}
	g.calls[lease] = struct{}{}
	return lease, nil
}

// sealAndSnapshot performs no SDK/JNI calls, cancellation or waiting under the
// gate. Its caller can request cancellation outside the gate. Neither an empty
// snapshot nor a nil failure is an exact cleanup or operational-close receipt.
func (g *dnsCallGate) sealAndSnapshot() ([]context.CancelFunc, dnsCallSnapshot) {
	g.access.Lock()
	defer g.access.Unlock()
	return g.sealAndSnapshotLocked()
}

func (g *dnsCallGate) sealAndSnapshotLocked() ([]context.CancelFunc, dnsCallSnapshot) {
	g.sealed = true
	cancels := make([]context.CancelFunc, 0, len(g.calls))
	for lease := range g.calls {
		cancels = append(cancels, lease.cancel)
	}
	return cancels, g.snapshotLocked()
}

func (g *dnsCallGate) snapshot() dnsCallSnapshot {
	g.access.Lock()
	defer g.access.Unlock()
	return g.snapshotLocked()
}

func (g *dnsCallGate) snapshotLocked() dnsCallSnapshot {
	return dnsCallSnapshot{sealed: g.sealed, inFlight: len(g.calls), failure: g.failure}
}

// returned is only for the platform-call owner after Exchange/Lookup actually
// returns. ctx.Done, upper-call timeout and cancellation must never call it.
// It does not join callbacks: a running drain task retains the lease until all
// registrations finish, including when this method runs inside a callback.
func (l *dnsCallLease) returned(registrations ...*dnsCancelRegistration) {
	l.once.Do(func() {
		// The drain task exclusively owns this copy even if a future caller
		// accidentally reuses its input slice after returned finishes.
		registrations = append([]*dnsCancelRegistration(nil), registrations...)
		var pending []<-chan struct{}
		for _, registration := range registrations {
			finished := registration.stopAndDetach()
			select {
			case <-finished:
			default:
				pending = append(pending, finished)
			}
		}
		release := func() {
			for _, finished := range pending {
				<-finished
			}
			var failures []error
			for _, registration := range registrations {
				failures = append(failures, registration.result())
			}
			g := l.owner
			g.access.Lock()
			delete(g.calls, l)
			g.failure = errors.Join(g.failure, errors.Join(failures...))
			cancel := l.cleanupCancel
			l.ctx, l.cancel, l.cleanupCancel = nil, nil, nil
			g.access.Unlock()
			cancel()
		}
		if len(pending) == 0 {
			release()
		} else {
			go release()
		}
	})
}
