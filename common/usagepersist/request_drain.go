package usagepersist

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
)

// RequestDrain joins all admitted HTTP producers before their final usage flush.
// It does not impose an additional timeout or alter a live request's context.
type RequestDrain struct {
	access sync.Mutex
	closed bool
	next   uint64
	active map[uint64]context.CancelFunc
	group  sync.WaitGroup
	once   sync.Once
	done   chan struct{}
	err    error
}

func (d *RequestDrain) Wrap(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.access.Lock()
		if d.closed {
			d.access.Unlock()
			http.Error(w, "service is shutting down", http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithCancel(r.Context())
		if d.active == nil {
			d.active = make(map[uint64]context.CancelFunc)
		}
		d.next++
		id := d.next
		d.active[id] = cancel
		d.group.Add(1)
		d.access.Unlock()
		defer func() {
			cancel()
			d.access.Lock()
			delete(d.active, id)
			d.access.Unlock()
			d.group.Done()
		}()
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

// PendingError deliberately does not unwrap the observer cancellation: Scope
// filters ordinary cancellation, but an unfinished persistence tail is not a
// successfully completed close. Cause remains available for diagnostics.
type PendingError struct {
	Cause error
}

func (e *PendingError) Error() string {
	return fmt.Sprintf("usage producers/final flush remain pending: %v", e.Cause)
}

// Close returns the caller's deadline if producers have not joined. The single
// retained finalizer keeps ownership and flushes only after they actually exit;
// later Close calls observe the same completion, not a second final flush.
func (d *RequestDrain) Close(ctx context.Context, closeServer func() error, finalize func() error) error {
	d.once.Do(func() {
		d.done = make(chan struct{})
		d.access.Lock()
		d.closed = true
		for _, cancel := range d.active {
			cancel()
		}
		d.access.Unlock()
		go func() {
			defer close(d.done)
			defer func() {
				if recovered := recover(); recovered != nil {
					d.err = errors.Join(d.err, fmt.Errorf("panic while draining usage: %v", recovered))
				}
			}()
			serverErr := guardedCleanup("server close", closeServer)
			d.group.Wait()
			d.err = errors.Join(serverErr, guardedCleanup("final usage flush", finalize))
		}()
	})
	select {
	case <-d.done:
		return d.err
	case <-ctx.Done():
		select {
		case <-d.done:
			return d.err
		default:
			return &PendingError{Cause: ctx.Err()}
		}
	}
}

// Shutdown callbacks run outside Scope's stack after an observer timeout, so
// they must preserve its panic-to-error boundary themselves.
func guardedCleanup(stage string, cleanup func() error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("panic during %s: %v", stage, recovered)
		}
	}()
	return cleanup()
}
