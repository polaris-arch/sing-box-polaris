package tun

import (
	"context"
	"errors"
	"sync"

	"github.com/sagernet/sing-tun"
)

// stackShutdown is one sticky cleanup result, not a lifetime authority. Close
// runs only on the scope's shutdown path, outside callbacks/engine guards.
// The separate observer never turns canceled waiting into completed cleanup.
type stackShutdown struct {
	stack tun.Stack

	once     sync.Once
	done     chan struct{}
	err      error
	detached bool
}

func newStackShutdown(stack tun.Stack) *stackShutdown {
	return &stackShutdown{stack: stack, done: make(chan struct{})}
}

func (s *stackShutdown) Close() error {
	s.once.Do(func() {
		s.err = errors.New("TUN stack shutdown did not complete")
		defer close(s.done)
		closeErr := s.stack.Close()
		waiter, ok := s.stack.(tun.StackWithDetachWaiter)
		if !ok {
			s.err = errors.Join(closeErr, errors.New("TUN stack has no detach completion adapter"))
			return
		}
		detachErr := waiter.WaitDetached(context.Background())
		s.detached = detachErr == nil
		s.err = errors.Join(closeErr, detachErr)
	})
	return s.err
}

func (s *stackShutdown) WaitDetached(ctx context.Context) error {
	select {
	case <-s.done:
		return s.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// closeNative preserves ordinary stack-close errors without confusing them with
// failed detach. The done channel publishes both fields; an unfinished or
// failed detach must never release the underlying native device.
func (s *stackShutdown) closeNative(ctx context.Context, closeDevice func() error) error {
	select {
	case <-s.done:
		if !s.detached {
			return s.err
		}
		return errors.Join(s.err, closeDevice())
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WaitDetached observes scope shutdown; it does not initiate it or certify a
// native port implementation's independent callback deregistration.
func (t *Inbound) WaitDetached(ctx context.Context) error {
	if t.runtime != nil {
		t.runtime.mu.Lock()
		operation := t.runtime.operation
		t.runtime.mu.Unlock()
		if operation != nil {
			select {
			case <-operation.done:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		t.runtime.mu.Lock()
		physical := t.runtime.physical
		t.runtime.mu.Unlock()
		if physical == nil {
			return nil
		}
		select {
		case <-physical.done:
			return physical.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if t.stackShutdown == nil {
		return nil
	}
	return t.stackShutdown.WaitDetached(ctx)
}

var _ tun.StackWithDetachWaiter = (*Inbound)(nil)
