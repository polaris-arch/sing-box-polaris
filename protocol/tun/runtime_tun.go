package tun

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
)

type (
	runtimePhysicalTunKey struct{}
	runtimeTunPhysical    struct {
		inbound   *Inbound
		scope     *adapter.Scope
		callbacks *outbound.RuntimeIOFence
		cancel    context.CancelFunc
		gate      atomic.Bool
		once      sync.Once
		done      chan struct{}
		err       error
	}
)

func (p *runtimeTunPhysical) close() error {
	p.once.Do(func() {
		p.gate.Store(false)
		p.cancel()
		p.err = tls.NewRuntimeCleanupError(errors.New("TUN physical cleanup did not complete"))
		defer close(p.done)
		p.err = errors.Join(p.callbacks.RuntimeCloseAndWait(), p.scope.Close())
	})
	<-p.done
	return p.err
}

type (
	runtimeTunOperation struct {
		done chan struct{}
		err  error
	}
	runtimeTunState struct {
		mu           sync.Mutex
		owner        *Inbound
		options      option.TunInboundOptions
		openPhysical func(*runtimeTunPhysical) error
		physical     *runtimeTunPhysical
		operation    *runtimeTunOperation
		closing      bool
		closed       chan struct{}
		closeOnce    sync.Once
		closeErr     error
	}
)

func (t *Inbound) initializeRuntimeTun(options option.TunInboundOptions) error {
	state := &runtimeTunState{owner: t, options: options, closed: make(chan struct{})}
	t.runtime = state
	state.openPhysical = t.openRuntimePhysical
	if err := adapter.DeferConstructionCleanup(t.ctx, t.RuntimeCloseAndWait); err != nil {
		return err
	}
	return adapter.ConstructionScopeErr(t.ctx)
}

func (t *Inbound) RuntimeValidate() error {
	if t.runtime == nil {
		return errors.New("TUN lacks private physical lifecycle")
	}
	return nil
}

func (t *Inbound) PrepareRuntime(adapter.StartStage, *adapter.Scope) error {
	return t.RuntimeValidate()
}
func (t *Inbound) RuntimeListeners() []*listener.Listener { return nil }
func (t *Inbound) RuntimeStop() {
	if t.runtime == nil {
		return
	}
	t.runtime.mu.Lock()
	p := t.runtime.physical
	t.runtime.mu.Unlock()
	if p != nil {
		p.gate.Store(false)
	}
}

func (t *Inbound) RuntimeCloseAndWait() error {
	r := t.runtime
	if r == nil {
		return errors.New("missing TUN runtime owner")
	}
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closing = true
		operation := r.operation
		r.mu.Unlock()
		r.closeErr = tls.NewRuntimeCleanupError(errors.New("TUN owner cleanup did not complete"))
		defer close(r.closed)
		if operation != nil {
			<-operation.done
		}
		r.mu.Lock()
		physical := r.physical
		r.mu.Unlock()
		if physical != nil {
			r.closeErr = physical.close()
		} else {
			r.closeErr = nil
		}
		if operation != nil && tls.IsRuntimeCleanupIncomplete(operation.err) {
			r.closeErr = tls.NewRuntimeCleanupError(errors.Join(r.closeErr, operation.err))
		}
	})
	<-r.closed
	return r.closeErr
}

// runPhysical owns an actual operation until its goroutine returns. A caller's
// cancellation only ends observation; it never clears the operation or closes
// an object that the still-running constructor is using.
func (r *runtimeTunState) runPhysical(ctx context.Context, fn func() error) error {
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return errors.New("TUN owner closing")
	}
	if previous := r.operation; previous != nil {
		select {
		case <-previous.done:
		default:
			r.mu.Unlock()
			return errors.New("TUN physical operation still in progress")
		}
	}
	operation := &runtimeTunOperation{done: make(chan struct{})}
	r.operation = operation
	r.mu.Unlock()
	go func() {
		operation.err = tls.NewRuntimeCleanupError(errors.New("TUN physical operation did not return"))
		defer func() {
			if recover() != nil {
				operation.err = tls.NewRuntimeCleanupError(errors.New("TUN physical operation panicked; resource retained"))
			}
			close(operation.done)
		}()
		operation.err = fn()
	}()
	select {
	case <-operation.done:
		return operation.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *Inbound) RuntimeStagePhysical(ctx context.Context) error {
	if err := t.RuntimeValidate(); err != nil {
		return err
	}
	r := t.runtime
	return r.runPhysical(ctx, func() error {
		r.mu.Lock()
		existing := r.physical
		r.mu.Unlock()
		if existing != nil {
			select {
			case <-existing.done:
				if existing.err != nil {
					return existing.err
				}
			default:
				return errors.New("TUN physical instance already exists")
			}
		}
		physicalContext, cancel := context.WithCancel(t.ctx)
		callbacks := outbound.NewRuntimeIOFence(nil)
		logger := outbound.WrapRuntimeLogger(t.logger, callbacks)
		scope := adapter.NewScope(physicalContext, logger)
		physical := &runtimeTunPhysical{scope: scope, callbacks: callbacks, cancel: cancel, done: make(chan struct{})}
		// Retain failed/partial physical state before invoking constructors or OS I/O.
		r.mu.Lock()
		r.physical = physical
		r.mu.Unlock()
		if err := r.openPhysical(physical); err != nil {
			return errors.Join(err, physical.close())
		}
		return nil
	})
}

func (t *Inbound) RuntimeSuspendPhysical(ctx context.Context) error {
	if err := t.RuntimeValidate(); err != nil {
		return err
	}
	return t.runtime.runPhysical(ctx, func() error {
		t.runtime.mu.Lock()
		physical := t.runtime.physical
		t.runtime.mu.Unlock()
		if physical == nil {
			return nil
		}
		return physical.close()
	})
}

// RuntimeTunPublication is a prevalidated, concrete memory-only participant.
// The Box store guard excludes new graph admissions while Publish opens gates.
type RuntimeTunPublication struct{ physical []*runtimeTunPhysical }

func PrepareRuntimeTunPublication(inbounds []*Inbound) (*RuntimeTunPublication, error) {
	result := &RuntimeTunPublication{}
	for _, t := range inbounds {
		r := t.runtime
		if r == nil {
			return nil, errors.New("missing staged TUN owner")
		}
		r.mu.Lock()
		p, operation, closing := r.physical, r.operation, r.closing
		r.mu.Unlock()
		if closing || p == nil || operation == nil {
			return nil, errors.New("TUN physical preparation incomplete")
		}
		select {
		case <-operation.done:
			if operation.err != nil {
				return nil, operation.err
			}
		default:
			return nil, errors.New("TUN physical preparation still running")
		}
		select {
		case <-p.done:
			return nil, errors.New("TUN physical instance is closed")
		default:
		}
		result.physical = append(result.physical, p)
	}
	return result, nil
}

func (p *RuntimeTunPublication) Publish() {
	for _, physical := range p.physical {
		physical.gate.Store(true)
	}
}

var _ inbound.RuntimePreparedInbound = (*Inbound)(nil)

func (t *Inbound) openRuntimePhysical(physical *runtimeTunPhysical) error {
	childContext := context.WithValue(physical.scope.Context(), runtimePhysicalTunKey{}, true)
	childContext = adapter.ContextWithConstructionScope(childContext, physical.scope)
	child, err := NewInbound(childContext, t.router, outbound.WrapRuntimeLogger(t.logger, physical.callbacks), t.tag, t.runtime.options)
	if err != nil {
		return errors.Join(err, physical.close())
	}
	childInbound := child.(*Inbound)
	childInbound.runtimePhysical = physical
	t.runtime.mu.Lock()
	physical.inbound = childInbound
	t.runtime.mu.Unlock()
	for _, stage := range adapter.ListStartStages {
		if err := physical.scope.Context().Err(); err != nil {
			return errors.Join(err, physical.close())
		}
		if err := physical.inbound.Start(stage, physical.scope); err != nil {
			return errors.Join(err, physical.close())
		}
	}
	return nil
}
