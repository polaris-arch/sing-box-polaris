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
	"github.com/sagernet/sing-tun"
)

type (
	runtimePhysicalTunKey struct{}
	runtimeTunPhysical    struct {
		inbound     *Inbound
		scope       *adapter.Scope
		callbacks   *outbound.RuntimeIOFence
		cancel      context.CancelFunc
		gate        atomic.Bool
		once        sync.Once
		done        chan struct{}
		err         error
		nativeOwner *Inbound
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
		mu              sync.Mutex
		owner           *Inbound
		options         option.TunInboundOptions
		openPhysical    func(*runtimeTunPhysical) error
		physical        *runtimeTunPhysical
		operation       *runtimeTunOperation
		closing         bool
		closed          chan struct{}
		closeOnce       sync.Once
		closeErr        error
		native          adapter.RuntimeTunSession
		nativePrevious  adapter.RuntimeTunSession
		nativeReceipt   *adapter.RuntimeTunReceipt
		nativeFinalized bool
		nativeError     error
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
	p, receipt := t.runtime.physical, t.runtime.nativeReceipt
	t.runtime.mu.Unlock()
	if p != nil {
		p.gate.Store(false)
	}
	if receipt != nil {
		receipt.Suspend()
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
		physical, receipt := r.physical, r.nativeReceipt
		r.mu.Unlock()
		if physical != nil {
			physical.gate.Store(false)
		}
		if receipt != nil {
			receipt.Suspend()
		}
		if physical != nil {
			r.closeErr = physical.close()
		} else {
			r.closeErr = nil
		}
		if r.closeErr == nil && (operation == nil || !tls.IsRuntimeCleanupIncomplete(operation.err)) {
			r.closeErr = t.finishRuntimeNative()
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
			if tls.IsRuntimeCleanupIncomplete(previous.err) {
				r.mu.Unlock()
				return previous.err
			}
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
		physical := &runtimeTunPhysical{scope: scope, callbacks: callbacks, cancel: cancel, done: make(chan struct{}), nativeOwner: t}
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
		physical, receipt := t.runtime.physical, t.runtime.nativeReceipt
		t.runtime.mu.Unlock()
		if physical != nil {
			physical.gate.Store(false)
		}
		if receipt != nil {
			receipt.Suspend()
		}
		if physical == nil {
			return nil
		}
		return physical.close()
	})
}

// RuntimeTunPublication is a prevalidated, concrete memory-only participant.
// The Box store guard excludes new graph admissions while Publish opens gates.
type RuntimeTunPublication struct {
	physical []*runtimeTunPhysical
	receipts []*adapter.RuntimeTunReceipt
}

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
		r.mu.Lock()
		native, receipt, finalized := r.native, r.nativeReceipt, r.nativeFinalized
		r.mu.Unlock()
		if finalized {
			return nil, errors.New("native TUN preparation already finalized")
		}
		if native != nil {
			if receipt == nil || native.OwnerID() != receipt.OwnerID() {
				return nil, errors.New("native TUN owner receipt mismatch")
			}
			if err := native.Validate(); err != nil {
				return nil, err
			}
			result.receipts = append(result.receipts, receipt)
		}
		result.physical = append(result.physical, p)
	}
	return result, nil
}

func (p *RuntimeTunPublication) Publish() {
	for _, receipt := range p.receipts {
		receipt.Publish()
	}
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

// RuntimeReplacementSupported requires an actual optional native owner. An old
// binding's duplicate, GOOS or new header alone cannot supply this capability.
func (t *Inbound) RuntimeReplacementSupported() error {
	if err := t.RuntimeValidate(); err != nil {
		return err
	}
	if t.platformInterface != nil && t.platformInterface.UsePlatformInterface() {
		platform, ok := t.platformInterface.(adapter.RuntimeTunPlatform)
		if !ok || platform.RuntimeTunVersion() != 1 {
			return errors.New("TUN native FD/settings bridge unavailable")
		}
		t.runtime.mu.Lock()
		physical, native := t.runtime.physical, t.runtime.native
		t.runtime.mu.Unlock()
		if physical != nil && native == nil {
			return errors.New("legacy native TUN has no transferable original owner")
		}
	}
	return nil
}

// bindRuntimeNativePrevious is inventory-only and runs before old readers stop.
// Current client policy keeps exactly one native main carrier with the same tag.
func (t *Inbound) bindRuntimeNativePrevious(previous *Inbound) error {
	if t.platformInterface == nil || !t.platformInterface.UsePlatformInterface() {
		return nil
	}
	if previous == nil || previous.platformInterface != t.platformInterface || previous.tag != t.tag {
		return errors.New("native TUN replacement requires the same provider and carrier")
	}
	previous.runtime.mu.Lock()
	native, finalized := previous.runtime.native, previous.runtime.nativeFinalized
	previous.runtime.mu.Unlock()
	if native == nil || finalized {
		return errors.New("native TUN previous original owner unavailable")
	}
	t.runtime.mu.Lock()
	t.runtime.nativePrevious = native
	t.runtime.mu.Unlock()
	return nil
}

func (t *Inbound) openRuntimeNativeInterface(options *tun.Options, platformOptions option.TunPlatformOptions) (tun.Tun, error) {
	r := t.runtime
	r.mu.Lock()
	native, previous, finalized := r.native, r.nativePrevious, r.nativeFinalized
	r.mu.Unlock()
	if finalized {
		return nil, errors.New("native TUN owner already finalized")
	}
	platform, ok := t.platformInterface.(adapter.RuntimeTunPlatform)
	if native == nil && (!ok || platform.RuntimeTunVersion() != 1) {
		if previous != nil {
			return nil, errors.New("native TUN original bridge lost during replacement")
		}
		// Only genuinely old bindings can use this path; registered libbox
		// bridges reject legacy OpenTun, including after quarantine.
		return t.platformInterface.OpenInterface(options, platformOptions)
	}
	if native == nil {
		receipt, err := adapter.NewRuntimeTunReceipt()
		if err != nil {
			return nil, err
		}
		native, err = platform.NewRuntimeTunSession(options, platformOptions, previous, receipt)
		if err != nil {
			return nil, err
		}
		if native == nil {
			return nil, errors.New("native TUN allocation returned no original owner")
		}
		// Retain the returned original owner before any platform side effect.
		r.mu.Lock()
		r.native, r.nativeReceipt = native, receipt
		r.mu.Unlock()
		if native.OwnerID() != receipt.OwnerID() {
			return nil, errors.New("native TUN allocation owner mismatch")
		}
		if err = native.Prepare(); err != nil {
			return nil, err
		}
	}
	// During compensation this is the old session, whose Abort replacement has
	// updated its actual descriptor. Never invoke legacy OpenTun to restore it.
	return native.OpenInterface(options)
}

func (t *Inbound) finishRuntimeNative() error {
	r := t.runtime
	r.mu.Lock()
	native, receipt := r.native, r.nativeReceipt
	if native == nil {
		r.mu.Unlock()
		return nil
	}
	if r.nativeFinalized {
		err := r.nativeError
		r.mu.Unlock()
		return err
	}
	r.nativeFinalized = true
	r.nativeError = tls.NewRuntimeCleanupError(errors.New("native TUN cleanup did not complete"))
	r.mu.Unlock()
	var err error
	if receipt != nil && receipt.WasPublished() {
		err = native.Retire()
	} else {
		err = native.Abort()
	}
	if err != nil {
		err = tls.NewRuntimeCleanupError(err)
	}
	r.mu.Lock()
	r.nativeError = err
	r.mu.Unlock()
	return err
}

func (t *Inbound) RuntimeAbortNative(ctx context.Context) error {
	if err := t.RuntimeValidate(); err != nil {
		return err
	}
	return t.runtime.runPhysical(ctx, t.finishRuntimeNative)
}
