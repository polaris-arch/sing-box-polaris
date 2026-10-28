package masque

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/tls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type runtimeClientState struct {
	source           adapter.RuntimeResourceSource
	scope            *adapter.Scope
	ctx              context.Context
	cancel           context.CancelFunc
	callbacks        *outbound.RuntimeIOFence
	carriers         *outbound.RuntimeIOFenceSet
	begin            func(context.Context) (context.Context, func(), error)
	gate             atomic.Bool
	ingress          atomic.Bool
	mu               sync.Mutex
	staged           bool
	stageDone        chan struct{}
	stageErr         error
	closing          bool
	closeOnce        sync.Once
	closeDone        chan struct{}
	closeErr         error
	nativeOnce       sync.Once
	nativeErr        error
	nativeClose      func() error
	nativeRelease    func()
	diagnosticPhase  atomic.Uint32
	diagnosticFailed atomic.Bool
}

func (e *endpointBase) initializeRuntime(ctx context.Context, system bool) error {
	if !adapter.IsRuntimePreparation(ctx) {
		return nil
	}
	if system {
		return errors.New("system endpoint device requires restart")
	}
	source, ok := adapter.RuntimeResourceSourceFromContext(ctx)
	if !ok {
		return errors.New("endpoint runtime owner missing")
	}
	owned, cancel := context.WithCancel(ctx)
	r := &runtimeClientState{source: source, ctx: owned, cancel: cancel, callbacks: outbound.NewRuntimeIOFence(nil), carriers: outbound.NewRuntimeIOFenceSet(), closeDone: make(chan struct{})}
	e.runtime = r
	e.logger = outbound.WrapRuntimeLogger(e.logger, r.callbacks)
	r.scope = adapter.NewScope(owned, e.logger)
	var err error
	r.begin, err = outbound.RegisterRuntimeOwnedFence(ctx, r.callbacks)
	if err != nil {
		cancel()
		return err
	}
	if err := adapter.DeferConstructionCleanup(ctx, r.close); err != nil {
		return err
	}
	r.mu.Lock()
	closed := r.closing
	r.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	return adapter.ConstructionScopeErr(ctx)
}

func (r *runtimeClientState) installNative(closeNative func() error) error {
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		err := closeNative()
		if err != nil {
			return tls.NewRuntimeCleanupError(err)
		}
		return net.ErrClosed
	}
	r.nativeClose = closeNative
	r.mu.Unlock()
	return nil
}

func (r *runtimeClientState) closeNative() error {
	r.nativeOnce.Do(func() {
		if r.nativeRelease != nil {
			defer r.nativeRelease()
		}
		if r.nativeClose != nil {
			r.nativeErr = r.nativeClose()
		}
	})
	if r.nativeErr != nil {
		return tls.NewRuntimeCleanupError(r.nativeErr)
	}
	return nil
}

func (r *runtimeClientState) close() error {
	r.closeOnce.Do(func() {
		r.diagnosticPhase.Store(1) // cancellation and fence sealing
		r.closeErr = tls.NewRuntimeCleanupError(errors.New("endpoint cleanup did not complete"))
		defer close(r.closeDone)
		defer func() { r.diagnosticFailed.Store(r.closeErr != nil) }()
		r.mu.Lock()
		r.closing = true
		done := r.stageDone
		r.mu.Unlock()
		r.gate.Store(false)
		r.ingress.Store(false)
		r.cancel()
		_ = r.callbacks.Close()
		r.carriers.Stop()
		r.diagnosticPhase.Store(2) // stage join
		if done != nil {
			<-done
		}
		r.diagnosticPhase.Store(3) // native client close
		nativeErr := r.closeNative()
		r.diagnosticPhase.Store(4) // callbacks join
		callbackErr := r.callbacks.Wait()
		r.diagnosticPhase.Store(5) // endpoint/device scope close
		scopeErr := r.scope.Close()
		r.diagnosticPhase.Store(6) // owned carrier join
		carrierErr := r.carriers.Wait()
		r.closeErr = errors.Join(nativeErr, callbackErr, scopeErr, carrierErr)
		if tls.IsRuntimeCleanupIncomplete(r.stageErr) {
			r.closeErr = errors.Join(r.closeErr, r.stageErr)
		}
		if r.closeErr != nil {
			r.closeErr = tls.NewRuntimeCleanupError(r.closeErr)
		}
		r.diagnosticFailed.Store(r.closeErr != nil)
		r.diagnosticPhase.Store(7) // actual close returned
	})
	<-r.closeDone
	return r.closeErr
}

func (c *ClientEndpoint) RuntimeValidate() error {
	if c.runtime == nil {
		return errors.New("endpoint lacks prepared userspace ownership")
	}
	return nil
}

func (c *ClientEndpoint) RuntimeResourceID() adapter.RuntimeResourceID {
	if c.runtime == nil {
		return adapter.RuntimeResourceID{}
	}
	return c.runtime.source.ID()
}

func (c *ClientEndpoint) PrepareRuntime(adapter.StartStage, *adapter.Scope) error {
	return c.RuntimeValidate()
}

func (c *ClientEndpoint) RuntimeReservePhysical(context.Context) error {
	if err := c.RuntimeValidate(); err != nil {
		return err
	}
	c.runtime.mu.Lock()
	defer c.runtime.mu.Unlock()
	if c.runtime.closing {
		return net.ErrClosed
	}
	return nil
}

func (c *ClientEndpoint) RuntimeReleasePhysicalReservation(context.Context) error {
	return c.RuntimeValidate()
}

func (c *ClientEndpoint) RuntimeStagePhysical(ctx context.Context) error {
	if err := c.RuntimeValidate(); err != nil {
		return err
	}
	r := c.runtime
	r.mu.Lock()
	if r.closing || r.stageDone != nil {
		r.mu.Unlock()
		return errors.New("endpoint stage unavailable")
	}
	r.stageDone = make(chan struct{})
	done := r.stageDone
	r.mu.Unlock()
	go func() {
		r.stageErr = tls.NewRuntimeCleanupError(errors.New("endpoint stage did not complete"))
		defer func() {
			if recover() != nil {
				r.stageErr = tls.NewRuntimeCleanupError(errors.New("endpoint stage panicked; owner retained"))
			}
			close(done)
		}()
		for _, stage := range adapter.ListStartStages {
			if err := r.scope.Start("prepared endpoint", c, stage); err != nil {
				r.stageErr = err
				return
			}
		}
		r.staged = true
		r.stageErr = nil
	}()
	select {
	case <-done:
		return r.stageErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *ClientEndpoint) RuntimePreparePublication() (func(), error) {
	if err := c.RuntimeValidate(); err != nil {
		return nil, err
	}
	r := c.runtime
	r.mu.Lock()
	done, closing := r.stageDone, r.closing
	r.mu.Unlock()
	if closing || done == nil {
		return nil, net.ErrClosed
	}
	select {
	case <-done:
	default:
		return nil, errors.New("endpoint stage still running")
	}
	if r.stageErr != nil {
		return nil, r.stageErr
	}
	if !r.staged {
		return nil, errors.New("endpoint not staged")
	}
	return func() { r.gate.Store(true); r.ingress.Store(true) }, nil
}

func (c *ClientEndpoint) RuntimeStop() {
	if c.runtime != nil {
		c.runtime.ingress.Store(false)
	}
}

func (c *ClientEndpoint) RuntimeCloseAndWait() error {
	if c.runtime == nil {
		return errors.New("endpoint runtime owner missing")
	}
	return c.runtime.close()
}

func (c *ClientEndpoint) closeNativeClient() error {
	if c.runtime != nil {
		return c.runtime.closeNative()
	}
	return c.client.Close()
}

func (r *runtimeClientState) acquire() (func(), error) {
	if !r.gate.Load() {
		return nil, net.ErrClosed
	}
	return r.callbacks.Acquire()
}

func (r *runtimeClientState) wrapDialer(base N.Dialer) N.Dialer {
	return &runtimeClientDialer{runtime: r, base: base}
}

type runtimeClientDialer struct {
	runtime *runtimeClientState
	base    N.Dialer
}

func (d *runtimeClientDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	r := d.runtime
	creation, err := r.carriers.Begin()
	if err != nil {
		return nil, err
	}
	defer creation.Done()
	ctx, release, err := r.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	ctx, err = outbound.ContextForRuntimeOwnedSession(ctx, r.source)
	if err != nil {
		return nil, err
	}
	raw, err := d.base.DialContext(ctx, network, destination)
	if raw == nil {
		return nil, err
	}
	wrapped, fence := outbound.WrapRuntimeOwnedConn(raw)
	registered := creation.Register(fence)
	if err != nil || registered != nil || r.ctx.Err() != nil {
		return nil, errors.Join(err, registered, r.ctx.Err(), fence.RuntimeCloseAndWait())
	}
	return wrapped, nil
}

func (d *runtimeClientDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	r := d.runtime
	creation, err := r.carriers.Begin()
	if err != nil {
		return nil, err
	}
	defer creation.Done()
	ctx, release, err := r.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	ctx, err = outbound.ContextForRuntimeOwnedSession(ctx, r.source)
	if err != nil {
		return nil, err
	}
	raw, err := d.base.ListenPacket(ctx, destination)
	if raw == nil {
		return nil, err
	}
	wrapped, fence := outbound.WrapRuntimeOwnedPacketConn(raw)
	registered := creation.Register(fence)
	if err != nil || registered != nil || r.ctx.Err() != nil {
		return nil, errors.Join(err, registered, r.ctx.Err(), fence.RuntimeCloseAndWait())
	}
	return wrapped, nil
}

var _ endpoint.RuntimePreparedEndpoint = (*ClientEndpoint)(nil)
