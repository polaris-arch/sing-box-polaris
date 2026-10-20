package naive

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service"
)

// This fence joins graph-facing callbacks, not unrelated protocol-private tails.
// Physical carriers and each callback hold independent exact continuations.
type inboundRuntime struct {
	ctx             context.Context
	source          adapter.RuntimeResourceSource
	callbacks       *outbound.RuntimeIOFence
	startOnce       sync.Once
	startErr        error
	taskMu          sync.Mutex
	taskErr         error
	failed          chan struct{}
	failOnce        sync.Once
	prepareReturned bool
	prepareEntered  bool
}

// Registration can invoke cleanup synchronously on an already canceled scope.
// That same-stack path requests cleanup and reports incomplete ownership; it
// never waits for a constructor-return signal that only its caller can release.
type inboundConstructionGate struct {
	done        chan struct{}
	once        sync.Once
	registering atomic.Bool
}

func (g *inboundConstructionGate) finish() { g.once.Do(func() { close(g.done) }) }

type inboundConstructionPending struct{}

func (*inboundConstructionPending) Error() string {
	return "runtime inbound cleanup is waiting for constructor return"
}
func (*inboundConstructionPending) RuntimeCleanupIncomplete() bool { return true }
func newInboundRuntimeConstruction(ctx context.Context, closeProtocol func() error) (*inboundRuntime, func(), error) {
	if !adapter.IsRuntimePreparation(ctx) {
		return nil, func() {}, nil
	}
	gate := &inboundConstructionGate{done: make(chan struct{})}
	gate.registering.Store(true)
	returned := false
	defer func() {
		if !returned {
			gate.finish()
		}
	}()
	runtime, err := newInboundRuntimeState(ctx, closeProtocol, gate)
	returned = true
	return runtime, gate.finish, err
}

func newInboundRuntime(ctx context.Context, closeProtocol func() error) (*inboundRuntime, error) {
	return newInboundRuntimeState(ctx, closeProtocol, nil)
}

func newInboundRuntimeState(ctx context.Context, closeProtocol func() error, gate *inboundConstructionGate) (*inboundRuntime, error) {
	if !adapter.IsRuntimePreparation(ctx) {
		return nil, nil
	}
	source, ok := adapter.RuntimeResourceSourceFromContext(ctx)
	if !ok || !adapter.HasConstructionScope(ctx) {
		return nil, errors.New("runtime inbound requires its constructor resource and cleanup scope")
	}
	r := &inboundRuntime{ctx: ctx, source: source, failed: make(chan struct{})}
	r.callbacks = outbound.NewRuntimeIOFence(func() error {
		if gate != nil {
			<-gate.done
		}
		// Join a partially returned Start before closing its protocol state. Calling
		// Do first also prevents a never-started candidate starting after rollback.
		r.startOnce.Do(func() { r.startErr = errors.New("runtime inbound closed before preparation") })
		if r.prepareEntered && !r.prepareReturned {
			r.record(errors.New("preparation unwound without returning"))
		}
		return closeProtocol()
	})
	cleanup := r.closeAndWait
	if gate != nil {
		cleanup = func() error {
			if gate.registering.Load() {
				_ = r.callbacks.Close()
				return &inboundConstructionPending{}
			}
			return r.closeAndWait()
		}
	}
	err := adapter.DeferConstructionCleanup(ctx, cleanup)
	if gate != nil {
		gate.registering.Store(false)
	}
	if err != nil {
		return r, err
	}
	if err := adapter.ConstructionScopeErr(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *inboundRuntime) wrapLogger(base logger.ContextLogger) logger.ContextLogger {
	if r == nil {
		return base
	}
	return outbound.WrapRuntimeLogger(base, r.callbacks)
}

func (r *inboundRuntime) enter(ctx context.Context) (context.Context, func(), error) {
	if r == nil {
		return ctx, func() {}, nil
	}
	leave, err := r.callbacks.Acquire()
	if err != nil {
		return nil, nil, err
	}
	// A stale incoming handle never falls back to the currently active graph or
	// root receiver source. Detours must be present in the admitted graph too.
	owned, release, err := adapter.AcquireRuntimeOperation(ctx, nil)
	if err != nil {
		leave()
		return nil, nil, err
	}
	graph, ok := adapter.RuntimeLeaseFromContext(owned)
	if !ok {
		release()
		leave()
		return nil, nil, errors.New("runtime inbound callback has no admitted graph")
	}
	resource, err := graph.RetainResource(r.source.ID())
	if err != nil {
		release()
		leave()
		return nil, nil, err
	}
	owned = adapter.ContextWithRuntimeResourceLease(owned, resource)
	var once sync.Once
	return owned, func() {
		failure := recover()
		once.Do(func() {
			if failure != nil {
				r.record(fmt.Errorf("inbound callback panic: %v", failure))
				leave()
				return
			}
			resource.Release()
			release()
			leave()
		})
		if failure != nil {
			panic(failure)
		}
	}, nil
}

func (r *inboundRuntime) prepare(start func() error) error {
	if r == nil {
		return errors.New("inbound has no staged runtime binding")
	}
	leave, err := r.callbacks.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	r.startOnce.Do(func() {
		r.startErr = errors.New("runtime inbound preparation did not return")
		r.prepareEntered = true
		r.startErr = start()
		r.prepareReturned = true
	})
	return r.startErr
}

func (r *inboundRuntime) record(err error) {
	if err == nil {
		return
	}
	r.failOnce.Do(func() { close(r.failed) })
	r.taskMu.Lock()
	r.taskErr = errors.Join(r.taskErr, fmt.Errorf("ingress lifetime incomplete: %v", err))
	r.taskMu.Unlock()
	_ = r.callbacks.Close()
}

func (r *inboundRuntime) closeAndWait() error {
	err := r.callbacks.RuntimeCloseAndWait()
	r.taskMu.Lock()
	defer r.taskMu.Unlock()
	return errors.Join(err, r.taskErr)
}

// Background acceptance owns only a callback slot, never request admission.
// Session tasks retain exact inherited operations before any goroutine exists.
func (r *inboundRuntime) runTask(ctx context.Context, task func(context.Context)) bool {
	leave, err := r.callbacks.Acquire()
	if err != nil {
		return false
	}
	owned := ctx
	release := func() {}
	if ctx != r.ctx {
		owned, release, err = r.retain(ctx)
		if err != nil {
			leave()
			return false
		}
	}
	go func() {
		returned := false
		defer leave()
		defer func() {
			value := recover()
			if value != nil || !returned {
				r.record(fmt.Errorf("server task did not complete (panic=%v)", value))
				// Retain the exact operation on uncertainty, while joining the real task.
				_ = r.callbacks.Close()
				return
			}
			release()
		}()
		task(owned)
		returned = true
	}()
	return true
}

func (r *inboundRuntime) retain(ctx context.Context) (context.Context, func(), error) {
	owned, release, err := adapter.AcquireRuntimeOperation(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	graph, ok := adapter.RuntimeLeaseFromContext(owned)
	if !ok {
		release()
		return nil, nil, errors.New("session task lacks admitted graph")
	}
	resource, err := graph.RetainResource(r.source.ID())
	if err != nil {
		release()
		return nil, nil, err
	}
	owned = adapter.ContextWithRuntimeResourceLease(owned, resource)
	var once sync.Once
	return owned, func() { once.Do(func() { resource.Release(); release() }) }, nil
}

type inboundClock struct {
	clock   func() time.Time
	runtime *inboundRuntime
}

func (c inboundClock) TimeFunc() func() time.Time {
	return func() (now time.Time) {
		leave, err := c.runtime.callbacks.Acquire()
		if err != nil {
			return time.Now()
		}
		defer leave()
		defer func() {
			if value := recover(); value != nil {
				c.runtime.record(fmt.Errorf("clock callback panic: %v", value))
				now = time.Now()
			}
		}()
		return c.clock()
	}
}

func (r *inboundRuntime) bindContext(ctx context.Context) context.Context {
	clock := ntp.TimeFuncFromContext(ctx)
	if clock != nil {
		ctx = service.ContextWith[ntp.TimeService](service.ExtendContext(ctx), inboundClock{clock, r})
	}
	r.ctx = ctx
	return ctx
}

func cloneInboundOptions[T any](ctx context.Context, options T) (T, error) {
	if !adapter.IsRuntimePreparation(ctx) {
		return options, nil
	}
	data, err := json.MarshalContext(ctx, options)
	if err != nil {
		return options, err
	}
	var cloned T
	err = json.UnmarshalContext(ctx, data, &cloned)
	return cloned, err
}

var _ inbound.RuntimePreparedInbound = (*Inbound)(nil)

func (n *Inbound) RuntimeValidate() error {
	if n.runtime == nil {
		return errors.New("inbound lacks staged runtime binding")
	}
	select {
	case <-n.runtime.failed:
		return errors.New("inbound lifecycle has failed")
	default:
	}
	if err := n.listener.ValidateRuntime(); err != nil {
		return err
	}
	if common.Contains(n.network, N.NetworkUDP) && PrepareRuntimeHTTP3ListenerFunc == nil {
		return errors.New("naive HTTP3 lacks compiled staged adapter")
	}
	return tls.ValidateRuntimeServer(n.tlsConfig)
}

func (n *Inbound) RuntimeListeners() []*listener.Listener { return []*listener.Listener{n.listener} }

func (n *Inbound) PrepareRuntime(stage adapter.StartStage, _ *adapter.Scope) error {
	if err := n.RuntimeValidate(); err != nil {
		return err
	}
	if stage != adapter.StartStateStart {
		return nil
	}
	return n.runtime.prepare(func() error {
		if n.tlsConfig != nil {
			if err := n.tlsConfig.Start(); err != nil {
				return err
			}
		}
		if n.runtimeTCP != nil {
			if err := n.runtimeTCP.prepare(); err != nil {
				return err
			}
		}
		if common.Contains(n.network, N.NetworkUDP) {
			server, err := PrepareRuntimeHTTP3ListenerFunc(n.ctx, n.logger, n.listener, n, n.tlsConfig, n.options)
			if err != nil {
				return err
			}
			n.http3Server = server
		}
		return nil
	})
}

func (n *Inbound) closeRuntimeProtocol() error {
	var err error
	if n.runtimeTCP != nil {
		err = n.runtimeTCP.Close()
	}
	if n.http3Server != nil {
		err = errors.Join(err, n.http3Server.Close())
	}
	if err != nil {
		return fmt.Errorf("naive ingress cleanup incomplete: %v", err)
	}
	return nil
}
