package vless

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
 "github.com/sagernet/sing-box/transport/v2ray"
 "github.com/sagernet/sing/common/logger"
)

// This fence joins graph-facing callbacks, not unrelated protocol-private tails.
// Physical carriers and each callback hold independent exact continuations.
type inboundRuntime struct {
 ctx context.Context
 source adapter.RuntimeResourceSource
 callbacks *outbound.RuntimeIOFence
 startOnce sync.Once
 startErr error
}
// Registration can invoke cleanup synchronously on an already canceled scope.
// That same-stack path requests cleanup and reports incomplete ownership; it
// never waits for a constructor-return signal that only its caller can release.
type inboundConstructionGate struct {
 done chan struct{}
 once sync.Once
 registering atomic.Bool
}
func (g *inboundConstructionGate) finish() { g.once.Do(func(){close(g.done)}) }
type inboundConstructionPending struct{}
func (*inboundConstructionPending) Error() string { return "runtime inbound cleanup is waiting for constructor return" }
func (*inboundConstructionPending) RuntimeCleanupIncomplete() bool { return true }
func newInboundRuntimeConstruction(ctx context.Context, closeProtocol func() error) (*inboundRuntime, func(), error) {
 if !adapter.IsRuntimePreparation(ctx) { return nil, func(){}, nil }
 gate := &inboundConstructionGate{done:make(chan struct{})}
 gate.registering.Store(true)
 returned := false
 defer func(){ if !returned { gate.finish() } }()
 runtime, err := newInboundRuntimeState(ctx, closeProtocol, gate)
 returned = true
 return runtime, gate.finish, err
}
func newInboundRuntime(ctx context.Context, closeProtocol func() error) (*inboundRuntime, error) {
 return newInboundRuntimeState(ctx, closeProtocol, nil)
}
func newInboundRuntimeState(ctx context.Context, closeProtocol func() error, gate *inboundConstructionGate) (*inboundRuntime, error) {
 if !adapter.IsRuntimePreparation(ctx) { return nil, nil }
 source, ok := adapter.RuntimeResourceSourceFromContext(ctx)
 if !ok || !adapter.HasConstructionScope(ctx) { return nil, errors.New("runtime inbound requires its constructor resource and cleanup scope") }
 r := &inboundRuntime{ctx:ctx, source:source}
 r.callbacks = outbound.NewRuntimeIOFence(func() error {
  if gate != nil { <-gate.done }
  // Join a partially returned Start before closing its protocol state. Calling
  // Do first also prevents a never-started candidate starting after rollback.
  r.startOnce.Do(func(){ r.startErr = errors.New("runtime inbound closed before preparation") })
  return closeProtocol()
 })
 cleanup := r.callbacks.RuntimeCloseAndWait
 if gate != nil {
  cleanup = func() error {
   if gate.registering.Load() {
    _ = r.callbacks.Close()
    return &inboundConstructionPending{}
   }
   return r.callbacks.RuntimeCloseAndWait()
  }
 }
 err := adapter.DeferConstructionCleanup(ctx, cleanup)
 if gate != nil { gate.registering.Store(false) }
 if err != nil { return r, err }
 if err := adapter.ConstructionScopeErr(ctx); err != nil { return nil, err }
 return r, nil
}
func (r *inboundRuntime) wrapLogger(base logger.ContextLogger) logger.ContextLogger {
 if r == nil { return base }
 return outbound.WrapRuntimeLogger(base, r.callbacks)
}
func (r *inboundRuntime) enter(ctx context.Context) (context.Context, func(), error) {
 if r == nil { return ctx, func(){}, nil }
 leave, err := r.callbacks.Acquire()
 if err != nil { return nil, nil, err }
 // A stale incoming handle never falls back to the currently active graph or
 // root receiver source. Detours must be present in the admitted graph too.
 owned, release, err := adapter.AcquireRuntimeOperation(ctx, nil)
 if err != nil { leave(); return nil, nil, err }
 graph, ok := adapter.RuntimeLeaseFromContext(owned)
 if !ok { release(); leave(); return nil, nil, errors.New("runtime inbound callback has no admitted graph") }
 resource, err := graph.RetainResource(r.source.ID())
 if err != nil { release(); leave(); return nil, nil, err }
 owned = adapter.ContextWithRuntimeResourceLease(owned, resource)
 var once sync.Once
 return owned, func(){ once.Do(func(){resource.Release(); release(); leave()}) }, nil
}
func (r *inboundRuntime) prepare(start func() error) error {
 if r == nil { return errors.New("inbound has no staged runtime binding") }
 leave, err := r.callbacks.Acquire()
 if err != nil { return err }; defer leave()
 r.startOnce.Do(func(){ r.startErr = errors.New("runtime inbound preparation did not return"); r.startErr = start() })
 return r.startErr
}

var _ inbound.RuntimePreparedInbound = (*Inbound)(nil)
func (h *Inbound) RuntimeValidate() error {
 if h.runtime == nil { return errors.New("inbound has no staged runtime binding") }
 if err := h.listener.ValidateRuntime(); err != nil { return err }
 if err := tls.ValidateRuntimeServer(h.tlsConfig); err != nil { return err }
 if h.transport != nil { if err := v2ray.ValidateRuntimeServer(h.transport); err != nil { return err } }
 return nil
}
func (h *Inbound) RuntimeListeners() []*listener.Listener { return []*listener.Listener{h.listener} }
func (h *Inbound) PrepareRuntime(stage adapter.StartStage, _ *adapter.Scope) error {
 if err := h.RuntimeValidate(); err != nil { return err }
 if stage != adapter.StartStateStart { return nil }
 return h.runtime.prepare(func() error {
  if h.tlsConfig != nil { if err := h.tlsConfig.Start(); err != nil { return err } }
  if h.transport != nil { return v2ray.PrepareRuntimeServer(h.runtime.ctx, h.transport, h.listener) }
  return nil
 })
}
func (h *Inbound) closeRuntimeProtocol() error {
 return nil
}
