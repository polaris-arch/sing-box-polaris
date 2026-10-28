package urltest

import (
	"context"
	"errors"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

type (
	runtimeAdmissionKey   struct{}
	runtimeAdmissionValue struct{ admission adapter.RuntimeAdmission }
)

func ContextWithRuntimeAdmission(ctx context.Context, admission adapter.RuntimeAdmission) context.Context {
	return context.WithValue(ctx, runtimeAdmissionKey{}, runtimeAdmissionValue{admission})
}

func RuntimeAdmissionFromContext(ctx context.Context) (adapter.RuntimeAdmission, bool) {
	value, ok := ctx.Value(runtimeAdmissionKey{}).(runtimeAdmissionValue)
	return value.admission, ok && value.admission != nil
}

// RuntimeProbe owns admission before asynchronous dispatch. Release belongs to
// the actual worker, not its canceled waiter. Nested native group workers fork
// the borrowed capabilities in Context before they launch their own work.
type RuntimeProbe struct {
	ctx       context.Context
	admission adapter.RuntimeAdmission
	graph     adapter.RuntimeLease
	resource  adapter.RuntimeResourceLease
	outbound  adapter.Outbound
	manager   adapter.OutboundManager
	history   *HistoryStorage
	epoch     *HistoryEpoch
	stop      context.CancelFunc
	once      sync.Once
}

func AcquireRuntimeProbe(ctx context.Context, admission adapter.RuntimeAdmission, tag string) (*RuntimeProbe, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if manager := service.FromContext[pause.Manager](ctx); manager != nil && (manager.IsDevicePaused() || manager.IsNetworkPaused()) {
		return nil, ErrStaleHistory
	}
	if admission == nil {
		return nil, errors.New("runtime probe admission unavailable")
	}
	graph, err := admission.Acquire()
	if err != nil {
		return nil, err
	}
	view, ok := graph.View().(RuntimeHistoryView)
	if !ok {
		graph.Release()
		return nil, errors.New("runtime history view unavailable")
	}
	history, id, ok := view.RuntimeURLTestHistory(tag)
	if !ok || history == nil {
		graph.Release()
		return nil, errors.New("runtime probe target unavailable")
	}
	outbound, ok := graph.View().OutboundManager().Outbound(tag)
	if !ok {
		graph.Release()
		return nil, errors.New("runtime probe outbound unavailable")
	}
	resource, err := graph.RetainResource(id)
	if err != nil {
		graph.Release()
		return nil, err
	}
	ctx = adapter.ContextWithRuntimeLease(ctx, graph)
	ctx = adapter.ContextWithRuntimeResourceLease(ctx, resource)
	epoch := history.Epoch()
	ctx, stop, err := history.ProbeContext(ctx, epoch)
	if err != nil {
		resource.Release()
		graph.Release()
		return nil, err
	}
	if manager := service.FromContext[pause.Manager](ctx); manager != nil {
		pausedContext, cancelPause := context.WithCancel(ctx)
		callback := manager.RegisterCallback(func(int) {
			if manager.IsDevicePaused() || manager.IsNetworkPaused() {
				cancelPause()
			}
		})
		if manager.IsDevicePaused() || manager.IsNetworkPaused() {
			cancelPause()
		}
		previousStop := stop
		stop = func() { manager.UnregisterCallback(callback); cancelPause(); previousStop() }
		ctx = pausedContext
	}
	if err := ctx.Err(); err != nil {
		stop()
		resource.Release()
		graph.Release()
		return nil, err
	}
	return &RuntimeProbe{ctx: ctx, admission: admission, graph: graph, resource: resource, outbound: outbound, manager: graph.View().OutboundManager(), history: history, epoch: epoch, stop: stop}, nil
}

// The registry supplies host lifetime, pause authority and admission; caller
// supplies request cancellation and ordinary values. Caller cancellation stays
// attached even when the caller did not inherit the host service registry.
func AcquireRuntimeProbeFromContext(registry, caller context.Context, tag string) (*RuntimeProbe, bool, error) {
	admission, bound := RuntimeAdmissionFromContext(registry)
	if !bound {
		return nil, false, nil
	}
	ctx, cancel := context.WithCancel(caller)
	if manager := service.FromContext[pause.Manager](registry); manager != nil {
		ctx = service.ContextWith[pause.Manager](ctx, manager)
	}
	stopHost := context.AfterFunc(registry, cancel)
	if registry.Err() != nil {
		cancel()
	}
	probe, err := AcquireRuntimeProbe(ctx, admission, tag)
	if err != nil {
		stopHost()
		cancel()
		return nil, true, err
	}
	stop := probe.stop
	probe.stop = func() { stopHost(); cancel(); stop() }
	return probe, true, nil
}

func (p *RuntimeProbe) Context() context.Context                 { return p.ctx }
func (p *RuntimeProbe) Outbound() adapter.Outbound               { return p.outbound }
func (p *RuntimeProbe) OutboundManager() adapter.OutboundManager { return p.manager }
func (p *RuntimeProbe) History() *HistoryStorage                 { return p.history }
func (p *RuntimeProbe) Epoch() *HistoryEpoch                     { return p.epoch }
func (p *RuntimeProbe) IsCurrent() bool {
	if p.ctx.Err() != nil || !p.history.IsCurrent(p.epoch) {
		return false
	}
	lease, err := p.admission.Acquire()
	if err != nil {
		return false
	}
	defer lease.Release()
	view, ok := lease.View().(RuntimeHistoryView)
	if !ok {
		return false
	}
	history, id, ok := view.RuntimeURLTestHistory(p.outbound.Tag())
	return ok && history == p.history && id == p.resource.ID()
}

func (p *RuntimeProbe) Release() {
	p.once.Do(func() { p.stop(); p.resource.Release(); p.graph.Release() })
}

// PublishRuntimeResult fans out only within the pinned graph's immutable
// captured consumers. Old work cannot discover a newer same-tag history. It
// does not select an outbound; the existing native update owner does that.
func PublishRuntimeResult(ctx context.Context, epoch *HistoryEpoch, tag string, result *adapter.URLTestHistory) bool {
	if ctx.Err() != nil {
		return false
	}
	borrowed, ok := adapter.RuntimeLeaseFromContext(ctx)
	if !ok {
		return false
	}
	lease, err := borrowed.Fork()
	if err != nil {
		return false
	}
	defer lease.Release()
	view, ok := lease.View().(RuntimeHistoryView)
	if !ok {
		return false
	}
	committed := false
	seen := make(map[*HistoryStorage]bool)
	for _, history := range view.RuntimeURLTestConsumers(tag) {
		if history == nil || seen[history] {
			continue
		}
		seen[history] = true
		if result == nil {
			committed = history.DeleteIfCurrent(epoch, tag) || committed
		} else {
			committed = history.StoreIfCurrent(epoch, tag, result) || committed
		}
	}
	return committed
}
