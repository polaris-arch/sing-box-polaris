package box

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
)

func (c *runtimeCoordinator) VisitRuntimeNetwork(ctx context.Context, visit func(context.Context, adapter.Outbound, adapter.Router)) {
	type entry struct {
		resource *runtimeResource
		lease    adapter.RuntimeResourceLease
	}
	c.access.Lock()
	entries := make([]entry, 0, len(c.catalog))
	for _, resource := range c.catalog {
		if !resource.networkReady {
			continue
		}
		// Existing allocations can be observed while retired; an exhausted owner
		// cannot be resurrected by a late network notification.
		if lease, err := resource.owner.RetainExisting(); err == nil {
			entries = append(entries, entry{resource, lease})
		}
	}
	c.access.Unlock()
	defer func() {
		for _, entry := range entries {
			entry.lease.Release()
		}
	}()
	for _, entry := range entries {
		bound := adapter.ContextWithRuntimeResourceLease(ctx, entry.lease)
		for _, component := range entry.resource.components {
			// Pass a literal nil: a nil *route.Router would become a non-nil adapter.Router.
			if component.router != nil {
				visit(bound, component.outbound, component.router)
			} else if component.outbound != nil {
				visit(bound, component.outbound, nil)
			}
			if component.endpoint != nil {
				visit(bound, component.endpoint, nil)
			}
		}
	}
}

// RuntimeWIFIState borrows the selected graph while copying monitor state.
func (c *runtimeCoordinator) RuntimeWIFIState() (adapter.WIFIState, bool, bool) {
	lease, err := c.store.Acquire()
	if err != nil {
		return adapter.WIFIState{}, false, false
	}
	defer lease.Release()
	view, ok := lease.View().(*runtimeView)
	if !ok || view.platform == nil {
		return adapter.WIFIState{}, false, false
	}
	return view.platform.WIFIState(), view.platform.NeedWIFIState(), true
}

func (c *runtimeCoordinator) RuntimeUpdateWIFIState(ctx context.Context) bool {
	lease, err := c.store.Acquire()
	if err != nil {
		return false
	}
	defer lease.Release()
	view, ok := lease.View().(*runtimeView)
	if !ok || view.platform == nil {
		return false
	}
	view.platform.Refresh(ctx)
	return true
}
