package boxruntime

import (
	"context"
	"math"

	"github.com/sagernet/sing-box/adapter"
)

func (c *runtimeCoordinator) SelectRuntimeOutbound(expected adapter.RuntimeResourceID, group, selected string) bool {
	accepted, _ := c.selectRuntimeOutbound(context.Background(), expected, adapter.RuntimeRevision{}, group, selected)
	return accepted
}

func (c *runtimeCoordinator) selectRuntimeOutbound(ctx context.Context, expected adapter.RuntimeResourceID, graph adapter.RuntimeRevision, group, selected string) (bool, error) {
	if err := c.controlEffects.LockContext(ctx); err != nil {
		return false, err
	}
	defer c.controlEffects.Unlock()
	c.access.Lock()
	guarded := graph != (adapter.RuntimeRevision{})
	if !c.stopped && guarded && c.active.graphRevision() != graph {
		c.access.Unlock()
		return false, adapter.ErrProbeGraphChanged
	}
	if c.stopped || c.active.ControlRevision == math.MaxUint64 {
		c.access.Unlock()
		return false, nil
	}
	lease, err := c.store.Acquire()
	if err != nil {
		c.access.Unlock()
		return false, nil
	}
	defer lease.Release()
	view, ok := lease.View().(*runtimeView)
	if !ok || (!guarded && view.componentIDs["outbound:"+group] != expected) {
		c.access.Unlock()
		return false, nil
	}
	expected = view.componentIDs["outbound:"+group]
	outbound, exists := view.outbounds.Outbound(group)
	selector, selectable := outbound.(interface {
		RuntimeSelect(string) (bool, bool, func())
	})
	if !exists || !selectable || ctx.Err() != nil {
		c.access.Unlock()
		return false, ctx.Err()
	}
	changed, accepted, effect := selector.RuntimeSelect(selected)
	if changed {
		c.cancelRuntimeExitIPProbeLocked()
		c.active.ControlRevision++
		c.pendingPersistence = nil
	}
	revision := c.active.ControlRevision
	c.access.Unlock()
	if !accepted || effect == nil {
		return accepted, nil
	}
	// Effects execute outside the coordinator guard. Publication cannot pass
	// this accepted control operation before its actual persistence tail.
	c.access.Lock()
	current := !c.stopped && c.active.ControlRevision == revision
	if current {
		active, acquireErr := c.store.Acquire()
		if acquireErr != nil {
			current = false
		} else {
			activeView, valid := active.View().(*runtimeView)
			current = valid && activeView.componentIDs["outbound:"+group] == expected
			active.Release()
		}
	}
	c.access.Unlock()
	if current {
		effect()
	}
	return accepted, nil
}

func (c *runtimeCoordinator) SetRuntimeClashMode(mode string) bool {
	c.controlEffects.Lock()
	defer c.controlEffects.Unlock()
	c.access.Lock()
	if c.stopped || c.clashMode == nil || c.active.ControlRevision == math.MaxUint64 {
		c.access.Unlock()
		return false
	}
	lease, err := c.store.Acquire()
	if err != nil {
		c.access.Unlock()
		return false
	}
	changed, accepted, effect := c.clashMode.RuntimeSetMode(mode)
	if changed {
		c.cancelRuntimeExitIPProbeLocked()
		c.active.ControlRevision++
		c.pendingPersistence = nil
	}
	revision := c.active.ControlRevision
	c.access.Unlock()
	// Detached cache/history effects still use stable graph dependencies.
	// Keep them alive through the actual effect, including final shutdown.
	defer lease.Release()
	if !accepted || effect == nil {
		return accepted
	}
	c.access.Lock()
	current := !c.stopped && c.active.ControlRevision == revision
	c.access.Unlock()
	if current {
		effect()
	}
	return accepted
}
