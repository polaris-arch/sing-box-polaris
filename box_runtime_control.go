package box

import (
	"math"
	"github.com/sagernet/sing-box/adapter"
)

func (c *runtimeCoordinator) SelectRuntimeOutbound(expected adapter.RuntimeResourceID, group, selected string) bool {
	c.controlEffects.Lock()
	defer c.controlEffects.Unlock()
	c.access.Lock()
	if c.stopped || c.active.ControlRevision == math.MaxUint64 { c.access.Unlock(); return false }
	lease, err := c.store.Acquire()
	if err != nil { c.access.Unlock(); return false }
	view, ok := lease.View().(*runtimeView)
	if !ok || view.componentIDs["outbound:" + group] != expected { c.access.Unlock(); lease.Release(); return false }
	outbound, exists := view.outbounds.Outbound(group)
	selector, selectable := outbound.(interface { RuntimeSelect(string) (bool, bool, func()) })
	if !exists || !selectable { c.access.Unlock(); lease.Release(); return false }
	changed, accepted, effect := selector.RuntimeSelect(selected)
	if changed { c.active.ControlRevision++ }
	revision := c.active.ControlRevision
	c.access.Unlock()
	defer lease.Release()
	if !accepted || effect == nil { return accepted }
	// Effects execute outside the coordinator guard. Publication cannot pass
	// this accepted control operation before its actual persistence tail.
	c.access.Lock()
	current := !c.stopped && c.active.ControlRevision == revision
	if current {
		active, acquireErr := c.store.Acquire()
		if acquireErr != nil { current = false } else {
			activeView, valid := active.View().(*runtimeView)
			current = valid && activeView.componentIDs["outbound:" + group] == expected
			active.Release()
		}
	}
	c.access.Unlock()
	if current { effect() }
	return accepted
}

func (c *runtimeCoordinator) SetRuntimeClashMode(mode string) bool {
	c.controlEffects.Lock()
	defer c.controlEffects.Unlock()
	c.access.Lock()
	if c.stopped || c.clashMode == nil || c.active.ControlRevision == math.MaxUint64 { c.access.Unlock(); return false }
	lease, err := c.store.Acquire()
	if err != nil { c.access.Unlock(); return false }
	changed, accepted, effect := c.clashMode.RuntimeSetMode(mode)
	if changed { c.active.ControlRevision++ }
	revision := c.active.ControlRevision
	c.access.Unlock()
	// Detached cache/history effects still use stable graph dependencies.
	// Keep them alive through the actual effect, including final shutdown.
	defer lease.Release()
	if !accepted || effect == nil { return accepted }
	c.access.Lock(); current := !c.stopped && c.active.ControlRevision == revision; c.access.Unlock()
	if current { effect() }
	return accepted
}
