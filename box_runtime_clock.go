package box

import (
	"context"
	"errors"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/ntp"
)

func (c *runtimeCoordinator) runtimeClockWriter(id adapter.RuntimeResourceID) func(context.Context, time.Time) error {
	return func(ctx context.Context, value time.Time) error {
		return c.writeRuntimeClock(ctx, id, value, ntp.SetSystemTime)
	}
}

func (c *runtimeCoordinator) writeRuntimeClock(ctx context.Context, id adapter.RuntimeResourceID, value time.Time, write func(time.Time) error) error {
	borrowed, ok := adapter.RuntimeResourceLeaseFromContext(ctx, id)
	if !ok {
		return errors.New("clock write lacks its exact resource continuation")
	}
	held, err := borrowed.Fork()
	if err != nil {
		return err
	}
	defer held.Release()
	if err := c.controlEffects.LockContext(ctx); err != nil {
		return err
	}
	defer c.controlEffects.Unlock()
	c.access.Lock()
	active := false
	if !c.stopped {
		for _, resource := range c.resources {
			if resource.id == id {
				active = true
				break
			}
		}
	}
	c.access.Unlock()
	if !active {
		return errors.New("clock allocation is no longer active")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// No user callback or system call under the graph/coordinator guard. The
	// control-effects gate prevents replacement until this admitted write returns.
	return write(value)
}
