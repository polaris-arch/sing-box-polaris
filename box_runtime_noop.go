package box

import (
	"context"
	"errors"

	"github.com/sagernet/sing-box/adapter"
)

// No-op is a configuration-only operation: it preserves all live controls.
// Capture root content under an actual owner lease; a filename or canonical
// option digest alone cannot certify that external dependencies are unchanged.
func (c *runtimeCoordinator) runtimeCaptureRootDigest(ctx context.Context, expected RuntimeIdentity) ([32]byte, error) {
	c.access.Lock()
	if c.stopped || c.active != expected {
		c.access.Unlock()
		return [32]byte{}, errors.New("runtime changed before root capture")
	}
	var root *runtimeResource
	var lease adapter.RuntimeResourceLease
	for _, resource := range c.resources {
		if resource.kind == "certificate-store" && resource.rootStore != nil {
			root = resource
			var err error
			lease, err = resource.owner.Acquire()
			if err != nil {
				root = nil
			}
			break
		}
	}
	c.access.Unlock()
	if root == nil {
		return [32]byte{}, errors.New("active root store unavailable")
	}
	defer lease.Release()
	snapshot, err := root.rootStore.Snapshot(ctx)
	if err != nil {
		return [32]byte{}, err
	}
	defer snapshot.Release()
	return snapshot.Digest(), nil
}

func (c *runtimeCoordinator) runtimeNoOpDependenciesCurrent(ctx context.Context, expected RuntimeIdentity, sources []runtimeSourceSnapshot) bool {
	if runtimeCheckSources(ctx, sources) != nil {
		return false
	}
	digest, err := c.runtimeCaptureRootDigest(ctx, expected)
	if err != nil {
		return false
	}
	c.access.Lock()
	defer c.access.Unlock()
	return !c.stopped && c.active == expected && digest == c.rootDigest
}

func (c *runtimeCoordinator) checkRuntimeNoOpApply(ctx context.Context, actor string, request RuntimeConfigApply) error {
	c.access.Lock()
	record := c.plans[request.TransactionID]
	check := record != nil && record.actor == actor && record.plan.PlanID == request.PlanID && record.plan.NoOp && !record.consumed
	var sources []runtimeSourceSnapshot
	if check {
		sources = append([]runtimeSourceSnapshot(nil), record.sources...)
	}
	c.access.Unlock()
	if check && !c.runtimeNoOpDependenciesCurrent(ctx, request.Expected, sources) {
		return errors.New("no-op dependencies changed; prepare a new plan")
	}
	return nil
}
