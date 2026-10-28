package runtimegraph

// ResourceCleanupSnapshot is observation only. It never retains or releases a
// lease. Unavailable is explicit rather than waiting for an ownership mutex.
type ResourceCleanupSnapshot struct {
	Available    bool
	State        uint8
	References   uint64
	Dependencies uint64
	Failed       bool
}

func (o *ResourceOwner) CleanupSnapshot() ResourceCleanupSnapshot {
	r := o.owner
	if !r.mu.TryLock() {
		return ResourceCleanupSnapshot{}
	}
	result := ResourceCleanupSnapshot{true, uint8(r.state), r.refs, uint64(len(r.dependencies)), r.state == resourceClosed && r.closeErr != nil}
	r.mu.Unlock()
	return result
}
