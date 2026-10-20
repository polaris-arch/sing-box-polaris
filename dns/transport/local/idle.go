package local

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
)

var _ adapter.IdleConnectionKeeper = (*Transport)(nil)

func (t *Transport) SetKeepIdleConnections(keep bool) {
	t.initRuntime()
	_, done, err := t.work.Operation(context.Background(), t.runtimeResource)
	if err != nil {
		return
	}
	defer done()
	t.idleAccess.Lock()
	defer t.idleAccess.Unlock()
	t.idleDisabled = !keep
	setLocalKeepIdle(t.serverSet.Load(), keep)
	t.runtimeStateAccess.Lock()
	resolved := t.resolved
	t.runtimeStateAccess.Unlock()
	if resolved != nil {
		resolved.SetKeepIdleConnections(keep)
	}
	t.system.setKeepIdleConnections(keep)
	// The local mDNS child owns only per-query sockets, not idle connections.
}

func (t *Transport) CloseIdleConnections() {
	t.initRuntime()
	_, done, err := t.work.Operation(context.Background(), t.runtimeResource)
	if err != nil {
		return
	}
	defer done()
	t.idleAccess.Lock()
	defer t.idleAccess.Unlock()
	if set := t.serverSet.Load(); set != nil {
		for _, server := range set.transports {
			server.(adapter.IdleConnectionKeeper).CloseIdleConnections()
		}
	}
	t.runtimeStateAccess.Lock()
	resolved := t.resolved
	t.runtimeStateAccess.Unlock()
	if resolved != nil {
		resolved.CloseIdleConnections()
	}
	t.system.closeIdleConnections()
}

func (t *Transport) swapServerSet(set *localServerSet) *localServerSet {
	t.idleAccess.Lock()
	defer t.idleAccess.Unlock()
	setLocalKeepIdle(set, !t.idleDisabled)
	return t.serverSet.Swap(set)
}

func setLocalKeepIdle(set *localServerSet, keep bool) {
	if set == nil {
		return
	}
	for _, server := range set.transports {
		server.(adapter.IdleConnectionKeeper).SetKeepIdleConnections(keep)
	}
}

func (t *Transport) installResolved(resolved ResolvedResolver) {
	t.idleAccess.Lock()
	defer t.idleAccess.Unlock()
	if resolved != nil {
		resolved.SetKeepIdleConnections(!t.idleDisabled)
	}
	t.runtimeStateAccess.Lock()
	t.resolved = resolved
	t.runtimeStateAccess.Unlock()
}
