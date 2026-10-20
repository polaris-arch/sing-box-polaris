package local

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
)

var _ adapter.IdleConnectionKeeper = (*DBusResolvedResolver)(nil)

func (t *DBusResolvedResolver) SetKeepIdleConnections(keep bool) {
	_, done, err := t.work.Operation(context.Background(), t.runtimeResource)
	if err != nil { return }; defer done()
	t.idleAccess.Lock()
	defer t.idleAccess.Unlock()
	t.idleDisabled = !keep
	forResolvedIdle(t.savedServerSet.Load(), func(keeper adapter.IdleConnectionKeeper) {
		keeper.SetKeepIdleConnections(keep)
	})
}

func (t *DBusResolvedResolver) CloseIdleConnections() {
	_, done, err := t.work.Operation(context.Background(), t.runtimeResource)
	if err != nil { return }; defer done()
	t.idleAccess.Lock()
	defer t.idleAccess.Unlock()
	forResolvedIdle(t.savedServerSet.Load(), func(keeper adapter.IdleConnectionKeeper) {
		keeper.CloseIdleConnections()
	})
	// The D-Bus control connection is an owned configuration producer, not an
	// idle query socket, and must remain live until normal resolver shutdown.
}

func (t *DBusResolvedResolver) swapIdleServerSet(set *resolvedServerSet) *resolvedServerSet {
	t.idleAccess.Lock()
	defer t.idleAccess.Unlock()
	forResolvedIdle(set, func(keeper adapter.IdleConnectionKeeper) {
		keeper.SetKeepIdleConnections(!t.idleDisabled)
	})
	return t.savedServerSet.Swap(set)
}

func forResolvedIdle(set *resolvedServerSet, action func(adapter.IdleConnectionKeeper)) {
	if set == nil { return }
	for _, scope := range set.scopes {
		for _, server := range scope.servers {
			action(server.primaryTransport.(adapter.IdleConnectionKeeper))
			if server.fallbackTransport != nil { action(server.fallbackTransport.(adapter.IdleConnectionKeeper)) }
		}
	}
}
