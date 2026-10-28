package dhcp

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
	setStateKeepIdle(t.savedState.Load(), keep)
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
	if state := t.savedState.Load(); state != nil {
		for _, server := range state.serverTransports {
			server.(adapter.IdleConnectionKeeper).CloseIdleConnections()
		}
	}
	// Discovery sockets belong to the active discovery operation. They are
	// never pooled and are deliberately unaffected by this idle-only effect.
}

// storeState serializes lazy cohort publication with idle-policy changes.
// The discovery/refresh lock is never needed by the idle observer.
func (t *Transport) storeState(state *transportState) {
	t.idleAccess.Lock()
	defer t.idleAccess.Unlock()
	setStateKeepIdle(state, !t.idleDisabled)
	t.savedState.Store(state)
}

func setStateKeepIdle(state *transportState, keep bool) {
	if state == nil {
		return
	}
	for _, server := range state.serverTransports {
		server.(adapter.IdleConnectionKeeper).SetKeepIdleConnections(keep)
	}
}
