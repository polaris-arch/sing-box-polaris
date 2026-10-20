package hosts

import "github.com/sagernet/sing-box/adapter"

var _ adapter.IdleConnectionKeeper = (*Transport)(nil)

// Hosts lookups have no connection pool. Idle control must leave the files,
// their watchers and any admitted lookup/callback owned until normal shutdown.
func (*Transport) SetKeepIdleConnections(bool) {}
func (*Transport) CloseIdleConnections()       {}
