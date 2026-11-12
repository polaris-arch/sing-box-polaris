package fakeip

import "github.com/sagernet/sing-box/adapter"

var _ adapter.IdleConnectionKeeper = (*Transport)(nil)

// Fake-IP allocation has no network connection pool. Its mappings, answer
// reservations and cache writes are not idle connections.
func (*Transport) SetKeepIdleConnections(bool) {}
func (*Transport) CloseIdleConnections()       {}
