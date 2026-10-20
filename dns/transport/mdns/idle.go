package mdns

import "github.com/sagernet/sing-box/adapter"

var _ adapter.IdleConnectionKeeper = (*Transport)(nil)

// Every multicast socket belongs to one exchange and closes with that
// exchange. There are no retained idle sockets or configuration resets here.
func (*Transport) SetKeepIdleConnections(bool) {}
func (*Transport) CloseIdleConnections() {}
