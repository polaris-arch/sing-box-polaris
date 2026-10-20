package dhcp

import (
	"errors"
	"net"
	"sync"

	"github.com/sagernet/sing-box/dns/transport/lifecycle"
)

// Discovery belongs to the existing producer/cold-query operation. Preserve
// cancellation and normal-return destruction failures until those workers join.
type discoverySocketErrors struct {
	mu  sync.Mutex
	err error
}

func (e *discoverySocketErrors) record(err error) {
	if err == nil {
		return
	}
	e.mu.Lock()
	e.err = errors.Join(e.err, lifecycle.Uncertain("DHCP discovery socket", err))
	e.mu.Unlock()
}
func (e *discoverySocketErrors) result() error { e.mu.Lock(); defer e.mu.Unlock(); return e.err }

type ownedDiscoveryPacket struct {
	net.PacketConn
	once   sync.Once
	err    error
	errors *discoverySocketErrors
}

func (c *ownedDiscoveryPacket) Close() error {
	c.once.Do(func() { c.err = c.PacketConn.Close(); c.errors.record(c.err) })
	return c.err
}
