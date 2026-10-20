package mdns

import (
	"errors"
	"net"
	"sync"

	"github.com/sagernet/sing-box/dns/transport/lifecycle"
)

type packetSocketErrors struct {
	mu  sync.Mutex
	err error
}

func (e *packetSocketErrors) record(err error) {
	if err == nil {
		return
	}
	e.mu.Lock()
	e.err = errors.Join(e.err, lifecycle.Uncertain("mDNS packet socket", err))
	e.mu.Unlock()
}
func (e *packetSocketErrors) result() error { e.mu.Lock(); defer e.mu.Unlock(); return e.err }

// Cancellation and normal-return defers share one physical close and result.
type ownedPacketConn struct {
	net.PacketConn
	once   sync.Once
	err    error
	errors *packetSocketErrors
}

func (c *ownedPacketConn) Close() error {
	c.once.Do(func() { c.err = c.PacketConn.Close(); c.errors.record(c.err) })
	return c.err
}

func (t *Transport) closeSetupPacket(conn net.PacketConn) { t.socketErrors.record(conn.Close()) }
