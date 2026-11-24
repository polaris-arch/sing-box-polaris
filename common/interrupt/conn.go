package interrupt

import (
	"net"
	"sync"

	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
)

type Conn struct {
	net.Conn
	group        *Group
	element      *list.Element[*groupConnItem]
	closeRequest bool
	closeOnce    sync.Once
	closeErr     error
}

func (c *Conn) Close() error {
	c.group.access.Lock()
	c.group.connections.Remove(c.element)
	c.group.access.Unlock()
	if c.closeRequest {
		return c.Conn.Close()
	}
	c.closeOnce.Do(func() { c.closeErr = c.Conn.Close() })
	return c.closeErr
}

// CloseRequestParent exposes the exact connection with an idempotent, deferred
// Close contract captured at registration, so its owner can join completion.
func (c *Conn) CloseRequestParent() net.Conn {
	if c.closeRequest {
		return c.Conn
	}
	return nil
}

func (c *Conn) ReaderReplaceable() bool {
	return true
}

func (c *Conn) WriterReplaceable() bool {
	return true
}

func (c *Conn) Upstream() any {
	return c.Conn
}

type PacketConn struct {
	N.NetPacketConn
	group              *Group
	element            *list.Element[*groupConnItem]
	closeRequestParent net.PacketConn
	closeOnce          sync.Once
	closeErr           error
}

func newPacketConn(group *Group, conn net.PacketConn) *PacketConn {
	return &PacketConn{NetPacketConn: bufio.NewPacketConn(conn), group: group}
}

func (c *PacketConn) Close() error {
	c.group.access.Lock()
	c.group.connections.Remove(c.element)
	c.group.access.Unlock()
	if c.closeRequestParent != nil {
		return c.NetPacketConn.Close()
	}
	c.closeOnce.Do(func() { c.closeErr = c.NetPacketConn.Close() })
	return c.closeErr
}

// CloseRequestParent returns the exact deferred carrier supplied at registration.
func (c *PacketConn) CloseRequestParent() net.PacketConn { return c.closeRequestParent }

func (c *PacketConn) ReaderReplaceable() bool {
	return true
}

func (c *PacketConn) WriterReplaceable() bool {
	return true
}

func (c *PacketConn) Upstream() any {
	return c.NetPacketConn
}
