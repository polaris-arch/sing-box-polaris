package interrupt

import (
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing/common/x/list"
)

type Group struct {
	access      sync.Mutex
	connections list.List[*groupConnItem]
}

type groupConnItem struct {
	conn       io.Closer
	isExternal bool
}

func NewGroup() *Group {
	return &Group{}
}

func (g *Group) Add(closer io.Closer, isExternal bool) (remove func()) {
	g.access.Lock()
	defer g.access.Unlock()
	element := g.connections.PushBack(&groupConnItem{closer, isExternal})
	return func() {
		g.access.Lock()
		defer g.access.Unlock()
		g.connections.Remove(element)
	}
}

func (g *Group) NewConn(conn net.Conn, isExternal bool) net.Conn {
	return g.newConn(conn, isExternal, false)
}

// NewConnWithCloseRequest registers a connection whose Close starts an
// idempotent request and can report a different result once it completes.
func (g *Group) NewConnWithCloseRequest(conn net.Conn, isExternal bool) net.Conn {
	return g.newConn(conn, isExternal, true)
}

func (g *Group) newConn(conn net.Conn, isExternal, closeRequest bool) net.Conn {
	g.access.Lock()
	defer g.access.Unlock()
	wrapper := &Conn{Conn: conn, group: g, closeRequest: closeRequest}
	wrapper.element = g.connections.PushBack(&groupConnItem{wrapper, isExternal})
	return wrapper
}

func (g *Group) NewPacketConn(conn net.PacketConn, isExternal bool) net.PacketConn {
	return g.newPacketConn(conn, isExternal, false)
}

// NewPacketConnWithCloseRequest registers a packet connection whose Close
// starts an idempotent request and can report a different result after completion.
func (g *Group) NewPacketConnWithCloseRequest(conn net.PacketConn, isExternal bool) net.PacketConn {
	return g.newPacketConn(conn, isExternal, true)
}

func (g *Group) newPacketConn(conn net.PacketConn, isExternal, closeRequest bool) net.PacketConn {
	g.access.Lock()
	defer g.access.Unlock()
	wrapper := newPacketConn(g, conn)
	if closeRequest {
		wrapper.closeRequestParent = conn
	}
	wrapper.element = g.connections.PushBack(&groupConnItem{wrapper, isExternal})
	return wrapper
}

func (g *Group) Interrupt(interruptExternalConnections bool) {
	g.access.Lock()
	var closers []io.Closer
	for element := g.connections.Front(); element != nil; {
		nextElement := element.Next()
		if !element.Value.isExternal || interruptExternalConnections {
			closers = append(closers, element.Value.conn)
			g.connections.Remove(element)
		}
		element = nextElement
	}
	g.access.Unlock()
	for _, closer := range closers {
		closer.Close()
	}
}
