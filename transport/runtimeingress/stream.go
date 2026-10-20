package runtimeingress

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	N "github.com/sagernet/sing/common/network"
)

// StreamAcceptor transfers the existing physical carrier into a private server.
// Ready closes only when the concrete Serve loop actually calls Accept.
type StreamAcceptor struct {
	queue     chan net.Conn
	closed    chan struct{}
	ready     chan struct{}
	once      sync.Once
	readyOnce sync.Once
}

func (a *StreamAcceptor) Accept() (net.Conn, error) {
	a.readyOnce.Do(func() { close(a.ready) })
	select {
	case <-a.closed:
		return nil, net.ErrClosed
	case conn := <-a.queue:
		return conn, nil
	}
}
func (a *StreamAcceptor) Close() error   { a.once.Do(func() { close(a.closed) }); return nil }
func (a *StreamAcceptor) Addr() net.Addr { return &net.TCPAddr{} }
func (a *StreamAcceptor) NewConnection(ctx context.Context, conn net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	// The Listener already owns both the invocation and physical carrier. The
	// server receives that exact context, not a fresh active-graph snapshot.
	lineage, ok := outbound.RuntimeConnContext(conn)
	if !ok {
		_ = conn.Close()
		if onClose != nil {
			onClose(net.ErrClosed)
		}
		return
	}
	select {
	case <-a.closed:
		_ = conn.Close()
		if onClose != nil {
			onClose(net.ErrClosed)
		}
	case <-ctx.Done():
		_ = conn.Close()
		if onClose != nil {
			onClose(ctx.Err())
		}
	case a.queue <- &Conn{Conn: conn, Context: lineage}:
	}
}

func NewStreamAcceptor() *StreamAcceptor {
	return &StreamAcceptor{queue: make(chan net.Conn), closed: make(chan struct{}), ready: make(chan struct{})}
}
func (a *StreamAcceptor) Ready() <-chan struct{} { return a.ready }
