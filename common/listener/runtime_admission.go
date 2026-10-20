package listener

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

var ErrAdmissionPaused = errors.New("listener admission is paused")

// AdmissionGateway belongs to a physical ingress, not a runtime graph. Pausing
// closes the acquire boundary and joins admission attempts. Already admitted
// sessions own graph/resource leases independently and continue after Pause.
// Acquisition and lease release are deliberately outside the gateway mutex.
type AdmissionGateway struct {
	mu        sync.Mutex
	admission adapter.RuntimeAdmission
	source    adapter.RuntimeResourceSource
	open      bool
	sealed    bool
	pausing   int
	pending   int
	idle      chan struct{}
	changed   chan struct{}
}

func NewAdmissionGateway(admission adapter.RuntimeAdmission, source adapter.RuntimeResourceSource) *AdmissionGateway {
	idle := make(chan struct{})
	close(idle)
	return &AdmissionGateway{admission: admission, source: source, idle: idle, changed: make(chan struct{})}
}

func (g *AdmissionGateway) Resume() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sealed {
		return net.ErrClosed
	}
	if g.pausing != 0 {
		return ErrRuntimeTransition
	}
	if g.admission == nil || g.source == nil {
		return errors.New("listener admission requires graph and exact resource source")
	}
	if !g.open {
		g.open = true
		close(g.changed)
		g.changed = make(chan struct{})
	}
	return nil
}

func (g *AdmissionGateway) WaitOpen(stop <-chan struct{}) bool {
	for {
		g.mu.Lock()
		open, sealed, changed := g.open, g.sealed, g.changed
		g.mu.Unlock()
		if sealed {
			return false
		}
		if open {
			select {
			case <-stop:
				return false
			default:
				return true
			}
		}
		select {
		case <-stop:
			return false
		case <-changed:
		}
	}
}

func (g *AdmissionGateway) pause(seal bool) {
	g.mu.Lock()
	if g.open {
		g.open = false
		close(g.changed)
		g.changed = make(chan struct{})
	}
	g.pausing++
	if seal && !g.sealed {
		g.sealed = true
		close(g.changed)
		g.changed = make(chan struct{})
	}
	idle := g.idle
	g.mu.Unlock()
	<-idle
	g.mu.Lock()
	g.pausing--
	g.mu.Unlock()
}
func (g *AdmissionGateway) PauseAndWait() { g.pause(false) }
func (g *AdmissionGateway) SealAndWait()  { g.pause(true) }

// Acquire requires exact membership in the newly admitted graph. It never
// falls back to source.Acquire: that would combine an old listener/auth graph
// with an unrelated newly published graph. Caller owns release until transfer.
func (g *AdmissionGateway) Acquire(ctx context.Context) (context.Context, func(), error) {
	g.mu.Lock()
	if !g.open || g.sealed {
		g.mu.Unlock()
		return nil, nil, ErrAdmissionPaused
	}
	if g.pending == 0 {
		g.idle = make(chan struct{})
	}
	g.pending++
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.pending--
		if g.pending == 0 {
			close(g.idle)
		}
		g.mu.Unlock()
	}()
	graph, err := g.admission.Acquire()
	if err != nil {
		return nil, nil, err
	}
	resource, err := graph.RetainResource(g.source.ID())
	if err != nil {
		graph.Release()
		return nil, nil, err
	}
	ctx = adapter.ContextWithRuntimeOwnership(ctx, context.Background())
	ctx = adapter.ContextWithRuntimeLease(ctx, graph)
	ctx = adapter.ContextWithRuntimeResourceLease(ctx, resource)
	var once sync.Once
	return ctx, func() { once.Do(func() { resource.Release(); graph.Release() }) }, nil
}

// RuntimePacketHandler must fork incoming ownership before storing a packet,
// scheduling a callback or creating a NAT/QUIC session. Existing PacketHandler
// has no context and cannot make that promise on behalf of its implementation.
type RuntimePacketHandler interface {
	NewPacketContext(context.Context, *buf.Buffer, M.Socksaddr)
}
type RuntimePacketBatchHandler interface {
	NewPacketBatchContext(context.Context, []*buf.Buffer, []M.Socksaddr)
}
type RuntimeOOBPacketHandler interface {
	NewPacketContext(context.Context, *buf.Buffer, []byte, M.Socksaddr)
}

func (l *Listener) dispatchRuntimeConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) {
	owned, release, err := l.runtime.gateway.Acquire(ctx)
	if err != nil {
		_ = conn.Close()
		return
	}
	// Invocation and carrier are separate: Close/onClose may run synchronously
	// while the handshake callback is still unwinding through its dependencies.
	invocation, releaseInvocation, err := adapter.AcquireRuntimeOperation(owned, nil)
	if err != nil {
		release()
		_ = conn.Close()
		return
	}
	carrier := outbound.WrapRuntimeConn(owned, release, conn)
	go func() {
		defer releaseInvocation()
		l.connHandler.NewConnection(invocation, carrier, metadata, func(error) { _ = carrier.Close() })
	}()
}

func (l *Listener) dispatchRuntimePacket(buffer *buf.Buffer, source M.Socksaddr) {
	if l.dispatchRuntimeControl(buffer.Bytes(), source) {
		if l.threadUnsafePacketWriter {
			buffer.Release()
		}
		return
	}
	ctx, release, err := l.runtime.gateway.Acquire(l.ctx)
	if err != nil {
		if l.threadUnsafePacketWriter {
			buffer.Release()
		}
		return
	}
	defer release()
	l.packetHandler.(RuntimePacketHandler).NewPacketContext(ctx, buffer, source)
}

func (l *Listener) dispatchRuntimeOOBPacket(buffer *buf.Buffer, oob []byte, source M.Socksaddr) {
	if l.dispatchRuntimeControl(buffer.Bytes(), source) {
		if l.threadUnsafePacketWriter {
			buffer.Release()
		}
		return
	}
	ctx, release, err := l.runtime.gateway.Acquire(l.ctx)
	if err != nil {
		if l.threadUnsafePacketWriter {
			buffer.Release()
		}
		return
	}
	defer release()
	l.oobPacketHandler.(RuntimeOOBPacketHandler).NewPacketContext(ctx, buffer, oob, source)
}

func (l *Listener) dispatchRuntimePacketBatch(buffers []*buf.Buffer, sources []M.Socksaddr) {
	ctx, release, err := l.runtime.gateway.Acquire(l.ctx)
	if err != nil {
		buf.ReleaseMulti(buffers)
		return
	}
	defer release()
	l.packetHandler.(RuntimePacketBatchHandler).NewPacketBatchContext(ctx, buffers, sources)
}
