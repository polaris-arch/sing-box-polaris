package listener

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type (
	runtimeDatagram struct {
		buffer *buf.Buffer
		source M.Socksaddr
	}
	RuntimePacketTransport struct {
		listener                        *Listener
		mu                              sync.Mutex
		queue                           chan runtimeDatagram
		closed                          chan struct{}
		closing                         bool
		readDeadline, timeWriteDeadline time.Time
		changed                         chan struct{}
	}
)

// PrepareRuntimePacketTransport installs an inert packet endpoint. The normal
// listener transaction binds and gates its physical socket; the QUIC worker may
// wait on this private queue before publication without reading any network data.
func (l *Listener) PrepareRuntimePacketTransport() (*RuntimePacketTransport, error) {
	if l.runtime == nil {
		return nil, ErrRuntimeRawTransport
	}
	l.runtime.mu.Lock()
	defer l.runtime.mu.Unlock()
	if l.runtime.phase != "inert" {
		return nil, ErrRuntimeTransition
	}
	endpoint := &RuntimePacketTransport{listener: l, queue: make(chan runtimeDatagram, 64), closed: make(chan struct{}), changed: make(chan struct{})}
	found := false
	for _, network := range l.network {
		if network == N.NetworkUDP {
			found = true
		}
	}
	if !found {
		l.network = append(l.network, N.NetworkUDP)
	}
	l.packetHandler = endpoint
	l.oobPacketHandler = nil
	l.threadUnsafePacketWriter = true
	l.disablePacketOutput = false
	return endpoint, nil
}

func (l *Listener) AcquireRuntimeSession(ctx context.Context) (context.Context, func(), error) {
	if l.runtime == nil {
		return nil, nil, ErrRuntimeRawTransport
	}
	return l.runtime.gateway.Acquire(ctx)
}
func (p *RuntimePacketTransport) NewPacket(buffer *buf.Buffer, _ M.Socksaddr) { buffer.Release() }
func (p *RuntimePacketTransport) NewPacketContext(_ context.Context, buffer *buf.Buffer, source M.Socksaddr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		buffer.Release()
		return
	}
	select {
	case p.queue <- runtimeDatagram{buffer, source}:
	default:
		buffer.Release()
	}
}

func (p *RuntimePacketTransport) ReadFrom(output []byte) (int, net.Addr, error) {
	for {
		p.mu.Lock()
		closing, deadline, changed := p.closing, p.readDeadline, p.changed
		p.mu.Unlock()
		if closing {
			return 0, nil, net.ErrClosed
		}
		var timer *time.Timer
		var expired <-chan time.Time
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(remaining)
			expired = timer.C
		}
		select {
		case packet := <-p.queue:
			if timer != nil {
				timer.Stop()
			}
			n := copy(output, packet.buffer.Bytes())
			packet.buffer.Release()
			return n, packet.source.UDPAddr(), nil
		case <-p.closed:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		case <-expired:
			return 0, nil, os.ErrDeadlineExceeded
		}
	}
}

func (p *RuntimePacketTransport) WriteTo(data []byte, address net.Addr) (int, error) {
	p.mu.Lock()
	closed, deadline := p.closing, p.timeWriteDeadline
	p.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	packet := buf.NewSize(len(data))
	_, _ = packet.Write(data)
	if err := p.listener.PacketWriter().WritePacket(packet, M.SocksaddrFromNet(address)); err != nil {
		return 0, err
	}
	// Like the existing packet writer, this is bounded datagram queue acceptance;
	// congestion may drop a datagram. No cross-owner socket deadline is modified.
	return len(data), nil
}

func (p *RuntimePacketTransport) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return nil
	}
	p.closing = true
	close(p.closed)
	for {
		select {
		case packet := <-p.queue:
			packet.buffer.Release()
		default:
			return nil
		}
	}
}
func (p *RuntimePacketTransport) LocalAddr() net.Addr { return p.listener.RuntimePacketLocalAddr() }

// RuntimePacketLocalAddr is an address-only immutable/atomic view. It exposes
// neither the socket nor an I/O method, and remains safe before/after binding.
func (l *Listener) RuntimePacketLocalAddr() net.Addr {
	if l.runtime != nil {
		if address := l.runtime.udpLocal.Load(); address != nil {
			copyAddress := *address
			copyAddress.IP = append(net.IP(nil), address.IP...)
			return &copyAddress
		}
	}
	options := l.listenOptions
	return M.SocksaddrFrom(options.Listen.Build(netip.AddrFrom4([4]byte{127, 0, 0, 1})), options.ListenPort).UDPAddr()
}

func (p *RuntimePacketTransport) SetReadDeadline(deadline time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return net.ErrClosed
	}
	p.readDeadline = deadline
	close(p.changed)
	p.changed = make(chan struct{})
	return nil
}

func (p *RuntimePacketTransport) SetWriteDeadline(deadline time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return net.ErrClosed
	}
	p.timeWriteDeadline = deadline
	return nil
}

func (p *RuntimePacketTransport) SetDeadline(deadline time.Time) error {
	if err := p.SetReadDeadline(deadline); err != nil {
		return err
	}
	return p.SetWriteDeadline(deadline)
}

var (
	_ adapter.PacketHandler = (*RuntimePacketTransport)(nil)
	_ RuntimePacketHandler  = (*RuntimePacketTransport)(nil)
	_ net.PacketConn        = (*RuntimePacketTransport)(nil)
)
