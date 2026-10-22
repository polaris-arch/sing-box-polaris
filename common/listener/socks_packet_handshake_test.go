package listener

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

// Real pinned SOCKS handshake, with byte transcripts and in-memory carriers.
// No network namespace, real socket, remote peer, or timing sleep is required.
type socksControlFixture struct {
	request   *bytes.Reader
	writes    int
	writeErr  error
	closed    chan struct{}
	readDone  chan struct{}
	closeOnce sync.Once
	closes    atomic.Int32
}

func (c *socksControlFixture) Read(p []byte) (int, error) {
	if c.request.Len() != 0 {
		return c.request.Read(p)
	}
	<-c.closed
	close(c.readDone)
	return 0, io.EOF
}

func (c *socksControlFixture) Write(p []byte) (int, error) {
	c.writes++
	if c.writes == 2 && c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(p), nil
}

func (c *socksControlFixture) Close() error {
	c.closeOnce.Do(func() { c.closes.Add(1); close(c.closed) })
	return nil
}

func (*socksControlFixture) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IP{127, 0, 0, 1}, Port: 10000}
}

func (*socksControlFixture) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IP{127, 0, 0, 1}, Port: 10001}
}
func (*socksControlFixture) SetDeadline(time.Time) error      { return nil }
func (*socksControlFixture) SetReadDeadline(time.Time) error  { return nil }
func (*socksControlFixture) SetWriteDeadline(time.Time) error { return nil }

type socksDatagramFixture struct {
	socksPacketFixture
	first     atomic.Bool
	readErr   error
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *socksDatagramFixture) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.readErr != nil {
		return 0, nil, c.readErr
	}
	if c.first.CompareAndSwap(false, true) {
		packet := []byte{0, 0, 0, 1, 203, 0, 113, 10, 0, 80, 'o', 'k'}
		return copy(p, packet), &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 10002}, nil
	}
	<-c.closed
	return 0, nil, net.ErrClosed
}

func (c *socksDatagramFixture) Close() error {
	c.closeOnce.Do(func() { c.closes.Add(1); close(c.closed) })
	return nil
}

type socksPacketHandlerFixture struct {
	packet N.PacketConn
	finish N.CloseHandlerFunc
}

func (*socksPacketHandlerFixture) NewConnectionEx(context.Context, net.Conn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
	panic("UDP transcript unexpectedly selected TCP")
}

func (h *socksPacketHandlerFixture) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, finish N.CloseHandlerFunc) {
	h.packet, h.finish = conn, finish
}

func TestSOCKSPacketPinnedHandshakeRollbackAndControlLifetime(t *testing.T) {
	for _, mode := range []string{"response-write-error", "first-packet-error", "success-control-close"} {
		t.Run(mode, func(t *testing.T) {
			failure := errors.New(mode)
			control := &socksControlFixture{
				request: bytes.NewReader([]byte{5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0}),
				closed:  make(chan struct{}), readDone: make(chan struct{}),
			}
			defer control.Close()
			packet := &socksDatagramFixture{closed: make(chan struct{})}
			defer packet.Close()
			if mode == "response-write-error" {
				control.writeErr = failure
			}
			if mode == "first-packet-error" {
				packet.readErr = failure
			}
			allocations := 0
			transaction := NewSOCKSPacketListener(func(_ net.ListenConfig, _ context.Context, network, address string) (net.PacketConn, error) {
				allocations++
				if network != "udp" || address != "127.0.0.1:0" {
					t.Fatalf("unexpected UDP bind scope: %s %s", network, address)
				}
				return packet, nil
			})
			handler := new(socksPacketHandlerFixture)
			terminals := 0
			callback := func(error) { terminals++; _ = control.Close() }
			err := socks.HandleConnectionEx(context.Background(), control, bufio.NewReader(control), nil, handler, transaction, 0, M.Socksaddr{}, callback)
			err = transaction.Finish(err)
			if allocations != 1 {
				t.Fatal("handshake did not use exactly one captured allocation")
			}
			if mode == "success-control-close" {
				if err != nil || handler.packet == nil || packet.closes.Load() != 0 || control.closes.Load() != 0 || terminals != 0 {
					t.Fatalf("success prematurely ended UDP ownership: %v", err)
				}
				first := buf.NewPacket()
				destination, readErr := handler.packet.ReadPacket(first)
				payload := string(first.Bytes())
				first.Release()
				if readErr != nil || destination.String() != "203.0.113.10:80" || payload != "ok" {
					t.Fatal("cached first packet was lost")
				}
				_ = control.Close()
				waitSOCKSClosure(t, packet.closed)
				// Model the route's terminal callback after observing actual
				// control/UDP closure, not completion of the parser itself.
				handler.finish(nil)
				_ = handler.packet.Close()
			} else {
				if !errors.Is(err, failure) || handler.packet != nil || packet.closes.Load() != 1 {
					t.Fatal("failed handshake leaked allocated UDP carrier")
				}
				N.CloseOnHandshakeFailure(control, callback, err)
			}
			if mode != "response-write-error" {
				waitSOCKSClosure(t, control.readDone)
			}
			if terminals != 1 || packet.closes.Load() != 1 || control.closes.Load() != 1 {
				t.Fatal("TCP control/UDP/terminal ownership was not closed exactly once")
			}
		})
	}
}

func waitSOCKSClosure(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SOCKS control goroutine did not terminate")
	}
}
