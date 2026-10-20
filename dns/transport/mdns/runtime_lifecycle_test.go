package mdns

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	mDNS "github.com/miekg/dns"
)

type barrierPacketConn struct {
	readStarted chan struct{}
	closeStarted chan struct{}
	readMayReturn chan struct{}
	closeOnce sync.Once
}
func (c *barrierPacketConn) ReadFrom([]byte) (int, net.Addr, error) { close(c.readStarted); <-c.readMayReturn; return 0, nil, net.ErrClosed }
func (c *barrierPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *barrierPacketConn) Close() error { c.closeOnce.Do(func() { close(c.closeStarted) }); return nil }
func (c *barrierPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (c *barrierPacketConn) SetDeadline(time.Time) error { return nil }
func (c *barrierPacketConn) SetReadDeadline(time.Time) error { return nil }
func (c *barrierPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestMDNSCancellationWaitsForActualSocketReader(t *testing.T) {
	conn := &barrierPacketConn{readStarted: make(chan struct{}), closeStarted: make(chan struct{}), readMayReturn: make(chan struct{})}
	original := listenTargetPacket
	listenTargetPacket = func(*Transport, context.Context, queryTarget) (net.PacketConn, net.Addr, error) { return conn, &net.UDPAddr{}, nil }
	t.Cleanup(func() { listenTargetPacket = original })
	transport := &Transport{logger: log.NewNOPFactory().Logger()}
	ctx, cancel := context.WithCancel(context.Background()); defer cancel()
	done := make(chan struct{})
	go func() {
		_, _ = transport.exchangeTarget(ctx, queryTarget{}, []byte{0}, mDNS.Question{Name: "host.local.", Qtype: mDNS.TypeA}, time.Now().Add(time.Minute))
		close(done)
	}()
	select { case <-conn.readStarted: case <-time.After(5*time.Second): t.Fatal("reader did not start") }
	cancel()
	select { case <-conn.closeStarted: case <-time.After(5*time.Second): t.Fatal("cancel did not close socket") }
	select { case <-done: t.Fatal("socket close was treated as reader completion"); default: }
	close(conn.readMayReturn)
	select { case <-done: case <-time.After(5*time.Second): t.Fatal("reader completion was not joined") }
}
