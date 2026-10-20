package dhcp

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/control"
)

type discoveryBarrierConn struct {
	readStarted   chan struct{}
	closeStarted  chan struct{}
	readMayReturn chan struct{}
	closeOnce     sync.Once
}

func (c *discoveryBarrierConn) ReadFrom([]byte) (int, net.Addr, error) {
	close(c.readStarted)
	<-c.readMayReturn
	return 0, nil, net.ErrClosed
}
func (c *discoveryBarrierConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *discoveryBarrierConn) Close() error {
	c.closeOnce.Do(func() { close(c.closeStarted) })
	return nil
}
func (c *discoveryBarrierConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *discoveryBarrierConn) SetDeadline(time.Time) error      { return nil }
func (c *discoveryBarrierConn) SetReadDeadline(time.Time) error  { return nil }
func (c *discoveryBarrierConn) SetWriteDeadline(time.Time) error { return nil }

type discoveryNetwork struct{ adapter.NetworkManager }

func (discoveryNetwork) InterfaceFinder() control.InterfaceFinder { return nil }

func TestDHCPCancellationWaitsForActualDiscoveryReader(t *testing.T) {
	conn := &discoveryBarrierConn{readStarted: make(chan struct{}), closeStarted: make(chan struct{}), readMayReturn: make(chan struct{})}
	original := listenDiscoveryPacket
	listenDiscoveryPacket = func(*net.ListenConfig, context.Context, string, string) (net.PacketConn, error) { return conn, nil }
	t.Cleanup(func() { listenDiscoveryPacket = original })
	transport := &Transport{logger: log.NewNOPFactory().Logger(), networkManager: discoveryNetwork{}}
	iface := &control.Interface{}
	iface.Name = "barrier"
	iface.HardwareAddr = net.HardwareAddr{2, 0, 0, 0, 0, 1}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = transport.fetchServers0(ctx, iface); close(done) }()
	select {
	case <-conn.readStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not start")
	}
	cancel()
	select {
	case <-conn.closeStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not close discovery socket")
	}
	select {
	case <-done:
		t.Fatal("discovery cancellation was falsely completed")
	default:
	}
	close(conn.readMayReturn)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("discovery did not join its reader")
	}
}

func TestRetiredDHCPProducerCannotRestartFromCopiedMonitorCallback(t *testing.T) {
	transport := &Transport{ctx: context.Background(), logger: log.NewNOPFactory().Logger()}
	transport.initRuntime()
	transport.StopRuntimeProducers()
	// A copied callback may execute after monitor.UnregisterCallback. It must
	// fail its producer gate before reaching the deliberately absent network.
	transport.interfaceUpdated(context.Background())
	transport.startRefresh()
	transport.producers.Wait()
}
