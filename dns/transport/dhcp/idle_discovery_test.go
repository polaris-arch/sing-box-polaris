package dhcp

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/control"
)

func TestDHCPIdleControlPreservesActiveDiscovery(t *testing.T) {
	conn := &discoveryBarrierConn{readStarted: make(chan struct{}), closeStarted: make(chan struct{}), readMayReturn: make(chan struct{})}
	original := listenDiscoveryPacket
	listenDiscoveryPacket = func(*net.ListenConfig, context.Context, string, string) (net.PacketConn, error) { return conn, nil }
	t.Cleanup(func() { listenDiscoveryPacket = original })
	var once sync.Once
	unblock := func() { once.Do(func() { close(conn.readMayReturn) }) }; defer unblock()
	transport := &Transport{ctx: context.Background(), logger: log.NewNOPFactory().Logger(), networkManager: discoveryNetwork{}}
	iface := &control.Interface{}
	iface.Name = "barrier"; iface.HardwareAddr = net.HardwareAddr{2, 0, 0, 0, 0, 1}
	ctx, cancel := context.WithCancel(context.Background()); defer cancel()
	done := make(chan struct{})
	go func() { _ = transport.fetchServers0(ctx, iface); close(done) }()
	select { case <-conn.readStarted: case <-time.After(5*time.Second): t.Fatal("discovery reader did not start") }
	transport.SetKeepIdleConnections(false)
	transport.CloseIdleConnections()
	select { case <-conn.closeStarted: t.Fatal("idle control closed an active discovery socket"); default: }
	select { case <-done: t.Fatal("idle control released discovery ownership"); default: }
	cancel(); unblock()
	select { case <-done: case <-time.After(5*time.Second): t.Fatal("normal cancellation did not join discovery") }
}
