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

func TestMDNSIdleControlPreservesActiveSocket(t *testing.T) {
	conn := &barrierPacketConn{readStarted: make(chan struct{}), closeStarted: make(chan struct{}), readMayReturn: make(chan struct{})}
	original := listenTargetPacket
	listenTargetPacket = func(*Transport, context.Context, queryTarget) (net.PacketConn, net.Addr, error) {
		return conn, &net.UDPAddr{}, nil
	}
	t.Cleanup(func() { listenTargetPacket = original })
	var once sync.Once
	unblock := func() { once.Do(func() { close(conn.readMayReturn) }) }
	defer unblock()
	transport := &Transport{logger: log.NewNOPFactory().Logger()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_, _ = transport.exchangeTarget(ctx, queryTarget{}, []byte{0}, mDNS.Question{Name: "host.local.", Qtype: mDNS.TypeA}, time.Now().Add(time.Minute))
		close(done)
	}()
	select {
	case <-conn.readStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not start")
	}
	transport.SetKeepIdleConnections(false)
	transport.CloseIdleConnections()
	transport.SetKeepIdleConnections(true)
	select {
	case <-conn.closeStarted:
		t.Fatal("idle control closed an active multicast socket")
	default:
	}
	select {
	case <-done:
		t.Fatal("idle control released active query ownership")
	default:
	}
	cancel()
	unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("normal cancellation did not join reader")
	}
}
