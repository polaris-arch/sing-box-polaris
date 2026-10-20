package dhcp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
)

type discoveryFailurePacket struct {
	net.PacketConn
	calls    int
	closeErr error
	writeErr error
}

func (c *discoveryFailurePacket) Close() error                              { c.calls++; return c.closeErr }
func (c *discoveryFailurePacket) WriteTo(p []byte, _ net.Addr) (int, error) { return 0, c.writeErr }
func (c *discoveryFailurePacket) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func TestDHCPDiscoveryCloseFailureIsOnceAndSticky(t *testing.T) {
	failure := errors.New("close failure")
	raw := &discoveryFailurePacket{closeErr: failure}
	tr := &Transport{ctx: context.Background()}
	owned := &ownedDiscoveryPacket{PacketConn: raw, errors: &tr.discoveryErrors}
	firstClose := owned.Close()
	secondClose := owned.Close()
	if !errors.Is(firstClose, failure) || !errors.Is(secondClose, failure) || raw.calls != 1 {
		t.Fatal("physical close repeated or failure lost")
	}
	first := tr.close()
	second := tr.close()
	if first == nil || first != second {
		t.Fatal("discovery uncertainty was not sticky")
	}
}

func TestDHCPFailedDiscoveryCompensatesSocket(t *testing.T) {
	failure := errors.New("close failure")
	writeFailure := errors.New("discovery write failure")
	raw := &discoveryFailurePacket{closeErr: failure, writeErr: writeFailure}
	original := listenDiscoveryPacket
	listenDiscoveryPacket = func(*net.ListenConfig, context.Context, string, string) (net.PacketConn, error) { return raw, nil }
	t.Cleanup(func() { listenDiscoveryPacket = original })
	tr := &Transport{ctx: context.Background(), logger: log.NewNOPFactory().Logger(), networkManager: discoveryNetwork{}}
	iface := &control.Interface{}
	iface.Name = "fixture"
	iface.HardwareAddr = net.HardwareAddr{2, 0, 0, 0, 0, 1}
	if err := tr.fetchServers0(context.Background(), iface); !errors.Is(err, writeFailure) {
		t.Fatal("discovery error changed", err)
	}
	if raw.calls != 1 || tr.close() == nil {
		t.Fatal("failed construction compensation missing")
	}
}

func TestDHCPNormalDiscoveryReturnRecordsCloseFailure(t *testing.T) {
	raw := &discoveryFailurePacket{closeErr: errors.New("close failure")}
	original := listenDiscoveryPacket
	listenDiscoveryPacket = func(*net.ListenConfig, context.Context, string, string) (net.PacketConn, error) { return raw, nil }
	t.Cleanup(func() { listenDiscoveryPacket = original })
	tr := &Transport{ctx: context.Background(), logger: log.NewNOPFactory().Logger(), networkManager: discoveryNetwork{}}
	iface := &control.Interface{}
	iface.Name = "fixture"
	iface.HardwareAddr = net.HardwareAddr{2, 0, 0, 0, 0, 1}
	_ = tr.fetchServers0(context.Background(), iface)
	if raw.calls != 1 || tr.close() == nil {
		t.Fatal("normal defer lost close result")
	}
}

func TestDHCPMetadataReturnsDetachedSlices(t *testing.T) {
	tr := &Transport{ctx: context.Background()}
	defer tr.close()
	address := M.SocksaddrFrom(netip.MustParseAddr("192.0.2.53"), 53)
	tr.savedState.Store(&transportState{updatedAt: time.Now(), search: []string{"example."}, servers: []M.Socksaddr{address}})
	search := tr.SearchDomains()
	search[0] = "changed."
	servers := tr.Fetch()
	servers[0] = M.Socksaddr{}
	if tr.SearchDomains()[0] != "example." || tr.Fetch()[0] != address {
		t.Fatal("caller mutated owned discovery metadata")
	}
}

type discoveryCancelFailure struct {
	discoveryBarrierConn
	calls   int
	failure error
}

func (c *discoveryCancelFailure) Close() error {
	c.calls++
	_ = c.discoveryBarrierConn.Close()
	return c.failure
}

func TestDHCPCancellationCloseFailureJoinsAndSurvives(t *testing.T) {
	raw := &discoveryCancelFailure{readStarted: make(chan struct{}), closeStarted: make(chan struct{}), readMayReturn: make(chan struct{}), failure: errors.New("cancel close failure")}
	original := listenDiscoveryPacket
	listenDiscoveryPacket = func(*net.ListenConfig, context.Context, string, string) (net.PacketConn, error) { return raw, nil }
	t.Cleanup(func() { listenDiscoveryPacket = original })
	tr := &Transport{ctx: context.Background(), logger: log.NewNOPFactory().Logger(), networkManager: discoveryNetwork{}}
	iface := &control.Interface{}
	iface.Name = "fixture"
	iface.HardwareAddr = net.HardwareAddr{2, 0, 0, 0, 0, 1}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = tr.fetchServers0(ctx, iface) }()
	select {
	case <-raw.readStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not start")
	}
	cancel()
	select {
	case <-raw.closeStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not close socket")
	}
	select {
	case <-done:
		t.Fatal("reader completion fabricated")
	default:
	}
	close(raw.readMayReturn)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not join")
	}
	if raw.calls != 1 || tr.close() == nil {
		t.Fatal("cancel close failure lost")
	}
}
