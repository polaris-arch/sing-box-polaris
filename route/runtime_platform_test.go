package route

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/service"
)

func TestRuntimeNeighborFreshNativeAndLeaseReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnsmasq.leases")
	write := func(name string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("0 02:00:00:00:00:01 192.0.2.7 "+name+" *\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("first")
	address := netip.MustParseAddr("192.0.2.8")
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 2}
	reads := 0
	failed := false
	n := &runtimeNeighbor{leaseFiles: []string{path}, read: func() ([]adapter.NeighborEntry, error) {
		reads++
		if failed {
			return nil, errors.New("native read unavailable")
		}
		return []adapter.NeighborEntry{{Address: address, MACAddress: mac}}, nil
	}}
	if err := n.refresh(); err != nil {
		t.Fatal(err)
	}
	mac[5] = 9
	got, ok := n.LookupMAC(address)
	if !ok || got[5] != 2 {
		t.Fatal("native result was not captured independently", got)
	}
	got[5] = 7
	again, _ := n.LookupMAC(address)
	if again[5] != 2 {
		t.Fatal("lookup leaked mutable table")
	}
	if name, ok := n.LookupHostname(netip.MustParseAddr("192.0.2.7")); !ok || name != "first" {
		t.Fatal(name, ok)
	}
	write("second")
	if err := n.refresh(); err != nil {
		t.Fatal(err)
	}
	if name, _ := n.LookupHostname(netip.MustParseAddr("192.0.2.7")); name != "second" || reads != 2 {
		t.Fatal("refresh reused an old subscription cache", name, reads)
	}
	failed = true
	if err := n.refresh(); err == nil {
		t.Fatal("fresh native failure was hidden")
	}
	if name, _ := n.LookupHostname(netip.MustParseAddr("192.0.2.7")); name != "second" {
		t.Fatal("failed refresh destroyed retained sample")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	failed = false
	if err := n.refresh(); err == nil {
		t.Fatal("missing explicit lease file silently became an empty sample")
	}
}

type runtimeBlockingWIFIReader struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	closes  atomic.Int32
}

func (*runtimeBlockingWIFIReader) Start() error { return nil }
func (r *runtimeBlockingWIFIReader) ReadWIFIState(context.Context) adapter.WIFIState {
	r.once.Do(func() { close(r.entered) })
	<-r.release
	return adapter.WIFIState{SSID: "fresh"}
}
func (r *runtimeBlockingWIFIReader) Close() error { r.closes.Add(1); return nil }
func TestRuntimePlatformCloseJoinsUncancellableNativeRead(t *testing.T) {
	reader := &runtimeBlockingWIFIReader{entered: make(chan struct{}), release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	p := &RuntimePlatform{ctx: ctx, cancel: cancel, wifi: reader}
	refreshDone := make(chan struct{})
	go func() { p.Refresh(ctx); close(refreshDone) }()
	select {
	case <-reader.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("read did not start")
	}
	closed := make(chan struct{})
	go func() { _ = p.Close(); close(closed) }()
	<-ctx.Done()
	select {
	case <-closed:
		t.Fatal("Close reported completion while a native read was still executing")
	default:
	}
	if reader.closes.Load() != 0 {
		t.Fatal("native handle closed under an active read")
	}
	close(reader.release)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("read completion was not joined")
	}
	<-refreshDone
	if reader.closes.Load() != 1 {
		t.Fatal("reader owner not closed exactly once")
	}
	if err := p.Close(); err != nil || reader.closes.Load() != 1 {
		t.Fatal("close replay", err)
	}
}

func TestRuntimePlatformMetadataHasNoNativeSideEffects(t *testing.T) {
	// A nonexistent absolute file remains eligible metadata; opening it belongs
	// to prepare, which must fail before publication.
	path := filepath.Join(t.TempDir(), "not-created.leases")
	need := RuntimeRequirements{Neighbor: true, DHCPLeaseFiles: []string{path}}
	native := C.IsLinux && !C.IsAndroid || C.IsDarwin && !C.IsIos
	if got := RuntimePlatformPreparationAvailable(context.Background(), RuntimeRequirements{}, need); got != native {
		t.Fatal(got, native)
	}
	bridge := service.ContextWith[adapter.PlatformInterface](context.Background(), &runtimeUnownedNeighborBridge{})
	if RuntimePlatformPreparationAvailable(bridge, RuntimeRequirements{}, need) {
		t.Fatal("provided neighbor bridge without independent owner was admitted")
	}
	have := RuntimeRequirements{Neighbor: true, DHCPLeaseFiles: []string{path}}
	if RuntimePlatformPreparationAvailable(bridge, have, RuntimeRequirements{Neighbor: true}) {
		t.Fatal("lease-list removal allocated an unowned replacement reader")
	}
	need.DHCPLeaseFiles = []string{"relative.leases"}
	if RuntimePlatformPreparationAvailable(context.Background(), RuntimeRequirements{}, need) {
		t.Fatal("relative path obtained new host authority")
	}
	need.DHCPLeaseFiles = make([]string, 65)
	if RuntimePlatformPreparationAvailable(context.Background(), RuntimeRequirements{}, need) {
		t.Fatal("unbounded lease set admitted")
	}
}

type runtimeUnownedNeighborBridge struct{ adapter.PlatformInterface }

func (*runtimeUnownedNeighborBridge) UsePlatformNeighborResolver() bool { return true }
func (*runtimeUnownedNeighborBridge) UsePlatformWIFIMonitor() bool      { return false }
