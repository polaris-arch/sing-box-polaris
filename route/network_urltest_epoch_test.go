package route

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

type offlineEpochMonitor struct{ tun.DefaultInterfaceMonitor }

func (*offlineEpochMonitor) DefaultInterface() *control.Interface { return nil }

func TestInterfaceEpochInvalidatesBeforeStartAndOfflineReturn(t *testing.T) {
	ctx := pause.WithDefaultManager(context.Background())
	history := urltest.NewHistoryStorage()
	defer history.Close()
	old := history.Epoch()
	oldUpdate, cancel := context.WithCancel(ctx)
	r := &NetworkManager{urlTestHistory: history, interfaceUpdateCancel: cancel}
	r.notifyInterfaceUpdate(nil, 0)
	if oldUpdate.Err() == nil {
		t.Fatal("previous preparation not canceled")
	}
	if history.IsCurrent(old) || history.IsCurrent(history.Epoch()) {
		t.Fatal("not-started transition left admission ready")
	}
	first := history.Epoch()
	r.startedCtx = ctx
	r.pauseManager = service.FromContext[pause.Manager](ctx)
	r.logger = log.NewNOPFactory().Logger()
	r.interfaceMonitor = &offlineEpochMonitor{}
	r.notifyInterfaceUpdate(nil, 0)
	if first == history.Epoch() {
		t.Fatal("second transition did not invalidate")
	}
	if !r.pauseManager.IsNetworkPaused() || history.IsCurrent(history.Epoch()) {
		t.Fatal("offline early return woke probes")
	}
	if history.MarkReady(first) {
		t.Fatal("old completion readied offline epoch")
	}
}

type readyEpochMonitor struct {
	tun.DefaultInterfaceMonitor
	mu      sync.Mutex
	current *control.Interface
}

func (m *readyEpochMonitor) DefaultInterface() *control.Interface {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}
func (m *readyEpochMonitor) AndroidVPNEnabled() bool { return false }

type heldEpochWIFI struct{ entered, release chan struct{} }

func (m *heldEpochWIFI) ReadWIFIState(context.Context) adapter.WIFIState {
	close(m.entered)
	<-m.release
	return adapter.WIFIState{SSID: "test"}
}
func (*heldEpochWIFI) Start() error { return nil }
func (*heldEpochWIFI) Close() error { return nil }

func TestNetworkReadinessFollowsEnvironmentPreparation(t *testing.T) {
	ctx := pause.WithDefaultManager(context.Background())
	pm := service.FromContext[pause.Manager](ctx)
	pm.NetworkPause()
	history := urltest.NewHistoryStorage()
	defer history.Close()
	epoch := history.AdvanceNetworkEpoch()
	iface := &control.Interface{Index: 1, Name: "test"}
	monitor := &readyEpochMonitor{current: iface}
	wifi := &heldEpochWIFI{make(chan struct{}), make(chan struct{})}
	r := &NetworkManager{urlTestHistory: history, pauseManager: pm, interfaceMonitor: monitor, wifiMonitor: wifi, wifiState: adapter.WIFIState{SSID: "test"}, logger: log.NewNOPFactory().Logger()}
	// Explicit gateway plus SSID prevents system gateway/neighbor discovery.
	r.networkInterfaces.Store([]adapter.NetworkInterface{{Interface: *iface, Gateways: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}})
	woke := make(chan bool, 1)
	callback := pm.RegisterCallback(func(event int) {
		if event == pause.EventNetworkWake {
			woke <- r.NetworkEnvironment() != 0 && history.IsCurrent(epoch)
		}
	})
	defer pm.UnregisterCallback(callback)
	finished := make(chan struct{})
	go func() { r.updateInterface(ctx, iface, epoch); close(finished) }()
	select {
	case <-wifi.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("WIFI barrier")
	}
	if history.IsCurrent(epoch) || !pm.IsNetworkPaused() {
		t.Fatal("admitted before environment prepared")
	}
	if _, _, err := history.ProbeContext(ctx, epoch); err == nil {
		t.Fatal("direct probe admitted during preparation")
	}
	close(wifi.release)
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("preparation did not finish")
	}
	select {
	case ready := <-woke:
		if !ready {
			t.Fatal("Wake before environment/readiness")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("missing Wake")
	}
}
