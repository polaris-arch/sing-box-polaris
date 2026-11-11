package route

import (
	"context"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/settings"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/service"
)

// RuntimePlatformPreparationAvailable is metadata-only. Native construction,
// permission failures and the first fresh sample belong to private preparation.
func RuntimePlatformPreparationAvailable(ctx context.Context, have, need RuntimeRequirements) bool {
	desktop := C.IsWindows || C.IsLinux && !C.IsAndroid || C.IsDarwin && !C.IsIos
	if need.Process && !have.Process && !desktop {
		return false
	}
	nativeNeighbor := C.IsLinux && !C.IsAndroid || C.IsDarwin && !C.IsIos
	sameFiles := slices.Equal(have.DHCPLeaseFiles, need.DHCPLeaseFiles)
	needsNeighborOwner := (need.Neighbor || len(need.DHCPLeaseFiles) > 0) && (!have.Neighbor || !sameFiles)
	if needsNeighborOwner && !nativeNeighbor {
		return false
	}
	platform := service.FromContext[adapter.PlatformInterface](ctx)
	if needsNeighborOwner && platform != nil && platform.UsePlatformNeighborResolver() {
		// The current libbox bridge drops listener identity on Close. It cannot
		// prove an independent candidate owner or rollback of a new subscription.
		return false
	}
	if need.WIFI && !have.WIFI && !(platform != nil && platform.UsePlatformWIFIMonitor()) && !(C.IsLinux && !C.IsAndroid || C.IsWindows) {
		return false
	}
	if !needsNeighborOwner {
		return true
	}
	if len(need.DHCPLeaseFiles) > 64 {
		return false
	}
	for _, path := range need.DHCPLeaseFiles {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return false
		}
	}
	return true
}

// RuntimePlatform is one ordinary graph resource. Initial stable providers
// remain borrowed; new demand owns fresh native readers and one joined poller.
// A read that ignores cancellation remains owned until it actually returns.
type RuntimePlatform struct {
	network    *NetworkManager
	initial    *Router
	requested  RuntimeRequirements
	bootstrap  bool
	ctx        context.Context
	cancel     context.CancelFunc
	access     sync.RWMutex
	readAccess sync.Mutex
	neighbor   adapter.NeighborResolver
	wifi       settings.WIFIMonitor
	wifiState  adapter.WIFIState
	started    bool
	polling    bool
	done       chan struct{}
	closeOnce  sync.Once
	closeErr   error
	published  atomic.Bool
}

func NewRuntimePlatform(ctx context.Context, network *NetworkManager, initial *Router, need RuntimeRequirements, bootstrap bool) *RuntimePlatform {
	ctx, cancel := context.WithCancel(ctx)
	need.DHCPLeaseFiles = append([]string(nil), need.DHCPLeaseFiles...)
	return &RuntimePlatform{network: network, initial: initial, requested: need, bootstrap: bootstrap, ctx: ctx, cancel: cancel, done: make(chan struct{})}
}
func (p *RuntimePlatform) BindInitial(initial *Router) { p.initial = initial }
func (p *RuntimePlatform) Start(request context.Context) error {
	request, cancel := context.WithCancel(request)
	stop := context.AfterFunc(p.ctx, cancel)
	defer func() { stop(); cancel() }()
	if p.bootstrap {
		return nil
	}
	if err := request.Err(); err != nil {
		return err
	}
	if p.requested.Neighbor {
		if p.initial != nil && p.initial.neighborResolver != nil && slices.Equal(p.initial.leaseFiles, p.requested.DHCPLeaseFiles) {
			p.neighbor = p.initial.neighborResolver
		} else {
			neighbor, err := newRuntimeNeighbor(p.requested.DHCPLeaseFiles)
			if err != nil {
				return err
			}
			if err = neighbor.refreshContext(request); err != nil {
				return err
			}
			p.neighbor = neighbor
		}
	}
	if p.requested.WIFI && !p.borrowWIFI() {
		var err error
		platform := p.network.platformInterface
		if platform != nil && platform.UsePlatformWIFIMonitor() {
			p.wifi = &runtimePlatformWIFIReader{platform}
		} else {
			// nil deliberately disables backend notification workers. This graph owns
			// the only polling worker, cancellation and native-reader close order.
			p.wifi, err = settings.NewWIFIMonitor(nil)
			if err != nil {
				return err
			}
		}
		if err = p.wifi.Start(); err != nil {
			return err
		}
		p.wifiState = p.wifi.ReadWIFIState(request)
		p.wifiState.BSSID = adapter.NormalizeWIFIBSSID(p.wifiState.BSSID)
	}
	if err := request.Err(); err != nil {
		return err
	}
	p.started = true
	if p.wifi != nil || p.ownsNeighbor() {
		p.polling = true
		go p.poll()
	}
	return nil
}

func (p *RuntimePlatform) borrowWIFI() bool {
	return p.network != nil && p.network.runtimeStableWIFIAvailable()
}
func (p *RuntimePlatform) ownsNeighbor() bool { _, ok := p.neighbor.(*runtimeNeighbor); return ok }
func (p *RuntimePlatform) NeighborResolver() adapter.NeighborResolver {
	if p.bootstrap && p.initial != nil {
		return p.initial.NeighborResolver()
	}
	return p.neighbor
}

func (p *RuntimePlatform) NeedWIFIState() bool {
	return p.requested.WIFI && (p.wifi != nil && p.started || p.borrowWIFI())
}

func (p *RuntimePlatform) WIFIState() adapter.WIFIState {
	if p.wifi == nil {
		if p.network != nil {
			return p.network.runtimeStableWIFIState()
		}
		return adapter.WIFIState{}
	}
	p.access.RLock()
	defer p.access.RUnlock()
	return p.wifiState
}

func (p *RuntimePlatform) Refresh(ctx context.Context) {
	p.readAccess.Lock()
	defer p.readAccess.Unlock()
	if p.ctx.Err() != nil {
		return
	}
	if p.wifi == nil && p.borrowWIFI() && (p.bootstrap || p.published.Load()) {
		p.network.runtimeUpdateStableWIFI(ctx)
	}
	if neighbor, ok := p.neighbor.(*runtimeNeighbor); ok {
		_ = neighbor.refreshContext(ctx)
	}
	if p.wifi != nil {
		next := p.wifi.ReadWIFIState(ctx)
		next.BSSID = adapter.NormalizeWIFIBSSID(next.BSSID)
		p.access.Lock()
		changed := p.wifiState != next
		p.wifiState = next
		p.access.Unlock()
		if changed && p.published.Load() {
			p.network.postUpdateNetworkEnvironment()
		}
	}
}

func (p *RuntimePlatform) poll() {
	defer close(p.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.Refresh(p.ctx)
		}
	}
}

func (p *RuntimePlatform) Activate() {
	p.published.Store(true)
	if p.network != nil && p.requested.WIFI {
		p.network.postUpdateNetworkEnvironment()
	}
}
func (p *RuntimePlatform) Stop() { p.cancel() }
func (p *RuntimePlatform) Close() error {
	p.closeOnce.Do(func() {
		p.cancel()
		if p.polling {
			<-p.done
		}
		p.readAccess.Lock()
		defer p.readAccess.Unlock()
		if p.wifi != nil {
			p.closeErr = p.wifi.Close()
		}
	})
	return p.closeErr
}

func (p *RuntimePlatform) NetworkView(base adapter.NetworkManager) adapter.NetworkManager {
	return &runtimePlatformNetworkView{NetworkManager: base, platform: p}
}

type runtimePlatformNetworkView struct {
	adapter.NetworkManager
	platform *RuntimePlatform
}

func (v *runtimePlatformNetworkView) NeedWIFIState() bool { return v.platform.NeedWIFIState() }

func (v *runtimePlatformNetworkView) WIFIState() adapter.WIFIState { return v.platform.WIFIState() }

func (v *runtimePlatformNetworkView) UpdateWIFIState(ctx context.Context) { v.platform.Refresh(ctx) }

type runtimePlatformWIFIReader struct{ adapter.PlatformInterface }

func (p *runtimePlatformWIFIReader) ReadWIFIState(ctx context.Context) adapter.WIFIState {
	return p.PlatformInterface.ReadWIFIState(ctx)
}
func (*runtimePlatformWIFIReader) Start() error { return nil }
func (*runtimePlatformWIFIReader) Close() error { return nil }
