package route

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"
)

// RuntimeTrackers is a Box-lifetime registry. Leaves capture this stable hub;
// registering a tracker never mutates a live leaf's tracker slice.
type RuntimeTrackers struct {
	access   sync.RWMutex
	trackers []adapter.ConnectionTracker
}

func (t *RuntimeTrackers) Append(tracker adapter.ConnectionTracker) {
	t.access.Lock()
	t.trackers = append(t.trackers, tracker)
	t.access.Unlock()
}

func (t *RuntimeTrackers) snapshot() []adapter.ConnectionTracker {
	t.access.RLock()
	defer t.access.RUnlock()
	return append([]adapter.ConnectionTracker(nil), t.trackers...)
}

func (t *RuntimeTrackers) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, rule adapter.Rule, outbound adapter.Outbound) net.Conn {
	for _, tracker := range t.snapshot() {
		conn = tracker.RoutedConnection(ctx, conn, metadata, rule, outbound)
	}
	return conn
}

func (t *RuntimeTrackers) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, rule adapter.Rule, outbound adapter.Outbound) N.PacketConn {
	for _, tracker := range t.snapshot() {
		conn = tracker.RoutedPacketConnection(ctx, conn, metadata, rule, outbound)
	}
	return conn
}

func (t *RuntimeTrackers) RoutedFlow(ctx context.Context, metadata adapter.InboundContext, rule adapter.Rule, outbound adapter.Outbound) tun.FlowTracker {
	var trackers []tun.FlowTracker
	for _, tracker := range t.snapshot() {
		if flow := tracker.RoutedFlow(ctx, metadata, rule, outbound); flow != nil {
			trackers = append(trackers, flow)
		}
	}
	if len(trackers) == 0 {
		return nil
	}
	return multiFlowTracker(trackers)
}
