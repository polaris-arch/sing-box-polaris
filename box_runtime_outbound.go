package box

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	outboundAdapter "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
)

// Compatibility objects contain immutable scalar snapshots and identities, never
// an unleased leaf pointer. Operations revalidate the exact incarnation and pin
// the admitted graph for the operation or returned connection lifetime.
type runtimeOutboundManager struct{ coordinator *runtimeCoordinator }

func (*runtimeOutboundManager) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (*runtimeOutboundManager) Create(context.Context, adapter.Router, log.ContextLogger, string, string, any) error {
	return errors.New("use runtime configuration transaction")
}

func (m *runtimeOutboundManager) Outbounds() []adapter.Outbound {
	lease, err := m.coordinator.store.Acquire()
	if err != nil {
		return nil
	}
	defer lease.Release()
	var result []adapter.Outbound
	for _, outbound := range lease.View().OutboundManager().Outbounds() {
		result = append(result, m.wrap(lease.View(), outbound))
	}
	return result
}

func (m *runtimeOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	lease, err := m.coordinator.store.Acquire()
	if err != nil {
		return nil, false
	}
	defer lease.Release()
	outbound, exists := lease.View().OutboundManager().Outbound(tag)
	if !exists {
		return nil, false
	}
	return m.wrap(lease.View(), outbound), true
}

func (m *runtimeOutboundManager) Default() adapter.Outbound {
	lease, err := m.coordinator.store.Acquire()
	if err != nil {
		return nil
	}
	defer lease.Release()
	return m.wrap(lease.View(), lease.View().OutboundManager().Default())
}

func (m *runtimeOutboundManager) wrap(view adapter.RuntimeView, outbound adapter.Outbound) adapter.Outbound {
	if outbound == nil {
		return nil
	}
	id := runtimeOutboundComponentID(view.(*runtimeView), outbound.Tag())
	base := &runtimeOutbound{manager: m, id: id, tag: outbound.Tag(), kind: outbound.Type(), networks: append([]string(nil), outbound.Network()...), dependencies: append([]string(nil), outbound.Dependencies()...)}
	if _, ok := outbound.(adapter.OutboundGroup); ok {
		group := &runtimeOutboundGroup{runtimeOutbound: base}
		if _, ok := outbound.(interface{ SelectOutbound(string) bool }); ok {
			return &runtimeSelector{runtimeOutboundGroup: group}
		}
		if _, ok := outbound.(adapter.URLTestGroup); ok {
			return &runtimeURLTest{runtimeOutboundGroup: group}
		}
		return group
	}
	return base
}

type runtimeOutbound struct {
	manager                *runtimeOutboundManager
	id                     adapter.RuntimeResourceID
	tag, kind              string
	networks, dependencies []string
}

func (o *runtimeOutbound) Type() string           { return o.kind }
func (o *runtimeOutbound) Tag() string            { return o.tag }
func (o *runtimeOutbound) Network() []string      { return append([]string(nil), o.networks...) }
func (o *runtimeOutbound) Dependencies() []string { return append([]string(nil), o.dependencies...) }

func (o *runtimeOutbound) acquire() (adapter.RuntimeLease, adapter.Outbound, error) {
	lease, err := o.manager.coordinator.store.Acquire()
	if err != nil {
		return nil, nil, err
	}
	view := lease.View().(*runtimeView)
	if runtimeOutboundComponentID(view, o.tag) != o.id {
		lease.Release()
		return nil, nil, errors.New("outbound incarnation changed")
	}
	outbound, exists := view.outbounds.Outbound(o.tag)
	if !exists {
		lease.Release()
		return nil, nil, errors.New("outbound removed")
	}
	return lease, outbound, nil
}

func (o *runtimeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	lease, outbound, err := o.acquire()
	if err != nil {
		return nil, err
	}
	conn, err := outbound.DialContext(adapter.ContextWithRuntimeLease(ctx, lease), network, destination)
	if err != nil {
		lease.Release()
		return nil, err
	}
	return outboundAdapter.WrapRuntimeConn(adapter.ContextWithRuntimeLease(ctx, lease), lease.Release, conn), nil
}

func (o *runtimeOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	lease, outbound, err := o.acquire()
	if err != nil {
		return nil, err
	}
	conn, err := outbound.ListenPacket(adapter.ContextWithRuntimeLease(ctx, lease), destination)
	if err != nil {
		lease.Release()
		return nil, err
	}
	return outboundAdapter.WrapRuntimePacketConn(adapter.ContextWithRuntimeLease(ctx, lease), lease.Release, conn), nil
}

type runtimeOutboundGroup struct{ *runtimeOutbound }

func (g *runtimeOutboundGroup) All() []string {
	lease, outbound, err := g.acquire()
	if err != nil {
		return nil
	}
	defer lease.Release()
	return append([]string(nil), outbound.(adapter.OutboundGroup).All()...)
}

func (g *runtimeOutboundGroup) Selected(network string) adapter.Outbound {
	lease, outbound, err := g.acquire()
	if err != nil {
		return nil
	}
	defer lease.Release()
	return g.manager.wrap(lease.View(), outbound.(adapter.OutboundGroup).Selected(network))
}

func (g *runtimeOutboundGroup) AttachConnection(closer io.Closer) func() {
	lease, outbound, err := g.acquire()
	if err != nil {
		_ = closer.Close()
		return func() {}
	}
	detach := outbound.(adapter.OutboundGroup).AttachConnection(closer)
	var once sync.Once
	return func() { once.Do(func() { defer lease.Release(); detach() }) }
}

type runtimeSelector struct{ *runtimeOutboundGroup }

func (s *runtimeSelector) SelectOutbound(tag string) bool {
	return s.manager.coordinator.SelectRuntimeOutbound(s.id, s.tag, tag)
}

type runtimeURLTest struct{ *runtimeOutboundGroup }

func (g *runtimeURLTest) URLTest(ctx context.Context) (map[string]uint16, error) {
	lease, outbound, err := g.acquire()
	if err != nil {
		return nil, err
	}
	defer lease.Release()
	return outbound.(adapter.URLTestGroup).URLTest(adapter.ContextWithRuntimeLease(ctx, lease))
}

func (g *runtimeURLTest) PerformUpdateCheck() {
	lease, outbound, err := g.acquire()
	if err != nil {
		return
	}
	defer lease.Release()
	outbound.(adapter.URLTestGroup).PerformUpdateCheck()
}

func (g *runtimeURLTest) CheckOutbounds() {
	lease, outbound, err := g.acquire()
	if err != nil {
		return
	}
	defer lease.Release()
	if check, ok := outbound.(interface{ CheckOutboundsContext(context.Context) }); ok {
		check.CheckOutboundsContext(adapter.ContextWithRuntimeLease(context.Background(), lease))
	}
}

// Endpoint aliases participate in the same outward API but retain their actual
// endpoint owner identity, never the zero outbound namespace identity.
func runtimeOutboundComponentID(view *runtimeView, tag string) adapter.RuntimeResourceID {
	if id, ok := view.componentIDs["outbound:"+tag]; ok {
		return id
	}
	return view.componentIDs["endpoint:"+tag]
}
