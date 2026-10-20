package route

import (
	"context"
	"maps"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

// RuntimeRouter is stable ingress, never a graph leaf. Structural bindings are
// supplied by the Box's stable-resource adapter; graph constructors use leaves.
type RuntimeRouter struct {
	admission  adapter.RuntimeAdmission
	structural runtimeRouterStructure
}

type RuntimeRouterStructure struct {
	RuleSets      map[string]adapter.RuleSet
	FindProcess   bool
	FindNeighbor  bool
	Neighbor      adapter.NeighborResolver
	NeighborView  func() adapter.NeighborResolver
	AppendTracker func(adapter.ConnectionTracker)
	ResetNetwork  func()
}
type runtimeRouterStructure = RuntimeRouterStructure

func NewRuntimeRouter(admission adapter.RuntimeAdmission, structure RuntimeRouterStructure) *RuntimeRouter {
	rules := make(map[string]adapter.RuleSet, len(structure.RuleSets))
	maps.Copy(rules, structure.RuleSets)
	structure.RuleSets = rules
	return &RuntimeRouter{admission: admission, structural: structure}
}

// BindInitialStructure is called once before inbound constructors or admissions.
func (r *RuntimeRouter) BindInitialStructure(structure RuntimeRouterStructure) {
	r.structural = structure
}

func (*RuntimeRouter) Start(adapter.StartStage, *adapter.Scope) error { return nil }

func (r *RuntimeRouter) admit(ctx context.Context) (adapter.RuntimeLease, error) {
	if previous, ok := adapter.RuntimeLeaseFromContext(ctx); ok {
		lease, err := previous.Fork()
		if err != nil {
			return nil, err
		}
		return withRuntimeMappings(lease), nil
	}
	lease, err := r.admission.Acquire()
	if err != nil {
		return nil, err
	}
	return withRuntimeMappings(lease), nil
}

func (r *RuntimeRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	lease, err := r.admit(ctx)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	invocation, forkErr := lease.Fork()
	if forkErr != nil {
		lease.Release()
		N.CloseOnHandshakeFailure(conn, onClose, forkErr)
		return
	}
	var invocationOnce, flowOnce sync.Once
	releaseInvocation := func() { invocationOnce.Do(invocation.Release) }
	releaseFlow := func() { flowOnce.Do(lease.Release) }
	defer releaseInvocation()
	ctx = adapter.ContextWithRuntimeCarrierHandoff(ctx, func() { releaseFlow(); releaseInvocation() })
	var once sync.Once
	finish := func(err error) {
		once.Do(func() {
			defer releaseFlow()
			if onClose != nil {
				onClose(err)
			}
		})
	}
	owned := &runtimeConn{Conn: conn, finish: finish}
	lease.View().Router().RouteConnectionEx(adapter.ContextWithRuntimeLease(ctx, lease), owned, metadata, finish)
}

func (r *RuntimeRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	lease, err := r.admit(ctx)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	invocation, forkErr := lease.Fork()
	if forkErr != nil {
		lease.Release()
		N.CloseOnHandshakeFailure(conn, onClose, forkErr)
		return
	}
	var invocationOnce, flowOnce sync.Once
	releaseInvocation := func() { invocationOnce.Do(invocation.Release) }
	releaseFlow := func() { flowOnce.Do(lease.Release) }
	defer releaseInvocation()
	ctx = adapter.ContextWithRuntimeCarrierHandoff(ctx, func() { releaseFlow(); releaseInvocation() })
	var once sync.Once
	finish := func(err error) {
		once.Do(func() {
			defer releaseFlow()
			if onClose != nil {
				onClose(err)
			}
		})
	}
	owned := &runtimePacketConn{PacketConn: conn, finish: finish}
	lease.View().Router().RoutePacketConnectionEx(adapter.ContextWithRuntimeLease(ctx, lease), owned, metadata, finish)
}

func (r *RuntimeRouter) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	lease, err := r.admit(ctx)
	if err != nil {
		return err
	}
	defer lease.Release()
	return lease.View().Router().RouteConnection(adapter.ContextWithRuntimeLease(ctx, lease), conn, metadata)
}

func (r *RuntimeRouter) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	lease, err := r.admit(ctx)
	if err != nil {
		return err
	}
	defer lease.Release()
	return lease.View().Router().RoutePacketConnection(adapter.ContextWithRuntimeLease(ctx, lease), conn, metadata)
}

func (r *RuntimeRouter) PreMatch(metadata adapter.InboundContext, firstPacket []byte) adapter.PreMatchResult {
	lease, err := r.admission.Acquire()
	if err != nil {
		return adapter.PreMatchResult{Action: adapter.PreMatchDrop}
	}
	lease = withRuntimeMappings(lease)
	// The concrete leaf receives a bound continuation before metadata resolution
	// or any outbound Port method. No second current-graph admission occurs.
	leaf, ok := lease.View().Router().(interface {
		PreMatchContext(context.Context, adapter.InboundContext, []byte) adapter.PreMatchResult
	})
	if !ok {
		lease.Release()
		return adapter.PreMatchResult{Action: adapter.PreMatchDrop}
	}
	result := leaf.PreMatchContext(adapter.ContextWithRuntimeLease(context.Background(), lease), metadata, firstPacket)
	result.Ownership = lease
	return result
}

func (r *RuntimeRouter) HijackDNSPacket(ctx context.Context, payload []byte, writer N.PacketWriter, metadata adapter.InboundContext) {
	lease, err := r.admit(ctx)
	if err != nil {
		return
	}
	defer lease.Release()
	// The leaf forks before its asynchronous exchange and holds through write.
	lease.View().Router().HijackDNSPacket(adapter.ContextWithRuntimeLease(ctx, lease), payload, writer, metadata)
}

func (r *RuntimeRouter) RuleSet(tag string) (adapter.RuleSet, bool) {
	rule, ok := r.structural.RuleSets[tag]
	return rule, ok
}

// Raw live rules cannot escape an admission. Existing display consumers use
// WithRuntimeRules; graph consumers bind their own leaf before construction.
func (*RuntimeRouter) Rules() []adapter.Rule { return nil }

func (r *RuntimeRouter) WithRuntimeRules(consume func([]adapter.Rule)) {
	lease, err := r.admission.Acquire()
	if err != nil {
		return
	}
	defer lease.Release()
	consume(lease.View().Router().Rules())
}
func (r *RuntimeRouter) NeedFindProcess() bool  { return r.structural.FindProcess }
func (r *RuntimeRouter) NeedFindNeighbor() bool { return r.structural.FindNeighbor }
func (r *RuntimeRouter) NeighborResolver() adapter.NeighborResolver {
	if r.structural.NeighborView != nil {
		return r.structural.NeighborView()
	}
	return r.structural.Neighbor
}

func (r *RuntimeRouter) AppendTracker(tracker adapter.ConnectionTracker) {
	if r.structural.AppendTracker != nil {
		r.structural.AppendTracker(tracker)
	}
}

func (r *RuntimeRouter) ResetNetwork() {
	if r.structural.ResetNetwork != nil {
		r.structural.ResetNetwork()
	}
}

type runtimeConn struct {
	net.Conn
	finish N.CloseHandlerFunc
}

func (c *runtimeConn) Close() error { err := c.Conn.Close(); c.finish(err); return err }

type runtimePacketConn struct {
	N.PacketConn
	finish N.CloseHandlerFunc
}

func (c *runtimePacketConn) Close() error { err := c.PacketConn.Close(); c.finish(err); return err }

var _ adapter.Router = (*RuntimeRouter)(nil)
