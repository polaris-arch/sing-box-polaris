package outbound

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	endpointmanager "github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/log"
)

type runtimeOutbound struct {
	adapter.Outbound
	tag string
	dependencies []string
	starts map[adapter.StartStage]int
	closed int
	order *[]string
	failure error
}
func (o *runtimeOutbound) Type() string { return "test" }
func (o *runtimeOutbound) Tag() string { return o.tag }
func (o *runtimeOutbound) Dependencies() []string { return o.dependencies }
func (o *runtimeOutbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	o.starts[stage]++
	if stage == adapter.StartStateInitialize { scope.Add(func() error { o.closed++; return nil }) }
	if stage == adapter.StartStateStart && o.order != nil { *o.order = append(*o.order, o.tag) }
	return o.failure
}
// Endpoint inventory requires its resource adapter even for borrowed members.
// Keep this wrapper separate so outbound fixtures do not gain endpoint eligibility.
type runtimeBorrowedEndpoint struct { *runtimeOutbound }
func (e *runtimeBorrowedEndpoint) RuntimeValidate() error { return nil }
func (e *runtimeBorrowedEndpoint) RuntimeResourceID() adapter.RuntimeResourceID {
 return adapter.RuntimeResourceID{Incarnation: "borrowed-endpoint-test", Sequence: 1}
}
func (e *runtimeBorrowedEndpoint) PrepareRuntime(stage adapter.StartStage, scope *adapter.Scope) error {
 return e.Start(stage, scope)
}

func runtimeMember(tag string, dependencies ...string) *runtimeOutbound {
	return &runtimeOutbound{tag: tag, dependencies: dependencies, starts: make(map[adapter.StartStage]int)}
}
func runtimeScope(t *testing.T) *adapter.Scope {
	t.Helper()
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = scope.Close() })
	return scope
}
func runtimeEndpointManager(t *testing.T) *endpointmanager.Manager {
	t.Helper()
	manager := endpointmanager.NewRuntimeManager(nil)
	if err := manager.Freeze(); err != nil { t.Fatal(err) }
	return manager
}

func TestRuntimeBorrowedManagerMembersNeverStartedOrClosed(t *testing.T) {
	endpoints := endpointmanager.NewRuntimeManager(nil)
	borrowedEndpoint := &runtimeBorrowedEndpoint{runtimeMember("stable-endpoint", "old-only-captured-dependency")}
	if err := endpoints.Insert(borrowedEndpoint, nil); err != nil { t.Fatal(err) }
	if err := endpoints.Freeze(); err != nil { t.Fatal(err) }
	manager := NewRuntimeManager(nil, endpoints, "changed")
	borrowed := runtimeMember("borrowed", "old-only-captured-dependency")
	changed := runtimeMember("changed", "borrowed", "stable-endpoint")
	scope := runtimeScope(t)
	if err := manager.Insert(changed, scope); err != nil { t.Fatal(err) }
	if err := manager.Insert(borrowed, nil); err != nil { t.Fatal(err) }
	if err := manager.Freeze(); err != nil { t.Fatal(err) }
	for _, stage := range adapter.ListStartStages {
		if err := endpoints.Start(stage, runtimeScope(t)); err != nil { t.Fatal(err) }
		if err := manager.Start(stage, runtimeScope(t)); err != nil { t.Fatal(err) }
		if err := manager.Start(stage, runtimeScope(t)); err != nil { t.Fatal(err) }
		if changed.starts[stage] != 1 { t.Fatalf("stage %v started %d times", stage, changed.starts[stage]) }
	}
	if err := scope.Close(); err != nil { t.Fatal(err) }
	if changed.closed != 1 || len(borrowed.starts) != 0 || borrowed.closed != 0 || len(borrowedEndpoint.starts) != 0 || borrowedEndpoint.closed != 0 {
		t.Fatal("mixed manager crossed lifecycle ownership")
	}
}

func TestRuntimeOutboundDependencyOrderAndInventoryClone(t *testing.T) {
	manager := NewRuntimeManager(nil, runtimeEndpointManager(t), "dependent")
	order := []string{}
	dependent, dependency := runtimeMember("dependent", "dependency"), runtimeMember("dependency", "borrowed")
	dependent.order, dependency.order = &order, &order
	for _, member := range []*runtimeOutbound{dependent, dependency} { if err := manager.Insert(member, runtimeScope(t)); err != nil { t.Fatal(err) } }
	borrowed := runtimeMember("borrowed")
	if err := manager.Insert(borrowed, nil); err != nil { t.Fatal(err) }
	if err := manager.Freeze(); err != nil { t.Fatal(err) }
	copy := manager.Outbounds(); copy[0] = borrowed
	if manager.Outbounds()[0] != dependent || manager.Default() != dependent { t.Fatal("inventory escaped") }
	if err := manager.Start(adapter.StartStateStart, nil); err != nil { t.Fatal(err) }
	if !reflect.DeepEqual(order, []string{"dependency", "dependent"}) { t.Fatalf("order: %v", order) }
	if err := manager.Insert(runtimeMember("late"), nil); err == nil { t.Fatal("frozen inventory mutated") }
	if err := manager.Create(context.Background(), nil, nil, "late", "test", nil); err == nil { t.Fatal("frozen Create accepted") }
}

func TestRuntimeOutboundDependencyDiagnostics(t *testing.T) {
	for _, test := range []struct { name string; members []*runtimeOutbound; want string }{
		{"missing", []*runtimeOutbound{runtimeMember("a", "missing")}, "dependency[missing] not found for outbound[a]"},
		{"cycle", []*runtimeOutbound{runtimeMember("a", "b"), runtimeMember("b", "a")}, "circular outbound dependency: a -> b -> a"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := NewRuntimeManager(nil, runtimeEndpointManager(t), "a")
			for _, member := range test.members { if err := manager.Insert(member, runtimeScope(t)); err != nil { t.Fatal(err) } }
			if err := manager.Freeze(); err != nil { t.Fatal(err) }
			if err := manager.Start(adapter.StartStateStart, nil); err == nil || err.Error() != test.want { t.Fatalf("got %v, want %s", err, test.want) }
		})
	}
}

type countingRuntimeRegistry struct { adapter.OutboundRegistry; calls int }
func (r *countingRuntimeRegistry) CreateOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) (adapter.Outbound, error) {
	r.calls++
	return runtimeMember(tag), nil
}
func TestOutboundDuplicateRejectedBeforeConstructor(t *testing.T) {
	registry := &countingRuntimeRegistry{}
	manager := NewManager(registry, runtimeEndpointManager(t), "a")
	if err := manager.Create(context.Background(), nil, nil, "a", "test", nil); err != nil { t.Fatal(err) }
	if err := manager.Create(context.Background(), nil, nil, "a", "test", nil); err == nil { t.Fatal("duplicate accepted") }
	if registry.calls != 1 { t.Fatal("duplicate constructor allocated") }
}

func TestRuntimeDuplicateInsertionLeavesCallerCleanup(t *testing.T) {
	manager := NewRuntimeManager(nil, runtimeEndpointManager(t), "a")
	if err := manager.Insert(runtimeMember("a"), nil); err != nil { t.Fatal(err) }
	scope := runtimeScope(t)
	closed := 0
	scope.Add(func() error { closed++; return nil })
	if err := manager.Insert(runtimeMember("a"), scope); err == nil { t.Fatal("duplicate accepted") }
	if closed != 0 { t.Fatal("manager closed rejected caller-owned resource") }
	if err := scope.Close(); err != nil { t.Fatal(err) }
	if closed != 1 { t.Fatal("caller cleanup lost") }
}

func TestRuntimeStartFailureIsSticky(t *testing.T) {
	manager := NewRuntimeManager(nil, runtimeEndpointManager(t), "a")
	member := runtimeMember("a")
	member.failure = errors.New("start failed")
	scope := runtimeScope(t)
	if err := manager.Insert(member, scope); err != nil { t.Fatal(err) }
	if err := manager.Freeze(); err != nil { t.Fatal(err) }
	first := manager.Start(adapter.StartStateInitialize, nil)
	second := manager.Start(adapter.StartStateInitialize, nil)
	if first == nil || first != second || member.starts[adapter.StartStateInitialize] != 1 { t.Fatal("failed stage retried or hidden") }
	if err := scope.Close(); err != nil { t.Fatal(err) }
	if member.closed != 1 { t.Fatal("failed stage cleanup lost") }
}

func TestRuntimeFallbackRequiresExplicitNode(t *testing.T) {
	manager := NewRuntimeManager(nil, runtimeEndpointManager(t), "generated-default")
	calls := 0
	manager.Initialize(func() (adapter.Outbound, error) { calls++; return runtimeMember("generated-default"), nil })
	if err := manager.Freeze(); err == nil { t.Fatal("unresolved default accepted") }
	if calls != 0 { t.Fatal("Freeze allocated fallback") }
}
