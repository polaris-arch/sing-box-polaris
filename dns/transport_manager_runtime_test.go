package dns

import (
	"context"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
)

type runtimeTransport struct {
	adapter.DNSTransport
	tag          string
	kind         string
	dependencies []string
	starts       map[adapter.StartStage]int
	closed       int
	order        *[]string
}

func (t *runtimeTransport) Type() string {
	if t.kind != "" {
		return t.kind
	}
	return "test"
}
func (t *runtimeTransport) Tag() string            { return t.tag }
func (t *runtimeTransport) Dependencies() []string { return t.dependencies }
func (t *runtimeTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	t.starts[stage]++
	if stage == adapter.StartStateInitialize {
		scope.Add(func() error { t.closed++; return nil })
	}
	if stage == adapter.StartStateStart && t.order != nil {
		*t.order = append(*t.order, t.tag)
	}
	return nil
}

type runtimeFakeIP struct{ *runtimeTransport }

func (t *runtimeFakeIP) Store() adapter.FakeIPStore { return nil }
func newRuntimeTransport(tag string, dependencies ...string) *runtimeTransport {
	return &runtimeTransport{tag: tag, dependencies: dependencies, starts: make(map[adapter.StartStage]int)}
}

func runtimeTransportScope(t *testing.T) *adapter.Scope {
	t.Helper()
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = scope.Close() })
	return scope
}

func TestRuntimeTransportsBorrowedReadyOwnedOrder(t *testing.T) {
	manager := NewRuntimeTransportManager(nil, nil, "dependent")
	dependent := newRuntimeTransport("dependent", "dependency")
	dependency := newRuntimeTransport("dependency", "borrowed")
	borrowed := newRuntimeTransport("borrowed", "old-only-captured-dependency")
	fake := &runtimeFakeIP{runtimeTransport: newRuntimeTransport("fake")}
	fake.kind = C.DNSTypeFakeIP
	order := []string{}
	dependent.order, dependency.order = &order, &order
	dependentScope, dependencyScope := runtimeTransportScope(t), runtimeTransportScope(t)
	if err := manager.Insert(dependent, dependentScope); err != nil {
		t.Fatal(err)
	}
	if err := manager.Insert(dependency, dependencyScope); err != nil {
		t.Fatal(err)
	}
	if err := manager.Insert(borrowed, nil); err != nil {
		t.Fatal(err)
	}
	if err := manager.Insert(fake, nil); err != nil {
		t.Fatal(err)
	}
	if err := manager.Freeze(); err != nil {
		t.Fatal(err)
	}
	for _, stage := range adapter.ListStartStages {
		if err := manager.Start(stage, nil); err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(stage, nil); err != nil {
			t.Fatal(err)
		}
		if dependent.starts[stage] != 1 || dependency.starts[stage] != 1 {
			t.Fatal("owned member stage count")
		}
	}
	if !reflect.DeepEqual(order, []string{"dependency", "dependent"}) {
		t.Fatalf("dependency order: %v", order)
	}
	copy := manager.Transports()
	copy[0] = borrowed
	if manager.Transports()[0] != dependent || manager.Default() != dependent || manager.FakeIP() != fake {
		t.Fatal("frozen lookup changed")
	}
	if err := dependentScope.Close(); err != nil {
		t.Fatal(err)
	}
	if err := dependencyScope.Close(); err != nil {
		t.Fatal(err)
	}
	if dependent.closed != 1 || dependency.closed != 1 || borrowed.closed != 0 || fake.closed != 0 || len(borrowed.starts) != 0 || len(fake.starts) != 0 {
		t.Fatal("borrowed lifecycle was touched")
	}
	if err := manager.Insert(newRuntimeTransport("late"), nil); err == nil {
		t.Fatal("frozen insertion accepted")
	}
	if err := manager.Create(context.Background(), nil, "late", "test", nil); err == nil {
		t.Fatal("frozen Create accepted")
	}
}

func TestRuntimeTransportDependencyDiagnostics(t *testing.T) {
	for _, test := range []struct {
		name    string
		members []*runtimeTransport
		want    string
	}{
		{"missing", []*runtimeTransport{newRuntimeTransport("a", "missing")}, "dependency[missing] not found for server[a]"},
		{"cycle", []*runtimeTransport{newRuntimeTransport("a", "b"), newRuntimeTransport("b", "a")}, "circular server dependency: a -> b -> a"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := NewRuntimeTransportManager(nil, nil, "a")
			for _, member := range test.members {
				if err := manager.Insert(member, runtimeTransportScope(t)); err != nil {
					t.Fatal(err)
				}
			}
			if err := manager.Freeze(); err != nil {
				t.Fatal(err)
			}
			if err := manager.Start(adapter.StartStateStart, nil); err == nil || err.Error() != test.want {
				t.Fatalf("got %v, want %s", err, test.want)
			}
		})
	}
}

type runtimeTransportRegistry struct {
	adapter.DNSTransportRegistry
	calls int
}

func (r *runtimeTransportRegistry) CreateDNSTransport(ctx context.Context, logger log.ContextLogger, tag string, kind string, options any) (adapter.DNSTransport, error) {
	r.calls++
	return newRuntimeTransport(tag), nil
}

func TestTransportDuplicateRejectedBeforeConstructor(t *testing.T) {
	registry := &runtimeTransportRegistry{}
	manager := NewTransportManager(registry, nil, "a")
	if err := manager.Create(context.Background(), nil, "a", "test", nil); err != nil {
		t.Fatal(err)
	}
	if err := manager.Create(context.Background(), nil, "a", "test", nil); err == nil {
		t.Fatal("duplicate accepted")
	}
	if registry.calls != 1 {
		t.Fatal("duplicate constructor allocated")
	}
}

func TestRuntimeTransportDefaultsAndRejectedInsertCleanup(t *testing.T) {
	manager := NewRuntimeTransportManager(nil, nil, "a")
	fallbackCalls := 0
	manager.Initialize(func() (adapter.DNSTransport, error) { fallbackCalls++; return newRuntimeTransport("a"), nil })
	if err := manager.Freeze(); err == nil {
		t.Fatal("implicit fallback accepted")
	}
	if fallbackCalls != 0 {
		t.Fatal("Freeze allocated")
	}
	if err := manager.Insert(newRuntimeTransport("a"), nil); err != nil {
		t.Fatal(err)
	}
	scope := runtimeTransportScope(t)
	closed := 0
	scope.Add(func() error { closed++; return nil })
	if err := manager.Insert(newRuntimeTransport("a"), scope); err == nil {
		t.Fatal("duplicate insert accepted")
	}
	if closed != 0 {
		t.Fatal("manager took caller cleanup")
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if closed != 1 {
		t.Fatal("rejected allocation cleanup lost")
	}
	fakeManager := NewRuntimeTransportManager(nil, nil, "fake")
	fake := &runtimeFakeIP{runtimeTransport: newRuntimeTransport("fake")}
	fake.kind = C.DNSTypeFakeIP
	if err := fakeManager.Insert(fake, nil); err != nil {
		t.Fatal(err)
	}
	if err := fakeManager.Freeze(); err == nil {
		t.Fatal("fake-IP default accepted")
	}
}
