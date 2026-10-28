package endpoint

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

type runtimeEndpoint struct {
	adapter.Endpoint
	tag    string
	starts map[adapter.StartStage]int
	closed int
}

func (e *runtimeEndpoint) RuntimeValidate() error { return nil }
func (e *runtimeEndpoint) RuntimeResourceID() adapter.RuntimeResourceID {
	return adapter.RuntimeResourceID{Incarnation: "test", Sequence: 1}
}

func (e *runtimeEndpoint) PrepareRuntime(stage adapter.StartStage, scope *adapter.Scope) error {
	return e.Start(stage, scope)
}
func (e *runtimeEndpoint) Tag() string  { return e.tag }
func (e *runtimeEndpoint) Type() string { return "test" }
func (e *runtimeEndpoint) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	e.starts[stage]++
	if stage == adapter.StartStateInitialize {
		scope.Add(func() error { e.closed++; return nil })
	}
	return nil
}

func TestRuntimeEndpointBorrowingAndFrozenInventory(t *testing.T) {
	manager := NewRuntimeManager(nil)
	borrowed := &runtimeEndpoint{tag: "borrowed", starts: make(map[adapter.StartStage]int)}
	owned := &runtimeEndpoint{tag: "owned", starts: make(map[adapter.StartStage]int)}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = scope.Close() })
	if err := manager.Insert(borrowed, nil); err != nil {
		t.Fatal(err)
	}
	if err := manager.Insert(owned, scope); err != nil {
		t.Fatal(err)
	}
	if err := manager.Freeze(); err != nil {
		t.Fatal(err)
	}
	copy := manager.Endpoints()
	copy[0] = owned
	if manager.Endpoints()[0] != borrowed {
		t.Fatal("inventory escaped")
	}
	for _, stage := range adapter.ListStartStages {
		if err := manager.Start(stage, nil); err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(stage, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := manager.StartEndpoint(borrowed); err != nil {
		t.Fatal(err)
	}
	if err := manager.StartEndpoint(owned); err != nil {
		t.Fatal(err)
	}
	if err := manager.StartEndpoint(owned); err != nil {
		t.Fatal(err)
	}
	for _, stage := range adapter.ListStartStages {
		if owned.starts[stage] != 1 {
			t.Fatalf("owned stage %v count %d", stage, owned.starts[stage])
		}
	}
	if len(borrowed.starts) != 0 {
		t.Fatal("borrowed endpoint restarted")
	}
	if manager.OwnsEndpoint("borrowed") || !manager.OwnsEndpoint("owned") {
		t.Fatal("ownership does not match inventory")
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if owned.closed != 1 || borrowed.closed != 0 {
		t.Fatal("wrong cleanup owner")
	}
	if err := manager.Insert(&runtimeEndpoint{tag: "late"}, nil); err == nil {
		t.Fatal("frozen insert accepted")
	}
}
