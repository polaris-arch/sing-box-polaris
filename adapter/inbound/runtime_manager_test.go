package inbound

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/log"
)

type preparedInboundFixture struct {
	tag      string
	stages   atomic.Int64
	validate func() error
	prepare  func() error
}

func (*preparedInboundFixture) Type() string  { return "fixture" }
func (i *preparedInboundFixture) Tag() string { return i.tag }
func (*preparedInboundFixture) Start(adapter.StartStage, *adapter.Scope) error {
	return errors.New("ordinary Start must not run for candidate")
}

func (i *preparedInboundFixture) RuntimeValidate() error {
	if i.validate != nil {
		return i.validate()
	}
	return nil
}

func (i *preparedInboundFixture) PrepareRuntime(adapter.StartStage, *adapter.Scope) error {
	i.stages.Add(1)
	if i.prepare != nil {
		return i.prepare()
	}
	return nil
}
func (*preparedInboundFixture) RuntimeListeners() []*listener.Listener { return nil }
func TestRuntimeInventoryFreezesAndCopiesWithoutRestartingBorrowedMembers(t *testing.T) {
	manager := NewRuntimeManager(nil, nil)
	owned := &preparedInboundFixture{tag: "owned"}
	borrowed := &preparedInboundFixture{tag: "borrowed"}
	owned.validate = func() error { manager.Inbounds(); return nil }
	owned.prepare = func() error {
		if _, ok := manager.Get("owned"); !ok {
			return errors.New("frozen lookup missing")
		}
		return nil
	}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	if err := manager.Insert(owned, scope); err != nil {
		t.Fatal(err)
	}
	if err := manager.Insert(borrowed, nil); err != nil {
		t.Fatal(err)
	}
	if err := manager.Freeze(); err != nil {
		t.Fatal(err)
	}
	copy := manager.Inbounds()
	copy[0] = nil
	if manager.Inbounds()[0] != owned {
		t.Fatal("inventory slice escaped")
	}
	if err := manager.Insert(&preparedInboundFixture{tag: "late"}, scope); err == nil {
		t.Fatal("frozen inventory mutated")
	}
	if err := manager.Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	if owned.stages.Load() != 1 || borrowed.stages.Load() != 0 {
		t.Fatal("duplicate or borrowed preparation")
	}
}

func TestRuntimeInventoryDoesNotAllocateThroughLegacyCreate(t *testing.T) {
	manager := NewRuntimeManager(nil, nil)
	if err := manager.Create(context.Background(), nil, nil, "tag", "fixture", nil); err == nil {
		t.Fatal("runtime manager invoked unrestricted constructor")
	}
}

func TestRuntimeInventoryPreservesConcretePreparationFailure(t *testing.T) {
	manager := NewRuntimeManager(nil, nil)
	sentinel := errors.New("native callback fence missing")
	member := &preparedInboundFixture{tag: "bad", validate: func() error { return sentinel }}
	if err := manager.Insert(member, nil); !errors.Is(err, sentinel) {
		t.Fatal("missing lifecycle contract hidden")
	}
	if len(manager.Inbounds()) != 0 {
		t.Fatal("invalid candidate published in inventory")
	}
}
