package clashmode

import (
	"testing"

	"github.com/sagernet/sing/common/observable"
)

func TestRuntimeRemoveUpdateHookPreservesOtherRegistrations(t *testing.T) {
	first := observable.NewSubscriber[struct{}](1)
	second := observable.NewSubscriber[struct{}](1)
	defer first.Close()
	defer second.Close()
	m := new(Manager)
	m.AddUpdateHook(first)
	m.AddUpdateHook(second)
	m.AddUpdateHook(first)
	m.RemoveUpdateHook(first)
	m.RemoveUpdateHook(first)
	if len(m.updateHooks) != 1 || m.updateHooks[0] != second { t.Fatal("removal changed another observer or retained duplicate registration") }
}
