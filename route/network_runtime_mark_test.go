package route

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

type runtimeMarkOwnerFixture struct {
	adapter.NetworkManager
	mark          uint32
	registrations int
}

func (o *runtimeMarkOwnerFixture) RegisterAutoRedirectOutputMark(mark uint32) error {
	o.mark = mark
	o.registrations++
	return nil
}
func (o *runtimeMarkOwnerFixture) AutoDetectInterface() bool      { return false }
func (o *runtimeMarkOwnerFixture) AutoRedirectOutputMark() uint32 { return o.mark }
func TestRuntimeNetworkMarkDoesNotMutateStableOwner(t *testing.T) {
	owner := &runtimeMarkOwnerFixture{mark: 7}
	old, err := NewRuntimeNetworkOptionsView(owner, adapter.NetworkOptions{}, 11)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := NewRuntimeNetworkOptionsView(owner, adapter.NetworkOptions{}, 22)
	if err != nil {
		t.Fatal(err)
	}
	if err := candidate.RegisterAutoRedirectOutputMark(22); err != nil {
		t.Fatal(err)
	}
	if err := candidate.RegisterAutoRedirectOutputMark(11); err == nil {
		t.Fatal("undeclared mark admitted")
	}
	if owner.mark != 7 || owner.registrations != 0 || old.AutoRedirectOutputMark() != 11 || candidate.AutoRedirectOutputMark() != 22 {
		t.Fatal("candidate mutated stable/old state")
	}
}

func TestRuntimeNetworkDisabledMarkControlDoesNotTouchSocket(t *testing.T) {
	view, err := NewRuntimeNetworkOptionsView(&runtimeMarkOwnerFixture{}, adapter.NetworkOptions{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := view.AutoRedirectOutputMarkFunc()("tcp", "", nil); err != nil {
		t.Fatal(err)
	}
	if err := view.RegisterAutoRedirectOutputMark(0); err == nil {
		t.Fatal("missing declaration accepted")
	}
}
