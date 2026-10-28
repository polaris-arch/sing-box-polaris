package socks

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
)

var _ inbound.RuntimePreparedInbound = (*Inbound)(nil)

func (h *Inbound) RuntimeValidate() error                 { return h.listener.ValidateRuntime() }
func (h *Inbound) RuntimeListeners() []*listener.Listener { return []*listener.Listener{h.listener} }

func (h *Inbound) PrepareRuntime(stage adapter.StartStage, scope *adapter.Scope) error {
	// Listener cleanup was registered during construction. The replacement
	// transaction owns socket preparation because an exclusive address might
	// still belong to the previous instance at this stage.
	return h.RuntimeValidate()
}
