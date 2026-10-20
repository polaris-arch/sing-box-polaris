package route

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

// networkOptionsView owns only its defaults snapshot. All other methods borrow
// the stable owner's live OS state and controls; this is not a candidate sandbox.
type networkOptionsView struct {
	adapter.NetworkManager
	defaults adapter.NetworkOptions
}

func NewNetworkOptionsView(owner adapter.NetworkManager, defaults adapter.NetworkOptions) (adapter.NetworkManager, error) {
	if owner == nil {
		return nil, E.New("network options view requires an owner")
	}
	return &networkOptionsView{NetworkManager: owner, defaults: cloneNetworkOptions(defaults)}, nil
}

func (v *networkOptionsView) DefaultOptions() adapter.NetworkOptions {
	return cloneNetworkOptions(v.defaults)
}

func (*networkOptionsView) Start(adapter.StartStage, *adapter.Scope) error {
	return E.New("network options view is non-owning and cannot be started")
}

// ContextWithNetworkOptions clones the service registry before binding defaults.
// The caller supplies the resource-owned operational context and must bind all
// other generation-local services into this child before constructing consumers.
// In particular DNSRouter and DNSRuleSetUpdateValidator must both be rebound;
// replacing only DNSRouter leaves a copied validator pointing to the old graph.
// This does not authorize starting another graph or mutating stable OS resources.
func ContextWithNetworkOptions(ctx context.Context, owner adapter.NetworkManager, options option.RouteOptions) (context.Context, error) {
	defaults, err := BuildNetworkOptions(options)
	if err != nil {
		return nil, err
	}
	view, err := NewNetworkOptionsView(owner, defaults)
	if err != nil {
		return nil, err
	}
	child := service.ExtendContext(service.ContextWithDefaultRegistry(ctx))
	service.MustRegister[adapter.NetworkManager](child, view)
	return child, nil
}
