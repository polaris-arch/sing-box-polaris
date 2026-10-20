package route

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
)

// RuntimeNetworkInventory pins current and retained resource allocations for the
// entire callback. The provider invokes visitors outside its coordinator guard.
// Async listeners must retain their own continuation before returning.
type RuntimeNetworkInventory interface {
	VisitRuntimeNetwork(context.Context, func(context.Context, adapter.Outbound, adapter.Router))
}

// BindRuntimeInventory is called once, before network monitors are started.
func (r *NetworkManager) BindRuntimeInventory(inventory RuntimeNetworkInventory) {
	r.runtimeInventory = inventory
}
