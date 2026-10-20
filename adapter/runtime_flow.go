package adapter

import (
	"context"
	"errors"

	"github.com/sagernet/sing-tun"
)

// RuntimeFlowOwnership transfers one admitted graph continuation to the TUN
// dispatcher. Context binding is borrowed; escaping users must Retain first.
func RuntimeFlowOwnership(lease RuntimeLease) tun.FlowOwnership {
	if lease == nil {
		return nil
	}
	return &runtimeFlowOwnership{lease: lease}
}

type runtimeFlowOwnership struct { lease RuntimeLease }

func (o *runtimeFlowOwnership) Retain() (tun.FlowOwnership, error) {
	lease, err := o.lease.Fork()
	if err != nil { return nil, err }
	return RuntimeFlowOwnership(lease), nil
}

func (o *runtimeFlowOwnership) BindContext(ctx context.Context) context.Context {
	return ContextWithRuntimeLease(ctx, o.lease)
}

func (o *runtimeFlowOwnership) RetainPort(port tun.Port) (tun.PortOwnership, error) {
	view, ok := o.lease.View().(RuntimePortView)
	if !ok { return nil, errors.New("runtime view has no port resource inventory") }
	id, ok := view.RuntimePortResource(port)
	if !ok { return nil, errors.New("port is outside admitted runtime closure") }
	lease, err := o.lease.RetainResource(id)
	if err != nil { return nil, err }
	return &runtimePortOwnership{lease: lease}, nil
}

func (o *runtimeFlowOwnership) Release() { o.lease.Release() }

type runtimePortOwnership struct { lease RuntimeResourceLease }

func (o *runtimePortOwnership) Retain() (tun.PortOwnership, error) {
	lease, err := o.lease.Fork()
	if err != nil { return nil, err }
	return &runtimePortOwnership{lease: lease}, nil
}
func (o *runtimePortOwnership) Retiring() <-chan struct{} { return o.lease.Retiring() }
func (o *runtimePortOwnership) Release() { o.lease.Release() }

