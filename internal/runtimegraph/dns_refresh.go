package runtimegraph

import "context"

// DNSRefreshOwner measures core DNS refresh invocations and their callbacks.
// It does not own graph resources or certify transport-internal/store workers.
// The parent is an operational host context, never a preparation or wait RPC.
type DNSRefreshOwner struct {
	resource *resourceOwner
	ctx context.Context
	cancel context.CancelFunc
}

func NewDNSRefreshOwner(parent context.Context) *DNSRefreshOwner {
	ctx, cancel := context.WithCancel(parent)
	return &DNSRefreshOwner{resource: newResourceOwner(parent, nil), ctx: ctx, cancel: cancel}
}

func (o *DNSRefreshOwner) Context() context.Context { return o.ctx }

type DNSRefreshOperation struct { lease *resourceLease }

func (o *DNSRefreshOwner) Acquire() (*DNSRefreshOperation, error) {
	lease, err := o.resource.acquire()
	if err != nil { return nil, err }
	return &DNSRefreshOperation{lease: lease}, nil
}

func (operation *DNSRefreshOperation) Release() { operation.lease.release() }

// Stop is nonjoining, including from a refresh callback. Resource admission
// seals before operation cancellation; cancellation never waits for drain.
func (o *DNSRefreshOwner) Stop() {
	o.resource.requestClose()
	o.cancel()
}

// Wait reports core operation completion only. A caller timeout leaves the
// actual operations and completion signal intact. Never call from own work.
func (o *DNSRefreshOwner) Wait(ctx context.Context) error { return o.resource.waitClosed(ctx) }
