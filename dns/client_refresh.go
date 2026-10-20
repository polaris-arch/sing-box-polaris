package dns

import (
	"context"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/runtimegraph"
)

type dnsRefreshLineageKey struct{}

func dnsRefreshLineage(ctx context.Context) *runtimegraph.DNSRefreshOwner {
	owner, _ := ctx.Value(dnsRefreshLineageKey{}).(*runtimegraph.DNSRefreshOwner)
	return owner
}

// Receiving Client stores and registry stay bound to c.ctx. Only operation
// ownership is inherited. Do not adopt a foreground waiter's short deadline.
func (c *Client) admitBackgroundRefresh(caller context.Context) (context.Context, func(), bool) {
	owner := dnsRefreshLineage(caller)
	if owner == nil { owner = c.refreshOwner }
	operation, err := owner.Acquire()
	if err != nil { return nil, nil, false }
	runtimeCtx, releaseRuntime, err := adapter.AcquireRuntimeOperation(caller, c.runtimeResource)
	if err != nil { operation.Release(); return nil, nil, false }
	ctx, cancel := context.WithCancel(c.ctx)
	cancelDone := make(chan struct{})
	stop := context.AfterFunc(owner.Context(), func() { defer close(cancelDone); cancel() })
	if owner.Context().Err() != nil { cancel() }
	ctx = adapter.ContextWithRuntimeOwnership(ctx, runtimeCtx)
	ctx = context.WithValue(ctx, dnsRefreshLineageKey{}, owner)
	var once sync.Once
	return ctx, func() { once.Do(func() {
		if !stop() { <-cancelDone }
		cancel()
		operation.Release()
		releaseRuntime()
	}) }, true
}

// Lineage cancellation and actual lineage completion remain separate. A receiver
// may also have foreign-lineage work, whose resource reservations are independent
// of this lineage-only wait and are joined by the runtime resource owner.
func (c *Client) stopBackgroundRefreshes() { c.refreshOwner.Stop() }
func (c *Client) waitBackgroundRefreshes(ctx context.Context) error { return c.refreshOwner.Wait(ctx) }
