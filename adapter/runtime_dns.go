package adapter

import "context"

type runtimeDNSIngressKey struct{}

// ContextWithRuntimeDNSIngress binds the stable query gateway independently of
// the graph-local DNSRouter registry binding used by nested dialers.
func ContextWithRuntimeDNSIngress(ctx context.Context, router DNSRouter) context.Context {
	return context.WithValue(ctx, runtimeDNSIngressKey{}, router)
}

func RuntimeDNSIngressFromContext(ctx context.Context) (DNSRouter, bool) {
	router, ok := ctx.Value(runtimeDNSIngressKey{}).(DNSRouter)
	return router, ok && router != nil
}

type runtimeCarrierHandoffKey struct{}

// ContextWithRuntimeCarrierHandoff is installed only by actual flow ingress.
// The hook is single-use and releases the initial routing continuation after a
// core-owned DNS carrier has stopped capturing the old leaf.
func ContextWithRuntimeCarrierHandoff(ctx context.Context, handoff func()) context.Context {
	return context.WithValue(ctx, runtimeCarrierHandoffKey{}, handoff)
}

func RuntimeDNSCarrierContext(ctx context.Context, fallback DNSRouter) (context.Context, DNSRouter) {
	gateway, ok := RuntimeDNSIngressFromContext(ctx)
	if !ok {
		return ctx, fallback
	}
	if handoff, ok := ctx.Value(runtimeCarrierHandoffKey{}).(func()); ok {
		handoff()
	}
	ctx = ContextWithRuntimeLease(ctx, nil)
	// Mask the hook so descendants cannot release an unrelated later admission.
	ctx = ContextWithRuntimeCarrierHandoff(ctx, func() {})
	return ctx, gateway
}
