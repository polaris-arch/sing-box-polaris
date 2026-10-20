package route

import (
	"context"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-box/adapter"

	"github.com/miekg/dns"
)

// RuntimeDNSRouter is the stable application-query ingress. Nested dialers use
// the leaf returned by RuntimeView.DNSRouter instead. Each call admits current,
// even when its carrier context contains an older routing continuation.
type RuntimeDNSRouter struct{ admission adapter.RuntimeAdmission }

func NewRuntimeDNSRouter(admission adapter.RuntimeAdmission) *RuntimeDNSRouter {
	return &RuntimeDNSRouter{admission: admission}
}

func (*RuntimeDNSRouter) Start(adapter.StartStage, *adapter.Scope) error { return nil }

func (r *RuntimeDNSRouter) Exchange(ctx context.Context, message *dns.Msg, options adapter.DNSQueryOptions) (*dns.Msg, error) {
	lease, err := r.admission.Acquire()
	if err != nil {
		return nil, err
	}
	defer lease.Release()
	return lease.View().DNSRouter().Exchange(adapter.ContextWithRuntimeLease(ctx, lease), message, options)
}

func (r *RuntimeDNSRouter) ExchangeAsync(ctx context.Context, message *dns.Msg, options adapter.DNSQueryOptions, callback func(*dns.Msg, error)) {
	lease, err := r.admission.Acquire()
	if err != nil {
		callback(nil, err)
		return
	}
	invocation, forkErr := lease.Fork()
	if forkErr != nil {
		lease.Release()
		callback(nil, forkErr)
		return
	}
	defer invocation.Release()
	var once sync.Once
	finished := func(response *dns.Msg, err error) {
		once.Do(func() { defer lease.Release(); callback(response, err) })
	}
	// Invocation and callback are independent: a synchronous callback can return
	// before the leaf's stack unwinds, and a deferred callback can outlive it.
	defer func() {
		if recovered := recover(); recovered != nil {
			once.Do(lease.Release)
			panic(recovered)
		}
	}()
	invocation.View().DNSRouter().ExchangeAsync(adapter.ContextWithRuntimeLease(ctx, invocation), message, options, finished)
}

func (r *RuntimeDNSRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	lease, err := r.admission.Acquire()
	if err != nil {
		return nil, err
	}
	defer lease.Release()
	return lease.View().DNSRouter().Lookup(adapter.ContextWithRuntimeLease(ctx, lease), domain, options)
}

func (r *RuntimeDNSRouter) ClearCache() {
	lease, err := r.admission.Acquire()
	if err != nil {
		return
	}
	defer lease.Release()
	lease.View().DNSRouter().ClearCache()
}

func (r *RuntimeDNSRouter) LookupReverseMapping(ip netip.Addr) (string, bool) {
	lease, err := r.admission.Acquire()
	if err != nil {
		return "", false
	}
	defer lease.Release()
	return lease.View().DNSRouter().LookupReverseMapping(ip)
}

func (r *RuntimeDNSRouter) ResetNetwork() {
	lease, err := r.admission.Acquire()
	if err != nil {
		return
	}
	defer lease.Release()
	lease.View().DNSRouter().ResetNetwork()
}

func (r *RuntimeDNSRouter) HasResolverPolicy(id string) bool {
	lease, err := r.admission.Acquire()
	if err != nil {
		return false
	}
	defer lease.Release()
	policy, ok := lease.View().DNSRouter().(interface{ HasResolverPolicy(string) bool })
	return ok && policy.HasResolverPolicy(id)
}

var _ adapter.DNSRouter = (*RuntimeDNSRouter)(nil)
