package box

import (
	"context"
	"errors"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/service"
)

// The cache file is a stable Box resource for the daily update scope. Only the
// private DNS client's buffering/policy view changes; no duplicate physical
// open, live cache-ID mutation or candidate-time clearing is permitted.
func (s *Box) prepareRuntimeDNSStores(ctx context.Context, graph *preparedRuntimeGraph, resource *runtimeResource, options option.DNSOptions) (dns.RouterClientDependencies, error) {
	physical := service.FromContext[adapter.CacheFile](s.runtime.ctx)
	if physical == nil || (!physical.StoreDNS() && !physical.StoreRDRC()) { return dns.PrivateClientDependencies(physical) }
	cache, ok := physical.(*cachefile.CacheFile)
	if !ok { return dns.RouterClientDependencies{}, errors.New("persistent DNS cache lacks retained logical-view adapter") }
	var optimisticTimeout time.Duration
	optimistic := common.PtrValueOrDefault(options.Optimistic)
	if optimistic.Enabled {
		optimisticTimeout = time.Duration(optimistic.Timeout)
		if optimisticTimeout == 0 { optimisticTimeout = 3 * 24 * time.Hour }
	}
	view, err := cache.NewDNSRuntimeView(ctx, cachefile.DNSRuntimeViewOptions{Namespace:resource.fingerprint, DisableExpire:options.DisableExpire, OptimisticTimeout:optimisticTimeout})
	if err != nil { return dns.RouterClientDependencies{}, err }
	resource.scope.Add(func() error { return runtimeCleanupResult(view.Close()) })
	graph.dnsStores = append(graph.dnsStores, view)
	return dns.PrivateClientDependencies(physical, view)
}
