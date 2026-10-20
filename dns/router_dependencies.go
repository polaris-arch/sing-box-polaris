package dns

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"errors"
)

// RouterClientDependencies borrows explicitly bound stores. Neither nil field
// permits discovery of an ambient CacheFile: nil DNSCache selects private memory
// and nil RDRC disables rejected-response persistence. Store lifecycle ownership
// remains with the caller; the router does not start or close these stores.
type RouterClientDependencies struct {
	DNSCache adapter.DNSCacheStore
	RDRC     adapter.RDRCStore
}

func NewRouterWithClientDependencies(ctx context.Context, logFactory log.Factory, options option.DNSOptions, dependencies RouterClientDependencies) (*Router, error) {
	return newRouter(ctx, logFactory, options, &dependencies)
}

// RuntimeClientStores must be an explicitly retained logical view of the
// actual stable cache. Its caller owns Prepare/Activate/Close ordering. The
// view has immutable per-graph settings and cannot reset the physical store.
type RuntimeClientStores interface {
 adapter.DNSCacheStore
 adapter.RDRCStore
 StoreDNS() bool
 StoreRDRC() bool
 RuntimeDNSPhysicalCache() adapter.CacheFile
}

func PrivateClientDependencies(liveCache adapter.CacheFile, views ...RuntimeClientStores) (RouterClientDependencies, error) {
 if len(views)>1 { return RouterClientDependencies{}, errors.New("multiple private DNS store views") }
 if len(views)==1 && views[0]!=nil {
  view:=views[0]
  if liveCache==nil || view.RuntimeDNSPhysicalCache()!=liveCache { return RouterClientDependencies{}, errors.New("private DNS store view belongs to a different physical cache") }
  if view.StoreDNS()!=liveCache.StoreDNS() || view.StoreRDRC()!=liveCache.StoreRDRC() { return RouterClientDependencies{}, errors.New("private DNS store settings differ from the retained physical cache") }
  var dependencies RouterClientDependencies
  if view.StoreDNS() { dependencies.DNSCache=view }
  if view.StoreRDRC() { dependencies.RDRC=view }
  return dependencies,nil
 }
 if liveCache!=nil && (liveCache.StoreDNS() || liveCache.StoreRDRC()) { return RouterClientDependencies{}, errors.New("persistent DNS/RDRC requires a retained private logical view") }
 return RouterClientDependencies{},nil
}
