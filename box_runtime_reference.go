package box

import (
	"errors"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/service"
)

// AcquireReferenceSnapshot transfers one current graph admission. The stable
// inventories contain only Box-owned components; dynamic inventories and census
// options come from this exact immutable graph, never a subsequent tag lookup.
func (s *Box) AcquireReferenceSnapshot() (route.RuntimeReferenceSnapshot, error) {
	c := s.runtime
	if c == nil { return route.RuntimeReferenceSnapshot{}, errors.New("runtime reference graph unavailable") }
	c.access.Lock()
	defer c.access.Unlock()
	if c.stopped { return route.RuntimeReferenceSnapshot{}, errors.New("runtime reference graph stopped") }
	lease, err := c.store.Acquire()
	if err != nil { return route.RuntimeReferenceSnapshot{}, err }
	view, ok := lease.View().(*runtimeView)
	if !ok { lease.Release(); return route.RuntimeReferenceSnapshot{}, errors.New("invalid runtime reference view") }
	resources := make(map[any]adapter.RuntimeResourceID,len(view.referenceResources))
	for object, id := range view.referenceResources { resources[object] = id }
	mode := ""
	if c.clashMode != nil { mode = c.clashMode.Mode() }
	return route.RuntimeReferenceSnapshot{Lease:lease, Options:view.referenceOptions,
		Inbounds:view.inbounds, Services:s.service, HTTPClient:view.httpClients,
		Mode:mode, StableResource:c.stable.id, Resources:resources},nil
}

func (s *Box) RegisterReferenceHook(hook *observable.Subscriber[struct{}]) (func() error,error) {
	c := s.runtime
	if c == nil { return nil, errors.New("runtime reference hooks unavailable") }
	history := service.PtrFromContext[urltest.HistoryStorage](c.ctx)
	if history == nil || c.clashMode == nil { return nil,errors.New("runtime reference notification owner unavailable") }
	var once sync.Once
	remove := func() error { once.Do(func(){ history.RemoveUpdateHook(hook); c.clashMode.RemoveUpdateHook(hook) }); return nil }
	history.AddUpdateHook(hook)
	c.clashMode.AddUpdateHook(hook)
	return remove,nil
}
