package box

import (
	"slices"
	"time"

	"github.com/sagernet/sing-box/adapter"
 runtimeEndpoint "github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
)

// CaptureTailscaleStateStores records the Tailscale endpoints of this box the
// first time it is called. The snapshot is part of this Box, not a separate
// registry.
func (s *Box) CaptureTailscaleStateStores() []adapter.Endpoint {
	s.tsStoreMu.Lock()
	defer s.tsStoreMu.Unlock()
	if !s.tsCaptured {
		if s.endpoint != nil {
			for _, endpoint := range s.endpoint.Endpoints() {
				if endpoint.Type() == C.TypeTailscale {
     if _,logical:=endpoint.(runtimeEndpoint.RuntimePreparedEndpoint);logical{continue}
					s.tsStores = append(s.tsStores, endpoint)
				}
			}
		}
		s.tsCaptured = true
	}
	return append([]adapter.Endpoint(nil), s.tsStores...)
}

func (s *Box) TailscaleStateStoreScopes() []adapter.TailscaleStoreNode {
	endpoints := s.CaptureTailscaleStateStores()
	nodes := make([]adapter.TailscaleStoreNode, 0, len(endpoints))
	for _, endpoint := range endpoints {
		node := adapter.TailscaleStoreNode{Tag: endpoint.Tag(), WriterState: "Unknown", StateFileState: "Unknown", ProfileState: "Unknown"}
		if owner, ok := endpoint.(adapter.TailscaleStateStoreOwner); ok {
			node = owner.TailscaleStateStoreScope()
		}
		nodes = append(nodes, node)
	}
	return nodes
}

func (s *Box) retireTailscaleStateStores() {
	endpoints := s.CaptureTailscaleStateStores()
	// A newly inserted TS endpoint is sealed as well, but its extra entry makes
	// the original daemon census incomplete rather than silently losing it.
	if s.endpoint != nil {
		for _, current := range s.endpoint.Endpoints() {
			if _,logical:=current.(runtimeEndpoint.RuntimePreparedEndpoint);logical{continue}
   if current.Type() != C.TypeTailscale {
				continue
			}
			if !slices.Contains(endpoints, current) {
				endpoints = append(endpoints, current)
			}
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	nodes := make([]adapter.TailscaleStoreNode, 0, len(endpoints))
	for _, endpoint := range endpoints {
		node := adapter.TailscaleStoreNode{Tag: endpoint.Tag(), WriterState: "Unknown", StateFileState: "Unknown", ProfileState: "Unknown"}
		if owner, ok := endpoint.(adapter.TailscaleStateStoreOwner); ok {
			node = owner.RetireTailscaleStateStore(deadline)
		}
		nodes = append(nodes, node)
	}
	s.tsStoreMu.Lock()
	s.tsRetirement = nodes
	s.tsStoreMu.Unlock()
}

func (s *Box) TailscaleStoreRetirement() []adapter.TailscaleStoreNode {
	s.tsStoreMu.Lock()
	defer s.tsStoreMu.Unlock()
	return append([]adapter.TailscaleStoreNode(nil), s.tsRetirement...)
}
