package box

import (
	"slices"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

func (s *Box) directoryEndpoints() []adapter.Endpoint {
	endpoints := s.CaptureTailscaleStateStores()
	if s.endpoint != nil {
		for _, current := range s.endpoint.Endpoints() {
			if current.Type() != C.TypeTailscale {
				continue
			}
			if !slices.Contains(endpoints, current) {
				endpoints = append(endpoints, current)
			}
		}
	}
	return endpoints
}

func (s *Box) TailscaleDirectoryScopes() []adapter.TailscaleDirectoryNode {
	var nodes []adapter.TailscaleDirectoryNode
	for _, endpoint := range s.directoryEndpoints() {
		node := adapter.TailscaleDirectoryNode{Tag: endpoint.Tag(), WriterState: "Unknown"}
		if owner, ok := endpoint.(adapter.TailscaleDirectoryOwner); ok {
			node = owner.TailscaleDirectoryScope()
		}
		nodes = append(nodes, node)
	}
	return nodes
}

func (s *Box) sealTailscaleDirectories() {
	for _, endpoint := range s.directoryEndpoints() {
		if owner, ok := endpoint.(adapter.TailscaleDirectoryOwner); ok {
			owner.SealTailscaleDirectory()
		}
	}
}

// The daemon freezes these results only after original Box.CloseWithResult.
// Each endpoint already used its bounded shutdown worker during Scope.Close.
func (s *Box) TailscaleDirectoryRetirement() []adapter.TailscaleDirectoryNode {
	var nodes []adapter.TailscaleDirectoryNode
	deadline := time.Now()
	for _, endpoint := range s.directoryEndpoints() {
		node := adapter.TailscaleDirectoryNode{Tag: endpoint.Tag(), WriterState: "Unknown"}
		if owner, ok := endpoint.(adapter.TailscaleDirectoryOwner); ok {
			node = owner.RetireTailscaleDirectory(deadline)
		}
		nodes = append(nodes, node)
	}
	return nodes
}
