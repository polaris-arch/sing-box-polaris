package box

import (
	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

// Migration is candidate-private. The commit's control revision check rejects a
// concurrent manual choice; no cache write or old-flow interruption occurs here.
func (s *Box) migrateRuntimeSelections(candidate *preparedRuntimeGraph) {
	lease, err := s.runtime.store.Acquire()
	if err != nil { return }
	defer lease.Release()
	for _, resource := range candidate.created {
		for _, component := range resource.components {
			if component.outbound == nil { continue }
			migration, ok := component.outbound.(interface { RuntimeSelectInitial(string) bool })
			if !ok { continue }
			previous, exists := lease.View().OutboundManager().Outbound(component.outbound.Tag())
			if !exists { continue }
			group, ok := previous.(adapter.OutboundGroup)
			if !ok { continue }
			selected := group.Selected(N.NetworkTCP)
			if selected != nil { migration.RuntimeSelectInitial(selected.Tag()) }
		}
	}
}
