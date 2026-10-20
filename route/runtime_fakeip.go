package route

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-box/adapter"
)

// Mapping ownership follows the actual admitted operation lineage. A socket's
// Close callback does not release mappings still used by a copy or TUN verdict
// continuation. The set contains acquired tokens, never tag-based lookups.
type runtimeMappingSet struct {
	access     sync.Mutex
	references uint64
	mappings   []adapter.FakeIPMappingLease
}
type runtimeMappingLease struct {
	access   sync.Mutex
	released bool
	graph    adapter.RuntimeLease
	mappings *runtimeMappingSet
}

func withRuntimeMappings(graph adapter.RuntimeLease) adapter.RuntimeLease {
	if _, ok := graph.(*runtimeMappingLease); ok {
		return graph
	}
	return &runtimeMappingLease{graph: graph, mappings: &runtimeMappingSet{references: 1}}
}
func (l *runtimeMappingLease) View() adapter.RuntimeView { return l.graph.View() }
func (l *runtimeMappingLease) Fork() (adapter.RuntimeLease, error) {
	l.access.Lock()
	defer l.access.Unlock()
	if l.released {
		return nil, errors.New("mapping admission already released")
	}
	fork, err := l.graph.Fork()
	if err != nil {
		return nil, err
	}
	l.mappings.access.Lock()
	l.mappings.references++
	l.mappings.access.Unlock()
	return &runtimeMappingLease{graph: fork, mappings: l.mappings}, nil
}

func (l *runtimeMappingLease) RetainResource(id adapter.RuntimeResourceID) (adapter.RuntimeResourceLease, error) {
	l.access.Lock()
	defer l.access.Unlock()
	if l.released {
		return nil, errors.New("mapping admission already released")
	}
	return l.graph.RetainResource(id)
}

func (l *runtimeMappingLease) Release() {
	l.access.Lock()
	if l.released {
		l.access.Unlock()
		return
	}
	l.released = true
	l.access.Unlock()
	l.graph.Release()
	l.mappings.access.Lock()
	l.mappings.references--
	var mappings []adapter.FakeIPMappingLease
	if l.mappings.references == 0 {
		mappings = l.mappings.mappings
		l.mappings.mappings = nil
	}
	l.mappings.access.Unlock()
	for _, mapping := range mappings {
		mapping.Release()
	}
}

func (l *runtimeMappingLease) addMapping(mapping adapter.FakeIPMappingLease) error {
	l.access.Lock()
	defer l.access.Unlock()
	if l.released {
		return errors.New("mapping admission already released")
	}
	l.mappings.access.Lock()
	l.mappings.mappings = append(l.mappings.mappings, mapping)
	l.mappings.access.Unlock()
	return nil
}

// recognizeRuntimeFakeIP makes recognition and pinning atomic at the authority.
// The caller changes metadata only after ownership is attached successfully.
func recognizeRuntimeFakeIP(ctx context.Context, protection adapter.FakeIPProtection, address netip.Addr) (string, bool, error) {
	mapping, recognized, err := protection.AcquireMapping(address)
	if err != nil {
		return "", false, err
	}
	if !recognized {
		return "", false, nil
	}
	if mapping == nil {
		return "", false, errors.New("fake-IP authority returned no mapping reservation")
	}
	lease, ok := adapter.RuntimeLeaseFromContext(ctx)
	if !ok {
		mapping.Release()
		return "", false, errors.New("fake-IP mapping requires admitted flow ownership")
	}
	owner, ok := lease.(*runtimeMappingLease)
	if !ok {
		mapping.Release()
		return "", false, errors.New("flow admission lacks mapping ownership")
	}
	if err := owner.addMapping(mapping); err != nil {
		mapping.Release()
		return "", false, err
	}
	return mapping.Domain(), true, nil
}

var _ adapter.RuntimeLease = (*runtimeMappingLease)(nil)
