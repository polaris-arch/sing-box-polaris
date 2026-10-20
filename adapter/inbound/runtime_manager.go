package inbound

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/listener"
)

// RuntimePreparedInbound is an explicit concrete protocol contract. Implementing
// it certifies that constructors are inert, PrepareRuntime never publishes
// callbacks, and every non-listener graph-facing owner has registered a concrete
// cancellation/close/join barrier. Scope alone does not certify those properties.
// Unsupported variants report their missing mechanism from RuntimeValidate;
// they remain production-valid configuration and produce an honest Plan impact.
type RuntimePreparedInbound interface {
	adapter.Inbound
	RuntimeValidate() error
	PrepareRuntime(adapter.StartStage, *adapter.Scope) error
	RuntimeListeners() []*listener.Listener
}

type runtimeStage struct {
	done chan struct{}
	err  error
}

func NewRuntimeManager(registry adapter.InboundRegistry, endpoint adapter.EndpointManager) *Manager {
	m := NewManager(registry, endpoint)
	m.runtime = true
	m.owned = make(map[string]*adapter.Scope)
	m.stages = make(map[adapter.StartStage]*runtimeStage)
	m.runtimeEndpoints = make(map[string]adapter.Inbound)
	return m
}

// Insert transfers no lifetime by itself. Box retains each constructor's exact
// resource owner through preparation and publication. A nil scope is a borrowed
// unchanged member, never a request to restart or register duplicate cleanup.
func (m *Manager) Insert(member adapter.Inbound, ownedScope *adapter.Scope) error {
	if member == nil || member.Tag() == "" {
		return errors.New("runtime inbound requires a tagged member")
	}
	prepared, ok := member.(RuntimePreparedInbound)
	if !ok {
		return fmt.Errorf("inbound %s/%s has no staged lifecycle adapter", member.Type(), member.Tag())
	}
	if err := prepared.RuntimeValidate(); err != nil {
		return err
	}
	tag := member.Tag()
	m.access.Lock()
	defer m.access.Unlock()
	if !m.runtime || m.frozen {
		return errors.New("inbound inventory is not mutable")
	}
	if _, found := m.inboundByTag[tag]; found {
		return fmt.Errorf("duplicate inbound tag: %s", tag)
	}
	m.inbounds = append(m.inbounds, member)
	m.inboundByTag[tag] = member
	if ownedScope != nil {
		m.owned[tag] = ownedScope
	}
	return nil
}

func (m *Manager) Freeze() error {
	// Snapshot a separately frozen endpoint inventory outside this manager lock.
	endpoints := make(map[string]adapter.Inbound)
	if m.endpoint != nil {
		frozen, ok := m.endpoint.(interface{ RuntimeFrozen() bool })
		if !ok || !frozen.RuntimeFrozen() {
			return errors.New("runtime endpoint inventory must be frozen first")
		}
		for _, member := range m.endpoint.Endpoints() {
			endpoints[member.Tag()] = member
		}
	}
	m.access.Lock()
	defer m.access.Unlock()
	if !m.runtime {
		return errors.New("not a runtime inbound manager")
	}
	if m.frozen {
		return nil
	}
	for tag := range endpoints {
		if _, found := m.inboundByTag[tag]; found {
			return fmt.Errorf("duplicate inbound/endpoint tag: %s", tag)
		}
	}
	m.runtimeEndpoints = endpoints
	m.frozen = true
	return nil
}

func (m *Manager) RuntimeFrozen() bool {
	m.access.Lock()
	defer m.access.Unlock()
	return m.runtime && m.frozen
}

func (m *Manager) startRuntime(stage adapter.StartStage) error {
	m.access.Lock()
	if !m.frozen {
		m.access.Unlock()
		return errors.New("inbound inventory not frozen")
	}
	if previous := m.stages[stage]; previous != nil {
		done := previous.done
		m.access.Unlock()
		<-done
		return previous.err
	}
	current := &runtimeStage{done: make(chan struct{})}
	m.stages[stage] = current
	members := slices.Clone(m.inbounds)
	owned := make(map[string]*adapter.Scope, len(m.owned))
	maps.Copy(owned, m.owned)
	m.access.Unlock()
	// A panic cannot be published as success to another lifecycle caller.
	current.err = errors.New("runtime inbound preparation did not complete")
	defer close(current.done)
	for _, member := range members {
		if scope := owned[member.Tag()]; scope != nil {
			if err := member.(RuntimePreparedInbound).PrepareRuntime(stage, scope); err != nil {
				current.err = err
				return err
			}
		}
	}
	current.err = nil
	return nil
}

func (m *Manager) PreparedListeners() ([]*listener.Listener, error) {
	m.access.Lock()
	if !m.runtime || !m.frozen {
		m.access.Unlock()
		return nil, errors.New("inbound inventory not frozen")
	}
	members := slices.Clone(m.inbounds)
	owned := make(map[string]bool, len(m.owned))
	for tag := range m.owned {
		owned[tag] = true
	}
	m.access.Unlock()
	var result []*listener.Listener
	for _, member := range members {
		if owned[member.Tag()] {
			result = append(result, member.(RuntimePreparedInbound).RuntimeListeners()...)
		}
	}
	return result, nil
}
