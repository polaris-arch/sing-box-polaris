package inbound

import (
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.InboundManager = (*Manager)(nil)

type Manager struct {
	registry     adapter.InboundRegistry
	endpoint     adapter.EndpointManager
	access       sync.Mutex
	inbounds     []adapter.Inbound
	inboundByTag map[string]adapter.Inbound
	pending map[string]bool
	runtime bool
	frozen bool
	owned map[string]*adapter.Scope
	stages map[adapter.StartStage]*runtimeStage
	runtimeEndpoints map[string]adapter.Inbound
}

func NewManager(registry adapter.InboundRegistry, endpoint adapter.EndpointManager) *Manager {
	return &Manager{
		registry:     registry,
		endpoint:     endpoint,
		inboundByTag: make(map[string]adapter.Inbound),
		pending: make(map[string]bool),
	}
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if m.runtime { return m.startRuntime(stage) }
	m.access.Lock()
	inbounds := slices.Clone(m.inbounds)
	m.access.Unlock()
	for _, inbound := range inbounds {
		name := "inbound/" + inbound.Type() + "[" + inbound.Tag() + "]"
		err := scope.Start(name, inbound, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) Inbounds() []adapter.Inbound {
	m.access.Lock()
	defer m.access.Unlock()
	return slices.Clone(m.inbounds)
}

func (m *Manager) Get(tag string) (adapter.Inbound, bool) {
	m.access.Lock()
	inbound, found := m.inboundByTag[tag]
	if !found && m.runtime { inbound, found = m.runtimeEndpoints[tag] }
	runtime := m.runtime
	m.access.Unlock()
	if found {
		return inbound, true
	}
	if runtime || m.endpoint == nil { return nil, false }
	return m.endpoint.Get(tag)
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, inboundType string, options any) error {
	m.access.Lock()
	if m.runtime || m.frozen { m.access.Unlock(); return errors.New("runtime inbound construction requires an owned prepared member") }
	if _, loaded := m.inboundByTag[tag]; loaded || m.pending[tag] { m.access.Unlock(); return E.New("duplicate inbound tag: ", tag) }
	m.pending[tag] = true
	m.access.Unlock()
	// Constructor callbacks run outside manager locks. A reserved tag prevents
	// a second constructor from allocating resources which cannot be inserted.
	member, err := m.registry.Create(ctx, router, logger, tag, inboundType, options)
	m.access.Lock()
	delete(m.pending, tag)
	if err == nil { m.inbounds = append(m.inbounds, member); m.inboundByTag[tag] = member }
	m.access.Unlock()
	return err
}
