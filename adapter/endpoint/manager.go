package endpoint

import (
	"context"
	"errors"
	"os"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.EndpointManager = (*Manager)(nil)

type Manager struct {
	registry      adapter.EndpointRegistry
	access        sync.Mutex
	scope         *adapter.Scope
	endpoints     []adapter.Endpoint
	endpointByTag map[string]adapter.Endpoint
	runtime bool
	frozen bool
	owned map[string]*adapter.Scope
	pending map[string]bool
	stages map[adapter.StartStage]error
	endpointStages map[string]error
}

func NewManager(registry adapter.EndpointRegistry) *Manager {
	return &Manager{
		registry:      registry,
		endpointByTag: make(map[string]adapter.Endpoint),
		pending: make(map[string]bool),
	}
}

func NewRuntimeManager(registry adapter.EndpointRegistry) *Manager {
	m := NewManager(registry)
	m.runtime = true
	m.owned = make(map[string]*adapter.Scope)
	m.stages = make(map[adapter.StartStage]error)
	m.endpointStages = make(map[string]error)
	return m
}

func (m *Manager) Insert(member adapter.Endpoint, ownedScope *adapter.Scope) error {
	if member == nil || member.Tag() == "" { return os.ErrInvalid }
 prepared,ok:=member.(RuntimePreparedEndpoint);if !ok{return errors.New("endpoint lacks its runtime resource adapter")};if err:=prepared.RuntimeValidate();err!=nil{return err}
	m.access.Lock()
	defer m.access.Unlock()
	if !m.runtime || m.frozen { return errors.New("endpoint inventory is not mutable") }
	if _, exists := m.endpointByTag[member.Tag()]; exists { return E.New("duplicate endpoint tag: ", member.Tag()) }
	m.endpoints = append(m.endpoints, member)
	m.endpointByTag[member.Tag()] = member
	if ownedScope != nil { m.owned[member.Tag()] = ownedScope }
	return nil
}

func (m *Manager) Freeze() error {
	m.access.Lock()
	defer m.access.Unlock()
	if !m.runtime { return errors.New("not a runtime endpoint manager") }
	m.frozen = true
	return nil
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.access.Lock()
	if m.runtime {
		if !m.frozen { m.access.Unlock(); return errors.New("endpoint inventory not frozen") }
		if result, exists := m.stages[stage]; exists { m.access.Unlock(); return result }
		m.stages[stage] = errors.New("endpoint stage in progress")
	}
	if stage == adapter.StartStateInitialize { m.scope = scope }
	endpoints := slices.Clone(m.endpoints)
	m.access.Unlock()
	var result error
	if stage != adapter.StartStateStart {
		for _, endpoint := range endpoints {
			memberScope := scope
			if m.runtime { memberScope = m.owned[endpoint.Tag()]; if memberScope == nil { continue } }
			var err error
   if m.runtime{err=endpoint.(RuntimePreparedEndpoint).PrepareRuntime(stage,memberScope)}else{err=memberScope.Start("endpoint/"+endpoint.Type()+"["+endpoint.Tag()+"]", endpoint, stage)}
   if err!=nil{result=err;break}
		}
	}
	if m.runtime { m.access.Lock(); m.stages[stage] = result; m.access.Unlock() }
	return result
}

func (m *Manager) StartEndpoint(endpoint adapter.Endpoint) error {
	m.access.Lock()
	scope := m.scope
	if m.runtime {
		if !m.frozen || m.endpointByTag[endpoint.Tag()] != endpoint { m.access.Unlock(); return errors.New("endpoint is not a frozen member") }
		scope = m.owned[endpoint.Tag()]
		if scope == nil { m.access.Unlock(); return nil }
		if result, exists := m.endpointStages[endpoint.Tag()]; exists { m.access.Unlock(); return result }
		m.endpointStages[endpoint.Tag()] = errors.New("endpoint start in progress")
	}
	m.access.Unlock()
	if scope == nil { return errors.New("endpoint manager not initialized") }
	var err error
 if m.runtime{err=endpoint.(RuntimePreparedEndpoint).PrepareRuntime(adapter.StartStateStart,scope)}else{err=scope.Start("endpoint/"+endpoint.Type()+"["+endpoint.Tag()+"]", endpoint, adapter.StartStateStart)}
	if m.runtime { m.access.Lock(); m.endpointStages[endpoint.Tag()] = err; m.access.Unlock() }
	return err
}

func (m *Manager) Endpoints() []adapter.Endpoint {
	m.access.Lock()
	defer m.access.Unlock()
	return slices.Clone(m.endpoints)
}

func (m *Manager) Get(tag string) (adapter.Endpoint, bool) {
	m.access.Lock()
	defer m.access.Unlock()
	endpoint, found := m.endpointByTag[tag]
	return endpoint, found
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {
	if tag == "" { return os.ErrInvalid }
	m.access.Lock()
	if m.runtime || m.frozen { m.access.Unlock(); return errors.New("runtime endpoints require explicit insertion") }
	if _, exists := m.endpointByTag[tag]; exists || m.pending[tag] { m.access.Unlock(); return E.New("duplicate endpoint tag: ", tag) }
	m.pending[tag] = true
	m.access.Unlock()
	defer func() { m.access.Lock(); delete(m.pending, tag); m.access.Unlock() }()
	endpoint, err := m.registry.Create(ctx, router, logger, tag, outboundType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	_, loaded := m.endpointByTag[tag]
	if loaded {
		return E.New("duplicate endpoint tag: ", tag)
	}
	m.endpoints = append(m.endpoints, endpoint)
	m.endpointByTag[tag] = endpoint
	return nil
}

// OwnsEndpoint separates lookup availability from lifecycle scheduling.
func (m *Manager) OwnsEndpoint(tag string) bool {
	m.access.Lock()
	defer m.access.Unlock()
	return !m.runtime || m.owned[tag] != nil
}

// RuntimeFrozen proves this shell will neither mutate lookup membership nor
// route borrowed members through the legacy manager's lifecycle owner.
func (m *Manager) RuntimeFrozen() bool {
	m.access.Lock()
	defer m.access.Unlock()
	return m.runtime && m.frozen
}
