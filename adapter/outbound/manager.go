package outbound

import (
	"context"
	"errors"
	"net"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.OutboundManager = (*Manager)(nil)

type Manager struct {
	registry                adapter.OutboundRegistry
	endpoint                adapter.EndpointManager
	defaultTag              string
	access                  sync.RWMutex
	outbounds               []adapter.Outbound
	outboundByTag           map[string]adapter.Outbound
	defaultOutbound         adapter.Outbound
	defaultOutboundFallback func() (adapter.Outbound, error)
	runtime                 bool
	frozen                  bool
	owned                   map[string]*adapter.Scope
	pending                 map[string]bool
	stages                  map[adapter.StartStage]error
}

func NewManager(registry adapter.OutboundRegistry, endpoint adapter.EndpointManager, defaultTag string) *Manager {
	return &Manager{
		registry:      registry,
		endpoint:      endpoint,
		defaultTag:    defaultTag,
		outboundByTag: make(map[string]adapter.Outbound),
		pending:       make(map[string]bool),
	}
}

// NewRuntimeManager is a candidate lookup shell. Insert transfers no cleanup
// ownership. A nil scope denotes a borrowed member; each owned member uses its
// resource-private scope, held live by Box's construction reservation.
func NewRuntimeManager(registry adapter.OutboundRegistry, endpoint adapter.EndpointManager, defaultTag string) *Manager {
	m := NewManager(registry, endpoint, defaultTag)
	m.runtime = true
	m.owned = make(map[string]*adapter.Scope)
	m.stages = make(map[adapter.StartStage]error)
	return m
}

func (m *Manager) Insert(member adapter.Outbound, ownedScope *adapter.Scope) error {
	if member == nil || member.Tag() == "" {
		return os.ErrInvalid
	}
	m.access.Lock()
	defer m.access.Unlock()
	if !m.runtime || m.frozen {
		return errors.New("outbound inventory is not mutable")
	}
	if _, exists := m.outboundByTag[member.Tag()]; exists {
		return E.New("duplicate outbound tag: ", member.Tag())
	}
	if _, exists := m.endpoint.Get(member.Tag()); exists {
		return E.New("duplicate outbound/endpoint tag: ", member.Tag())
	}
	m.outbounds = append(m.outbounds, member)
	m.outboundByTag[member.Tag()] = member
	if ownedScope != nil {
		m.owned[member.Tag()] = ownedScope
	}
	return nil
}

// Freeze resolves defaults without constructing a hidden fallback.
func (m *Manager) Freeze() error {
	m.access.Lock()
	defer m.access.Unlock()
	if !m.runtime {
		return errors.New("not a runtime outbound manager")
	}
	if m.frozen {
		return nil
	}
	endpointInventory, ok := m.endpoint.(interface {
		RuntimeFrozen() bool
		OwnsEndpoint(string) bool
	})
	if !ok || !endpointInventory.RuntimeFrozen() {
		return errors.New("runtime endpoint inventory must be frozen first")
	}
	if m.defaultTag != "" {
		m.defaultOutbound = m.outboundByTag[m.defaultTag]
		if m.defaultOutbound == nil {
			m.defaultOutbound, _ = m.endpoint.Get(m.defaultTag)
		}
	} else if len(m.outbounds) != 0 {
		m.defaultOutbound = m.outbounds[0]
	}
	if m.defaultOutbound == nil {
		return E.New("explicit default outbound required: ", m.defaultTag)
	}
	for _, endpoint := range m.endpoint.Endpoints() {
		if _, exists := m.outboundByTag[endpoint.Tag()]; exists {
			return E.New("duplicate outbound/endpoint tag: ", endpoint.Tag())
		}
	}
	m.frozen = true
	return nil
}

func (m *Manager) Initialize(defaultOutboundFallback func() (adapter.Outbound, error)) {
	m.access.Lock()
	defer m.access.Unlock()
	if !m.frozen {
		m.defaultOutboundFallback = defaultOutboundFallback
	}
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.access.Lock()
	if m.runtime {
		if !m.frozen {
			m.access.Unlock()
			return errors.New("outbound inventory not frozen")
		}
		if result, exists := m.stages[stage]; exists {
			m.access.Unlock()
			return result
		}
		m.stages[stage] = errors.New("outbound stage in progress")
		outbounds := slices.Clone(m.outbounds)
		m.access.Unlock()
		err := m.startRuntime(stage, outbounds)
		m.access.Lock()
		m.stages[stage] = err
		m.access.Unlock()
		return err
	}
	if stage == adapter.StartStateInitialize {
		if m.defaultTag != "" && m.defaultOutbound == nil {
			defaultEndpoint, loaded := m.endpoint.Get(m.defaultTag)
			if !loaded {
				m.access.Unlock()
				return E.New("default outbound not found: ", m.defaultTag)
			}
			m.defaultOutbound = defaultEndpoint
		}
		if m.defaultOutbound == nil {
			directOutbound, err := m.defaultOutboundFallback()
			if err != nil {
				m.access.Unlock()
				return E.Cause(err, "create direct outbound for fallback")
			}
			m.outbounds = append(m.outbounds, directOutbound)
			m.outboundByTag[directOutbound.Tag()] = directOutbound
			m.defaultOutbound = directOutbound
		}
	}
	outbounds := slices.Clone(m.outbounds)
	m.access.Unlock()
	if stage == adapter.StartStateStart {
		if err := m.startOutbounds(scope, append(outbounds, common.Map(m.endpoint.Endpoints(), func(it adapter.Endpoint) adapter.Outbound { return it })...)); err != nil {
			return err
		}
		return m.SelectedFailure(nil, "")
	}
	for _, outbound := range outbounds {
		lifecycle, isLifecycle := outbound.(adapter.Lifecycle)
		if !isLifecycle {
			continue
		}
		name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
		err := scope.Start(name, lifecycle, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) startRuntime(stage adapter.StartStage, outbounds []adapter.Outbound) error {
	if stage == adapter.StartStateStart {
		return m.startOutbounds(nil, append(outbounds, common.Map(m.endpoint.Endpoints(), func(it adapter.Endpoint) adapter.Outbound { return it })...))
	}
	for _, outbound := range outbounds {
		scope := m.owned[outbound.Tag()]
		if scope == nil {
			continue
		}
		if lifecycle, ok := outbound.(adapter.Lifecycle); ok {
			if err := scope.Start("outbound/"+outbound.Type()+"["+outbound.Tag()+"]", lifecycle, stage); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *Manager) startOutbounds(scope *adapter.Scope, outbounds []adapter.Outbound) error {
	started := make(map[string]bool)
	if m.runtime {
		for _, member := range outbounds {
			if _, endpoint := m.endpoint.Get(member.Tag()); endpoint {
				if ownership, ok := m.endpoint.(interface{ OwnsEndpoint(string) bool }); ok && !ownership.OwnsEndpoint(member.Tag()) {
					started[member.Tag()] = true
				}
			} else if m.owned[member.Tag()] == nil {
				started[member.Tag()] = true
			}
		}
	}
	for {
		canContinue := false
	startOne:
		for i, outboundToStart := range outbounds {
			outboundTag := outboundToStart.Tag()
			if started[outboundTag] {
				continue
			}
			dependencies := outboundToStart.Dependencies()
			for _, dependency := range dependencies {
				if !started[dependency] {
					continue startOne
				}
			}
			started[outboundTag] = true
			canContinue = true
			if endpoint, isEndpoint := m.endpoint.Get(outboundTag); isEndpoint {
				err := m.endpoint.StartEndpoint(endpoint)
				if err != nil {
					return err
				}
				continue
			}
			lifecycle, isLifecycle := outboundToStart.(adapter.Lifecycle)
			if !isLifecycle {
				continue
			}
			name := "outbound/" + outboundToStart.Type() + "[" + outboundTag + "]"
			memberScope := scope
			if m.runtime {
				memberScope = m.owned[outboundTag]
			}
			err := memberScope.Start(name, lifecycle, adapter.StartStateStart)
			if err != nil {
				if _, isGroup := outboundToStart.(adapter.OutboundGroup); isGroup {
					return err
				}
				// A failed leaf stays resolvable for groups and detours; only the
				// default outbound chain fails the start (SelectedFailure).
				memberScope.Logger().Error(err)
				failed := &failedOutbound{outboundToStart, err}
				m.access.Lock()
				// outbounds begins with the clone of m.outbounds.
				m.outbounds[i] = failed
				m.outboundByTag[outboundTag] = failed
				m.access.Unlock()
			}
		}
		if len(started) == len(outbounds) {
			break
		}
		if canContinue {
			continue
		}
		currentOutbound := common.Find(outbounds, func(it adapter.Outbound) bool {
			return !started[it.Tag()]
		})
		var lintOutbound func(oTree []string, oCurrent adapter.Outbound) error
		lintOutbound = func(oTree []string, oCurrent adapter.Outbound) error {
			problemOutboundTag := common.Find(oCurrent.Dependencies(), func(it string) bool {
				return !started[it]
			})
			if common.Contains(oTree, problemOutboundTag) {
				return E.New("circular outbound dependency: ", strings.Join(oTree, " -> "), " -> ", problemOutboundTag)
			}
			problemOutbound := common.Find(outbounds, func(it adapter.Outbound) bool {
				return it.Tag() == problemOutboundTag
			})
			if problemOutbound == nil {
				return E.New("dependency[", problemOutboundTag, "] not found for outbound[", oCurrent.Tag(), "]")
			}
			return lintOutbound(append(oTree, problemOutboundTag), problemOutbound)
		}
		return lintOutbound([]string{currentOutbound.Tag()}, currentOutbound)
	}
	return nil
}

// SelectedFailure returns the start error of a failed outbound on the default
// outbound chain: selected selector members, urltest groups whose members all
// failed, and detours. The chain starts at the default outbound and at routes
// whose only condition is the current clash mode, which stand in for
// route.final in mode-compiled configurations.
func (m *Manager) SelectedFailure(rules []option.Rule, mode string) error {
	var failure func(tag string) error
	failure = func(tag string) error {
		outbound, _ := m.Outbound(tag)
		switch it := outbound.(type) {
		case *failedOutbound:
			return it.err
		case adapter.URLTestGroup:
			var err error
			for _, member := range it.All() {
				if err = failure(member); err == nil {
					break
				}
			}
			return err
		case adapter.OutboundGroup:
			if selected := it.Selected(N.NetworkTCP); selected != nil {
				return failure(selected.Tag())
			}
		case adapter.Outbound:
			for _, dependency := range it.Dependencies() {
				if err := failure(dependency); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if defaultOutbound := m.Default(); defaultOutbound != nil {
		if err := failure(defaultOutbound.Tag()); err != nil {
			return err
		}
	}
	for _, rule := range rules {
		raw := rule.DefaultOptions.RawDefaultRule
		if rule.Type == C.RuleTypeDefault && rule.DefaultOptions.Action == C.RuleActionTypeRoute &&
			strings.EqualFold(raw.ClashMode, mode) && reflect.DeepEqual(raw, option.RawDefaultRule{ClashMode: raw.ClashMode}) {
			if err := failure(rule.DefaultOptions.RouteOptions.Outbound); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *Manager) Outbounds() []adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return slices.Clone(m.outbounds)
}

func (m *Manager) Outbound(tag string) (adapter.Outbound, bool) {
	m.access.RLock()
	outbound, found := m.outboundByTag[tag]
	m.access.RUnlock()
	if found {
		return outbound, true
	}
	return m.endpoint.Get(tag)
}

func (m *Manager) Default() adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.defaultOutbound
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, inboundType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}
	m.access.Lock()
	if m.runtime || m.frozen {
		m.access.Unlock()
		return errors.New("runtime outbounds require explicit insertion")
	}
	if _, exists := m.outboundByTag[tag]; exists || m.pending[tag] {
		m.access.Unlock()
		return E.New("duplicate outbound tag: ", tag)
	}
	m.pending[tag] = true
	m.access.Unlock()
	defer func() { m.access.Lock(); delete(m.pending, tag); m.access.Unlock() }()
	outbound, err := m.registry.CreateOutbound(ctx, router, logger, tag, inboundType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	_, loaded := m.outboundByTag[tag]
	if loaded {
		return E.New("duplicate outbound tag: ", tag)
	}
	m.outbounds = append(m.outbounds, outbound)
	m.outboundByTag[tag] = outbound
	if tag == m.defaultTag || (m.defaultTag == "" && m.defaultOutbound == nil) {
		m.defaultOutbound = outbound
	}
	return nil
}

type failedOutbound struct {
	adapter.Outbound
	err error
}

func (o *failedOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, o.err
}

func (o *failedOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, o.err
}
