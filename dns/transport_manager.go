package dns

import (
	"context"
	"os"
	"errors"
	"slices"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.DNSTransportManager = (*TransportManager)(nil)

type TransportManager struct {
	registry                 adapter.DNSTransportRegistry
	outbound                 adapter.OutboundManager
	defaultTag               string
	access                   sync.RWMutex
	transports               []adapter.DNSTransport
	transportByTag           map[string]adapter.DNSTransport
	defaultTransport         adapter.DNSTransport
	defaultTransportFallback func() (adapter.DNSTransport, error)
	fakeIPTransport          adapter.FakeIPTransport
	runtime bool
	frozen bool
	owned map[string]*adapter.Scope
	pending map[string]bool
	stages map[adapter.StartStage]error
}

func NewTransportManager(registry adapter.DNSTransportRegistry, outbound adapter.OutboundManager, defaultTag string) *TransportManager {
	return &TransportManager{
		registry:       registry,
		outbound:       outbound,
		defaultTag:     defaultTag,
		transportByTag: make(map[string]adapter.DNSTransport),
		pending: make(map[string]bool),
	}
}

func NewRuntimeTransportManager(registry adapter.DNSTransportRegistry, outbound adapter.OutboundManager, defaultTag string) *TransportManager {
	m := NewTransportManager(registry, outbound, defaultTag)
	m.runtime = true
	m.owned = make(map[string]*adapter.Scope)
	m.stages = make(map[adapter.StartStage]error)
	return m
}

// Insert does not adopt cleanup. Rejection leaves the caller's owner in charge.
func (m *TransportManager) Insert(member adapter.DNSTransport, ownedScope *adapter.Scope) error {
	if member == nil || member.Tag() == "" { return os.ErrInvalid }
	m.access.Lock()
	defer m.access.Unlock()
	if !m.runtime || m.frozen { return errors.New("DNS inventory is not mutable") }
	if _, exists := m.transportByTag[member.Tag()]; exists { return E.New("duplicate DNS server tag: ", member.Tag()) }
	var fakeIP adapter.FakeIPTransport
	if member.Type() == C.DNSTypeFakeIP {
		if m.fakeIPTransport != nil { return E.New("multiple fakeip server are not supported") }
		var ok bool
		fakeIP, ok = member.(adapter.FakeIPTransport)
		if !ok { return errors.New("fakeip transport lacks allocator interface") }
	}
	m.transports = append(m.transports, member)
	m.transportByTag[member.Tag()] = member
	if fakeIP != nil { m.fakeIPTransport = fakeIP }
	if ownedScope != nil { m.owned[member.Tag()] = ownedScope }
	return nil
}

func (m *TransportManager) Freeze() error {
	m.access.Lock()
	defer m.access.Unlock()
	if !m.runtime { return errors.New("not a runtime DNS manager") }
	if m.frozen { return nil }
	if m.defaultTag != "" { m.defaultTransport = m.transportByTag[m.defaultTag] } else if len(m.transports) != 0 { m.defaultTransport = m.transports[0] }
	if m.defaultTransport == nil { return E.New("explicit default DNS server required: ", m.defaultTag) }
	if m.defaultTransport.Type() == C.DNSTypeFakeIP { return E.New("default server cannot be fakeip") }
	m.frozen = true
	return nil
}

func (m *TransportManager) Initialize(defaultTransportFallback func() (adapter.DNSTransport, error)) {
	m.access.Lock()
	defer m.access.Unlock()
	if !m.frozen { m.defaultTransportFallback = defaultTransportFallback }
}

func (m *TransportManager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.access.Lock()
	if m.runtime {
		if !m.frozen { m.access.Unlock(); return errors.New("DNS inventory not frozen") }
		if result, exists := m.stages[stage]; exists { m.access.Unlock(); return result }
		m.stages[stage] = errors.New("DNS stage in progress")
		transports := slices.Clone(m.transports)
		m.access.Unlock()
		err := m.startRuntime(stage, transports)
		m.access.Lock(); m.stages[stage] = err; m.access.Unlock()
		return err
	}
	if stage == adapter.StartStateInitialize {
		if m.defaultTag != "" && m.defaultTransport == nil {
			m.access.Unlock()
			return E.New("default DNS server not found: ", m.defaultTag)
		}
		if m.defaultTransport == nil {
			defaultTransport, err := m.defaultTransportFallback()
			if err != nil {
				m.access.Unlock()
				return E.Cause(err, "default DNS server fallback")
			}
			m.transports = append(m.transports, defaultTransport)
			m.transportByTag[defaultTransport.Tag()] = defaultTransport
			m.defaultTransport = defaultTransport
		}
	}
	transports := slices.Clone(m.transports)
	m.access.Unlock()
	if stage == adapter.StartStateStart {
		return m.startTransports(scope, transports)
	}
	for _, transport := range transports {
		name := "dns/" + transport.Type() + "[" + transport.Tag() + "]"
		err := scope.Start(name, transport, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *TransportManager) startRuntime(stage adapter.StartStage, transports []adapter.DNSTransport) error {
	if stage == adapter.StartStateStart { return m.startTransports(nil, transports) }
	for _, transport := range transports {
		scope := m.owned[transport.Tag()]
		if scope == nil { continue }
		if err := scope.Start("dns/"+transport.Type()+"["+transport.Tag()+"]", transport, stage); err != nil { return err }
	}
	return nil
}

func (m *TransportManager) startTransports(scope *adapter.Scope, transports []adapter.DNSTransport) error {
	started := make(map[string]bool)
	if m.runtime {
		for _, member := range transports { if m.owned[member.Tag()] == nil { started[member.Tag()] = true } }
	}
	for {
		canContinue := false
	startOne:
		for _, transportToStart := range transports {
			transportTag := transportToStart.Tag()
			if started[transportTag] {
				continue
			}
			dependencies := transportToStart.Dependencies()
			for _, dependency := range dependencies {
				if !started[dependency] {
					continue startOne
				}
			}
			started[transportTag] = true
			canContinue = true
			name := "dns/" + transportToStart.Type() + "[" + transportTag + "]"
			memberScope := scope
			if m.runtime { memberScope = m.owned[transportTag] }
			err := memberScope.Start(name, transportToStart, adapter.StartStateStart)
			if err != nil {
				return err
			}
		}
		if len(started) == len(transports) {
			break
		}
		if canContinue {
			continue
		}
		currentTransport := common.Find(transports, func(it adapter.DNSTransport) bool {
			return !started[it.Tag()]
		})
		var lintTransport func(oTree []string, oCurrent adapter.DNSTransport) error
		lintTransport = func(oTree []string, oCurrent adapter.DNSTransport) error {
			problemTransportTag := common.Find(oCurrent.Dependencies(), func(it string) bool {
				return !started[it]
			})
			if common.Contains(oTree, problemTransportTag) {
				return E.New("circular server dependency: ", strings.Join(oTree, " -> "), " -> ", problemTransportTag)
			}
			m.access.Lock()
			problemTransport := m.transportByTag[problemTransportTag]
			m.access.Unlock()
			if problemTransport == nil {
				return E.New("dependency[", problemTransportTag, "] not found for server[", oCurrent.Tag(), "]")
			}
			return lintTransport(append(oTree, problemTransportTag), problemTransport)
		}
		return lintTransport([]string{currentTransport.Tag()}, currentTransport)
	}
	return nil
}

func (m *TransportManager) Transports() []adapter.DNSTransport {
	m.access.RLock()
	defer m.access.RUnlock()
	return slices.Clone(m.transports)
}

func (m *TransportManager) Transport(tag string) (adapter.DNSTransport, bool) {
	m.access.RLock()
	outbound, found := m.transportByTag[tag]
	m.access.RUnlock()
	return outbound, found
}

func (m *TransportManager) Default() adapter.DNSTransport {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.defaultTransport
}

func (m *TransportManager) FakeIP() adapter.FakeIPTransport {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.fakeIPTransport
}

func (m *TransportManager) Create(ctx context.Context, logger log.ContextLogger, tag string, transportType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}
	m.access.Lock()
	if m.runtime || m.frozen { m.access.Unlock(); return errors.New("runtime DNS transports require explicit insertion") }
	if _, exists := m.transportByTag[tag]; exists || m.pending[tag] { m.access.Unlock(); return E.New("duplicate DNS server tag: ", tag) }
	m.pending[tag] = true
	m.access.Unlock()
	defer func() { m.access.Lock(); delete(m.pending, tag); m.access.Unlock() }()
	transport, err := m.registry.CreateDNSTransport(ctx, logger, tag, transportType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	_, loaded := m.transportByTag[tag]
	if loaded {
		return E.New("duplicate DNS server tag: ", tag)
	}
	m.transports = append(m.transports, transport)
	m.transportByTag[tag] = transport
	if tag == m.defaultTag || (m.defaultTag == "" && m.defaultTransport == nil) {
		if transport.Type() == C.DNSTypeFakeIP {
			return E.New("default server cannot be fakeip")
		}
		m.defaultTransport = transport
	}
	if transport.Type() == C.DNSTypeFakeIP {
		if m.fakeIPTransport != nil {
			return E.New("multiple fakeip server are not supported")
		}
		m.fakeIPTransport = transport.(adapter.FakeIPTransport)
	}
	return nil
}
