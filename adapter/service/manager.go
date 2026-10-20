package service

import (
	"context"
	"sync"
 "slices"
 "errors"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.ServiceManager = (*Manager)(nil)

type Manager struct {
	runtime bool
 frozen bool
 owned map[string]*adapter.Scope
 stages map[adapter.StartStage]*runtimeStage
 registry     adapter.ServiceRegistry
	access       sync.Mutex
	services     []adapter.Service
	serviceByTag map[string]adapter.Service
}

func NewManager(registry adapter.ServiceRegistry) *Manager {
	return &Manager{
		registry:     registry,
		serviceByTag: make(map[string]adapter.Service),
	}
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.access.Lock()
 if m.runtime{m.access.Unlock();return m.startRuntime(stage)}
	services := slices.Clone(m.services)
	m.access.Unlock()
	for _, service := range services {
		name := "service/" + service.Type() + "[" + service.Tag() + "]"
		err := scope.Start(name, service, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) Services() []adapter.Service {
	m.access.Lock()
	defer m.access.Unlock()
	return slices.Clone(m.services)
}

func (m *Manager) Get(tag string) (adapter.Service, bool) {
	m.access.Lock()
	service, found := m.serviceByTag[tag]
	m.access.Unlock()
	return service, found
}

func (m *Manager) Create(ctx context.Context, logger log.ContextLogger, tag string, serviceType string, options any) error {
	m.access.Lock();runtime:=m.runtime;m.access.Unlock();if runtime{return errors.New("runtime services require prepared insertion")}
 service, err := m.registry.Create(ctx, logger, tag, serviceType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	_, loaded := m.serviceByTag[tag]
	if loaded {
		return E.New("duplicate service tag: ", tag)
	}
	m.services = append(m.services, service)
	m.serviceByTag[tag] = service
	return nil
}
