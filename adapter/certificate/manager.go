package certificate

import (
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.CertificateProviderManager = (*Manager)(nil)

type Manager struct {
	registry      adapter.CertificateProviderRegistry
	access        sync.Mutex
	providers     []adapter.CertificateProviderService
	providerByTag map[string]adapter.CertificateProviderService
	pending       map[string]bool
	runtime       bool
	frozen        bool
	owned         map[string]*adapter.Scope
	stages        map[adapter.StartStage]*runtimeStage
}

func NewManager(registry adapter.CertificateProviderRegistry) *Manager {
	return &Manager{
		registry:      registry,
		pending:       make(map[string]bool),
		providerByTag: make(map[string]adapter.CertificateProviderService),
	}
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if m.runtime {
		return m.startRuntime(stage)
	}
	m.access.Lock()
	providers := slices.Clone(m.providers)
	m.access.Unlock()
	for _, provider := range providers {
		name := "certificate-provider/" + provider.Type() + "[" + provider.Tag() + "]"
		err := scope.Start(name, provider, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) CertificateProviders() []adapter.CertificateProviderService {
	m.access.Lock()
	defer m.access.Unlock()
	return slices.Clone(m.providers)
}

func (m *Manager) Get(tag string) (adapter.CertificateProviderService, bool) {
	m.access.Lock()
	provider, found := m.providerByTag[tag]
	m.access.Unlock()
	return provider, found
}

func (m *Manager) Create(ctx context.Context, logger log.ContextLogger, tag string, providerType string, options any) error {
	m.access.Lock()
	if m.runtime || m.frozen {
		m.access.Unlock()
		return errors.New("runtime certificate construction requires an owned prepared member")
	}
	if _, found := m.providerByTag[tag]; found || m.pending[tag] {
		m.access.Unlock()
		return E.New("duplicate certificate provider tag: ", tag)
	}
	m.pending[tag] = true
	m.access.Unlock()
	defer func() { m.access.Lock(); delete(m.pending, tag); m.access.Unlock() }()
	provider, err := m.registry.Create(ctx, logger, tag, providerType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	m.providers = append(m.providers, provider)
	m.providerByTag[tag] = provider
	return nil
}
