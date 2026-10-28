package certificate

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/sagernet/sing-box/adapter"
)

// RuntimePreparedProvider has a private, side-effect-free preparation phase.
// StageRuntime explicitly performs synchronous first-certificate effects.
// RuntimeActivate runs outside the publication guard and starts the owned
// refresh worker. Retirement joins it before captured dependency edges leave.
type RuntimePreparedProvider interface {
	adapter.CertificateProviderService
	RuntimeValidate() error
	PrepareRuntime(adapter.StartStage, *adapter.Scope) error
	StageRuntime(context.Context) error
	RuntimeExternalEffects() bool
	CompensateRuntime() error
	RuntimeActivate()
	RuntimeStop()
	RuntimeCloseAndWait() error
	RuntimeResourceID() adapter.RuntimeResourceID
}

type runtimeStage struct {
	done chan struct{}
	err  error
}

func NewRuntimeManager(registry adapter.CertificateProviderRegistry) *Manager {
	m := NewManager(registry)
	m.runtime = true
	m.owned = make(map[string]*adapter.Scope)
	m.stages = make(map[adapter.StartStage]*runtimeStage)
	return m
}

// A nil owner borrows an unchanged provider. It neither prepares, activates,
// stops nor registers cleanup for that provider a second time.
func (m *Manager) Insert(provider adapter.CertificateProviderService, owner *adapter.Scope) error {
	if provider == nil || provider.Tag() == "" {
		return errors.New("runtime certificate provider requires a tagged member")
	}
	prepared, ok := provider.(RuntimePreparedProvider)
	if !ok {
		return fmt.Errorf("certificate provider %s/%s has no staged lifecycle", provider.Type(), provider.Tag())
	}
	if err := prepared.RuntimeValidate(); err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	if !m.runtime || m.frozen {
		return errors.New("certificate provider inventory is not mutable")
	}
	if _, found := m.providerByTag[provider.Tag()]; found {
		return fmt.Errorf("duplicate certificate provider tag: %s", provider.Tag())
	}
	m.providerByTag[provider.Tag()] = provider
	m.providers = append(m.providers, provider)
	if owner != nil {
		m.owned[provider.Tag()] = owner
	}
	return nil
}

func (m *Manager) Freeze() error {
	m.access.Lock()
	defer m.access.Unlock()
	if !m.runtime {
		return errors.New("not a runtime certificate provider inventory")
	}
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
		return errors.New("certificate provider inventory not frozen")
	}
	if previous := m.stages[stage]; previous != nil {
		done := previous.done
		m.access.Unlock()
		<-done
		return previous.err
	}
	current := &runtimeStage{done: make(chan struct{}), err: errors.New("certificate provider preparation did not complete")}
	m.stages[stage] = current
	providers := slices.Clone(m.providers)
	owned := make(map[string]*adapter.Scope, len(m.owned))
	maps.Copy(owned, m.owned)
	m.access.Unlock()
	defer close(current.done)
	for _, provider := range providers {
		if scope := owned[provider.Tag()]; scope != nil {
			if err := provider.(RuntimePreparedProvider).PrepareRuntime(stage, scope); err != nil {
				current.err = err
				return err
			}
		}
	}
	current.err = nil
	return nil
}

// PreparedProviders is for the transaction's post-publication activation and
// producer-stop registration. It deliberately omits borrowed members.
func (m *Manager) PreparedProviders() ([]RuntimePreparedProvider, error) {
	m.access.Lock()
	defer m.access.Unlock()
	if !m.runtime || !m.frozen {
		return nil, errors.New("certificate provider inventory not frozen")
	}
	var result []RuntimePreparedProvider
	for _, provider := range m.providers {
		if m.owned[provider.Tag()] != nil {
			result = append(result, provider.(RuntimePreparedProvider))
		}
	}
	return result, nil
}
