package clashmode

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/service"
)

type Manager struct {
	ctx          context.Context
	logger       log.Logger
	dnsRouter    adapter.DNSRouter
	mode         atomic.Value
	modeList     []string
	useCacheMode bool
	updateAccess sync.Mutex
	updateHooks  []*observable.Subscriber[struct{}]
}

func NewManager(ctx context.Context, logger log.Logger, defaultMode string, modeList []string) *Manager {
	useCacheMode := defaultMode == ""
	if defaultMode == "" {
		defaultMode = "Rule"
	}
	if !common.Contains(modeList, defaultMode) {
		modeList = append([]string{defaultMode}, modeList...)
	}
	m := &Manager{
		ctx:          ctx,
		logger:       logger,
		dnsRouter:    service.FromContext[adapter.DNSRouter](ctx),
		modeList:     modeList,
		useCacheMode: useCacheMode,
	}
	m.mode.Store(defaultMode)
	return m
}

func (m *Manager) Name() string {
	return "clash mode manager"
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart || !m.useCacheMode {
		return nil
	}
	cacheFile := service.FromContext[adapter.CacheFile](m.ctx)
	if cacheFile != nil {
		mode := cacheFile.LoadMode()
		if common.Any(m.modeList, func(it string) bool {
			return strings.EqualFold(it, mode)
		}) {
			m.mode.Store(mode)
		}
	}
	return nil
}

func (m *Manager) Mode() string {
	return m.mode.Load().(string)
}

func (m *Manager) ModeList() []string {
	m.updateAccess.Lock(); defer m.updateAccess.Unlock()
	return append([]string(nil), m.modeList...)
}

func (m *Manager) AddUpdateHook(hook *observable.Subscriber[struct{}]) {
	m.updateAccess.Lock()
	defer m.updateAccess.Unlock()
	m.updateHooks = append(m.updateHooks, hook)
}

func (m *Manager) SetMode(newMode string) {
	if controller, ok := adapter.RuntimeControlFromContext(m.ctx); ok {
		if modes, ok := controller.(adapter.RuntimeModeControl); ok { modes.SetRuntimeClashMode(newMode); return }
	}
	_, _, effect := m.RuntimeSetMode(newMode)
	if effect != nil { effect() }
}

// RuntimeSetMode performs only the in-memory transition. Its detached effects
// are ordered by the runtime coordinator outside the publication guard.
func (m *Manager) RuntimeSetMode(newMode string) (bool, bool, func()) {
	m.updateAccess.Lock()
	defer m.updateAccess.Unlock()
	if !common.Contains(m.modeList, newMode) { newMode = common.Find(m.modeList, func(it string) bool { return strings.EqualFold(it, newMode) }) }
	if !common.Contains(m.modeList, newMode) { return false, false, nil }
	if newMode == m.Mode() { return false, true, nil }
	m.mode.Store(newMode)
	hooks := append([]*observable.Subscriber[struct{}](nil), m.updateHooks...)
	return true, true, func() {
		for _, hook := range hooks { hook.Emit(struct{}{}) }
		m.dnsRouter.ClearCache()
		if cacheFile := service.FromContext[adapter.CacheFile](m.ctx); cacheFile != nil {
			if err := cacheFile.StoreMode(newMode); err != nil { m.logger.Error(E.Cause(err, "save mode")) }
		}
		m.logger.Info("updated mode: ", newMode)
	}
}

// RuntimeReplaceModes publishes a detached list while preserving the currently
// selected manual mode even when no new rule mentions it. It performs no IO.
func (m *Manager) RuntimeReplaceModes(modes []string) {
	m.updateAccess.Lock(); defer m.updateAccess.Unlock()
	m.modeList = append([]string(nil), modes...)
	if !common.Contains(m.modeList, m.Mode()) { m.modeList = append([]string{m.Mode()}, m.modeList...) }
}

var _ adapter.LifecycleService = (*Manager)(nil)
