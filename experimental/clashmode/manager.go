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
	return m.modeList
}

func (m *Manager) AddUpdateHook(hook *observable.Subscriber[struct{}]) {
	m.updateAccess.Lock()
	defer m.updateAccess.Unlock()
	m.updateHooks = append(m.updateHooks, hook)
}

func (m *Manager) SetMode(newMode string) {
	if !common.Contains(m.modeList, newMode) {
		newMode = common.Find(m.modeList, func(it string) bool {
			return strings.EqualFold(it, newMode)
		})
	}
	if !common.Contains(m.modeList, newMode) {
		return
	}
	m.updateAccess.Lock()
	defer m.updateAccess.Unlock()
	if newMode == m.Mode() {
		return
	}
	m.mode.Store(newMode)
	for _, hook := range m.updateHooks {
		hook.Emit(struct{}{})
	}
	m.dnsRouter.ClearCache()
	cacheFile := service.FromContext[adapter.CacheFile](m.ctx)
	if cacheFile != nil {
		err := cacheFile.StoreMode(newMode)
		if err != nil {
			m.logger.Error(E.Cause(err, "save mode"))
		}
	}
	m.logger.Info("updated mode: ", newMode)
}

var _ adapter.LifecycleService = (*Manager)(nil)
