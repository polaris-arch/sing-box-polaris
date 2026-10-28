package daemon

import (
	"bytes"
	"context"
	"sync/atomic"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/clashmode"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/experimental/locale"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/service/powerreport"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

type Instance struct {
	ctx                   context.Context
	cancel                context.CancelFunc
	instance              *box.Box
	connectionManager     adapter.ConnectionManager
	clashMode             *clashmode.Manager
	trafficManager        *trafficcontrol.Manager
	cacheFile             adapter.CacheFile
	pauseManager          pause.Manager
	pauseCallback         *list.Element[pause.Callback]
	urlTestHistoryStorage *urltest.HistoryStorage
	outboundManager       adapter.OutboundManager
	endpointManager       adapter.EndpointManager
	logFactory            log.Factory
	tailscaleRetirement   *tailscaleRetirementRun
	closeStarted          atomic.Bool
	closeFinished         chan struct{}
	closeResult           error
}

func (s *StartedService) CheckConfig(ctx context.Context, configContent string) error {
	// Construction checks have no retirement run/lease custody. Managed hosts
	// must not construct an independent writer, including during preparation.
	if adapter.TailscaleDirectoryDomainFromContext(s.ctx) != nil {
		return E.New("independent construction check is unavailable in managed directory domain")
	}
	selectedLocale := locale.FromContext(ctx)
	ctx, _ = locale.ContextWithLocale(s.ctx, selectedLocale.Locale)
	ctx = service.ExtendContext(ctx)
	options, err := parseConfig(ctx, configContent)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	if err == nil {
		instance.Close()
	}
	return err
}

func (s *StartedService) FormatConfig(ctx context.Context, configContent string) (string, error) {
	selectedLocale := locale.FromContext(ctx)
	ctx, _ = locale.ContextWithLocale(s.ctx, selectedLocale.Locale)
	options, err := parseConfig(ctx, configContent)
	if err != nil {
		return "", err
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(options)
	if err != nil {
		return "", err
	}
	return buffer.String(), nil
}

type OverrideOptions struct {
	AutoRedirect   bool
	IncludePackage []string
	ExcludePackage []string
}

func (s *StartedService) newInstance(ctx context.Context, profileContent string, overrideOptions *OverrideOptions, reloading bool) (*Instance, error) {
	if domain := adapter.TailscaleDirectoryDomainFromContext(s.ctx); domain != nil {
		if !domain.Activated() {
			return nil, E.New("managed directory domain is not activated")
		}
		if err := domain.FailurePersistenceError(); err != nil {
			return nil, err
		}
	}
	if err := guardRawDirectoryNamespace(s.ctx, profileContent); err != nil {
		return nil, err
	}
	selectedLocale := locale.FromContext(ctx)
	ctx, _ = locale.ContextWithLocale(s.ctx, selectedLocale.Locale)
	ctx = service.ExtendContext(ctx)
	service.MustRegister[deprecated.Manager](ctx, new(deprecatedManager))
	ctx, cancel := context.WithCancel(ctx)
	options, err := parseConfig(ctx, profileContent)
	if err != nil {
		cancel()
		return nil, err
	}
	if overrideOptions != nil {
		for _, inbound := range options.Inbounds {
			if tunInboundOptions, isTUN := inbound.Options.(*option.TunInboundOptions); isTUN {
				tunInboundOptions.AutoRedirect = overrideOptions.AutoRedirect && tunInboundOptions.AutoRoute
				tunInboundOptions.IncludePackage = append(tunInboundOptions.IncludePackage, overrideOptions.IncludePackage...)
				tunInboundOptions.ExcludePackage = append(tunInboundOptions.ExcludePackage, overrideOptions.ExcludePackage...)
				break
			}
		}
	}
	if s.oomKillerEnabled {
		if !common.Any(options.Services, func(it option.Service) bool {
			return it.Type == C.TypeOOMKiller
		}) {
			oomOptions := &option.OOMKillerServiceOptions{
				KillerDisabled:      s.oomKillerDisabled,
				MemoryLimitOverride: s.oomMemoryLimit,
			}
			options.Services = append(options.Services, option.Service{
				Type:    C.TypeOOMKiller,
				Options: oomOptions,
			})
		}
	}
	if len(s.tailscaleRetirementRuns) >= maxTailscaleRetirementRuns {
		cancel()
		return nil, E.New("Tailscale retirement census capacity reached")
	}
	retirement, err := newTailscaleRetirementRun(profileContent, options)
	if err != nil {
		cancel()
		return nil, err
	}
	s.tailscaleRetirementRuns = append(s.tailscaleRetirementRuns, retirement)
	ctx = service.ContextWithPtr(ctx, &retirement.binding)
	ctx, err = prepareTailscaleDirectoryMapping(ctx, options)
	if err != nil {
		cancel()
		return nil, err
	}
	urlTestHistoryStorage := urltest.NewHistoryStorage()
	ctx = service.ContextWithPtr(ctx, urlTestHistoryStorage)
	i := &Instance{
		ctx:                   ctx,
		cancel:                cancel,
		urlTestHistoryStorage: urlTestHistoryStorage,
		closeFinished:         make(chan struct{}),
		tailscaleRetirement:   retirement,
	}
	constructed := false
	defer func() {
		if !constructed {
			retirement.freeze(nil, false)
			retirement.freezeDirectories(nil, false)
		}
	}()
	boxInstance, err := box.New(box.Options{
		Context:           ctx,
		Options:           options,
		PlatformLogWriter: s,
	})
	if err != nil {
		cancel()
		return nil, err
	}
	constructed = true
	boxInstance.CaptureTailscaleStateStores()
	retirement.capture(boxInstance.TailscaleStateStoreScopes())
	retirement.captureDirectories(boxInstance.TailscaleDirectoryScopes)
	i.instance = boxInstance
	i.connectionManager = service.FromContext[adapter.ConnectionManager](ctx)
	i.clashMode = service.PtrFromContext[clashmode.Manager](ctx)
	i.trafficManager = service.PtrFromContext[trafficcontrol.Manager](ctx)
	i.pauseManager = service.FromContext[pause.Manager](ctx)
	i.registerPowerReport(ctx, reloading)
	i.cacheFile = service.FromContext[adapter.CacheFile](ctx)
	i.outboundManager = service.FromContext[adapter.OutboundManager](ctx)
	i.endpointManager = service.FromContext[adapter.EndpointManager](ctx)
	i.logFactory = boxInstance.LogFactory()
	if !s.keepDefaultLogger {
		log.SetStdLogger(boxInstance.LogFactory().Logger())
	}
	return i, nil
}

func attachInstance(ctx context.Context) *Instance {
	return &Instance{
		ctx:                   ctx,
		closeFinished:         make(chan struct{}),
		connectionManager:     service.FromContext[adapter.ConnectionManager](ctx),
		clashMode:             service.PtrFromContext[clashmode.Manager](ctx),
		trafficManager:        service.PtrFromContext[trafficcontrol.Manager](ctx),
		pauseManager:          service.FromContext[pause.Manager](ctx),
		cacheFile:             service.FromContext[adapter.CacheFile](ctx),
		urlTestHistoryStorage: service.PtrFromContext[urltest.HistoryStorage](ctx),
		outboundManager:       service.FromContext[adapter.OutboundManager](ctx),
		endpointManager:       service.FromContext[adapter.EndpointManager](ctx),
		logFactory:            service.FromContext[log.Factory](ctx),
	}
}

func (i *Instance) Start() error {
	return i.instance.Start()
}

func (i *Instance) Close() error {
	if !i.closeStarted.CompareAndSwap(false, true) {
		// Like Box.Close, a repeated close returns nil without waiting.
		return nil
	}
	i.finishClose()
	return i.closeResult
}

// CloseWithResult lets strict transient cleanup read the original result even
// if Box.Start already triggered automatic close before the daemon catches up.
func (i *Instance) CloseWithResult() error {
	if i.closeStarted.CompareAndSwap(false, true) {
		i.finishClose()
	}
	<-i.closeFinished
	return i.closeResult
}

func (i *Instance) finishClose() {
	i.closeResult = E.New("instance close did not complete")
	defer close(i.closeFinished)
	if i.cancel != nil {
		i.cancel()
	}
	if i.pauseCallback != nil {
		i.pauseManager.UnregisterCallback(i.pauseCallback)
		i.pauseCallback = nil
	}
	if i.urlTestHistoryStorage != nil {
		i.urlTestHistoryStorage.Close()
	}
	i.closeResult = i.instance.CloseWithResult()
	if i.tailscaleRetirement != nil {
		i.tailscaleRetirement.freeze(i.instance.TailscaleStoreRetirement(), true)
		i.tailscaleRetirement.freezeDirectories(i.instance.TailscaleDirectoryRetirement(), true)
	}
}

func (i *Instance) registerPowerReport(ctx context.Context, reloading bool) {
	powerManager := service.FromContext[*powerreport.Manager](ctx)
	if powerManager == nil {
		return
	}
	recorder := powerManager.Recorder()
	if recorder != nil {
		recorder.RecordServiceStart(i.instance.CreatedAt(), reloading)
	}
	if i.pauseManager == nil {
		return
	}
	i.pauseCallback = i.pauseManager.RegisterCallback(func(event int) {
		recorder := powerManager.Recorder()
		if recorder != nil {
			recorder.RecordPauseEvent(event)
		}
	})
}

func (i *Instance) Box() *box.Box {
	return i.instance
}

func (i *Instance) PauseManager() pause.Manager {
	return i.pauseManager
}

func (i *Instance) TrafficManager() *trafficcontrol.Manager {
	return i.trafficManager
}

func parseConfig(ctx context.Context, configContent string) (option.Options, error) {
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(configContent))
	if err != nil {
		return option.Options{}, E.Cause(err, "decode config")
	}
	return options, nil
}
