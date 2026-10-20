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
 runtimeOverrides *OverrideOptions // immutable detached startup projection
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

type preparedInstance struct {
 runtimeOverrides *OverrideOptions
 runtimeGraph bool
	ctx            context.Context
	profileContent string
	options        option.Options
	request context.Context
	directoryPlan preparedDirectoryResources
	directoryRun *tailscaleRetirementRun
	directoryCancel context.CancelFunc
	directoryWatch *directoryPreparationCancellation
	directoryCommitted bool
	directoryFinished chan struct{}
}

// prepareInstance decodes once and changes only its fresh options graph. It must
// not construct resources, revoke a directory domain, or run beforeStart.
func (s *StartedService) prepareInstance(ctx context.Context, profileContent string, overrideOptions *OverrideOptions) (*preparedInstance, error) {
	request := ctx
	selectedLocale := locale.FromContext(ctx)
	ctx, _ = locale.ContextWithLocale(s.ctx, selectedLocale.Locale)
	ctx = service.ExtendContext(ctx)
	service.MustRegister[deprecated.Manager](ctx, new(deprecatedManager))
	options, err := parseConfig(ctx, profileContent)
	if err != nil {
		return nil, err
	}
	s.serviceAccess.Lock()
	oomEnabled, oomDisabled, oomLimit := s.oomKillerEnabled, s.oomKillerDisabled, s.oomMemoryLimit
	s.serviceAccess.Unlock()
	if overrideOptions != nil {
		for _, inbound := range options.Inbounds {
			if tunInboundOptions, isTUN := inbound.Options.(*option.TunInboundOptions); isTUN {
				tunInboundOptions.AutoRedirect = overrideOptions.AutoRedirect && tunInboundOptions.AutoRoute
				tunInboundOptions.IncludePackage = appendRuntimeOverridePackages(tunInboundOptions.IncludePackage, overrideOptions.IncludePackage)
				tunInboundOptions.ExcludePackage = appendRuntimeOverridePackages(tunInboundOptions.ExcludePackage, overrideOptions.ExcludePackage)
				break
			}
		}
	}
	if oomEnabled {
		if !common.Any(options.Services, func(it option.Service) bool {
			return it.Type == C.TypeOOMKiller
		}) {
			oomOptions := &option.OOMKillerServiceOptions{
				KillerDisabled:      oomDisabled,
				MemoryLimitOverride: oomLimit,
			}
			options.Services = append(options.Services, option.Service{
				Type:    C.TypeOOMKiller,
				Options: oomOptions,
			})
		}
	}
	return &preparedInstance{runtimeOverrides: cloneRuntimeOverrides(overrideOptions), ctx: ctx, profileContent: profileContent, options: options, request:request,runtimeGraph:box.RuntimeUsesResourceGraph(ctx,options)}, nil
}

// newInstance is retained for constructor-only callers. The lifecycle owner
// serializes both admission and construction with lifecycleAccess.
func (s *StartedService) newInstance(ctx context.Context, profileContent string, overrideOptions *OverrideOptions, reloading bool) (*Instance, error) {
	prepared, err := s.prepareInstance(ctx, profileContent, overrideOptions)
	if err != nil {
		return nil, err
	}
	if err := s.admitTailscaleRetirementRun(); err != nil {
		return nil, err
	}
	if err := s.prepareManagedDirectories(ctx,prepared); err != nil { return nil,err }
	defer prepared.abortDirectories()
	return s.newPreparedInstance(prepared, reloading)
}

func (s *StartedService) newPreparedInstance(prepared *preparedInstance, reloading bool) (*Instance, error) {
	ctx, profileContent, options := prepared.ctx, prepared.profileContent, prepared.options
 if prepared.runtimeGraph { ctx=adapter.ContextWithRuntimeTailscaleChildRegistrar(ctx,s.registerRuntimeTailscaleChild) }
	if domain := adapter.TailscaleDirectoryDomainFromContext(s.ctx); domain != nil && prepared.directoryPlan == nil {
		if !domain.Activated() {
			return nil, E.New("managed directory domain is not activated")
		}
		if err := domain.FailurePersistenceError(); err != nil {
			return nil, err
		}
	}
	if prepared.directoryPlan == nil {
		if err := guardRawDirectoryNamespace(ctx, profileContent); err != nil { return nil,err }
	}
	var cancel context.CancelFunc
	retirement := prepared.directoryRun
	if prepared.directoryRun != nil {
		cancel = prepared.directoryCancel
	} else {
		ctx, cancel = context.WithCancel(ctx)
		var err error
		retirementOptions:=options
  if prepared.runtimeGraph{retirementOptions.Endpoints=nil}
  retirement,err = newTailscaleRetirementRun(profileContent,retirementOptions)
		if err != nil { cancel(); return nil,err }
		if err=s.appendTailscaleRetirementRun(retirement);err!=nil{cancel();return nil,err}
		ctx = service.ContextWithPtr(ctx,&retirement.binding)
		ctx,err = prepareTailscaleDirectoryMapping(ctx,options)
		if err != nil { cancel(); return nil,err }
	}
	urlTestHistoryStorage := urltest.NewHistoryStorage()
	ctx = service.ContextWithPtr(ctx, urlTestHistoryStorage)
	i := &Instance{
 runtimeOverrides: cloneRuntimeOverrides(prepared.runtimeOverrides),
		ctx:                   ctx,
		cancel:                cancel,
		urlTestHistoryStorage: urlTestHistoryStorage,
		closeFinished:         make(chan struct{}),
		tailscaleRetirement:   retirement,
	}
	if prepared.directoryRun != nil {
		if err := prepared.attachPreparedDirectoryRun(i); err != nil { cancel(); return nil,err }
	} else { retirement.access.Lock();retirement.closeFinished = i.closeFinished;retirement.access.Unlock() }
	constructed := false
	defer func() {
		if !constructed {
			retirement.freeze(nil, false)
			if prepared.directoryPlan == nil { retirement.freezeDirectories(nil, false) }
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
	if persist := runtimePersistenceForRequest(prepared.request, s.runtimePersistence); persist != nil && boxInstance.RuntimeCapabilities().Identity.Incarnation != "" {
		if err := boxInstance.BindRuntimePersistenceMode(persist, runtimePersistenceModeForRequest(prepared.request)); err != nil {
			cancel()
			_ = boxInstance.Close()
			return nil, err
		}
	}
	constructed = true
	boxInstance.CaptureTailscaleStateStores()
	retirement.capture(boxInstance.TailscaleStateStoreScopes())
	if prepared.directoryPlan != nil {
		if err := prepared.commitDirectories(boxInstance.TailscaleDirectoryScopes); err != nil { cancel(); _ = boxInstance.Close(); return nil,err }
	} else { retirement.captureDirectories(boxInstance.TailscaleDirectoryScopes);if prepared.runtimeGraph{prepared.directoryCommitted=true} }
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
		i.tailscaleRetirement.access.Lock()
		i.tailscaleRetirement.originalCloseSucceeded = i.closeResult == nil
		i.tailscaleRetirement.access.Unlock()
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
