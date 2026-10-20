package box

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxCertificate "github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/certificate"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/netns"
	"github.com/sagernet/sing-box/common/taskmonitor"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/experimental"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/experimental/clashmode"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

var _ adapter.SimpleLifecycle = (*Box)(nil)

type Box struct {
	runtime             *runtimeCoordinator
	createdAt           time.Time
	debugOptions        option.DebugOptions
	logFactory          log.Factory
	logger              log.ContextLogger
	network             *route.NetworkManager
	endpoint            *endpoint.Manager
	inbound             *inbound.Manager
	outbound            *outbound.Manager
	service             *boxService.Manager
	certificateProvider *boxCertificate.Manager
	dnsTransport        *dns.TransportManager
	dnsRouter           *dns.Router
	connection          *route.ConnectionManager
	router              *route.Router
	referenceManager    *route.ReferenceManager
	httpClientService   adapter.LifecycleService
	internalService     []adapter.LifecycleService
	ntpService          *ntp.Service
	scope               *adapter.Scope
	tsStoreMu           sync.Mutex
	tsStores            []adapter.Endpoint
	tsCaptured          bool
	tsRetirement        []adapter.TailscaleStoreNode
	closeStarted        atomic.Bool
	closeOnce           sync.Once
	closeResult         error
}

type Options struct {
	option.Options
	Context                    context.Context
	PlatformLogWriter          log.PlatformWriter
	NetworkNamespaceHolderArgs []string
}

func Context(
	ctx context.Context,
	inboundRegistry adapter.InboundRegistry,
	outboundRegistry adapter.OutboundRegistry,
	endpointRegistry adapter.EndpointRegistry,
	dnsTransportRegistry adapter.DNSTransportRegistry,
	serviceRegistry adapter.ServiceRegistry,
	certificateProviderRegistry adapter.CertificateProviderRegistry,
) context.Context {
	if service.FromContext[option.InboundOptionsRegistry](ctx) == nil ||
		service.FromContext[adapter.InboundRegistry](ctx) == nil {
		ctx = service.ContextWith[option.InboundOptionsRegistry](ctx, inboundRegistry)
		ctx = service.ContextWith[adapter.InboundRegistry](ctx, inboundRegistry)
	}
	if service.FromContext[option.OutboundOptionsRegistry](ctx) == nil ||
		service.FromContext[adapter.OutboundRegistry](ctx) == nil {
		ctx = service.ContextWith[option.OutboundOptionsRegistry](ctx, outboundRegistry)
		ctx = service.ContextWith[adapter.OutboundRegistry](ctx, outboundRegistry)
	}
	if service.FromContext[option.EndpointOptionsRegistry](ctx) == nil ||
		service.FromContext[adapter.EndpointRegistry](ctx) == nil {
		ctx = service.ContextWith[option.EndpointOptionsRegistry](ctx, endpointRegistry)
		ctx = service.ContextWith[adapter.EndpointRegistry](ctx, endpointRegistry)
	}
	if service.FromContext[adapter.DNSTransportRegistry](ctx) == nil {
		ctx = service.ContextWith[option.DNSTransportOptionsRegistry](ctx, dnsTransportRegistry)
		ctx = service.ContextWith[adapter.DNSTransportRegistry](ctx, dnsTransportRegistry)
	}
	if service.FromContext[adapter.ServiceRegistry](ctx) == nil {
		ctx = service.ContextWith[option.ServiceOptionsRegistry](ctx, serviceRegistry)
		ctx = service.ContextWith[adapter.ServiceRegistry](ctx, serviceRegistry)
	}
	if service.FromContext[adapter.CertificateProviderRegistry](ctx) == nil {
		ctx = service.ContextWith[option.CertificateProviderOptionsRegistry](ctx, certificateProviderRegistry)
		ctx = service.ContextWith[adapter.CertificateProviderRegistry](ctx, certificateProviderRegistry)
	}
	return ctx
}

// ConstructionReport describes what constructing a box left behind.
type ConstructionReport struct {
	// Attempted is true once construction got far enough to acquire resources.
	Attempted bool
	// CleanupError is the result of releasing those resources after a failed
	// construction.
	CleanupError error
}

// New constructs a box. When construction fails, the resources acquired so
// far are released in the background, so the error or panic is propagated
// without waiting for cleanup.
func New(options Options) (*Box, error) {
	var (
		scope    *adapter.Scope
		instance *Box
	)
	defer func() {
		if instance == nil && scope != nil {
			go func() {
				err := closeRecovering(scope.Close)
				if err != nil {
					log.Error(E.Cause(err, "release failed construction"))
				}
			}()
		}
	}()
	instance, err := newBox(options, &scope)
	return instance, err
}

// NewWithConstructionReport is like New, but waits for the cleanup of a
// failed construction and reports its result.
func NewWithConstructionReport(options Options) (instance *Box, err error, report ConstructionReport) {
	var scope *adapter.Scope
	defer func() {
		report.Attempted = scope != nil
		if instance == nil && scope != nil {
			report.CleanupError = closeRecovering(scope.Close)
		}
	}()
	instance, err = newBox(options, &scope)
	return
}

func newBox(options Options, constructionScope **adapter.Scope) (*Box, error) {
	createdAt := time.Now()
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = service.ContextWithDefaultRegistry(ctx)
	preparedContext, directoryErr := prepareWindowsDirectoryDomain(ctx, options.Options)
	if directoryErr != nil {
		return nil, directoryErr
	}
	ctx = preparedContext

	endpointRegistry := service.FromContext[adapter.EndpointRegistry](ctx)
	inboundRegistry := service.FromContext[adapter.InboundRegistry](ctx)
	outboundRegistry := service.FromContext[adapter.OutboundRegistry](ctx)
	dnsTransportRegistry := service.FromContext[adapter.DNSTransportRegistry](ctx)
	serviceRegistry := service.FromContext[adapter.ServiceRegistry](ctx)
	certificateProviderRegistry := service.FromContext[adapter.CertificateProviderRegistry](ctx)

	if endpointRegistry == nil {
		return nil, E.New("missing endpoint registry in context")
	}
	if inboundRegistry == nil {
		return nil, E.New("missing inbound registry in context")
	}
	if outboundRegistry == nil {
		return nil, E.New("missing outbound registry in context")
	}
	if dnsTransportRegistry == nil {
		return nil, E.New("missing DNS transport registry in context")
	}
	if serviceRegistry == nil {
		return nil, E.New("missing service registry in context")
	}
	if certificateProviderRegistry == nil {
		return nil, E.New("missing certificate provider registry in context")
	}

	ctx = pause.WithDefaultManager(ctx)
	experimentalOptions := common.PtrValueOrDefault(options.Experimental)
	debugOptions := common.PtrValueOrDefault(experimentalOptions.Debug)
	err := checkDebugOptions(debugOptions)
	if err != nil {
		return nil, err
	}
	var needCacheFile bool
	var needClashAPI bool
	var needV2RayAPI bool
	if experimentalOptions.CacheFile != nil && experimentalOptions.CacheFile.Enabled || options.PlatformLogWriter != nil {
		needCacheFile = true
	}
	if experimentalOptions.ClashAPI != nil {
		needClashAPI = true
	}
	if experimentalOptions.V2RayAPI != nil && experimentalOptions.V2RayAPI.Listen != "" {
		needV2RayAPI = true
	}
	needAPIService := common.Any(options.Services, func(it option.Service) bool {
		return it.Type == C.TypeAPI
	})
	if service.PtrFromContext[urltest.HistoryStorage](ctx) == nil {
		ctx = service.ContextWithPtr(ctx, urltest.NewHistoryStorage())
	}
	platformInterface := service.FromContext[adapter.PlatformInterface](ctx)
	var defaultLogWriter io.Writer
	if platformInterface != nil {
		defaultLogWriter = io.Discard
	}
	logFactory, err := log.New(log.Options{
		Context:        ctx,
		Options:        common.PtrValueOrDefault(options.Log),
		Observable:     needClashAPI && experimentalOptions.ClashAPI.ExternalController != "",
		DefaultWriter:  defaultLogWriter,
		BaseTime:       createdAt,
		PlatformWriter: options.PlatformLogWriter,
	})
	if err != nil {
		return nil, E.Cause(err, "create log factory")
	}
	service.MustRegister[log.Factory](ctx, logFactory)
	// The scope is shared by construction and runtime: constructors register
	// cleanup through adapter.DeferConstructionCleanup, components register
	// theirs when they start, and closing it releases both.
	scope := adapter.NewScope(ctx, logFactory.Logger())
	*constructionScope = scope
	ctx = adapter.ContextWithConstructionScope(ctx, scope)

	if !isConstructionValidation(ctx) && runtimeInitialEligible(ctx, options) {
		return newRuntimeBox(options, ctx, scope, logFactory, createdAt, nil)
	}

	var internalServices []adapter.LifecycleService
	routeOptions := common.PtrValueOrDefault(options.Route)
	certificateOptions := common.PtrValueOrDefault(options.Certificate)
	if C.IsAndroid || certificateOptions.Store != "" && certificateOptions.Store != C.CertificateStoreSystem ||
		len(certificateOptions.Certificate) > 0 ||
		len(certificateOptions.CertificatePath) > 0 ||
		len(certificateOptions.CertificateDirectoryPath) > 0 {
		certificateStore, err := certificate.NewStore(ctx, logFactory.NewLogger("certificate"), certificateOptions)
		if err != nil {
			return nil, err
		}
		service.MustRegister[adapter.CertificateStore](ctx, certificateStore)
		internalServices = append(internalServices, certificateStore)
	}
	netnsManager, err := netns.NewManager(logFactory.NewLogger("netns"), options.NetworkNamespaces, options.NetworkNamespaceHolderArgs)
	if err != nil {
		return nil, err
	}
	service.MustRegister[adapter.NetworkNamespaceManager](ctx, netnsManager)
	internalServices = append(internalServices, netnsManager)
	dnsOptions := common.PtrValueOrDefault(options.DNS)
	endpointManager := endpoint.NewManager(endpointRegistry)
	inboundManager := inbound.NewManager(inboundRegistry, endpointManager)
	outboundManager := outbound.NewManager(outboundRegistry, endpointManager, routeOptions.Final)
	dnsTransportManager := dns.NewTransportManager(dnsTransportRegistry, outboundManager, dnsOptions.Final)
	serviceManager := boxService.NewManager(serviceRegistry)
	certificateProviderManager := boxCertificate.NewManager(certificateProviderRegistry)
	service.MustRegister[adapter.EndpointManager](ctx, endpointManager)
	service.MustRegister[adapter.InboundManager](ctx, inboundManager)
	service.MustRegister[adapter.OutboundManager](ctx, outboundManager)
	service.MustRegister[adapter.DNSTransportManager](ctx, dnsTransportManager)
	service.MustRegister[adapter.ServiceManager](ctx, serviceManager)
	service.MustRegister[adapter.CertificateProviderManager](ctx, certificateProviderManager)
	dnsRouter, err := dns.NewRouter(ctx, logFactory, dnsOptions)
	if err != nil {
		return nil, E.Cause(err, "initialize DNS router")
	}
	service.MustRegister[adapter.DNSRouter](ctx, dnsRouter)
	service.MustRegister[adapter.DNSRuleSetUpdateValidator](ctx, dnsRouter)
	connectionManager := route.NewConnectionManager(logFactory.NewLogger("connection"))
	service.MustRegister[adapter.ConnectionManager](ctx, connectionManager)
	networkManager, err := route.NewNetworkManager(ctx, logFactory.NewLogger("network"), routeOptions, dnsOptions)
	if err != nil {
		return nil, E.Cause(err, "initialize network manager")
	}
	networkView, err := route.NewNetworkOptionsView(networkManager, networkManager.DefaultOptions())
	if err != nil {
		return nil, E.Cause(err, "initialize network options view")
	}
	service.MustRegister[adapter.NetworkManager](ctx, networkView)
	// Must register after ConnectionManager: the Apple HTTP engine's proxy bridge reads it from the context when Manager.Start resolves the default client.
	httpClientManager := httpclient.NewManager(ctx, logFactory.NewLogger("httpclient"), options.HTTPClients, routeOptions.DefaultHTTPClient)
	service.MustRegister[adapter.HTTPClientManager](ctx, httpClientManager)
	httpClientService := adapter.LifecycleService(httpClientManager)
	router := route.NewRouter(ctx, logFactory, routeOptions, dnsOptions)
	service.MustRegister[adapter.Router](ctx, router)
	err = router.Initialize(routeOptions.Rules, routeOptions.RuleSet)
	if err != nil {
		return nil, E.Cause(err, "initialize router")
	}
	if needClashAPI || needAPIService || options.PlatformLogWriter != nil {
		trafficManager := trafficcontrol.NewManager()
		service.MustRegisterPtr(ctx, trafficManager)
		router.AppendTracker(trafficManager)
		internalServices = append(internalServices, trafficManager)
		var clashDefaultMode string
		if experimentalOptions.ClashAPI != nil {
			clashDefaultMode = experimentalOptions.ClashAPI.DefaultMode
		}
		clashMode := clashmode.NewManager(ctx, logFactory.NewLogger("clash-mode"), clashDefaultMode, clashmode.CalculateModeList(options.Options))
		service.MustRegisterPtr(ctx, clashMode)
		internalServices = append(internalServices, clashMode)
	}
	referenceManager := route.NewReferenceManager(ctx, logFactory.NewLogger("reference"), options.Options)
	internalServices = append(internalServices, referenceManager)
	ntpOptions := common.PtrValueOrDefault(options.NTP)
	var timeService *tls.TimeServiceWrapper
	if ntpOptions.Enabled {
		timeService = new(tls.TimeServiceWrapper)
		service.MustRegister[ntp.TimeService](ctx, timeService)
	}
	for i, transportOptions := range dnsOptions.Servers {
		var tag string
		if transportOptions.Tag != "" {
			tag = transportOptions.Tag
		} else {
			tag = F.ToString(i)
		}
		err = dnsTransportManager.Create(
			ctx,
			logFactory.NewLogger(F.ToString("dns/", transportOptions.Type, "[", tag, "]")),
			tag,
			transportOptions.Type,
			transportOptions.Options,
		)
		if err != nil {
			return nil, E.Cause(err, "initialize DNS server[", i, "]")
		}
	}
	err = dnsRouter.Initialize(dnsOptions.Rules)
	if err != nil {
		return nil, E.Cause(err, "initialize dns router")
	}
	for i, endpointOptions := range options.Endpoints {
		var tag string
		if endpointOptions.Tag != "" {
			tag = endpointOptions.Tag
		} else {
			tag = F.ToString(i)
		}
		endpointCtx := ctx
		if tag != "" {
			// TODO: remove this
			endpointCtx = adapter.WithContext(endpointCtx, &adapter.InboundContext{
				Outbound: tag,
			})
		}
		err = endpointManager.Create(
			endpointCtx,
			router,
			logFactory.NewLogger(F.ToString("endpoint/", endpointOptions.Type, "[", tag, "]")),
			tag,
			endpointOptions.Type,
			endpointOptions.Options,
		)
		if err != nil {
			return nil, E.Cause(err, "initialize endpoint[", i, "]")
		}
	}
	for i, inboundOptions := range options.Inbounds {
		var tag string
		if inboundOptions.Tag != "" {
			tag = inboundOptions.Tag
		} else {
			tag = F.ToString(i)
		}
		err = inboundManager.Create(
			ctx,
			router,
			logFactory.NewLogger(F.ToString("inbound/", inboundOptions.Type, "[", tag, "]")),
			tag,
			inboundOptions.Type,
			inboundOptions.Options,
		)
		if err != nil {
			return nil, E.Cause(err, "initialize inbound[", i, "]")
		}
	}
	for i, serviceOptions := range options.Services {
		var tag string
		if serviceOptions.Tag != "" {
			tag = serviceOptions.Tag
		} else {
			tag = F.ToString(i)
		}
		err = serviceManager.Create(
			ctx,
			logFactory.NewLogger(F.ToString("service/", serviceOptions.Type, "[", tag, "]")),
			tag,
			serviceOptions.Type,
			serviceOptions.Options,
		)
		if err != nil {
			return nil, E.Cause(err, "initialize service[", i, "]")
		}
	}
	for i, outboundOptions := range options.Outbounds {
		var tag string
		if outboundOptions.Tag != "" {
			tag = outboundOptions.Tag
		} else {
			tag = F.ToString(i)
		}
		outboundCtx := ctx
		if tag != "" {
			// TODO: remove this
			outboundCtx = adapter.WithContext(outboundCtx, &adapter.InboundContext{
				Outbound: tag,
			})
		}
		err = outboundManager.Create(
			outboundCtx,
			router,
			logFactory.NewLogger(F.ToString("outbound/", outboundOptions.Type, "[", tag, "]")),
			tag,
			outboundOptions.Type,
			outboundOptions.Options,
		)
		if err != nil {
			return nil, E.Cause(err, "initialize outbound[", i, "]")
		}
	}
	for i, certificateProviderOptions := range options.CertificateProviders {
		var tag string
		if certificateProviderOptions.Tag != "" {
			tag = certificateProviderOptions.Tag
		} else {
			tag = F.ToString(i)
		}
		err = certificateProviderManager.Create(
			ctx,
			logFactory.NewLogger(F.ToString("certificate-provider/", certificateProviderOptions.Type, "[", tag, "]")),
			tag,
			certificateProviderOptions.Type,
			certificateProviderOptions.Options,
		)
		if err != nil {
			return nil, E.Cause(err, "initialize certificate provider[", i, "]")
		}
	}
	outboundManager.Initialize(func() (adapter.Outbound, error) {
		return direct.NewOutbound(
			ctx,
			router,
			logFactory.NewLogger("outbound/direct"),
			"direct",
			option.DirectOutboundOptions{},
		)
	})
	dnsTransportManager.Initialize(func() (adapter.DNSTransport, error) {
		return dnsTransportRegistry.CreateDNSTransport(
			ctx,
			logFactory.NewLogger("dns/local"),
			"local",
			C.DNSTypeLocal,
			&option.LocalDNSServerOptions{},
		)
	})
	httpClientManager.Initialize(func() (*httpclient.ManagedTransport, error) {
		deprecated.Report(ctx, deprecated.OptionImplicitDefaultHTTPClient)
		var httpClientOptions option.HTTPClientOptions
		httpClientOptions.DefaultOutbound = true
		return httpclient.NewTransport(ctx, logFactory.NewLogger("httpclient"), "", httpClientOptions)
	})
	if platformInterface != nil {
		err = platformInterface.Initialize(networkManager)
		if err != nil {
			return nil, E.Cause(err, "initialize platform interface")
		}
	}
	if needCacheFile {
		cacheFile := cachefile.New(ctx, logFactory.NewLogger("cache-file"), common.PtrValueOrDefault(experimentalOptions.CacheFile))
		service.MustRegister[adapter.CacheFile](ctx, cacheFile)
		internalServices = append(internalServices, cacheFile)
	}
	if needClashAPI {
		clashServer, err := experimental.NewClashServer(ctx, logFactory.(log.ObservableFactory), common.PtrValueOrDefault(experimentalOptions.ClashAPI))
		if err != nil {
			return nil, E.Cause(err, "create clash-server")
		}
		internalServices = append(internalServices, clashServer)
	}
	if needV2RayAPI {
		v2rayServer, err := experimental.NewV2RayServer(logFactory.NewLogger("v2ray-api"), common.PtrValueOrDefault(experimentalOptions.V2RayAPI))
		if err != nil {
			return nil, E.Cause(err, "create v2ray-server")
		}
		if v2rayServer.StatsService() != nil {
			router.AppendTracker(v2rayServer.StatsService())
			internalServices = append(internalServices, v2rayServer)
			service.MustRegister[adapter.V2RayServer](ctx, v2rayServer)
		}
	}
	var ntpService *ntp.Service
	if ntpOptions.Enabled {
		if ntpOptions.WriteToSystem {
			err = adapter.CheckSecurityFeature(ctx, "NTP `write_to_system`")
			if err != nil {
				return nil, err
			}
		}
		ntpDialer, err := dialer.New(ctx, ntpOptions.DialerOptions, ntpOptions.ServerIsDomain())
		if err != nil {
			return nil, E.Cause(err, "create NTP service")
		}
		ntpService = ntp.NewService(ntp.Options{
			Context:       ctx,
			Dialer:        ntpDialer,
			Logger:        logFactory.NewLogger("ntp"),
			Server:        ntpOptions.ServerOptions.Build(),
			Interval:      time.Duration(ntpOptions.Interval),
			WriteToSystem: ntpOptions.WriteToSystem,
		})
		timeService.TimeService = ntpService
	}
	return &Box{
		network:             networkManager,
		endpoint:            endpointManager,
		inbound:             inboundManager,
		outbound:            outboundManager,
		dnsTransport:        dnsTransportManager,
		service:             serviceManager,
		certificateProvider: certificateProviderManager,
		dnsRouter:           dnsRouter,
		connection:          connectionManager,
		router:              router,
		referenceManager:    referenceManager,
		httpClientService:   httpClientService,
		createdAt:           createdAt,
		debugOptions:        debugOptions,
		logFactory:          logFactory,
		logger:              logFactory.Logger(),
		internalService:     internalServices,
		ntpService:          ntpService,
		scope:               scope,
	}, nil
}

func (s *Box) PreStart() error {
	err := s.preStart()
	if err != nil {
		s.closeAfterStartFailure()
		return err
	}
	s.logger.Info("sing-box pre-started (", F.Seconds(time.Since(s.createdAt).Seconds()), "s)")
	return nil
}

func (s *Box) Start() error {
	err := s.start()
	if err != nil {
		s.closeAfterStartFailure()
		return err
	}
	s.logger.Info("sing-box started (", F.Seconds(time.Since(s.createdAt).Seconds()), "s)")
	return nil
}

type boxComponent struct {
	name      string
	lifecycle adapter.Lifecycle
}

func (s *Box) startComponents(stage adapter.StartStage, components ...boxComponent) error {
	for _, component := range components {
		err := s.scope.Start(component.name, component.lifecycle, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Box) startInternalServices(stage adapter.StartStage) error {
	for _, lifecycleService := range s.internalService {
		err := s.scope.Start(lifecycleService.Name(), lifecycleService, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Box) preStart() error {
	if s.runtime != nil {
		return s.preStartRuntime()
	}
	monitor := taskmonitor.New(s.logger, C.StartTimeout)
	monitor.Start("start logger")
	err := s.logFactory.Start()
	monitor.Finish()
	if err != nil {
		return E.Cause(err, "start logger")
	}
	s.scope.Add(s.logFactory.Close)
	applyDebugOptions(s.debugOptions)
	debugHTTPServer, err := startDebugHTTPServer(s.debugOptions)
	if err != nil {
		return err
	}
	if debugHTTPServer != nil {
		s.scope.Add(debugHTTPServer.Close)
	}
	err = s.startInternalServices(adapter.StartStateInitialize) // cache-file clash-api v2ray-api
	if err != nil {
		return err
	}
	err = s.startComponents(adapter.StartStateInitialize,
		boxComponent{s.httpClientService.Name(), s.httpClientService},
		boxComponent{"network", s.network},
		boxComponent{"dns-transport", s.dnsTransport},
		boxComponent{"dns-router", s.dnsRouter},
		boxComponent{"connection", s.connection},
		boxComponent{"router", s.router},
		boxComponent{"outbound", s.outbound},
		boxComponent{"endpoint", s.endpoint},
		boxComponent{"certificate-provider", s.certificateProvider},
		boxComponent{"inbound", s.inbound},
		boxComponent{"service", s.service},
	)
	if err != nil {
		return err
	}
	err = s.startComponents(adapter.StartStateStart,
		boxComponent{"outbound", s.outbound},
		boxComponent{"dns-transport", s.dnsTransport},
		boxComponent{"network", s.network},
		boxComponent{"connection", s.connection},
		boxComponent{s.httpClientService.Name(), s.httpClientService},
		boxComponent{"router", s.router},
		boxComponent{"dns-router", s.dnsRouter},
	)
	if err != nil {
		return err
	}
	return nil
}

func (s *Box) start() error {
	if s.runtime != nil {
		return s.startRuntime()
	}
	err := s.preStart()
	if err != nil {
		return err
	}
	err = s.startInternalServices(adapter.StartStateStart)
	if err != nil {
		return err
	}
	if s.ntpService != nil {
		done := adapter.LogElapsed(s.logger, "start ntp service")
		err = s.ntpService.Start()
		done()
		if err != nil {
			return E.Cause(err, "start ntp service")
		}
		s.scope.Add(s.ntpService.Close)
	}
	err = s.startComponents(adapter.StartStateStart,
		boxComponent{"endpoint", s.endpoint},
		boxComponent{"certificate-provider", s.certificateProvider},
		boxComponent{"inbound", s.inbound},
		boxComponent{"service", s.service},
	)
	if err != nil {
		return err
	}
	err = s.startComponents(adapter.StartStatePostStart,
		boxComponent{"outbound", s.outbound},
		boxComponent{"network", s.network},
		boxComponent{"dns-transport", s.dnsTransport},
		boxComponent{"dns-router", s.dnsRouter},
		boxComponent{"connection", s.connection},
		boxComponent{"router", s.router},
		boxComponent{"endpoint", s.endpoint},
		boxComponent{"certificate-provider", s.certificateProvider},
		boxComponent{"inbound", s.inbound},
		boxComponent{"service", s.service},
	)
	if err != nil {
		return err
	}
	err = s.startInternalServices(adapter.StartStatePostStart)
	if err != nil {
		return err
	}
	err = s.startComponents(adapter.StartStateStarted,
		boxComponent{"network", s.network},
		boxComponent{"dns-transport", s.dnsTransport},
		boxComponent{"dns-router", s.dnsRouter},
		boxComponent{"connection", s.connection},
		boxComponent{"router", s.router},
		boxComponent{"outbound", s.outbound},
		boxComponent{"endpoint", s.endpoint},
		boxComponent{"certificate-provider", s.certificateProvider},
		boxComponent{"inbound", s.inbound},
		boxComponent{"service", s.service},
	)
	if err != nil {
		return err
	}
	err = s.startInternalServices(adapter.StartStateStarted)
	if err != nil {
		return err
	}
	return nil
}

// closeAfterStartFailure closes the box after a failed start. If the box was
// already closed, for example by a Close racing with the start, the start may
// have registered cleanup after that close ran, so the scope is closed again
// to run it.
func (s *Box) closeAfterStartFailure() {
	s.Close()
	closeRecovering(s.scope.Close)
}

// closeRecovering runs closeFunc and turns a panic raised by one of its
// cleanups into an error.
func closeRecovering(closeFunc func() error) (err error) {
	defer func() {
		recovered := recover()
		if recovered != nil {
			err = E.New("panic during close: ", recovered)
		}
	}()
	return closeFunc()
}

// Close closes the box. Only the first close returns the cleanup result;
// later calls return nil without waiting for it.
func (s *Box) Close() error {
	if s.closeStarted.Swap(true) {
		return nil
	}
	return s.CloseWithResult()
}

// CloseWithResult closes the box if it is not closed yet and returns the
// result of the first close, waiting for it to complete if necessary. It
// preserves the cleanup result that Start and PreStart discard when they
// close the box after a failure.
func (s *Box) CloseWithResult() error {
	s.closeStarted.Store(true)
	s.closeOnce.Do(func() {
		s.closeResult = closeRecovering(s.finishClose)
	})
	return s.closeResult
}

func (s *Box) finishClose() error {
	// Seal the Tailscale state stores before anything is closed. A writer whose
	// retirement stays unknown is reported by the endpoint's construction
	// cleanup, which the scope runs last.
	s.retireTailscaleStateStores()
	s.sealTailscaleDirectories()
	return s.scope.Close()
}

func (s *Box) Network() adapter.NetworkManager {
	return s.network
}

func (s *Box) Router() adapter.Router {
	if s.runtime != nil {
		return s.runtime.gateway
	}
	return s.router
}

func (s *Box) Inbound() adapter.InboundManager {
	return s.inbound
}

func (s *Box) Outbound() adapter.OutboundManager {
	if s.runtime != nil {
		return &runtimeOutboundManager{s.runtime}
	}
	return s.outbound
}

func (s *Box) Endpoint() adapter.EndpointManager {
	return s.endpoint
}

func (s *Box) CreatedAt() time.Time {
	return s.createdAt
}

func (s *Box) CloseIdleConnections() {
	if s.runtime != nil {
		if s.runtime.reference != nil {
			ctx, cancel := context.WithTimeout(context.Background(), C.StopTimeout)
			defer cancel()
			if err := s.runtime.reference.CloseIdleConnections(ctx); err != nil {
				s.logger.Warn("runtime idle close incomplete: ", err)
			}
		}
		return
	}
	s.referenceManager.CloseIdleConnections()
}

func (s *Box) LogFactory() log.Factory {
	return s.logFactory
}
