package box

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxCertificate "github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/netns"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/dns/transport/lifecycle"
	"github.com/sagernet/sing-box/experimental"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/experimental/clashmode"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

// Initial runtime allocation uses the same resource constructor as Apply. This
// predicate is an adapter inventory, not a promise of whole-schema completion.
func runtimeInitialEligible(ctx context.Context, options Options) bool {
	return len(runtimeInitialEligibilityErrors(ctx, options)) == 0
}

// Eligibility diagnostics contain only schema paths and fixed messages. Never
// retain configuration values or errors returned by an option's marshaler.
func runtimeInitialEligibilityErrors(ctx context.Context, options Options) []RuntimePlanError {
	canonical, err := json.MarshalContext(ctx, options.Options)
	if err != nil {
		return []RuntimePlanError{{Code: "INITIAL_CONFIG_ENCODING_FAILED", Path: "runtime", Message: "initial configuration could not be evaluated for runtime updates"}}
	}
	_, problems := runtimeConfigCompatibility(ctx, canonical, canonical, options.Options)
	if len(problems) != 0 {
		return problems
	}
	pending := func(path, message string) {
		problems = append(problems, RuntimePlanError{Code: "PENDING_ADAPTER", Path: path, Message: message})
	}
	if options.Certificate != nil {
		pending("certificate", "initial certificate configuration requires a runtime adapter")
	}
	if len(options.NetworkNamespaces) != 0 {
		pending("network_namespaces", "initial network namespaces require a runtime adapter")
	}
	experimentalOptions := common.PtrValueOrDefault(options.Experimental)
	// Stable physical cache now has private DNS views and fixed FakeIP binding.
	if clash := experimentalOptions.ClashAPI; clash != nil {
		if clash.ExternalUI != "" {
			pending("experimental.clash_api.external_ui", "initial external dashboard requires a runtime adapter")
		}
		if clash.ExternalUIDownloadURL != "" {
			pending("experimental.clash_api.external_ui_download_url", "initial dashboard download requires a runtime adapter")
		}
		if clash.ExternalUIDownloadDetour != "" {
			pending("experimental.clash_api.external_ui_download_detour", "initial dashboard download dependency requires a runtime adapter")
		}
	}
	for index, input := range options.Inbounds {
		switch input.Type {
		case "socks", "http", "mixed", "tun":
		default:
			pending(fmt.Sprintf("inbounds[%d].lifecycle", index), "initial inbound lifecycle requires a runtime adapter")
		}
	}
	// Network bootstrap without an existing graph is a separate remaining
	// adapter; do not select a runtime startup that can only fail afterward.
	if options.Route != nil {
		for index, source := range options.Route.RuleSet {
			if source.Type == "remote" && source.RemoteOptions.InitialPath == "" {
				pending(fmt.Sprintf("route.rule_set[%d].initial_path", index), "initial remote rule-set bootstrap requires a local snapshot for runtime updates")
			}
		}
	}
	return problems
}

func newRuntimeBox(options Options, scope *adapter.Scope, factory log.Factory, createdAt time.Time, internal []adapter.LifecycleService) (*Box, error) {
	ctx := adapter.ContextWithConstructionScope(scope.Context(), scope)
	coordinator, err := newRuntimeCoordinator(ctx)
	if err != nil {
		return nil, err
	}
	stable := &runtimeResource{id: adapter.RuntimeResourceID{Incarnation: coordinator.active.Incarnation, Sequence: 1}, kind: "stable", components: make(map[string]*runtimeComponent)}
	coordinator.resourceSequence = 1
	stable.owner, err = runtimegraph.NewResourceOwner(ctx, stable.id, nil, func() error {
		// All graph users have drained before this owner callback. The allocator
		// must finish its final durable writes before the stable cache's child
		// scope closes the physical DB. A constructor-time Scope.Add would run
		// after the cache child because that child is registered later at Start.
		var fakeIPErr error
		if coordinator.fakeIP != nil {
			fakeIPErr = lifecycle.CleanupResult("Box fake-IP allocator", coordinator.fakeIP.Close)
		}
		return errors.Join(runtimeCleanupResult(fakeIPErr), stable.scope.Close())
	})
	if err != nil {
		return nil, err
	}
	stable.scope = adapter.NewScope(stable.owner.Context(), factory.Logger())
	coordinator.stable = stable
	coordinator.catalog[stable.id] = stable
	coordinator.stableReservation, err = stable.owner.Acquire()
	if err != nil {
		stable.owner.Seal()
		return nil, err
	}
	instance := &Box{runtime: coordinator, createdAt: createdAt, debugOptions: common.PtrValueOrDefault(common.PtrValueOrDefault(options.Experimental).Debug), logFactory: factory, logger: factory.Logger(), scope: scope, internalService: internal}
	// Scope cleanup also handles constructor failures. It does not claim graph
	// drain merely because the outer constructor has returned an error.
	scope.Add(instance.closeRuntimeResources)
	ctx = adapter.ContextWithConstructionScope(stable.scope.Context(), stable.scope)
	coordinator.ctx = ctx
	service.MustRegisterPtr(ctx, instance)
	coordinator.ingressScope = adapter.NewScope(ctx, factory.Logger())
	stable.scope.Add(coordinator.closeIngress)
	namespaceManager, err := netns.NewManager(factory.NewLogger("netns"), options.NetworkNamespaces, options.NetworkNamespaceHolderArgs)
	if err != nil {
		return nil, err
	}
	service.MustRegister[adapter.NetworkNamespaceManager](ctx, namespaceManager)
	instance.internalService = append(instance.internalService, namespaceManager)

	experimentalOptions := common.PtrValueOrDefault(options.Experimental)
	if options.PlatformLogWriter != nil || (experimentalOptions.CacheFile != nil && experimentalOptions.CacheFile.Enabled) {
		cache := cachefile.New(cachefile.ContextWithFakeIPRuntimeOpen(ctx, nil), factory.NewLogger("cache-file"), common.PtrValueOrDefault(experimentalOptions.CacheFile))
		service.MustRegister[adapter.CacheFile](ctx, cache)
		instance.internalService = append(instance.internalService, cache)
	}
	// Recognition exists even when this revision has no fake-IP server, so
	// later addition/removal never loses the authority for still-valid answers.
	coordinator.fakeIP = fakeip.NewEmptyManager(ctx, factory.NewLogger("fakeip"))
	if err := coordinator.fakeIP.Start(); err != nil {
		return nil, err
	}
	ctx = fakeip.ContextWithManager(ctx, coordinator.fakeIP)
	gateway := route.NewRuntimeRouter(coordinator.store, route.RuntimeRouterStructure{})
	dnsGateway := route.NewRuntimeDNSRouter(coordinator.store)
	ctx = adapter.ContextWithRuntimeDNSIngress(ctx, dnsGateway)
	ctx = adapter.ContextWithRuntimeControl(ctx, coordinator)
	ctx = urltest.ContextWithRuntimeAdmission(ctx, coordinator.store)
	service.PtrFromContext[urltest.HistoryStorage](ctx).BindRuntimeAdmission(coordinator.store)
	coordinator.ctx = ctx
	coordinator.gateway = gateway
	service.MustRegister[adapter.Router](ctx, gateway)
	service.MustRegister[adapter.DNSRouter](ctx, dnsGateway)
	defaultMode := ""
	if experimentalOptions.ClashAPI != nil {
		defaultMode = experimentalOptions.ClashAPI.DefaultMode
	}
	coordinator.clashMode = clashmode.NewManager(ctx, factory.NewLogger("clash-mode"), defaultMode, clashmode.CalculateModeList(options.Options))
	service.MustRegisterPtr(ctx, coordinator.clashMode)
	instance.internalService = append(instance.internalService, coordinator.clashMode)
	instance.endpoint = endpoint.NewManager(service.FromContext[adapter.EndpointRegistry](ctx))
	instance.inbound = inbound.NewManager(service.FromContext[adapter.InboundRegistry](ctx), instance.endpoint)
	// These stable inventories are empty. Dynamic graph callbacks use the
	// retained catalog provider, never these legacy lookup shells.
	instance.outbound = outbound.NewManager(service.FromContext[adapter.OutboundRegistry](ctx), instance.endpoint, "")
	instance.service = boxService.NewManager(service.FromContext[adapter.ServiceRegistry](ctx))
	instance.certificateProvider = boxCertificate.NewManager(service.FromContext[adapter.CertificateProviderRegistry](ctx))
	service.MustRegister[adapter.EndpointManager](ctx, instance.endpoint)
	service.MustRegister[adapter.InboundManager](ctx, instance.inbound)
	service.MustRegister[adapter.OutboundManager](ctx, &runtimeOutboundManager{coordinator})
	service.MustRegister[adapter.ServiceManager](ctx, instance.service)
	service.MustRegister[adapter.CertificateProviderManager](ctx, instance.certificateProvider)
	instance.connection = route.NewConnectionManager(factory.NewLogger("connection"))
	service.MustRegister[adapter.ConnectionManager](ctx, instance.connection)
	routeOptions := common.PtrValueOrDefault(options.Route)
	dnsOptions := common.PtrValueOrDefault(options.DNS)
	instance.network, err = route.NewNetworkManager(ctx, factory.NewLogger("network"), routeOptions, dnsOptions)
	if err != nil {
		return nil, err
	}
	instance.network.BindRuntimeInventory(coordinator)
	networkView, err := route.NewNetworkOptionsView(instance.network, instance.network.DefaultOptions())
	if err != nil {
		return nil, err
	}
	service.MustRegister[adapter.NetworkManager](ctx, networkView)
	// HTTP clients belong to each prepared graph and are constructed/frozen
	// with that graph's outbound and DNS dependencies. No stable placeholder.
	service.MustRegister[adapter.RuntimeDashboardHTTPProvider](ctx, instance)
	coordinator.reference = route.NewRuntimeReferenceManager(ctx, factory.NewLogger("reference"), instance, instance)
	coordinator.referenceReservation, err = stable.owner.Acquire()
	if err != nil {
		return nil, err
	}
	if options.PlatformLogWriter != nil || experimentalOptions.ClashAPI != nil || len(options.Services) > 0 {
		traffic := trafficcontrol.NewManager()
		service.MustRegisterPtr(ctx, traffic)
		coordinator.trackers.Append(traffic)
		instance.internalService = append(instance.internalService, traffic)
	}
	if experimentalOptions.ClashAPI != nil {
		server, serverErr := experimental.NewClashServer(ctx, factory.(log.ObservableFactory), *experimentalOptions.ClashAPI)
		if serverErr != nil {
			return nil, serverErr
		}
		instance.internalService = append(instance.internalService, server)
	}
	if experimentalOptions.V2RayAPI != nil && experimentalOptions.V2RayAPI.Listen != "" {
		server, serverErr := experimental.NewV2RayServer(factory.NewLogger("v2ray-api"), *experimentalOptions.V2RayAPI)
		if serverErr != nil {
			return nil, serverErr
		}
		if server.StatsService() != nil {
			coordinator.trackers.Append(server.StatsService())
			instance.internalService = append(instance.internalService, server)
			service.MustRegister[adapter.V2RayServer](ctx, server)
		}
	}
	for index, item := range options.Services {
		if !runtimeStableAPIService(item) {
			return nil, errors.New("unsupported stable runtime service")
		}
		tag := item.Tag
		if tag == "" {
			tag = fmt.Sprint(index)
		}
		if err := instance.service.Create(ctx, factory.NewLogger("service/api["+tag+"]"), tag, item.Type, item.Options); err != nil {
			return nil, err
		}
	}
	canonical, err := json.MarshalContext(ctx, options.Options)
	if err != nil {
		return nil, err
	}
	initialRemote, remoteErr := runtimeInitialRemoteSources(ctx, options.Options, runtimeDigest(canonical))
	if remoteErr != nil {
		return nil, remoteErr
	}
	frozen, sources, _, sourceErrors := runtimeSnapshotSources(ctx, ctx, options.Options, initialRemote)
	if len(sourceErrors) != 0 {
		return nil, errors.New("initial runtime source preparation failed")
	}
	coordinator.canonical = canonical
	coordinator.options = frozen
	coordinator.platformRequirements = route.RuntimeRequirementsFor(common.PtrValueOrDefault(frozen.Route), common.PtrValueOrDefault(frozen.DNS))
	identity := coordinator.active
	identity.Revision = 1
	identity.EffectiveDigest = runtimeDigest(canonical)
	prepared, err := instance.constructRuntimeGraph(ctx, identity, frozen, sources...)
	if prepared != nil {
		coordinator.initialPrepared = prepared
	}
	if err != nil {
		return nil, err
	}
	coordinator.initialRouter = prepared.view.router.(*route.Router)
	coordinator.initialSources = sources
	coordinator.currentSources = append([]runtimeSourceSnapshot(nil), sources...)
	gateway.BindInitialStructure(route.RuntimeRouterStructure{FindProcess: coordinator.initialRouter.NeedFindProcess(), FindNeighbor: coordinator.initialRouter.NeedFindNeighbor(), NeighborView: coordinator.initialRouter.NeighborResolver, AppendTracker: coordinator.trackers.Append, ResetNetwork: func() { instance.network.ResetNetwork(ctx) }})
	if platform := service.FromContext[adapter.PlatformInterface](ctx); platform != nil {
		if err := platform.Initialize(instance.network); err != nil {
			return nil, err
		}
	}
	return instance, nil
}

// RuntimeUsesResourceGraph lets the daemon select the same construction custody
// path before Box.New. It is an implementation selector, not a capability claim.
func RuntimeUsesResourceGraph(ctx context.Context, options option.Options) bool {
	return runtimeInitialEligible(ctx, Options{Options: options})
}
