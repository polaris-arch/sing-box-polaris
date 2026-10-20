package box

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"reflect"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/runtimeclock"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service"
)

const runtimeResourceLimit = 1024

func (s *Box) prepareRuntimeGraph(request context.Context, identity RuntimeIdentity, options option.Options, sources ...runtimeSourceSnapshot) (*preparedRuntimeGraph, error) {
	return s.prepareRuntimeGraphWithSelections(request, identity, options, nil, sources...)
}

func (s *Box) prepareRuntimeGraphWithSelections(request context.Context, identity RuntimeIdentity, options option.Options, intents []RuntimeSelectorIntent, sources ...runtimeSourceSnapshot) (*preparedRuntimeGraph, error) {
	prepared, err := s.constructRuntimeGraphWithSelections(request, identity, options, intents, sources...)
	if err != nil {
		return prepared, err
	}
	if err := s.checkPreparedRuntimeNodeReplacements(prepared); err != nil {
		return prepared, err
	}
	for _, stage := range adapter.ListStartStages {
		if err := request.Err(); err != nil {
			return prepared, err
		}
		if err := s.startRuntimeGraphStage(prepared, stage); err != nil {
			return prepared, err
		}
	}
	s.migrateRuntimeSelections(prepared)
	if err := s.applyRuntimeSelectorIntents(prepared, intents); err != nil {
		return prepared, err
	}
	prepared.endpointTransaction, err = s.stageRuntimeEndpoints(request, prepared)
	if err != nil {
		return prepared, err
	}
	if err := s.sealRuntimeGraph(prepared); err != nil {
		return prepared, err
	}
	return prepared, nil
}

func (s *Box) constructRuntimeGraph(request context.Context, identity RuntimeIdentity, options option.Options, sources ...runtimeSourceSnapshot) (prepared *preparedRuntimeGraph, err error) {
	return s.constructRuntimeGraphWithSelections(request, identity, options, nil, sources...)
}

func (s *Box) constructRuntimeGraphWithSelections(request context.Context, identity RuntimeIdentity, options option.Options, intents []RuntimeSelectorIntent, sources ...runtimeSourceSnapshot) (prepared *preparedRuntimeGraph, err error) {
	c := s.runtime
	options = runtimeResolveGraphDefaults(options)
	canonical, marshalErr := json.MarshalContext(c.ctx, options)
	if marshalErr != nil {
		return nil, marshalErr
	}
	prepared = &preparedRuntimeGraph{options: options, initial: identity.Revision == 1}
	logLevel := ""
	if options.Log != nil {
		logLevel = options.Log.Level
	}
	prepared.logPublication, err = log.PrepareRuntimeLevel(s.logFactory, logLevel)
	if err != nil {
		return prepared, err
	}
	prepared.tunDependencies, err = runtimeTunDependencySignatures(c.ctx, options)
	if err != nil {
		return prepared, err
	}
	defer func() {
		prepared.effectAccess.Lock()
		prepared.effectRegistrationClosed = true
		prepared.effectAccess.Unlock()
	}()
	c.access.Lock()
	c.pendingPrepared = prepared
	c.access.Unlock()
	if err := s.prepareRuntimeFakeIP(request, prepared); err != nil {
		return prepared, err
	}
	if err := s.prepareRuntimeRootStore(request, prepared, identity); err != nil {
		return prepared, err
	}
	nodes, configs, err := runtimeConfigNodes(c.ctx, options)
	if err != nil {
		return prepared, err
	}
	runtimeBindRootFingerprints(nodes, configs, prepared.rootDigest)
	runtimeBindSelectorIntentFingerprints(nodes, intents)
	for _, intent := range intents {
		for index := range nodes {
			if nodes[index].name == "outbound:"+intent.Group {
				nodes[index].fingerprint = runtimeDigest([]byte(fmt.Sprintf("%s:selection-revision:%d", nodes[index].fingerprint, identity.Revision)))
			}
		}
	}
	cohorts, err := runtimeCohorts(nodes)
	if err != nil {
		return prepared, err
	}
	c.access.Lock()
	c.pruneRuntimeCatalogLocked()
	old := append([]*runtimeResource(nil), c.resources...)
	provisioned := c.platformRequirements
	if len(c.catalog)+len(cohorts) > runtimeResourceLimit {
		c.access.Unlock()
		return prepared, errors.New("runtime resource capacity exhausted")
	}
	c.access.Unlock()
	if !prepared.initial {
		after := route.RuntimeRequirementsFor(common.PtrValueOrDefault(options.Route), common.PtrValueOrDefault(options.DNS))
		if !runtimePlatformRequirementsAvailable(provisioned, after) {
			return prepared, errors.New("runtime platform requirement adapter pending")
		}
	}
	byFingerprint := make(map[string]*runtimeResource, len(old))
	for _, resource := range old {
		byFingerprint[resource.fingerprint] = resource
	}
	bindings := make(map[string]*runtimeResource, len(nodes))
	owned := make(map[*runtimeResource]bool)
	for i, cohort := range cohorts {
		if err := request.Err(); err != nil {
			return prepared, err
		}
		hash := sha256.New()
		runtimeHashField(hash, cohort.fingerprint)
		var dependencies []adapter.RuntimeResourceLease
		stableLease, stableErr := c.stable.owner.Acquire()
		if stableErr != nil {
			return prepared, stableErr
		}
		dependencies = append(dependencies, stableLease)
		rootLease, rootErr := prepared.rootResource.owner.Acquire()
		if rootErr != nil {
			stableLease.Release()
			return prepared, rootErr
		}
		dependencies = append(dependencies, rootLease)
		for _, index := range cohort.dependencies {
			dependency := prepared.resources[index]
			runtimeHashField(hash, fmt.Sprint(dependency.id.Sequence))
			lease, acquireErr := dependency.owner.Acquire()
			if acquireErr != nil {
				for _, held := range dependencies {
					held.Release()
				}
				return prepared, acquireErr
			}
			dependencies = append(dependencies, lease)
		}
		fingerprint := hex.EncodeToString(hash.Sum(nil))
		resource := byFingerprint[fingerprint]
		if resource == nil {
			c.access.Lock()
			if c.stopped || c.resourceSequence == math.MaxUint64 {
				c.access.Unlock()
				for _, held := range dependencies {
					held.Release()
				}
				return prepared, errors.New("runtime resource admission stopped")
			}
			c.resourceSequence++
			id := adapter.RuntimeResourceID{Incarnation: identity.Incarnation, Sequence: c.resourceSequence}
			c.access.Unlock()
			resource = &runtimeResource{id: id, fingerprint: fingerprint, components: make(map[string]*runtimeComponent)}
			owner, ownerErr := runtimegraph.NewResourceOwner(c.ctx, id, dependencies, func() error { return resource.scope.Close() })
			if ownerErr != nil {
				for _, held := range dependencies {
					held.Release()
				}
				return prepared, ownerErr
			}
			resource.owner = owner
			resource.scope = adapter.NewScope(owner.Context(), s.logger)
			prepared.created = append(prepared.created, resource)
			owned[resource] = true
			c.access.Lock()
			c.catalog[id] = resource
			c.access.Unlock()
		}
		for _, held := range dependencies {
			held.Release()
		}
		reservation, reserveErr := resource.owner.Acquire()
		if reserveErr != nil {
			return prepared, reserveErr
		}
		prepared.construction = append(prepared.construction, reservation)
		prepared.resources = append(prepared.resources, resource)
		for _, name := range cohorts[i].members {
			bindings[name] = resource
		}
	}
	stableMembership, stableErr := c.stable.owner.Acquire()
	if stableErr != nil {
		return prepared, stableErr
	}
	prepared.construction = append(prepared.construction, stableMembership)
	prepared.resources = append(prepared.resources, c.stable, prepared.rootResource)
	providerRegistry := service.FromContext[adapter.CertificateProviderRegistry](c.ctx)
	certificateManager := certificate.NewRuntimeManager(providerRegistry)
	prepared.certificateManager = certificateManager
	serviceManager := boxService.NewRuntimeManager(service.FromContext[adapter.ServiceRegistry](c.ctx))
	prepared.serviceManager = serviceManager
	inboundRegistry := service.FromContext[adapter.InboundRegistry](c.ctx)
	outboundRegistry := service.FromContext[adapter.OutboundRegistry](c.ctx)
	transportRegistry := service.FromContext[adapter.DNSTransportRegistry](c.ctx)
	endpointManager := endpoint.NewRuntimeManager(service.FromContext[adapter.EndpointRegistry](c.ctx))
	prepared.endpointManager = endpointManager
	inboundManager := inbound.NewRuntimeManager(inboundRegistry, endpointManager)
	prepared.inboundManager = inboundManager
	routeOptions := common.PtrValueOrDefault(options.Route)
	dnsOptions := common.PtrValueOrDefault(options.DNS)
	outboundManager := outbound.NewRuntimeManager(outboundRegistry, endpointManager, routeOptions.Final)
	transportManager := dns.NewRuntimeTransportManager(transportRegistry, outboundManager, dnsOptions.Final)
	prepared.outboundManager = outboundManager
	prepared.transportManager = transportManager
	runtimeMark, markErr := runtimeAutoRedirectMark(c.ctx, options)
	if markErr != nil {
		return prepared, markErr
	}
	var leaf *route.Router
	var dnsLeaf *dns.Router
	var httpManager *httpclient.Manager
	var clock *runtimeclock.Service
	preparedIDs := make(map[adapter.RuntimeResourceID]bool, len(owned))
	for resource := range owned {
		preparedIDs[resource.id] = true
	}
	contexts := make(map[string]context.Context)
	componentContext := func(name string) (context.Context, error) {
		resource := bindings[name]
		ctx, err := route.ContextWithRuntimeNetworkOptions(resource.owner.Context(), s.network, routeOptions, runtimeMark)
		if err != nil {
			return nil, err
		}
		ctx = adapter.ContextWithConstructionScope(ctx, resource.scope)
		snapshot, snapshotErr := prepared.rootSnapshot.Retain()
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		resource.scope.Add(func() error { snapshot.Release(); return nil })
		service.MustRegister[adapter.CertificateStore](ctx, snapshot)
		ctx = adapter.ContextWithRuntimePreparation(ctx)
		ctx = adapter.ContextWithRuntimeTailscaleConfiguration(ctx, canonical)
		ctx = adapter.ContextWithRuntimePreparedResourceCheck(ctx, func(id adapter.RuntimeResourceID) bool { return preparedIDs[id] })
		ctx = adapter.ContextWithRuntimeControl(ctx, c)
		ctx = adapter.ContextWithRuntimeResourceSource(ctx, resource.owner)
		ctx = adapter.ContextWithRuntimeEffectRegistration(ctx, func(effect adapter.RuntimeStagedEffect) error {
			if effect == nil {
				return errors.New("nil runtime effect")
			}
			prepared.effectAccess.Lock()
			defer prepared.effectAccess.Unlock()
			if prepared.effectRegistrationClosed {
				return errors.New("runtime effect registration closed")
			}
			prepared.inlineEffects = append(prepared.inlineEffects, effect)
			prepared.activate = append(prepared.activate, effect.RuntimeActivate)
			resource.addRuntimeStop(effect.RuntimeStop, effect.RuntimeStop)
			return nil
		})
		ctx = adapter.ContextWithRuntimePostBindEffectRegistration(ctx, func(effect adapter.RuntimePostBindEffect) error {
			if effect == nil {
				return errors.New("nil runtime post-bind effect")
			}
			keys := append([]string(nil), effect.RuntimeConflictKeys()...)
			if len(keys) == 0 {
				return errors.New("post-bind effect requires exact conflict identities")
			}
			seen := make(map[string]bool, len(keys))
			for _, key := range keys {
				if key == "" || seen[key] {
					return errors.New("invalid post-bind conflict identity")
				}
				seen[key] = true
			}
			prepared.effectAccess.Lock()
			defer prepared.effectAccess.Unlock()
			if prepared.effectRegistrationClosed {
				return errors.New("runtime effect registration closed")
			}
			resource.postBindEffects = append(resource.postBindEffects, runtimePostBindRecord{effect: effect, keys: keys})
			prepared.activate = append(prepared.activate, effect.RuntimeActivate)
			resource.addRuntimeStop(effect.RuntimeStop, effect.RuntimeStop)
			return nil
		})
		if prepared.fakeIPMigration != nil {
			ctx = prepared.fakeIPMigration.Context(ctx)
		}
		if clock != nil {
			service.MustRegister[ntp.TimeService](ctx, clock)
		} else {
			service.MustRegister[ntp.TimeService](ctx, nil)
		}
		service.MustRegister[adapter.ServiceManager](ctx, serviceManager)
		service.MustRegister[adapter.CertificateProviderManager](ctx, certificateManager)
		service.MustRegister[adapter.InboundManager](ctx, inboundManager)
		service.MustRegister[adapter.OutboundManager](ctx, outboundManager)
		service.MustRegister[adapter.EndpointManager](ctx, endpointManager)
		service.MustRegister[adapter.DNSTransportManager](ctx, transportManager)
		if httpManager != nil {
			service.MustRegister[adapter.HTTPClientManager](ctx, httpManager)
		}
		if dnsLeaf != nil {
			service.MustRegister[adapter.DNSRouter](ctx, dnsLeaf)
			service.MustRegister[adapter.DNSRuleSetUpdateValidator](ctx, dnsLeaf)
		}
		if leaf != nil {
			service.MustRegister[adapter.Router](ctx, leaf)
		}
		contexts[name] = ctx
		return ctx, nil
	}
	getComponent := func(name string) *runtimeComponent {
		resource := bindings[name]
		component := resource.components[name]
		if component == nil {
			if !owned[resource] {
				panic("reused runtime cohort is missing a component")
			}
			component = &runtimeComponent{}
			resource.components[name] = component
		}
		return component
	}
	if options.NTP != nil && options.NTP.Enabled {
		component := getComponent("ntp")
		resource := bindings["ntp"]
		if owned[resource] {
			ctx, contextErr := componentContext("ntp")
			if contextErr != nil {
				return prepared, contextErr
			}
			clock, err = runtimeclock.New(ctx, s.logFactory.NewLogger("ntp"), *options.NTP, c.runtimeClockWriter(resource.id))
			if err != nil {
				return prepared, err
			}
			component.clock = clock
			resource.addRuntimeStop(clock.RuntimeStop, nil)
			prepared.activate = append(prepared.activate, clock.RuntimeActivate)
		} else {
			clock = component.clock
		}
		for _, ctx := range contexts {
			service.MustRegister[ntp.TimeService](ctx, clock)
		}
	}
	httpComponent := getComponent("http-manager")
	if owned[bindings["http-manager"]] {
		ctx, contextErr := componentContext("http-manager")
		if contextErr != nil {
			return prepared, contextErr
		}
		httpManager = httpclient.NewManager(ctx, s.logFactory.NewLogger("httpclient"), options.HTTPClients, routeOptions.DefaultHTTPClient)
		httpComponent.httpClients = httpManager
		bindings["http-manager"].scope.Add(func() error { return runtimeCleanupResult(httpManager.RuntimeCloseAndWait()) })
	} else {
		httpManager = httpComponent.httpClients
	}
	for _, ctx := range contexts {
		service.MustRegister[adapter.HTTPClientManager](ctx, httpManager)
	}
	dnsComponent := getComponent("dns-router")
	if owned[bindings["dns-router"]] {
		ctx, contextErr := componentContext("dns-router")
		if contextErr != nil {
			return prepared, contextErr
		}
		dependencies, dependencyErr := s.prepareRuntimeDNSStores(ctx, prepared, bindings["dns-router"], dnsOptions)
		if dependencyErr != nil {
			return prepared, dependencyErr
		}
		dnsLeaf, err = dns.NewRouterWithClientDependencies(ctx, s.logFactory, dnsOptions, dependencies)
		if err != nil {
			return prepared, err
		}
		dnsComponent.dns = dnsLeaf
		bindings["dns-router"].addRuntimeStop(dnsLeaf.StopRuntimeProducers, nil)
	} else {
		dnsLeaf = dnsComponent.dns
	}
	routeComponent := getComponent("route-router")
	if owned[bindings["route-router"]] {
		ctx, contextErr := componentContext("route-router")
		if contextErr != nil {
			return prepared, contextErr
		}
		leaf = route.NewRouter(ctx, s.logFactory, routeOptions, dnsOptions)
		leaf.AppendTracker(&c.trackers)
		if prepared.initial {
			leaf.ConfigureInitialRuntime(c.stable.scope)
		} else {
			leaf.BorrowRuntimePlatform(c.initialRouter)
		}
		routeComponent.router = leaf
	} else {
		leaf = routeComponent.router
	}
	for _, ctx := range contexts {
		service.MustRegister[adapter.Router](ctx, leaf)
		service.MustRegister[adapter.DNSRouter](ctx, dnsLeaf)
		service.MustRegister[adapter.DNSRuleSetUpdateValidator](ctx, dnsLeaf)
	}
	var ruleSets []adapter.RuleSet
	for _, node := range nodes {
		config := configs[node.name]
		if config.ruleSet == nil {
			continue
		}
		component := getComponent(node.name)
		if owned[bindings[node.name]] {
			ctx, contextErr := componentContext(node.name)
			if contextErr != nil {
				return prepared, contextErr
			}
			set, createErr := R.NewRuleSet(ctx, s.logger, config.ruleSet.Tag[0], *config.ruleSet)
			if createErr != nil {
				return prepared, createErr
			}
			component.ruleSet = set
			bindings[node.name].scope.Add(set.Close)
		}
		ruleSets = append(ruleSets, component.ruleSet)
	}
	if owned[bindings["route-router"]] {
		if err := leaf.InitializeRuntime(routeOptions.Rules, ruleSets); err != nil {
			return prepared, err
		}
	}
	for _, node := range nodes {
		config := configs[node.name]
		if config.transport == nil {
			continue
		}
		component := getComponent(node.name)
		var scope *adapter.Scope
		if owned[bindings[node.name]] {
			ctx, contextErr := componentContext(node.name)
			if contextErr != nil {
				return prepared, contextErr
			}
			value, createErr := transportRegistry.CreateDNSTransport(ctx, s.logFactory.NewLogger(node.name), config.transport.Tag, config.transport.Type, config.transport.Options)
			if createErr != nil {
				return prepared, createErr
			}
			component.transport = value
			scope = bindings[node.name].scope
			if producer, ok := value.(interface {
				StopRuntimeProducers()
				StopRuntimeOperations()
			}); ok {
				bindings[node.name].addRuntimeStop(producer.StopRuntimeProducers, producer.StopRuntimeOperations)
			}
		}
		if err := transportManager.Insert(component.transport, scope); err != nil {
			return prepared, err
		}
	}
	if err := transportManager.Freeze(); err != nil {
		return prepared, err
	}
	if owned[bindings["dns-router"]] {
		if err := dnsLeaf.Initialize(dnsOptions.Rules); err != nil {
			return prepared, err
		}
	}
	for _, node := range nodes {
		config := configs[node.name]
		if config.endpoint == nil {
			continue
		}
		component := getComponent(node.name)
		var scope *adapter.Scope
		if owned[bindings[node.name]] {
			ctx, contextErr := componentContext(node.name)
			if contextErr != nil {
				return prepared, contextErr
			}
			value, createErr := service.FromContext[adapter.EndpointRegistry](ctx).Create(ctx, c.gateway, s.logFactory.NewLogger(node.name), config.endpoint.Tag, config.endpoint.Type, config.endpoint.Options)
			if createErr != nil {
				return prepared, createErr
			}
			component.endpoint = value
			scope = bindings[node.name].scope
			if activate, ok := value.(interface{ RuntimeActivate() }); ok {
				prepared.activate = append(prepared.activate, activate.RuntimeActivate)
			}
			if producer, ok := value.(interface{ RuntimeStop() }); ok {
				bindings[node.name].addRuntimeStop(producer.RuntimeStop, nil)
			}
		}
		if err := endpointManager.Insert(component.endpoint, scope); err != nil {
			return prepared, err
		}
	}
	if err := endpointManager.Freeze(); err != nil {
		return prepared, err
	}
	for _, node := range nodes {
		config := configs[node.name]
		if config.outbound == nil {
			continue
		}
		component := getComponent(node.name)
		var scope *adapter.Scope
		if owned[bindings[node.name]] {
			ctx, contextErr := componentContext(node.name)
			if contextErr != nil {
				return prepared, contextErr
			}
			component.history = urltest.NewIncarnationHistory(service.PtrFromContext[urltest.HistoryStorage](c.ctx))
			service.MustRegisterPtr(ctx, component.history)
			bindings[node.name].scope.Add(component.history.Close)
			value, createErr := outboundRegistry.CreateOutbound(ctx, leaf, s.logFactory.NewLogger(node.name), config.outbound.Tag, config.outbound.Type, config.outbound.Options)
			if createErr != nil {
				return prepared, createErr
			}
			component.outbound = value
			scope = bindings[node.name].scope
			if producer, ok := value.(interface {
				RuntimeActivate()
				RuntimeStop()
			}); ok {
				prepared.activate = append(prepared.activate, producer.RuntimeActivate)
				previousStop := bindings[node.name].stop
				bindings[node.name].stop = func() {
					if previousStop != nil {
						previousStop()
					}
					producer.RuntimeStop()
				}
			} else if activate, ok := value.(interface{ RuntimeActivate() }); ok {
				prepared.activate = append(prepared.activate, activate.RuntimeActivate)
			}
		}
		if err := outboundManager.Insert(component.outbound, scope); err != nil {
			return prepared, err
		}
	}
	if err := outboundManager.Freeze(); err != nil {
		return prepared, err
	}
	if owned[bindings["http-manager"]] {
		httpContext := contexts["http-manager"]
		if err := httpManager.PrepareRuntime(func() (*httpclient.ManagedTransport, error) {
			var fallback option.HTTPClientOptions
			fallback.DefaultOutbound = true
			return httpclient.NewTransport(httpContext, s.logFactory.NewLogger("httpclient"), "", fallback)
		}); err != nil {
			return prepared, err
		}
		if err := httpManager.FreezeRuntime(); err != nil {
			return prepared, err
		}
	}

	for _, node := range nodes {
		config := configs[node.name]
		if config.provider == nil {
			continue
		}
		component := getComponent(node.name)
		var scope *adapter.Scope
		if owned[bindings[node.name]] {
			if providerRegistry == nil {
				return prepared, errors.New("missing certificate provider registry")
			}
			ctx, contextErr := componentContext(node.name)
			if contextErr != nil {
				return prepared, contextErr
			}
			value, createErr := providerRegistry.Create(ctx, s.logFactory.NewLogger(node.name), config.provider.Tag, config.provider.Type, config.provider.Options)
			if createErr != nil {
				return prepared, createErr
			}
			component.provider = value
			scope = bindings[node.name].scope
		}
		if err := certificateManager.Insert(component.provider, scope); err != nil {
			return prepared, err
		}
	}
	if err := certificateManager.Freeze(); err != nil {
		return prepared, err
	}
	providers, providerErr := certificateManager.PreparedProviders()
	if providerErr != nil {
		return prepared, providerErr
	}
	for _, provider := range providers {
		prepared.activate = append(prepared.activate, provider.RuntimeActivate)
		resource := bindings["certificate-provider:"+provider.Tag()]
		resource.addRuntimeStop(provider.RuntimeStop, provider.RuntimeStop)
	}

	for _, node := range nodes {
		config := configs[node.name]
		if config.inbound == nil {
			continue
		}
		component := getComponent(node.name)
		var scope *adapter.Scope
		if owned[bindings[node.name]] {
			ctx, contextErr := componentContext(node.name)
			if contextErr != nil {
				return prepared, contextErr
			}
			ctx = listener.ContextWithRuntimeBinding(ctx, listener.RuntimeBinding{Admission: c.store})
			inboundRouter := &runtimeInboundRouter{Router: c.gateway, rules: make(map[string]adapter.RuleSet)}
			for _, set := range ruleSets {
				inboundRouter.rules[set.Name()] = set
			}
			value, createErr := inboundRegistry.Create(ctx, inboundRouter, s.logFactory.NewLogger(node.name), config.inbound.Tag, config.inbound.Type, config.inbound.Options)
			if createErr != nil {
				return prepared, createErr
			}
			component.inbound = value
			scope = bindings[node.name].scope
			if producer, ok := value.(interface{ RuntimeStop() }); ok {
				bindings[node.name].addRuntimeStop(producer.RuntimeStop, nil)
			}
		}
		if err := inboundManager.Insert(component.inbound, scope); err != nil {
			return prepared, err
		}
	}
	if err := inboundManager.Freeze(); err != nil {
		return prepared, err
	}
	for _, node := range nodes {
		config := configs[node.name]
		if config.service == nil {
			continue
		}
		component := getComponent(node.name)
		var scope *adapter.Scope
		if owned[bindings[node.name]] {
			ctx, contextErr := componentContext(node.name)
			if contextErr != nil {
				return prepared, contextErr
			}
			ctx = listener.ContextWithRuntimeBinding(ctx, listener.RuntimeBinding{Admission: c.store})
			value, createErr := service.FromContext[adapter.ServiceRegistry](ctx).Create(ctx, s.logFactory.NewLogger(node.name), config.service.Tag, config.service.Type, config.service.Options)
			if createErr != nil {
				return prepared, createErr
			}
			component.service = value
			scope = bindings[node.name].scope
			if producer, ok := value.(interface {
				RuntimeActivate()
				RuntimeStop()
			}); ok {
				prepared.activate = append(prepared.activate, producer.RuntimeActivate)
				bindings[node.name].addRuntimeStop(producer.RuntimeStop, nil)
			}
		}
		if err := serviceManager.Insert(component.service, scope); err != nil {
			return prepared, err
		}
	}
	if err := serviceManager.Freeze(); err != nil {
		return prepared, err
	}
	for _, member := range serviceManager.Services() {
		if binder, ok := member.(interface{ BindRuntimeContext(context.Context) }); ok {
			for _, ctx := range contexts {
				binder.BindRuntimeContext(ctx)
			}
		}
	}

	networkOptions, err := route.BuildNetworkOptions(routeOptions)
	if err != nil {
		return prepared, err
	}
	network, err := route.NewRuntimeNetworkOptionsView(s.network, networkOptions, runtimeMark, routeOptions.AutoDetectInterface)
	if err != nil {
		return prepared, err
	}
	view := &runtimeView{histories: make(map[string]*urltest.HistoryStorage), identity: identity.graphRevision(), router: leaf, dns: dnsLeaf, inbounds: inboundManager, outbounds: outboundManager, endpoints: endpointManager, transports: transportManager, httpClients: httpManager, network: network, ports: make(map[tun.Port]adapter.RuntimeResourceID), componentIDs: make(map[string]adapter.RuntimeResourceID)}
	for name, resource := range bindings {
		view.componentIDs[name] = resource.id
		if component := resource.components[name]; component != nil && component.outbound != nil {
			view.histories[component.outbound.Tag()] = component.history
			if port, ok := component.outbound.(tun.Port); ok {
				view.ports[port] = resource.id
			}
		}
	}
	view.referenceOptions, err = route.NewRuntimeReferenceOptions(c.ctx, options)
	if err != nil {
		return prepared, err
	}
	view.referenceResources = make(map[any]adapter.RuntimeResourceID)
	view.referenceResources[httpManager] = bindings["http-manager"].id
	for name, resource := range bindings {
		component := resource.components[name]
		if component == nil {
			continue
		}
		if component.service != nil {
			if !reflect.TypeOf(component.service).Comparable() {
				return prepared, errors.New("runtime service lacks stable object identity")
			}
			view.referenceResources[component.service] = resource.id
		}
		if component.endpoint != nil {
			if !reflect.TypeOf(component.endpoint).Comparable() {
				return prepared, errors.New("runtime endpoint lacks stable object identity")
			}
			view.referenceResources[component.endpoint] = resource.id
			if port, ok := component.endpoint.(tun.Port); ok {
				view.ports[port] = resource.id
			}
		}
		if component.provider != nil {
			if !reflect.TypeOf(component.provider).Comparable() {
				return prepared, errors.New("runtime certificate provider lacks stable object identity")
			}
			view.referenceResources[component.provider] = resource.id
		}
		if component.inbound != nil {
			if !reflect.TypeOf(component.inbound).Comparable() {
				return prepared, errors.New("runtime inbound lacks stable object identity")
			}
			view.referenceResources[component.inbound] = resource.id
		}
		if component.outbound != nil {
			if !reflect.TypeOf(component.outbound).Comparable() {
				return prepared, errors.New("runtime outbound lacks stable object identity")
			}
			view.referenceResources[component.outbound] = resource.id
		}
		if component.transport != nil {
			if !reflect.TypeOf(component.transport).Comparable() {
				return prepared, errors.New("runtime transport lacks stable object identity")
			}
			view.referenceResources[component.transport] = resource.id
		}
	}
	view.bindRuntimeHistoryConsumers()
	prepared.view = view
	if err := s.prepareRuntimeSourceProducer(prepared, sources); err != nil {
		return prepared, err
	}
	return prepared, nil
}
