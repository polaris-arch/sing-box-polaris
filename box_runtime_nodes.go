package box

import (
	"context"
	"fmt"
	"sort"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

type runtimeNodeOptions struct {
	node      runtimeDependencyNode
	service   *option.Service
	endpoint  *option.Endpoint
	inbound   *option.Inbound
	outbound  *option.Outbound
	transport *option.DNSServerOptions
	ruleSet   *option.RuleSet
	provider  *option.CertificateProvider
}

func runtimeConfigNodes(ctx context.Context, options option.Options) ([]runtimeDependencyNode, map[string]runtimeNodeOptions, error) {
	configs := make(map[string]runtimeNodeOptions)
	routeOptions := common.PtrValueOrDefault(options.Route)
	dnsOptions := common.PtrValueOrDefault(options.DNS)
	defaults, err := route.BuildNetworkOptions(routeOptions)
	if err != nil {
		return nil, nil, err
	}
	mark, err := runtimeAutoRedirectMark(ctx, options)
	if err != nil {
		return nil, nil, err
	}
	defaultsBytes, err := json.Marshal(struct {
		Defaults            any
		AutoRedirectMark    uint32
		AutoDetectInterface bool
	}{defaults, mark, routeOptions.AutoDetectInterface})
	if err != nil {
		return nil, nil, err
	}
	makeNode := func(name string, config any, dependencies []string, capturesDefaults bool) (runtimeDependencyNode, error) {
		encoded, err := json.MarshalContext(ctx, config)
		if err != nil {
			return runtimeDependencyNode{}, err
		}
		if capturesDefaults {
			encoded = append(append(encoded, '\n'), defaultsBytes...)
		}
		sort.Strings(dependencies)
		return runtimeDependencyNode{name: name, fingerprint: runtimeDigest(encoded), dependencies: dependencies}, nil
	}
	var sets, transports, outbounds, inbounds []string
	endpointDNSConsumers := make(map[string][]string)
	// Inline provider HTTP clients are owned by the receiving HTTP manager.
	// Its fingerprint must include them, rather than merely retaining a provider
	// edge to an unchanged manager with stale captured detours/defaults.
	var providerHTTP []option.HTTPClientOptions
	providerDependencies := func(value any) ([]string, bool) {
		var client *option.HTTPClientOptions
		switch options := value.(type) {
		case *option.ACMECertificateProviderOptions:
			client = options.HTTPClient
		case *option.CloudflareOriginCACertificateProviderOptions:
			client = options.HTTPClient
		case *option.TailscaleCertificateProviderOptions:
			return []string{"endpoint:" + options.Endpoint, "dns-router"}, true
		default:
			return nil, false
		}
		resolved := common.PtrValueOrDefault(client)
		if resolved.Tag == "" {
			providerHTTP = append(providerHTTP, resolved)
		}
		return []string{"http-manager"}, true
	}
	for i := range options.CertificateProviders {
		provider := options.CertificateProviders[i]
		if provider.Tag == "" {
			provider.Tag = fmt.Sprint(i)
		}
		name := "certificate-provider:" + provider.Tag
		deps, defaults := providerDependencies(provider.Options)
		node, nodeErr := makeNode(name, provider, deps, defaults)
		if nodeErr != nil {
			return nil, nil, nodeErr
		}
		if _, exists := configs[name]; exists {
			return nil, nil, fmt.Errorf("duplicate runtime certificate provider")
		}
		configs[name] = runtimeNodeOptions{node: node, provider: &provider}
	}
	for i := range routeOptions.RuleSet {
		set := routeOptions.RuleSet[i]
		if set.Type != "" && set.Type != C.RuleSetTypeInline {
			return nil, nil, fmt.Errorf("runtime source was not frozen")
		}
		if len(set.Tag) != 1 {
			return nil, nil, fmt.Errorf("runtime inline source requires one resolved tag")
		}
		name := "rule-set:" + set.Tag[0]
		node, err := makeNode(name, set, nil, false)
		if err != nil {
			return nil, nil, err
		}
		if _, exists := configs[name]; exists {
			return nil, nil, fmt.Errorf("duplicate runtime source")
		}
		configs[name] = runtimeNodeOptions{node: node, ruleSet: &set}
		sets = append(sets, name)
	}
	for i := range dnsOptions.Servers {
		server := dnsOptions.Servers[i]
		if server.Tag == "" {
			server.Tag = fmt.Sprint(i)
		}
		name := "dns-transport:" + server.Tag
		var deps []string
		var callbackEndpoint string
		switch value := server.Options.(type) {
		case *option.OpenConnectDNSServerOptions:
			callbackEndpoint = value.Endpoint
		case *option.OpenVPNDNSServerOptions:
			callbackEndpoint = value.Endpoint
		}
		if server.Type == C.DNSTypeOpenConnect || server.Type == C.DNSTypeOpenVPN {
			if callbackEndpoint == "" {
				return nil, nil, fmt.Errorf("endpoint DNS requires an explicit endpoint tag")
			}
			deps = append(deps, "endpoint:"+callbackEndpoint)
			endpointDNSConsumers[callbackEndpoint] = append(endpointDNSConsumers[callbackEndpoint], name)
		}
		if resolved, ok := server.Options.(*option.ResolvedDNSServerOptions); ok {
			deps = append(deps, "service:"+resolved.Service)
		}
		if tailscale, ok := server.Options.(*option.TailscaleDNSServerOptions); ok {
			if tailscale.Endpoint == "" {
				return nil, nil, fmt.Errorf("runtime Tailscale DNS requires an explicit endpoint tag")
			}
			// The transport captures both the endpoint subscription and DNS router
			// used by the original child's immutable resolver snapshots.
			deps = append(deps, "endpoint:"+tailscale.Endpoint, "dns-router")
		}
		if wrapper, ok := server.Options.(option.DialerOptionsWrapper); ok {
			dialOptions := wrapper.TakeDialerOptions()
			if detour := dialOptions.Detour; detour != "" {
				deps = append(deps, "outbound:"+detour)
			}
			if resolver := dialOptions.DomainResolver; resolver != nil && resolver.Server != "" {
				deps = append(deps, "dns-transport:"+resolver.Server)
			}
		}
		if remote, ok := server.Options.(option.ServerOptionsWrapper); ok && remote.TakeServerOptions().ServerIsDomain() {
			// TLS/HTTPS/QUIC embed remote options too. Concrete-type matching only
			// the plain UDP/TCP option would omit their captured resolver router.
			if wrapper, ok := server.Options.(option.DialerOptionsWrapper); ok {
				dialOptions := wrapper.TakeDialerOptions()
				if dialOptions.Detour == "" || dialOptions.DomainResolver != nil {
					deps = append(deps, "dns-router")
				}
			}
		}
		node, err := makeNode(name, server, deps, true)
		if err != nil {
			return nil, nil, err
		}
		if _, exists := configs[name]; exists {
			return nil, nil, fmt.Errorf("duplicate runtime DNS server")
		}
		configs[name] = runtimeNodeOptions{node: node, transport: &server}
		transports = append(transports, name)
	}
	for i := range options.Inbounds {
		input := options.Inbounds[i]
		if input.Tag == "" {
			input.Tag = fmt.Sprint(i)
		}
		name := "inbound:" + input.Tag
		var deps []string
		if wrapper, ok := input.Options.(option.ListenOptionsWrapper); ok {
			if detour := wrapper.TakeListenOptions().Detour; detour != "" {
				deps = append(deps, "inbound:"+detour)
			}
		}
		capturesDefaults := false
		var tunPhysical []byte
		if tunOptions, ok := input.Options.(*option.TunInboundOptions); ok {
			physical, physicalErr := runtimeTunPhysicalInputs(ctx, options, tunOptions)
			if physicalErr != nil {
				return nil, nil, physicalErr
			}
			tunPhysical, physicalErr = json.Marshal(physical)
			if physicalErr != nil {
				return nil, nil, physicalErr
			}
			for index, output := range options.Outbounds {
				if output.Type == C.TypeBridge {
					tag := output.Tag
					if tag == "" {
						tag = fmt.Sprint(index)
					}
					deps = append(deps, "outbound:"+tag)
				}
			}
			for _, tag := range tunOptions.RouteAddressSet {
				deps = append(deps, "rule-set:"+tag)
			}
			for _, tag := range tunOptions.RouteExcludeAddressSet {
				deps = append(deps, "rule-set:"+tag)
			}
		}
		if wrapper, ok := input.Options.(option.InboundTLSOptionsWrapper); ok {
			tlsOptions := wrapper.TakeInboundTLSOptions()
			if tlsOptions != nil && tlsOptions.Enabled && tlsOptions.CertificateProvider != nil {
				provider := tlsOptions.CertificateProvider
				if provider.Tag != "" {
					deps = append(deps, "certificate-provider:"+provider.Tag)
				} else {
					providerDeps, defaults := providerDependencies(provider.Options)
					deps = append(deps, providerDeps...)
					capturesDefaults = capturesDefaults || defaults
				}
			}
			if tlsOptions != nil && tlsOptions.Enabled && tlsOptions.Reality != nil && tlsOptions.Reality.Enabled {
				handshake := tlsOptions.Reality.Handshake
				capturesDefaults = true
				if handshake.Detour != "" {
					deps = append(deps, "outbound:"+handshake.Detour)
				}
				resolver := handshake.DomainResolver
				if handshake.ServerIsDomain() && (handshake.Detour == "" || resolver != nil) {
					deps = append(deps, "dns-router")
					if resolver != nil && resolver.Server != "" {
						deps = append(deps, "dns-transport:"+resolver.Server)
					}
				}
			}
		}
		// The physical ingress routes through the stable admission gateway.
		// It does not capture the current route router merely by listening.
		node, err := makeNode(name, &input, deps, capturesDefaults)
		if err != nil {
			return nil, nil, err
		}
		if tunPhysical != nil {
			node.fingerprint = runtimeDigest(append(append([]byte(node.fingerprint), '\n'), tunPhysical...))
		}
		if _, exists := configs[name]; exists {
			return nil, nil, fmt.Errorf("duplicate runtime inbound")
		}
		configs[name] = runtimeNodeOptions{node: node, inbound: &input}
		inbounds = append(inbounds, name)
	}
	for i := range options.Endpoints {
		endpoint := options.Endpoints[i]
		if endpoint.Tag == "" {
			endpoint.Tag = fmt.Sprint(i)
		}
		name := "endpoint:" + endpoint.Tag
		// Endpoint DNS transports register callbacks into the original endpoint.
		// Both ends must be recreated together, never overwrite a borrowed owner.
		deps := append([]string(nil), endpointDNSConsumers[endpoint.Tag]...)
		if wrapper, ok := endpoint.Options.(option.DialerOptionsWrapper); ok {
			dial := wrapper.TakeDialerOptions()
			if dial.Detour != "" {
				deps = append(deps, "outbound:"+dial.Detour)
			}
			// Peer/control hosts and endpoint-owned DNS operations use their captured
			// graph, including background sessions independent of an inbound request.
			deps = append(deps, "dns-router")
			if dial.DomainResolver != nil && dial.DomainResolver.Server != "" {
				deps = append(deps, "dns-transport:"+dial.DomainResolver.Server)
			}
		}
		node, err := makeNode(name, &endpoint, deps, true)
		if err != nil {
			return nil, nil, err
		}
		if _, exists := configs[name]; exists {
			return nil, nil, fmt.Errorf("duplicate runtime endpoint")
		}
		configs[name] = runtimeNodeOptions{node: node, endpoint: &endpoint}
		outbounds = append(outbounds, name)
	}
	for i := range options.Outbounds {
		outbound := options.Outbounds[i]
		if outbound.Tag == "" {
			outbound.Tag = fmt.Sprint(i)
		}
		name := "outbound:" + outbound.Tag
		var deps []string
		switch value := outbound.Options.(type) {
		case *option.SelectorOutboundOptions:
			for _, tag := range value.Outbounds {
				deps = append(deps, "outbound:"+tag)
			}
		case *option.URLTestOutboundOptions:
			for _, tag := range value.Outbounds {
				deps = append(deps, "outbound:"+tag)
			}
		default:
			if wrapper, ok := outbound.Options.(option.DialerOptionsWrapper); ok {
				dialOptions := wrapper.TakeDialerOptions()
				if dialOptions.Detour != "" {
					deps = append(deps, "outbound:"+dialOptions.Detour)
				}
				if server, hasServer := outbound.Options.(option.ServerOptionsWrapper); hasServer && server.TakeServerOptions().ServerIsDomain() {
					resolver := dialOptions.DomainResolver
					hasResolver := resolver != nil && (resolver.Server != "" || resolver.Mode == option.DomainResolverModeRules)
					if dialOptions.Detour == "" || hasResolver {
						deps = append(deps, "dns-router")
						if resolver != nil && resolver.Server != "" {
							deps = append(deps, "dns-transport:"+resolver.Server)
						}
					}
				}
			}
			// Naive installs a native DNS callback even for an IP-addressed peer.
			// Its exact router must remain in the constructor dependency cohort.
			if outbound.Type == C.TypeDirect || outbound.Type == C.TypeNaive {
				deps = append(deps, "dns-router")
			}
			if httpOptions, ok := outbound.Options.(*option.HTTPOutboundOptions); ok {
				resolver := httpOptions.DomainResolver
				hasResolver := resolver != nil && (resolver.Server != "" || resolver.Mode == option.DomainResolverModeRules)
				if httpOptions.ServerIsDomain() && (httpOptions.Detour == "" || hasResolver) {
					deps = append(deps, "dns-router")
					if resolver != nil && resolver.Server != "" {
						deps = append(deps, "dns-transport:"+resolver.Server)
					}
				}
			}
			if socks, ok := outbound.Options.(*option.SOCKSOutboundOptions); ok {
				resolvesServer := socks.ServerIsDomain() && (socks.Detour == "" || socks.DomainResolver != nil)
				if resolvesServer || socks.Version == "4" {
					deps = append(deps, "dns-router")
				}
			}
		}
		_, capturesDialerDefaults := outbound.Options.(option.DialerOptionsWrapper)
		node, err := makeNode(name, &outbound, deps, capturesDialerDefaults)
		if err != nil {
			return nil, nil, err
		}
		if _, exists := configs[name]; exists {
			return nil, nil, fmt.Errorf("duplicate runtime outbound")
		}
		configs[name] = runtimeNodeOptions{node: node, outbound: &outbound}
		outbounds = append(outbounds, name)
	}
	for i := range options.Services {
		item := options.Services[i]
		if runtimeStableAPIService(item) {
			continue // Owned once by stable API ingress.
		}
		if item.Tag == "" {
			item.Tag = fmt.Sprint(i)
		}
		name := "service:" + item.Tag
		deps, clients, privateInbounds := runtimeServiceDependencies(item.Options)
		providerHTTP = append(providerHTTP, clients...)
		if wrapper, ok := item.Options.(option.InboundTLSOptionsWrapper); ok {
			tlsOptions := wrapper.TakeInboundTLSOptions()
			if tlsOptions != nil && tlsOptions.Enabled && tlsOptions.CertificateProvider != nil {
				provider := tlsOptions.CertificateProvider
				if provider.Tag != "" {
					deps = append(deps, "certificate-provider:"+provider.Tag)
				} else {
					extra, _ := providerDependencies(provider.Options)
					deps = append(deps, extra...)
				}
			}
		}
		node, err := makeNode(name, &item, deps, true)
		if err != nil {
			return nil, nil, err
		}
		if _, exists := configs[name]; exists {
			return nil, nil, fmt.Errorf("duplicate runtime service")
		}
		configs[name] = runtimeNodeOptions{node: node, service: &item}
		for _, inboundName := range privateInbounds {
			config, exists := configs[inboundName]
			if !exists {
				return nil, nil, fmt.Errorf("service managed inbound absent: %s", inboundName)
			}
			config.node.dependencies = append(config.node.dependencies, name)
			configs[inboundName] = config
		}
	}
	// Memory-pressure readers capture an exact OOM service pointer during native
	// setup. Multiple OOM definitions are rejected rather than map-order selected.
	oomName := ""
	for name, config := range configs {
		if config.service != nil {
			if _, ok := config.service.Options.(*option.OOMKillerServiceOptions); ok {
				if oomName != "" {
					return nil, nil, fmt.Errorf("multiple OOM services are ambiguous")
				}
				oomName = name
			}
		}
	}
	if oomName != "" {
		for name, config := range configs {
			kind := ""
			if config.inbound != nil {
				kind = config.inbound.Type
			}
			if config.outbound != nil {
				kind = config.outbound.Type
			}
			if config.endpoint != nil {
				kind = config.endpoint.Type
			}
			switch kind {
			case "wireguard", "tailscale", "tailcat", "openvpn", "openconnect", "masque":
				config.node.dependencies = append(config.node.dependencies, oomName)
				configs[name] = config
			}
		}
	}
	// Named HTTP definitions and the implicit default capture their actual
	// detour/resolver closure. The manager is a graph-owned component even when
	// there are no named definitions: its implicit default captures Final.
	var httpDeps []string
	if len(options.HTTPClients) == 0 && routeOptions.DefaultHTTPClient == "" {
		if routeOptions.Final != "" {
			httpDeps = append(httpDeps, "outbound:"+routeOptions.Final)
		}
	}
	var allHTTP []option.HTTPClientOptions
	for _, client := range options.HTTPClients {
		allHTTP = append(allHTTP, client.Options())
	}
	allHTTP = append(allHTTP, providerHTTP...)
	for _, value := range allHTTP {
		if value.Detour != "" {
			httpDeps = append(httpDeps, "outbound:"+value.Detour)
		}
		resolver := value.DomainResolver
		hasResolver := resolver != nil && (resolver.Server != "" || resolver.Mode == option.DomainResolverModeRules)
		if value.Detour == "" || value.ResolveOnDetour || hasResolver {
			httpDeps = append(httpDeps, "dns-router")
			if resolver != nil && resolver.Server != "" {
				httpDeps = append(httpDeps, "dns-transport:"+resolver.Server)
			}
		}
	}
	httpConfig := struct {
		Clients        []option.HTTPClient
		ProviderInline []option.HTTPClientOptions
		Default        string
	}{options.HTTPClients, providerHTTP, routeOptions.DefaultHTTPClient}
	httpNode, err := makeNode("http-manager", httpConfig, httpDeps, true)
	if err != nil {
		return nil, nil, err
	}
	configs["http-manager"] = runtimeNodeOptions{node: httpNode}
	dnsDeps := append(append([]string(nil), sets...), transports...)
	if dnsOptions.Final != "" {
		dnsDeps = append(dnsDeps, "dns-transport:"+dnsOptions.Final)
	}
	dnsNode, err := makeNode("dns-router", dnsOptions, dnsDeps, false)
	if err != nil {
		return nil, nil, err
	}
	configs["dns-router"] = runtimeNodeOptions{node: dnsNode}
	routeDeps := append(append(append([]string{"dns-router", "http-manager"}, sets...), outbounds...), inbounds...)
	if routeOptions.Final != "" {
		routeDeps = append(routeDeps, "outbound:"+routeOptions.Final)
	}
	routeNode, err := makeNode("route-router", routeOptions, routeDeps, false)
	if err != nil {
		return nil, nil, err
	}
	configs["route-router"] = runtimeNodeOptions{node: routeNode}
	if options.NTP != nil && options.NTP.Enabled {
		ntpOptions := *options.NTP
		var deps []string
		if ntpOptions.Detour != "" {
			deps = append(deps, "outbound:"+ntpOptions.Detour)
		}
		resolver := ntpOptions.DomainResolver
		serverDomain := ntpOptions.Server == "" || ntpOptions.ServerIsDomain()
		if serverDomain && (ntpOptions.Detour == "" || resolver != nil) {
			deps = append(deps, "dns-router")
			if resolver != nil && resolver.Server != "" {
				deps = append(deps, "dns-transport:"+resolver.Server)
			}
		}
		node, err := makeNode("ntp", ntpOptions, deps, true)
		if err != nil {
			return nil, nil, err
		}
		configs["ntp"] = runtimeNodeOptions{node: node}
		// Constructor-captured TLS clocks cannot silently switch to a replacement.
		// Shared clock/DNS cycles become one existing ownership cohort.
		for name, config := range configs {
			consumes := name == "http-manager" || config.service != nil || config.provider != nil || config.endpoint != nil || config.outbound != nil || config.transport != nil
			if config.inbound != nil && config.inbound.Type != C.TypeTun {
				consumes = true
			}
			if consumes {
				config.node.dependencies = append(config.node.dependencies, "ntp")
				configs[name] = config
			}
		}
	}
	// Outbound references may name an endpoint. Normalize only after the
	// complete inventory exists, and reject ambiguous namespaces before creation.
	endpointNames := make(map[string]string)
	for name, config := range configs {
		if config.endpoint != nil {
			if _, duplicate := configs["outbound:"+config.endpoint.Tag]; duplicate {
				return nil, nil, fmt.Errorf("duplicate outbound/endpoint tag: %s", config.endpoint.Tag)
			}
			endpointNames["outbound:"+config.endpoint.Tag] = name
		}
	}
	for name, config := range configs {
		for i, dependency := range config.node.dependencies {
			if endpointName, ok := endpointNames[dependency]; ok {
				config.node.dependencies[i] = endpointName
			}
		}
		configs[name] = config
	}
	var nodes []runtimeDependencyNode
	for _, config := range configs {
		nodes = append(nodes, config.node)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].name < nodes[j].name })
	return nodes, configs, nil
}

// TUN captures stable host services and constructor capabilities, not the
// immutable default-dialer/DNS policy used by ordinary graph consumers. The
// stable owner cannot replace monitor identities within one Box lifetime.
type runtimeTunPhysicalInput struct {
	NetworkMonitor, InterfaceMonitor, AndroidPackageRouting                                 bool
	Platform, PlatformInterface, NetworkExtension, IncludeAllNetworks, PlatformAutoRedirect bool
	OverrideAndroidVPN                                                                      bool
	BridgeInterfaces                                                                        []string
	LinuxGSO                                                                                bool
}

func runtimeTunPhysicalInputs(ctx context.Context, options option.Options, tunOptions *option.TunInboundOptions) (runtimeTunPhysicalInput, error) {
	var result runtimeTunPhysicalInput
	if options.Route != nil {
		result.OverrideAndroidVPN = options.Route.OverrideAndroidVPN
	}
	if network := service.FromContext[adapter.NetworkManager](ctx); network != nil {
		result.NetworkMonitor = network.NetworkMonitor() != nil
		result.InterfaceMonitor = network.InterfaceMonitor() != nil
		result.BridgeInterfaces = append([]string(nil), network.BridgeInterfaces()...)
		sort.Strings(result.BridgeInterfaces)
	}
	platform := service.FromContext[adapter.PlatformInterface](ctx)
	if platform != nil {
		result.Platform = true
		result.PlatformInterface = platform.UsePlatformInterface()
		result.NetworkExtension = platform.UnderNetworkExtension()
		if result.NetworkExtension {
			result.IncludeAllNetworks = platform.NetworkExtensionIncludeAllNetworks()
		}
		if tunOptions.AutoRedirect {
			result.PlatformAutoRedirect = platform.UsePlatformAutoRedirect()
		}
	}
	result.AndroidPackageRouting = C.IsAndroid && !result.Platform
	for _, outbound := range options.Outbounds {
		if outbound.Type == C.TypeBridge {
			return result, fmt.Errorf("TUN bridge topology cannot be precomputed before bridge physical startup; restart-required")
		}
	}
	if !C.IsLinux {
		return result, nil
	}
	mtu := tunOptions.MTU
	if mtu == 0 {
		if result.NetworkExtension {
			mtu = 4064
		} else if C.IsAndroid {
			mtu = 9000
		} else {
			mtu = 65535
		}
	}
	if !result.PlatformInterface {
		switch tunOptions.Stack {
		case "", "go", "gvisor":
			result.LinuxGSO = mtu < 49152
		}
	}
	// The concrete TUN Start scans TCP FlowOutbound only when there is no
	// platform interface object and constructor-derived GSO is still disabled.
	if !result.Platform && !result.LinuxGSO {
		flow, err := runtimeTunTCPFlowCapability(options)
		if err != nil {
			return result, err
		}
		result.LinuxGSO = flow
	}
	return result, nil
}

func runtimeTunTCPFlowCapability(options option.Options) (bool, error) {
	flow := false
	for _, outbound := range options.Outbounds {
		switch outbound.Type {
		case C.TypeBridge:
			flow = true // PreMatchFlow(TCP, invalid address) is Flow.
		case C.TypeDirect, C.TypeBlock, C.TypeDNS, C.TypeSOCKS, C.TypeHTTP, C.TypeShadowsocks, C.TypeSnell, C.TypeVMess, C.TypeTrojan, C.TypeNaive, C.TypeHysteria, C.TypeTor, C.TypeSSH, C.TypeShadowTLS, C.TypeAnyTLS, C.TypeShadowsocksR, C.TypeVLESS, C.TypeTUIC, C.TypeHysteria2, C.TypeSelector, C.TypeURLTest:
			// Direct only requests Flow for ICMP. These other built-ins do not
			// implement FlowOutbound; selector membership does not change that.
		default:
			return false, fmt.Errorf("TUN TCP FlowOutbound capability cannot be precomputed for outbound type %q", outbound.Type)
		}
	}
	for _, endpoint := range options.Endpoints {
		switch endpoint.Type {
		case C.TypeWireGuard, C.TypeTailscale, C.TypeOpenConnect, C.TypeOpenVPNClient, C.TypeOpenVPNServer, C.TypeMASQUEClient, C.TypeMASQUEServer:
			flow = true
		default:
			return false, fmt.Errorf("TUN TCP FlowOutbound capability cannot be precomputed for endpoint type %q", endpoint.Type)
		}
	}
	return flow, nil
}
