package runtimeconfig

import (
	"fmt"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/option"
)

// EndpointDNS collects dependency edges for DNS transports and their endpoints.
// Add DNS transports before resolving endpoint dependencies.
type EndpointDNS struct {
	callbackConsumers map[string][]string
}

func (p *EndpointDNS) DNSDependencies(server option.DNSServerOptions, name string) ([]string, error) {
	var dependencies []string
	var callbackEndpoint string
	switch options := server.Options.(type) {
	case *option.OpenConnectDNSServerOptions:
		callbackEndpoint = options.Endpoint
	case *option.OpenVPNDNSServerOptions:
		callbackEndpoint = options.Endpoint
	}
	if server.Type == C.DNSTypeOpenConnect || server.Type == C.DNSTypeOpenVPN {
		if callbackEndpoint == "" {
			return nil, fmt.Errorf("endpoint DNS requires an explicit endpoint tag")
		}
		dependencies = append(dependencies, "endpoint:"+callbackEndpoint)
		if p.callbackConsumers == nil {
			p.callbackConsumers = make(map[string][]string)
		}
		p.callbackConsumers[callbackEndpoint] = append(p.callbackConsumers[callbackEndpoint], name)
	}
	if resolved, ok := server.Options.(*option.ResolvedDNSServerOptions); ok {
		dependencies = append(dependencies, "service:"+resolved.Service)
	}
	if tailscale, ok := server.Options.(*option.TailscaleDNSServerOptions); ok {
		if tailscale.Endpoint == "" {
			return nil, fmt.Errorf("runtime Tailscale DNS requires an explicit endpoint tag")
		}
		// The transport captures both the endpoint subscription and DNS router
		// used by the original child's immutable resolver snapshots.
		dependencies = append(dependencies, "endpoint:"+tailscale.Endpoint, "dns-router")
	}
	if wrapper, ok := server.Options.(option.DialerOptionsWrapper); ok {
		dialOptions := wrapper.TakeDialerOptions()
		if dialOptions.Detour != "" {
			dependencies = append(dependencies, "outbound:"+dialOptions.Detour)
		}
		if resolver := dialOptions.DomainResolver; resolver != nil && resolver.Server != "" {
			dependencies = append(dependencies, "dns-transport:"+resolver.Server)
		}
	}
	if remote, ok := server.Options.(option.ServerOptionsWrapper); ok && remote.TakeServerOptions().ServerIsDomain() {
		// TLS/HTTPS/QUIC also capture a resolver router for remote hostnames.
		if wrapper, ok := server.Options.(option.DialerOptionsWrapper); ok {
			dialOptions := wrapper.TakeDialerOptions()
			if dialOptions.Detour == "" || dialOptions.DomainResolver != nil {
				dependencies = append(dependencies, "dns-router")
			}
		}
	}
	return dependencies, nil
}

func (p *EndpointDNS) EndpointDependencies(endpoint option.Endpoint) []string {
	// Endpoint DNS transports register callbacks into the original endpoint.
	// Both ends must be recreated together.
	dependencies := append([]string(nil), p.callbackConsumers[endpoint.Tag]...)
	if wrapper, ok := endpoint.Options.(option.DialerOptionsWrapper); ok {
		dial := wrapper.TakeDialerOptions()
		if dial.Detour != "" {
			dependencies = append(dependencies, "outbound:"+dial.Detour)
		}
		// Peer/control hosts and endpoint-owned DNS use the captured graph,
		// including background sessions independent of an inbound request.
		dependencies = append(dependencies, "dns-router")
		if dial.DomainResolver != nil && dial.DomainResolver.Server != "" {
			dependencies = append(dependencies, "dns-transport:"+dial.DomainResolver.Server)
		}
	}
	return dependencies
}

// ResolveEndpointReferences rewrites outbound edges that target endpoints
// once every node is present. Duplicate tags fail before any edge is changed.
func ResolveEndpointReferences(nodes []runtimegraph.DependencyNode) error {
	aliases := make(map[string]string)
	for _, node := range nodes {
		if tag, endpoint := strings.CutPrefix(node.Name, "endpoint:"); endpoint {
			aliases["outbound:"+tag] = node.Name
		}
	}
	for _, node := range nodes {
		if _, ambiguous := aliases[node.Name]; ambiguous {
			return fmt.Errorf("duplicate outbound/endpoint tag: %s", strings.TrimPrefix(node.Name, "outbound:"))
		}
	}
	for _, node := range nodes {
		for i, dependency := range node.Dependencies {
			if endpoint, ok := aliases[dependency]; ok {
				node.Dependencies[i] = endpoint
			}
		}
	}
	return nil
}
