package box

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestRuntimeEndpointReferencesUseActualEndpointCohort(t *testing.T) {
	options := runtimeResolveGraphDefaults(option.Options{
		Endpoints: []option.Endpoint{{Type: C.TypeWireGuard, Tag: "vpn", Options: &option.WireGuardEndpointOptions{}}},
		Outbounds: []option.Outbound{{Type: C.TypeSelector, Tag: "select", Options: &option.SelectorOutboundOptions{Outbounds: []string{"vpn"}}}},
	})
	nodes, configs, err := runtimeConfigNodes(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if configs["endpoint:vpn"].endpoint == nil {
		t.Fatal("endpoint inventory absent")
	}
	found := false
	for _, node := range nodes {
		if node.name == "outbound:select" {
			for _, dependency := range node.dependencies {
				if dependency == "outbound:vpn" {
					t.Fatal("endpoint reference retained wrong namespace")
				}
				if dependency == "endpoint:vpn" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("selector did not retain endpoint dependency")
	}
	if _, err := runtimeCohorts(nodes); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeEndpointOutboundAmbiguityRejectedBeforeConstruction(t *testing.T) {
	options := runtimeResolveGraphDefaults(option.Options{Endpoints: []option.Endpoint{{Type: C.TypeWireGuard, Tag: "vpn", Options: &option.WireGuardEndpointOptions{}}}, Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "vpn", Options: &option.DirectOutboundOptions{}}}})
	if _, _, err := runtimeConfigNodes(context.Background(), options); err == nil {
		t.Fatal("ambiguous endpoint/outbound namespace accepted")
	}
}

func TestRuntimeTailscaleDNSCapturesEndpointAndResolverRouter(t *testing.T) {
	options := runtimeResolveGraphDefaults(option.Options{
		Endpoints: []option.Endpoint{{Type: C.TypeTailscale, Tag: "tail", Options: &option.TailscaleEndpointOptions{}}},
		DNS:       &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{Servers: []option.DNSServerOptions{{Type: C.DNSTypeTailscale, Tag: "tail-dns", Options: &option.TailscaleDNSServerOptions{Endpoint: "tail"}}}}},
	})
	nodes, configs, err := runtimeConfigNodes(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	foundEndpoint, foundRouter := false, false
	for _, dependency := range configs["dns-transport:tail-dns"].node.dependencies {
		if dependency == "endpoint:tail" {
			foundEndpoint = true
		}
		if dependency == "dns-router" {
			foundRouter = true
		}
	}
	if !foundEndpoint || !foundRouter {
		t.Fatal("Tailscale DNS omitted its actual constructor captures")
	}
	if _, err := runtimeCohorts(nodes); err != nil {
		t.Fatal(err)
	}
	options.DNS.Servers[0].Options = &option.TailscaleDNSServerOptions{}
	if _, _, err := runtimeConfigNodes(context.Background(), options); err == nil {
		t.Fatal("missing endpoint admitted")
	}
}

func TestRuntimePushedDNSAndEndpointShareCallbackCohort(t *testing.T) {
	options := runtimeResolveGraphDefaults(option.Options{
		Endpoints: []option.Endpoint{{Type: C.TypeOpenConnect, Tag: "vpn", Options: &option.OpenConnectEndpointOptions{}}},
		DNS:       &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{Servers: []option.DNSServerOptions{{Type: C.DNSTypeOpenConnect, Tag: "pushed", Options: &option.OpenConnectDNSServerOptions{Endpoint: "vpn"}}}}},
	})
	nodes, _, err := runtimeConfigNodes(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	cohorts, err := runtimeCohorts(nodes)
	if err != nil {
		t.Fatal(err)
	}
	paired := false
	for _, cohort := range cohorts {
		endpoint, dns := false, false
		for _, name := range cohort.members {
			endpoint = endpoint || name == "endpoint:vpn"
			dns = dns || name == "dns-transport:pushed"
		}
		if endpoint && dns {
			paired = true
		}
	}
	if !paired {
		t.Fatal("endpoint callback and DNS owner can be reused separately")
	}
}
