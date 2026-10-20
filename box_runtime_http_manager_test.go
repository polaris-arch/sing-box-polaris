package box

import (
	"context"
	"slices"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func runtimeHTTPNode(t *testing.T, options option.Options, name string) runtimeDependencyNode {
	t.Helper()
	nodes, _, err := runtimeConfigNodes(context.Background(), runtimeResolveGraphDefaults(options))
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		if node.name == name {
			return node
		}
	}
	t.Fatalf("missing component %q", name)
	return runtimeDependencyNode{}
}

func TestRuntimeHTTPImplicitDefaultCapturesSourceOrderFinal(t *testing.T) {
	options := option.Options{Outbounds: []option.Outbound{
		{Type: "direct", Tag: "z-first", Options: &option.DirectOutboundOptions{}},
		{Type: "direct", Tag: "a-second", Options: &option.DirectOutboundOptions{}},
	}}
	manager := runtimeHTTPNode(t, options, "http-manager")
	if !slices.Contains(manager.dependencies, "outbound:z-first") || slices.Contains(manager.dependencies, "outbound:a-second") {
		t.Fatalf("incorrect implicit capture: %v", manager.dependencies)
	}
	router := runtimeHTTPNode(t, options, "route-router")
	if !slices.Contains(router.dependencies, "http-manager") {
		t.Fatal("router's HTTP manager capture is missing")
	}
}

func TestRuntimeHTTPNamedDefinitionsCaptureResolverAndDetour(t *testing.T) {
	options := option.Options{HTTPClients: []option.HTTPClient{{Tag: "updates", DialerOptions: option.DialerOptions{Detour: "proxy", AbstractDialerOptions: option.AbstractDialerOptions{DomainResolver: &option.DomainResolveOptions{Server: "bootstrap"}}}}}}
	node := runtimeHTTPNode(t, options, "http-manager")
	for _, dependency := range []string{"outbound:proxy", "dns-router", "dns-transport:bootstrap"} {
		if !slices.Contains(node.dependencies, dependency) {
			t.Fatalf("missing %q: %v", dependency, node.dependencies)
		}
	}
	options.HTTPClients[0].DomainResolver = &option.DomainResolveOptions{Server: "replacement"}
	changed := runtimeHTTPNode(t, options, "http-manager")
	if node.fingerprint == changed.fingerprint {
		t.Fatal("HTTP definition edit did not invalidate owner")
	}
	if slices.Contains(node.dependencies, "dns-transport:replacement") {
		t.Fatal("detached dependency snapshot was mutated")
	}
}

func TestRuntimeHTTPDefaultSelectionAffectsFingerprint(t *testing.T) {
	options := option.Options{HTTPClients: []option.HTTPClient{{Tag: "a"}, {Tag: "b"}}, Route: &option.RouteOptions{DefaultHTTPClient: "a"}}
	first := runtimeHTTPNode(t, options, "http-manager")
	options.Route.DefaultHTTPClient = "b"
	second := runtimeHTTPNode(t, options, "http-manager")
	if first.fingerprint == second.fingerprint {
		t.Fatal("HTTP default selection missing from owner identity")
	}
}

func TestRuntimeInlineProviderHTTPCapturesReceivingManagerClosure(t *testing.T) {
	client := &option.HTTPClientOptions{DialerOptions: option.DialerOptions{Detour: "issuer-proxy", AbstractDialerOptions: option.AbstractDialerOptions{DomainResolver: &option.DomainResolveOptions{Server: "issuer-dns"}}}}
	options := option.Options{CertificateProviders: []option.CertificateProvider{{Type: "acme", Tag: "cert", Options: &option.ACMECertificateProviderOptions{HTTPClient: client}}}}
	first := runtimeHTTPNode(t, options, "http-manager")
	for _, dependency := range []string{"outbound:issuer-proxy", "dns-router", "dns-transport:issuer-dns"} {
		if !slices.Contains(first.dependencies, dependency) {
			t.Fatalf("missing inline provider capture %q", dependency)
		}
	}
	provider := runtimeHTTPNode(t, options, "certificate-provider:cert")
	if !slices.Contains(provider.dependencies, "http-manager") {
		t.Fatal("provider must retain its actual manager")
	}
	client.Detour = "new-proxy"
	second := runtimeHTTPNode(t, options, "http-manager")
	if first.fingerprint == second.fingerprint {
		t.Fatal("inline provider changed but receiving manager was reused")
	}
	if slices.Contains(first.dependencies, "outbound:new-proxy") {
		t.Fatal("old dependency snapshot mutated")
	}
}

func TestRuntimeNamedProviderHTTPReferenceDoesNotCreateInlineTransport(t *testing.T) {
	options := option.Options{HTTPClients: []option.HTTPClient{{Tag: "issuer", DialerOptions: option.DialerOptions{Detour: "shared-proxy"}}}, CertificateProviders: []option.CertificateProvider{{Type: "acme", Tag: "cert", Options: &option.ACMECertificateProviderOptions{HTTPClient: &option.HTTPClientOptions{Tag: "issuer"}}}}}
	node := runtimeHTTPNode(t, options, "http-manager")
	if !slices.Contains(node.dependencies, "outbound:shared-proxy") {
		t.Fatal("shared HTTP definition lost")
	}
	options.CertificateProviders[0].Options = &option.ACMECertificateProviderOptions{HTTPClient: &option.HTTPClientOptions{Tag: "other"}}
	changed := runtimeHTTPNode(t, options, "http-manager")
	if changed.fingerprint != node.fingerprint {
		t.Fatal("reference-only change recreated unchanged HTTP definitions")
	}
	provider := runtimeHTTPNode(t, options, "certificate-provider:cert")
	if !slices.Contains(provider.dependencies, "http-manager") {
		t.Fatal("reference lacks manager ownership")
	}
}
