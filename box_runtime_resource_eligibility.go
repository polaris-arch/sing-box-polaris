package box

import (
	"context"
	"fmt"

	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/common/httpclient"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// The same typed checks govern cold graph selection and public Plan. They are
// inert: no provider constructors, accounts, sockets, clock or storage writes.
func runtimeResourceEligibility(_ context.Context, options option.Options) []RuntimePlanError {
	var problems []RuntimePlanError
	add := func(code, path, message string) {
		problems = append(problems, RuntimePlanError{Code: code, Path: path, Message: message})
	}
	clients := make(map[string]bool)
	checkHTTP := func(path string, client option.HTTPClientOptions) {
		if client.Tag != "" {
			if !clients[client.Tag] {
				add("INVALID_DEPENDENCY_GRAPH", path, "HTTP client reference is absent from the candidate")
			}
			return
		}
		if err := httpclient.ValidateRuntimeOptions(client); err != nil {
			add("PENDING_ADAPTER", path, err.Error())
		}
	}
	for i, client := range options.HTTPClients {
		path := fmt.Sprintf("http_clients[%d]", i)
		if client.Tag == "" || clients[client.Tag] {
			add("INVALID_DEPENDENCY_GRAPH", path, "HTTP client definitions require unique nonempty tags")
		}
		clients[client.Tag] = true
		checkHTTP(path, client.Options())
	}
	if options.Route != nil && options.Route.DefaultHTTPClient != "" && !clients[options.Route.DefaultHTTPClient] {
		add("INVALID_DEPENDENCY_GRAPH", "route.default_http_client", "default HTTP client is absent from the candidate")
	}
	checkProvider := func(path, kind string, value any) {
		switch kind {
		case C.TypeACME:
			v, ok := value.(*option.ACMECertificateProviderOptions)
			if !ok || v == nil {
				add("PENDING_ADAPTER", path, "certificate provider options do not match its type")
				return
			}
			if !certificate.RuntimeACMEAvailable {
				add("PENDING_ADAPTER", path, "ACME is unavailable in this build")
			}
			// Certmagic's DNS discovery, OCSP HTTP and handshake-spawned workers
			// still lack receiving-owner hooks. HTTP issuer injection alone cannot
			// certify these native tails. Preserve ordinary cold-start semantics.
			if v.DNS01Challenge != nil {
				add("PENDING_ADAPTER", path+".dns01_challenge", "ACME DNS discovery and propagation require an owned runtime adapter")
			} else if certificate.RuntimeACMEAvailable {
				add("PENDING_ADAPTER", path, "ACME OCSP, challenge connections and handshake workers require owned runtime adapters")
			}
			if v.HTTPClient != nil {
				checkHTTP(path+".http_client", *v.HTTPClient)
			}
		case C.TypeCloudflareOriginCA:
			if !certificate.RuntimeDirectoryStorageAvailable {
				add("PENDING_ADAPTER", path+".data_directory", "this platform cannot retain the certificate storage directory identity")
			}
			v, ok := value.(*option.CloudflareOriginCACertificateProviderOptions)
			if !ok || v == nil {
				add("PENDING_ADAPTER", path, "certificate provider options do not match its type")
				return
			}
			if v.HTTPClient != nil {
				checkHTTP(path+".http_client", *v.HTTPClient)
			}
		case C.TypeTailscale:
			v, ok := value.(*option.TailscaleCertificateProviderOptions)
			if !ok || v == nil {
				add("PENDING_ADAPTER", path, "certificate provider options do not match its type")
				return
			}
			if !certificate.RuntimeTailscaleAvailable {
				add("PENDING_ADAPTER", path, "Tailscale certificates are unavailable in this build")
			}
			found := false
			for index, endpoint := range options.Endpoints {
				tag := endpoint.Tag
				if tag == "" {
					tag = fmt.Sprint(index)
				}
				if tag == v.Endpoint && endpoint.Type == C.TypeTailscale {
					found = true
				}
			}
			if v.Endpoint == "" || !found {
				add("INVALID_DEPENDENCY_GRAPH", path+".endpoint", "certificate provider requires a candidate Tailscale endpoint")
			}
		default:
			add("PENDING_ADAPTER", path, "certificate provider has no runtime adapter")
		}
	}
	providers := make(map[string]bool)
	for i, provider := range options.CertificateProviders {
		tag := provider.Tag
		if tag == "" {
			tag = fmt.Sprint(i)
		}
		path := fmt.Sprintf("certificate_providers[%d]", i)
		if providers[tag] {
			add("INVALID_DEPENDENCY_GRAPH", path, "certificate provider tags must be unique")
		}
		providers[tag] = true
		checkProvider(path, provider.Type, provider.Options)
	}
	for i, inbound := range options.Inbounds {
		wrapper, ok := inbound.Options.(option.InboundTLSOptionsWrapper)
		if !ok {
			continue
		}
		tls := wrapper.TakeInboundTLSOptions()
		if tls == nil || !tls.Enabled || tls.CertificateProvider == nil {
			continue
		}
		path := fmt.Sprintf("inbounds[%d].tls.certificate_provider", i)
		provider := tls.CertificateProvider
		if provider.Tag != "" {
			if !providers[provider.Tag] {
				add("INVALID_DEPENDENCY_GRAPH", path, "certificate provider reference is absent from the candidate")
			}
		} else {
			checkProvider(path, provider.Type, provider.Options)
		}
	}
	if options.NTP != nil && options.NTP.Enabled && options.NTP.WriteToSystem {
		add("PENDING_ADAPTER", "ntp.write_to_system", "irreversible system clock writes require an explicit host-managed restart")
	}
	return problems
}
