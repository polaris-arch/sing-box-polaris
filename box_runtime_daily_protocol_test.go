package box

import (
	"context"
	"slices"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestDailyProtocolInventoryWithStablePersistentCache(t *testing.T) {
	for _, kind := range []string{C.TypeDirect, C.TypeSelector, C.TypeURLTest, C.TypeShadowsocks, C.TypeVMess, C.TypeVLESS, C.TypeTrojan, C.TypeAnyTLS, C.TypeSnell, C.TypeShadowTLS, C.TypeSSH, C.TypeHysteria, C.TypeTUIC} {
		t.Run(kind, func(t *testing.T) {
			options := option.Options{Outbounds: []option.Outbound{{Type: kind, Tag: "node"}}, DNS: &option.DNSOptions{Servers: []option.DNSServerOptions{{Type: C.DNSTypeUDP}}}, Experimental: &option.ExperimentalOptions{CacheFile: &option.CacheFileOptions{Enabled: true, StoreDNS: true, StoreFakeIP: true}}}
			_, problems := runtimeConfigCompatibility(context.Background(), []byte(`{}`), []byte(`{}`), options)
			if len(problems) != 0 {
				t.Fatalf("source-composed daily protocol blocked: %+v", problems)
			}
		})
	}
}

func TestDailyHysteria2RealmRequiresConcreteSupportedVariant(t *testing.T) {
	options := option.Options{Outbounds: []option.Outbound{{Type: C.TypeHysteria2, Tag: "node", Options: &option.Hysteria2OutboundOptions{}}}, DNS: &option.DNSOptions{Servers: []option.DNSServerOptions{{Type: C.DNSTypeFakeIP}}}}
	if _, problems := runtimeConfigCompatibility(context.Background(), []byte(`{}`), []byte(`{}`), options); len(problems) != 0 {
		t.Fatal(problems)
	}
	for _, mode := range []string{"supported", "missing-url", "missing-TLS", "custom-TLS", "missing-HTTP", "invalid-family"} {
		t.Run(mode, func(t *testing.T) {
			v := &option.Hysteria2OutboundOptions{}
			v.TLS = &option.OutboundTLSOptions{Enabled: true}
			v.Realm = &option.Hysteria2Realm{ServerURL: "https://control.invalid", STUNServers: []string{"127.0.0.1:3478"}}
			path, code := "", ""
			switch mode {
			case "missing-url":
				v.Realm.ServerURL = ""
				path, code = "outbounds[0].realm.server_url", "INVALID_DEPENDENCY_GRAPH"
			case "missing-TLS":
				v.TLS = nil
				path, code = "outbounds[0].tls", "INVALID_DEPENDENCY_GRAPH"
			case "custom-TLS":
				v.TLS.Engine = "apple"
				path, code = "outbounds[0].tls.engine", "PENDING_ADAPTER"
			case "missing-HTTP":
				v.Realm.HTTPClient = &option.HTTPClientOptions{Tag: "absent"}
				path, code = "outbounds[0].realm.http_client", "INVALID_DEPENDENCY_GRAPH"
			case "invalid-family":
				v.Realm.IPVersion = 7
				path, code = "outbounds[0].realm.ip_version", "INVALID_DEPENDENCY_GRAPH"
			}
			options.Outbounds[0].Options = v
			_, problems := runtimeConfigCompatibility(context.Background(), []byte(`{}`), []byte(`{}`), options)
			if path != "" && !slices.ContainsFunc(problems, func(p RuntimePlanError) bool { return p.Path == path && p.Code == code }) {
				t.Fatal("exact unsupported Realm variant lost its guard", problems)
			}
			for _, p := range problems {
				if p.Path == "outbounds[0].realm" && p.Code == "PENDING_ADAPTER" && !C.WithQUIC {
					continue
				}
				if p.Path == path && p.Code == code && path != "" {
					continue
				}
				t.Fatal("supported Realm variant stayed globally pending", problems)
			}
			if !C.WithQUIC && !slices.ContainsFunc(problems, func(p RuntimePlanError) bool { return p.Path == "outbounds[0].realm" && p.Code == "PENDING_ADAPTER" }) {
				t.Fatal("missing concrete build admitted Realm", problems)
			}
		})
	}
}

func TestDailyUserspaceEndpointAndPushedDNSInventory(t *testing.T) {
	for _, kind := range []string{C.TypeWireGuard, C.TypeOpenConnect, C.TypeOpenVPNClient, C.TypeMASQUEClient} {
		options := option.Options{Endpoints: []option.Endpoint{{Type: kind, Tag: "node"}}}
		if _, problems := runtimeConfigCompatibility(context.Background(), []byte(`{}`), []byte(`{}`), options); len(problems) != 0 {
			t.Fatal(kind, problems)
		}
	}
	for _, kind := range []string{C.DNSTypeOpenConnect, C.DNSTypeOpenVPN} {
		options := option.Options{DNS: &option.DNSOptions{Servers: []option.DNSServerOptions{{Type: kind, Tag: "pushed"}}}}
		if _, problems := runtimeConfigCompatibility(context.Background(), []byte(`{}`), []byte(`{}`), options); len(problems) != 0 {
			t.Fatal(kind, problems)
		}
	}
}

func TestDailyTorAndTFOUseSeparateReplacementValidation(t *testing.T) {
	for _, outbound := range []option.Outbound{
		{Type: C.TypeTor, Tag: "tor", Options: &option.TorOutboundOptions{}},
		{Type: C.TypeHTTP, Tag: "http", Options: &option.HTTPOutboundOptions{TCPFastOpen: true}},
	} {
		options := option.Options{Outbounds: []option.Outbound{outbound}}
		if _, problems := runtimeConfigCompatibility(context.Background(), []byte(`{}`), []byte(`{}`), options); len(problems) != 0 {
			t.Fatal(outbound.Type, problems)
		}
	}
}

func TestDailyNetworkProfileLocalAndDHCPDNSInventory(t *testing.T) {
	for _, kind := range []string{C.DNSTypeLocal, C.DNSTypeDHCP} {
		options := option.Options{DNS: &option.DNSOptions{Servers: []option.DNSServerOptions{{Type: kind, Tag: "network-profile"}}}}
		if _, problems := runtimeConfigCompatibility(context.Background(), []byte(`{}`), []byte(`{}`), options); len(problems) != 0 {
			t.Fatal(kind, problems)
		}
	}
	// This pure inventory fixture does not bypass DHCP's original auto-interface
	// monitor prerequisite or assert that privileged socket discovery will succeed.
}

func TestDailyTailscaleAndTailcatInventoryUsesReviewedAdapters(t *testing.T) {
	options := option.Options{
		Endpoints: []option.Endpoint{{Type: C.TypeTailscale, Tag: "tail", Options: &option.TailscaleEndpointOptions{}}},
		Outbounds: []option.Outbound{{Type: C.TypeTailcat, Tag: "lazy-tail"}},
		DNS:       &option.DNSOptions{Servers: []option.DNSServerOptions{{Type: C.DNSTypeTailscale, Tag: "tail-dns", Options: &option.TailscaleDNSServerOptions{Endpoint: "tail"}}}},
	}
	if _, problems := runtimeConfigCompatibility(context.Background(), []byte(`{}`), []byte(`{}`), options); len(problems) != 0 {
		t.Fatal(problems)
	}
	// Inventory eligibility does not bypass endpoint identity/directory preflight,
	// native build-tag registration, or Tailcat's original lazy session admission.
	// Endpoint/DNS references are checked separately before graph construction.
	capabilities := new(Box).RuntimeCapabilities()
	if capabilities.Enabled || capabilities.FullConfiguration {
		t.Fatal("source inventory enabled the public capability")
	}
	for _, pending := range capabilities.PendingAdapters {
		if pending == "outbounds[tailcat]" || pending == "endpoints[tailscale]" {
			t.Fatal("composed adapter still advertised as pending", pending)
		}
	}
}

func TestDailyStableAPICapabilityBoundary(t *testing.T) {
	capabilities := new(Box).RuntimeCapabilities()
	if capabilities.Enabled || capabilities.FullConfiguration {
		t.Fatal("stable API support enabled public capability")
	}
	found := false
	for _, pending := range capabilities.PendingAdapters {
		if pending == "services" {
			t.Fatal("unchanged plain loopback API is not a pending adapter")
		}
		if pending == "services[non-api-or-api-dependent-listener]" {
			found = true
		}
	}
	if !found {
		t.Fatal("unsupported service variants must remain explicit")
	}
}
