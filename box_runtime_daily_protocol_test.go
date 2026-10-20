package box

import (
	"context"
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

func TestDailyHysteria2RealmIsExplicitException(t *testing.T) {
	options := option.Options{Outbounds: []option.Outbound{{Type: C.TypeHysteria2, Tag: "node", Options: &option.Hysteria2OutboundOptions{}}}, DNS: &option.DNSOptions{Servers: []option.DNSServerOptions{{Type: C.DNSTypeFakeIP}}}}
	if _, problems := runtimeConfigCompatibility(context.Background(), []byte(`{}`), []byte(`{}`), options); len(problems) != 0 {
		t.Fatal(problems)
	}
	options.Outbounds[0].Options.(*option.Hysteria2OutboundOptions).Realm = &option.Hysteria2Realm{}
	_, problems := runtimeConfigCompatibility(context.Background(), []byte(`{}`), []byte(`{}`), options)
	if len(problems) != 1 || problems[0].Path != "outbounds[0].realm" {
		t.Fatal("Realm exception is not precise", problems)
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
