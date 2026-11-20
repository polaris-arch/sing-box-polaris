package adapter

import (
	"net/netip"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func TestRuntimeDashboardToggleExactClientShape(t *testing.T) {
	listen := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	off := option.APIServiceOptions{Listen: &listen, Secret: "same"}
	on := off
	on.Dashboard = &option.APIDashboardOptions{Enabled: true, Path: "/client/dashboard", HTTPClient: &option.HTTPClientOptions{Detour: "proxy"}}
	if !RuntimeDashboardToggleEligible(off, on) || !RuntimeDashboardToggleEligible(on, off) {
		t.Fatal("client toggle rejected")
	}
	if RuntimeDashboardToggleEligible(on, on) {
		t.Fatal("non-toggle claims new capability")
	}
	for _, change := range []func(*option.APIServiceOptions){
		func(v *option.APIServiceOptions) { v.Dashboard.DownloadURL = "https://foreign/archive.zip" },
		func(v *option.APIServiceOptions) { v.Dashboard.UpdateInterval = 1 },
		func(v *option.APIServiceOptions) { v.Dashboard.HTTPClient.Detour = "" },
		func(v *option.APIServiceOptions) { v.ReuseAddr = true },
		func(v *option.APIServiceOptions) { v.AccessControlAllowPrivateNetwork = true },
		func(v *option.APIServiceOptions) { x := badoption.Addr(netip.MustParseAddr("0.0.0.0")); v.Listen = &x },
		func(v *option.APIServiceOptions) { v.Dashboard.Path = "bad\x00path" },
	} {
		next := on
		d := *on.Dashboard
		c := *d.HTTPClient
		d.HTTPClient = &c
		next.Dashboard = &d
		change(&next)
		if RuntimeDashboardToggleEligible(off, next) {
			t.Fatalf("unsupported configuration admitted: %+v", next)
		}
	}
}

func TestRuntimeAPIDashboardAndRemoteListenersRemainLegacy(t *testing.T) {
	listen := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	options := &option.APIServiceOptions{Listen: &listen}
	item := option.Service{Type: C.TypeAPI, Options: options}
	if !RuntimeStableAPIService(item) {
		t.Fatal("plain local API rejected")
	}
	options.Dashboard = &option.APIDashboardOptions{Enabled: true}
	if RuntimeStableAPIService(item) {
		t.Fatal("dashboard dependency silently admitted")
	}
	options.Dashboard = nil
	listen = badoption.Addr(netip.MustParseAddr("0.0.0.0"))
	if RuntimeStableAPIService(item) {
		t.Fatal("non-loopback API admitted")
	}
}

func TestRuntimeDashboardDetourOnlyEligibility(t *testing.T) {
	listen := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	for _, test := range []struct {
		name   string
		change func(*option.HTTPClientOptions)
	}{
		{"named", func(c *option.HTTPClientOptions) { c.Tag = "named" }},
		{"empty", func(c *option.HTTPClientOptions) { c.Detour = "" }},
		{"engine", func(c *option.HTTPClientOptions) { c.Engine = "go" }},
		{"version", func(c *option.HTTPClientOptions) { c.Version = 2 }},
		{"hidden_default", func(c *option.HTTPClientOptions) { c.DefaultOutbound = true }},
		{"hidden_resolve", func(c *option.HTTPClientOptions) { c.ResolveOnDetour = true }},
		{"hidden_direct", func(c *option.HTTPClientOptions) { c.DirectResolver = true }},
		{"hidden_skip_check", func(c *option.HTTPClientOptions) { c.DisableEmptyDirectCheck = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &option.HTTPClientOptions{Detour: "select"}
			options := &option.APIServiceOptions{Listen: &listen, Dashboard: &option.APIDashboardOptions{Enabled: true, HTTPClient: client}}
			item := option.Service{Type: C.TypeAPI, Options: options}
			if !RuntimeStableAPIService(item) {
				t.Fatal("App inline detour-only dashboard rejected")
			}
			test.change(client)
			if RuntimeStableAPIService(item) {
				t.Fatal("unsupported dashboard client admitted")
			}
		})
	}
}

func TestRuntimeAPIListenerCanonicalizationAndCredentialBoundary(t *testing.T) {
	addr := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	mapped := badoption.Addr(netip.MustParseAddr("::ffff:127.0.0.1"))
	a := option.APIServiceOptions{Listen: &addr, ListenPort: 3001, Secret: "safe"}
	b := a
	b.Listen = &mapped
	da, _ := RuntimeAPIConfigDigest(a)
	db, _ := RuntimeAPIConfigDigest(b)
	if da != db || !RuntimeStableAPIService(option.Service{Type: C.TypeAPI, Options: &b}) {
		t.Fatal("mapped alias created a different physical owner")
	}
	zoned := badoption.Addr(netip.MustParseAddr("::1%lo"))
	b.Listen = &zoned
	if RuntimeStableAPIService(option.Service{Type: C.TypeAPI, Options: &b}) {
		t.Fatal("scoped address admitted")
	}
	if netip.Addr(*NormalizeRuntimeAPIOptions(b).Listen).Zone() == "" {
		t.Fatal("normalization erased a rejected scope")
	}
	for _, secret := range []string{"", "safe-!~"} {
		if !RuntimeAPISecretValid(secret) {
			t.Fatal("valid secret rejected")
		}
	}
	for _, secret := range []string{" leading", "line\nbreak", "unicode-密钥", string(make([]byte, 4097))} {
		if RuntimeAPISecretValid(secret) {
			t.Fatal("unsafe metadata credential admitted")
		}
	}
}
