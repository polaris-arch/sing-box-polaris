package adapter

import (
	"net/netip"
	"testing"

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
