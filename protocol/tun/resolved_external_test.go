package tun

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	nativeTun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/service"
)

type resolvedTestNetworkManager struct {
	adapter.NetworkManager
}

func (*resolvedTestNetworkManager) InterfaceMonitor() nativeTun.DefaultInterfaceMonitor {
	return nil
}

func TestJSONResolvedOwnershipReachesInboundNativeOptions(t *testing.T) {
	for _, external := range []bool{false, true} {
		options := option.TunInboundOptions{}
		encoded, err := json.Marshal(map[string]any{
			"auto_route": true, "dns_mode": "hijack", "linux_resolved_external": external,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(encoded, &options); err != nil {
			t.Fatal(err)
		}
		ctx := service.ContextWith[adapter.NetworkManager](context.Background(), &resolvedTestNetworkManager{})
		value, err := NewInbound(ctx, nil, log.NewNOPFactory().Logger(), "test", options)
		if err != nil {
			t.Fatal(err)
		}
		inbound := value.(*Inbound)
		if inbound.tunOptions.LinuxResolvedExternal != external || inbound.tunOptions.DNSModeOrDefault() != nativeTun.DNSModeHijack || !inbound.tunOptions.AutoRoute {
			t.Fatalf("native options lost resolver ownership or DNS interception: %+v", inbound.tunOptions)
		}
	}
}
