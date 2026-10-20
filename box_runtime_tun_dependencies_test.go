package box

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/service"
)

func tunDependencyFixtureNode(t *testing.T, ctx context.Context, options option.Options) runtimeDependencyNode {
	t.Helper()
	_, configs, err := runtimeConfigNodes(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	return configs["inbound:tun"].node
}

func TestRuntimeTunDoesNotCaptureDefaultResolverOrProxyConfiguration(t *testing.T) {
	options := option.Options{Inbounds: []option.Inbound{{Type: C.TypeTun, Tag: "tun", Options: &option.TunInboundOptions{}}}, Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}}}}
	before := tunDependencyFixtureNode(t, context.Background(), options)
	options.Route = &option.RouteOptions{DefaultDomainResolver: &option.DomainResolveOptions{Server: "resolver"}}
	options.DNS = &option.DNSOptions{Servers: []option.DNSServerOptions{{Type: C.DNSTypeUDP, Tag: "resolver", Options: &option.RemoteDNSServerOptions{}}}}
	after := tunDependencyFixtureNode(t, context.Background(), options)
	if before.fingerprint != after.fingerprint {
		t.Fatal("default DNS policy recreated unchanged TUN")
	}
	options.Outbounds = append(options.Outbounds, option.Outbound{Type: C.TypeVLESS, Tag: "new-proxy", Options: map[string]any{"server": "example.invalid"}})
	more := tunDependencyFixtureNode(t, context.Background(), options)
	if after.fingerprint != more.fingerprint {
		t.Fatal("ordinary proxy addition recreated unchanged TUN")
	}
}

func TestRuntimeTunKeepsExplicitRouteSetDependencies(t *testing.T) {
	options := option.Options{Inbounds: []option.Inbound{{Type: C.TypeTun, Tag: "tun", Options: &option.TunInboundOptions{RouteAddressSet: []string{"include"}, RouteExcludeAddressSet: []string{"exclude"}}}}}
	node := tunDependencyFixtureNode(t, context.Background(), options)
	joined := strings.Join(node.dependencies, ",")
	if !strings.Contains(joined, "rule-set:include") || !strings.Contains(joined, "rule-set:exclude") {
		t.Fatal("physical route set dependency omitted", node.dependencies)
	}
}

func TestRuntimeTunTCPFlowCapabilityIsNotProxyMembership(t *testing.T) {
	base := option.Options{Outbounds: []option.Outbound{{Type: C.TypeDirect}, {Type: C.TypeVLESS}, {Type: C.TypeSelector}}}
	flow, err := runtimeTunTCPFlowCapability(base)
	if err != nil || flow {
		t.Fatal("ordinary proxies incorrectly require TCP Flow", flow, err)
	}
	base.Endpoints = []option.Endpoint{{Type: C.TypeWireGuard}}
	flow, err = runtimeTunTCPFlowCapability(base)
	if err != nil || !flow {
		t.Fatal("WireGuard capability omitted", flow, err)
	}
	base.Endpoints = []option.Endpoint{{Type: "custom-unknown"}}
	if _, err = runtimeTunTCPFlowCapability(base); err == nil {
		t.Fatal("unknown endpoint capability guessed")
	}
}

func TestRuntimeTunLinuxGSOFingerprintCapturesFirstFlowEndpoint(t *testing.T) {
	if !C.IsLinux {
		t.Skip("native Linux TUN capability")
	}
	options := option.Options{}
	before, err := runtimeTunPhysicalInputs(context.Background(), options, &option.TunInboundOptions{})
	if err != nil {
		t.Fatal(err)
	}
	options.Endpoints = []option.Endpoint{{Type: C.TypeWireGuard}}
	after, err := runtimeTunPhysicalInputs(context.Background(), options, &option.TunInboundOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if before.LinuxGSO || !after.LinuxGSO {
		t.Fatal("startup capability transition not captured")
	}
	already, err := runtimeTunPhysicalInputs(context.Background(), option.Options{}, &option.TunInboundOptions{MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	if !already.LinuxGSO {
		t.Fatal("constructor-derived GSO omitted")
	}
}

type tunDependencyHostFixture struct {
	adapter.NetworkManager
	bridges []string
}

func (*tunDependencyHostFixture) NetworkMonitor() tun.NetworkUpdateMonitor      { return nil }
func (*tunDependencyHostFixture) InterfaceMonitor() tun.DefaultInterfaceMonitor { return nil }
func (h *tunDependencyHostFixture) BridgeInterfaces() []string                  { return h.bridges }
func TestRuntimeTunStableBridgeFingerprintAndUnknownTopologyGap(t *testing.T) {
	host := &tunDependencyHostFixture{bridges: []string{"br-b", "br-a"}}
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegister[adapter.NetworkManager](ctx, host)
	before, err := runtimeTunPhysicalInputs(ctx, option.Options{}, &option.TunInboundOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if before.BridgeInterfaces[0] != "br-a" || host.bridges[0] != "br-b" {
		t.Fatal("bridge fingerprint aliased live inventory")
	}
	host.bridges = []string{"br-c"}
	after, err := runtimeTunPhysicalInputs(ctx, option.Options{}, &option.TunInboundOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if before.BridgeInterfaces[0] == after.BridgeInterfaces[0] {
		t.Fatal("actual stable host bridge change omitted")
	}
	_, err = runtimeTunPhysicalInputs(ctx, option.Options{Outbounds: []option.Outbound{{Type: C.TypeBridge}}}, &option.TunInboundOptions{})
	if err == nil || !strings.Contains(err.Error(), "bridge topology") {
		t.Fatal("generated bridge topology was guessed", err)
	}
}
