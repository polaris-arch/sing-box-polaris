package api

import (
	"context"
	"runtime"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	boxCertificate "github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

type runtimeAPIPlatform struct{ adapter.PlatformInterface }

func (*runtimeAPIPlatform) UsePlatformAutoRedirect() bool            { return false }
func (*runtimeAPIPlatform) Initialize(adapter.NetworkManager) error  { return nil }
func (*runtimeAPIPlatform) UsePlatformDefaultInterfaceMonitor() bool { return true }
func (*runtimeAPIPlatform) CreateDefaultInterfaceMonitor(logger.Logger) tun.DefaultInterfaceMonitor {
	return nil
}
func (*runtimeAPIPlatform) UsePlatformNetworkInterfaces() bool                     { return true }
func (*runtimeAPIPlatform) NetworkInterfaces() ([]adapter.NetworkInterface, error) { return nil, nil }
func (*runtimeAPIPlatform) UsePlatformAutoDetectInterfaceControl() bool            { return false }
func (*runtimeAPIPlatform) UnderNetworkExtension() bool                            { return false }
func (*runtimeAPIPlatform) ClearDNSCache()                                         {}
func (*runtimeAPIPlatform) UsePlatformConnectionOwnerFinder() bool                 { return true }
func (*runtimeAPIPlatform) UsePlatformWIFIMonitor() bool                           { return true }
func (*runtimeAPIPlatform) UsePlatformNeighborResolver() bool                      { return false }

// Production API constructor, actual loopback transport and attached RPCs. The
// API JSON matches the App's default projection: no tag, dashboard, TLS or CORS.
// Only the OS monitor boundary is replaced. Port zero is test-only allocation.
func TestRuntimeDesktopDefaultAPIUsesOwningGraphAndExistingRPCs(t *testing.T) {
	if runtime.GOOS == "android" || runtime.GOOS == "windows" {
		t.Skip("native certificate/power boundary requires its platform fixture")
	}
	for _, secret := range []string{"", "synthetic"} {
		t.Run("secret="+secret, func(t *testing.T) {
			outbounds := outbound.NewRegistry()
			direct.RegisterOutbound(outbounds)
			socks.RegisterOutbound(outbounds)
			group.RegisterSelector(outbounds)
			transports := dns.NewTransportRegistry()
			transport.RegisterUDP(transports)
			services := boxService.NewRegistry()
			RegisterService(services)
			ctx := box.Context(context.Background(), inbound.NewRegistry(), outbounds, endpoint.NewRegistry(), transports, services, boxCertificate.NewRegistry())
			ctx = service.ContextWith[adapter.PlatformInterface](ctx, &runtimeAPIPlatform{})
			apiJSON := `{"type":"api","listen":"127.0.0.1","listen_port":0}`
			if secret != "" {
				apiJSON = `{"type":"api","listen":"127.0.0.1","listen_port":0,"secret":"synthetic"}`
			}
			content := `{"log":{"disabled":true},"dns":{"servers":[{"type":"udp","tag":"resolver","server":"192.0.2.53"}],"final":"resolver"},"outbounds":[{"type":"socks","tag":"a","server":"192.0.2.1","server_port":1080,"version":"5"},{"type":"socks","tag":"b","server":"192.0.2.2","server_port":1080,"version":"5"},{"type":"selector","tag":"select","outbounds":["a","b"],"default":"a"}],"route":{"final":"select","rule_set":[{"type":"inline","tag":"sites","rules":[{"domain_suffix":["example.test"]}]}]},"services":[` + apiJSON + `]}`
			var options option.Options
			if err := json.UnmarshalContext(ctx, []byte(content), &options); err != nil {
				t.Fatal(err)
			}
			instance, err := box.New(box.Options{Context: ctx, Options: options})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := instance.CloseWithResult(); err != nil {
					t.Errorf("Box cleanup: %v", err)
				}
			})
			if err := instance.Start(); err != nil {
				t.Fatal(err)
			}
			registered, found := service.FromContext[adapter.ServiceManager](ctx).Get("0")
			if !found {
				t.Fatal("default untagged API was not preserved")
			}
			api := registered.(*Service)
			if api.dashboard != nil || api.listener.TCPListener() == nil {
				t.Fatal("default API listener/dashboard projection changed")
			}
			connection, err := grpc.NewClient(api.listener.TCPListener().Addr().String(),
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithUnaryInterceptor(daemon.NewClientAuthUnaryInterceptor(secret)),
				grpc.WithStreamInterceptor(daemon.NewClientAuthStreamInterceptor(secret)))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			request, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var capabilities daemon.RuntimeCapabilities
			if err := connection.Invoke(request, "/daemon.RuntimeConfigService/GetRuntimeCapabilities", &emptypb.Empty{}, &capabilities); err != nil {
				t.Fatal(err)
			}
			if capabilities.Active == nil || capabilities.Active.Incarnation == "" || capabilities.Active.AppliedRevision != 1 || capabilities.ConnectedHotEnabled {
				t.Fatalf("attached owning identity/public gate mismatch: %+v", capabilities)
			}
			expectedRuleStatus := func() adapter.RuleSetLoadStatus {
				lease, _, connected, err := instance.AcquireRuntimeAPI()
				if err != nil || !connected {
					t.Fatalf("owning graph admission failed: connected=%v err=%v", connected, err)
				}
				defer lease.Release()
				identity := lease.View().Identity()
				if identity.Incarnation != capabilities.Active.Incarnation || identity.Revision != capabilities.Active.AppliedRevision {
					t.Fatal("attached API and direct admission identify different graphs")
				}
				set, found := lease.View().Router().RuleSet("sites")
				if !found {
					t.Fatal("owning graph is missing the fixture rule-set")
				}
				provider, ok := set.(adapter.RuleSetStatusProvider)
				if !ok {
					t.Fatal("owning rule-set has no status provider")
				}
				return provider.RuleSetStatus()
			}()
			// Inline rules have no accepted file bytes: reloadRules intentionally
			// publishes an empty digest. Revision/state prove the live inline set;
			// the empty digest must not be mistaken for a file acknowledgement.
			if expectedRuleStatus != (adapter.RuleSetLoadStatus{Revision: 1, WatcherState: "inline"}) {
				t.Fatalf("inline fixture status violates its source contract: %+v", expectedRuleStatus)
			}
			client := daemon.NewStartedServiceClient(connection)
			rules, err := client.GetRuleSetStatus(request, &daemon.RuleSetStatusRequest{Tags: []string{"sites"}})
			if err != nil || len(rules.GetRuleSets()) != 1 || rules.InstanceStartedAtUnixNano == 0 {
				t.Fatalf("attached rule-set status did not use the admitted graph: %+v %v", rules, err)
			}
			loaded := rules.RuleSets[0]
			actualRuleStatus := adapter.RuleSetLoadStatus{ActiveDigest: loaded.ActiveDigest, Revision: loaded.Revision, WatcherState: loaded.WatcherState, LastError: loaded.LastError, Closed: loaded.Closed}
			if loaded.Tag != "sites" || actualRuleStatus != expectedRuleStatus {
				t.Fatalf("attached rule-set status differs from its owning graph: tag=%q actual=%+v expected=%+v", loaded.Tag, actualRuleStatus, expectedRuleStatus)
			}
			stream, err := client.SubscribeOutbounds(request, &emptypb.Empty{})
			if err != nil {
				t.Fatal(err)
			}
			list, err := stream.Recv()
			if err != nil || len(list.GetOutbounds()) != 3 {
				t.Fatalf("attached outbound lookup failed: %+v %v", list, err)
			}
			if _, err := client.SelectOutbound(request, &daemon.SelectOutboundRequest{GroupTag: "select", OutboundTag: "b"}); err != nil {
				t.Fatal(err)
			}
			groupStream, err := client.SubscribeGroups(request, &emptypb.Empty{})
			if err != nil {
				t.Fatal(err)
			}
			groups, err := groupStream.Recv()
			if err != nil || len(groups.GetGroup()) != 1 || groups.Group[0].Selected != "b" {
				t.Fatalf("existing selector RPC no longer targets the live graph: %+v %v", groups, err)
			}
			if err := instance.CloseWithResult(); err != nil {
				t.Fatal(err)
			}
			if _, err := stream.Recv(); err == nil {
				t.Fatal("API subscription survived owning Box shutdown")
			}
		})
	}
}
