package api

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
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

// Production API constructor, actual loopback transport and attached RPCs, with
// the plain and bundled-dashboard variants of the untagged desktop API.
// Only the OS monitor boundary is replaced. Port zero is test-only allocation.
func TestRuntimeDesktopDefaultAPIUsesOwningGraphAndExistingRPCs(t *testing.T) {
	if runtime.GOOS == "android" || runtime.GOOS == "windows" {
		t.Skip("native certificate/power boundary requires its platform fixture")
	}
	for _, variant := range []struct {
		secret    string
		dashboard bool
	}{{"", false}, {"synthetic", false}, {"", true}, {"synthetic", true}} {
		t.Run(fmt.Sprintf("secret=%s/dashboard=%v", variant.secret, variant.dashboard), func(t *testing.T) {
			secret := variant.secret
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
			if variant.dashboard {
				path := t.TempDir()
				if err := os.WriteFile(filepath.Join(path, "index.html"), []byte("bundled-dashboard"), 0o644); err != nil {
					t.Fatal(err)
				}
				encodedPath, _ := json.Marshal(path)
				apiJSON = strings.TrimSuffix(apiJSON, "}") + `,"dashboard":{"enabled":true,"path":` + string(encodedPath) + `,"http_client":{"detour":"select"}}}`
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
			mode := "exact_configuration_file"
			if secret != "" {
				mode = "app_authoritative_regeneration"
			}
			var persistenceCalls atomic.Int32
			if err := instance.BindRuntimePersistenceOptions(func(identity box.RuntimeIdentity, content []byte) error {
				if identity.Incarnation == "" || len(content) == 0 {
					return errors.New("missing owner identity/content")
				}
				if persistenceCalls.Add(1) == 1 {
					return errors.New("synthetic transient owner failure")
				}
				if mode == "app_authoritative_regeneration" {
					return &box.RuntimeOwnerAcknowledgementRequiredError{Mode: mode}
				}
				return nil
			}, mode, true); err != nil {
				t.Fatal(err)
			}
			if err := instance.Start(); err != nil {
				t.Fatal(err)
			}
			registered, found := service.FromContext[adapter.ServiceManager](ctx).Get("0")
			if !found {
				t.Fatal("default untagged API was not preserved")
			}
			api := registered.(*Service)
			if (api.dashboard != nil) != variant.dashboard || api.listener.TCPListener() == nil {
				t.Fatal("default API listener/dashboard projection changed")
			}
			if variant.dashboard {
				if api.dashboard.done != nil {
					t.Fatal("user-provided bundle started a download worker")
				}
				response := httptest.NewRecorder()
				api.dashboard.serveHTTP(response, httptest.NewRequest("GET", "/dashboard/", nil))
				if response.Code != 200 || response.Body.String() != "bundled-dashboard" {
					t.Fatalf("bundle serving: %d %s", response.Code, response.Body.String())
				}
			}
			connection, err := grpc.NewClient(api.listener.TCPListener().Addr().String(),
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithUnaryInterceptor(daemon.NewClientAuthUnaryInterceptor(secret)),
				grpc.WithStreamInterceptor(daemon.NewClientAuthStreamInterceptor(secret)))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			requestStarted := time.Now()
			request, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			deadline, _ := request.Deadline()
			var phases []string
			observe := func(name string, at time.Time) {
				phases = append(phases, fmt.Sprintf("%s=+%s remaining=%s", name, at.Sub(requestStarted), deadline.Sub(at)))
			}
			mark := func(name string) { observe(name, time.Now()) }
			defer func() {
				t.Logf("API lifecycle observations: %s; %s", strings.Join(phases, "; "), runtimeAPICloseState(api))
			}()
			mark("RPC begin")
			if secret != "" {
				unauthorized, err := grpc.NewClient(api.listener.TCPListener().Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithUnaryInterceptor(daemon.NewClientAuthUnaryInterceptor("wrong-synthetic-secret")))
				if err != nil {
					t.Fatal(err)
				}
				_, denied := daemon.NewRuntimeConfigServiceClient(unauthorized).GetRuntimeCapabilities(request, &emptypb.Empty{})
				closeErr := unauthorized.Close()
				if status.Code(denied) != codes.Unauthenticated || closeErr != nil {
					t.Fatalf("public authentication boundary: %v, close: %v", denied, closeErr)
				}
			}
			var capabilities daemon.RuntimeCapabilities
			if err := connection.Invoke(request, "/daemon.RuntimeConfigService/GetRuntimeCapabilities", &emptypb.Empty{}, &capabilities); err != nil {
				t.Fatal(err)
			}
			if capabilities.Active == nil || capabilities.Active.Incarnation == "" || capabilities.Active.AppliedRevision != 1 || !capabilities.ConnectedHotEnabled {
				t.Fatalf("attached owning identity/public gate mismatch: %+v", capabilities)
			}
			mark("owning capabilities")
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
			mark("Outbounds first frame")
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
			mark("Groups first frame")
			// Use only generated public RPCs for the transaction. The control
			// revision is freshly read after the existing selector RPC above.
			runtimeClient := daemon.NewRuntimeConfigServiceClient(connection)
			current, err := runtimeClient.GetRuntimeCapabilities(request, &emptypb.Empty{})
			if err != nil || !current.GetConnectedHotEnabled() || current.GetImplementationManifestDigest() == "" {
				t.Fatalf("public capability: %+v %v", current, err)
			}
			plan, err := runtimeClient.PlanRuntimeConfig(request, &daemon.PlanRuntimeConfigRequest{ContractVersion: 1, Expected: current.Active, ExpectedControlRevision: current.ControlRevision, ConfigContent: strings.Replace(content, "example.test", "updated.test", 1)})
			if err != nil || !plan.GetApplicable() {
				t.Fatalf("public plan: %+v %v", plan, err)
			}
			mark("Plan complete")
			apply := &daemon.ApplyRuntimeConfigRequest{ContractVersion: 1, PlanId: plan.PlanId, TransactionId: plan.TransactionId, Expected: plan.Expected, ExpectedControlRevision: plan.ExpectedControlRevision, CandidateDigest: plan.CandidateDigest, AcceptedImpactDigest: plan.ImpactDigest}
			operation, err := runtimeClient.ApplyRuntimeConfig(request, apply)
			if err != nil || operation.GetState() != daemon.RuntimeOperationState_COMMITTED_DURABILITY_PENDING || operation.GetDurable() || persistenceCalls.Load() != 1 {
				t.Fatalf("public owner failure: %+v %v", operation, err)
			}
			if operation.Active.Incarnation != current.Active.Incarnation || operation.Active.AppliedRevision != current.Active.AppliedRevision+1 {
				t.Fatal("public Apply replaced instance or did not advance graph")
			}
			mark("Apply complete")
			receipt, err := runtimeClient.GetRuntimeConfigStatus(request, &daemon.RuntimeConfigStatusRequest{ContractVersion: 1, TransactionId: plan.TransactionId, RuntimeIncarnation: current.Active.Incarnation})
			if err != nil || receipt.GetOperation().GetState() != daemon.RuntimeOperationState_COMMITTED_DURABILITY_PENDING {
				t.Fatalf("public receipt: %+v %v", receipt, err)
			}
			mark("receipt complete")
			operation, err = runtimeClient.RetryRuntimePersistence(request, &daemon.RuntimePersistenceRetryRequest{ContractVersion: 1, TransactionId: plan.TransactionId, Active: operation.Active, ControlRevision: operation.ControlRevision, PersistenceMode: mode})
			if err != nil || persistenceCalls.Load() != 2 {
				t.Fatalf("public retry: %+v %v", operation, err)
			}
			if mode == "app_authoritative_regeneration" {
				if operation.Durable || !operation.OwnerReloadAcknowledged {
					t.Fatal("reload receipt confused with durable owner acknowledgement")
				}
				operation, err = runtimeClient.AcknowledgeRuntimePersistence(request, &daemon.RuntimePersistenceAcknowledgementRequest{ContractVersion: 1, TransactionId: plan.TransactionId, Active: operation.Active, ControlRevision: operation.ControlRevision, PersistenceMode: mode, DesiredStateDigest: strings.Repeat("a", 64), DesiredStateRevision: "fixture-desired-1"})
				if err != nil {
					t.Fatal(err)
				}
			}
			if !operation.Durable || operation.State != daemon.RuntimeOperationState_COMMITTED {
				t.Fatalf("public persistence completion: %+v", operation)
			}
			mark("persistence complete")
			replay, err := runtimeClient.ApplyRuntimeConfig(request, apply)
			if err != nil || !replay.GetDurable() || replay.GetActive().GetAppliedRevision() != operation.Active.AppliedRevision || persistenceCalls.Load() != 2 {
				t.Fatalf("public replay repeated publication/persistence: %+v %v", replay, err)
			}
			mark("replay complete")
			owner := api.runtime
			owner.mu.Lock()
			generations := append([]*apiGeneration(nil), owner.generations...)
			endpoints := append([]*apiEndpoint(nil), owner.endpoints...)
			owner.mu.Unlock()
			if len(generations) != 1 || len(endpoints) != 1 {
				t.Fatal("rule-only HOT unexpectedly replaced API generation or endpoint")
			}
			generation, endpoint := generations[0], endpoints[0]
			type observation struct {
				name string
				at   time.Time
				err  error
			}
			terminals := make(chan observation, 2)
			ready := make(chan string, 2)
			readTerminal := func(name string, receive func() error) {
				ready <- name
				// HOT may have queued valid updates. Each stream has exactly
				// one reader, already running when the owner is closed.
				for {
					if receiveErr := receive(); receiveErr != nil {
						terminals <- observation{name, time.Now(), receiveErr}
						return
					}
				}
			}
			go readTerminal("Outbounds terminal", func() error { _, err := stream.Recv(); return err })
			go readTerminal("Groups terminal", func() error { _, err := groupStream.Recv(); return err })
			for range 2 {
				select {
				case name := <-ready:
					mark(name + " reader ready")
				case <-request.Done():
					t.Fatalf("subscription readers missed total deadline: %v; %s", request.Err(), runtimeAPICloseState(api))
				}
			}
			select {
			case early := <-terminals:
				t.Fatalf("%s before Close: %v", early.name, early.err)
			default:
			}
			witnesses := make(chan observation, 4)
			for name, done := range map[string]<-chan struct{}{
				"owner cancellation observed":    owner.ctx.Done(),
				"owner closeDone observed":       owner.closeDone,
				"endpoint Serve return observed": endpoint.serveDone,
				"generation done observed":       generation.done,
			} {
				go func(name string, done <-chan struct{}) {
					select {
					case <-done:
						witnesses <- observation{name: name, at: time.Now()}
					case <-request.Done():
					}
				}(name, done)
			}
			entered := make(chan time.Time, 1)
			closed := make(chan observation, 1)
			go func() {
				entered <- time.Now()
				err := instance.CloseWithResult()
				closed <- observation{"Close return", time.Now(), err}
			}()
			var closeEntered time.Time
			select {
			case closeEntered = <-entered:
				observe("Close enter", closeEntered)
			case <-request.Done():
				t.Fatalf("Close did not enter before total deadline: %v; %s", request.Err(), runtimeAPICloseState(api))
			}
			for pendingClose, pendingStreams, pendingWitnesses := true, 2, 4; pendingClose || pendingStreams != 0 || pendingWitnesses != 0; {
				select {
				case result := <-closed:
					observe(result.name, result.at)
					if result.err != nil || request.Err() != nil || !result.at.Before(deadline) {
						t.Fatalf("Close failed or exceeded total deadline: %v context=%v; %s", result.err, request.Err(), runtimeAPICloseState(api))
					}
					pendingClose = false
				case result := <-terminals:
					observe(fmt.Sprintf("%s [%v]", result.name, result.err), result.at)
					if result.at.Before(closeEntered) {
						t.Fatalf("%s preceded Close: %v", result.name, result.err)
					}
					if err := runtimeAPISubscriptionTerminalError(request, result.err); err != nil || !result.at.Before(deadline) {
						t.Fatalf("%s is not owner shutdown before total deadline: %v; %s", result.name, err, runtimeAPICloseState(api))
					}
					pendingStreams--
				case witness := <-witnesses:
					observe(witness.name, witness.at)
					if request.Err() != nil || !witness.at.Before(deadline) {
						t.Fatalf("%s missed total deadline; %s", witness.name, runtimeAPICloseState(api))
					}
					pendingWitnesses--
				case <-request.Done():
					t.Fatalf("API shutdown exceeded total deadline: pending Close=%v streams=%d witnesses=%d: %v; %s", pendingClose, pendingStreams, pendingWitnesses, request.Err(), runtimeAPICloseState(api))
				}
			}
			endpoint.mu.Lock()
			carriers := len(endpoint.conns)
			endpoint.mu.Unlock()
			generation.mu.Lock()
			ordinary := generation.ordinary
			generation.mu.Unlock()
			if carriers != 0 || ordinary != 0 {
				t.Fatalf("closed API retained carriers=%d borrowers=%d; %s", carriers, ordinary, runtimeAPICloseState(api))
			}
		})
	}
}

// A client deadline/cancellation can terminate a stream while its owner remains
// live. Callers must also join the independent owner/handler/carrier witnesses.
func runtimeAPISubscriptionTerminalError(request context.Context, receiveErr error) error {
	if receiveErr == nil {
		return errors.New("subscription has no terminal error")
	}
	if status.Code(receiveErr) == codes.DeadlineExceeded || errors.Is(receiveErr, context.DeadlineExceeded) {
		return fmt.Errorf("subscription reached deadline: %w", receiveErr)
	}
	if err := request.Err(); err != nil {
		return fmt.Errorf("subscription request ended independently of owner shutdown: %w", err)
	}
	return nil
}

func runtimeAPIChannelClosed(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// This is a locked diagnostic snapshot, not an inferred completion event. The
// named done channels above are observed separately and remain authoritative.
func runtimeAPICloseState(api *Service) string {
	owner := api.runtime
	owner.mu.Lock()
	closing := owner.closing
	generations := append([]*apiGeneration(nil), owner.generations...)
	endpoints := append([]*apiEndpoint(nil), owner.endpoints...)
	owner.mu.Unlock()
	state := fmt.Sprintf("owner closing=%v canceled=%v done=%v", closing, owner.ctx.Err(), runtimeAPIChannelClosed(owner.closeDone))
	for index, endpoint := range endpoints {
		endpoint.mu.Lock()
		closing, carriers := endpoint.closing, len(endpoint.conns)
		endpoint.mu.Unlock()
		state += fmt.Sprintf(" endpoint[%d] closing=%v carriers=%d serveDone=%v", index, closing, carriers, runtimeAPIChannelClosed(endpoint.serveDone))
	}
	for index, generation := range generations {
		generation.mu.Lock()
		closing, ordinary := generation.closing, generation.ordinary
		generation.mu.Unlock()
		state += fmt.Sprintf(" generation[%d] closing=%v borrowers=%d done=%v", index, closing, ordinary, runtimeAPIChannelClosed(generation.done))
	}
	return state
}
