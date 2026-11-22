package daemon

import (
	"context"
	"crypto/sha256"
	"net"
	"strconv"
	"strings"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	boxCertificate "github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/group"
	boxHTTP "github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// These authentication-entry tests deliberately make no generated-message or
// wire compatibility claim. Descriptor/serialization tests must be added after
// the separately authorized protobuf output has been generated and inspected.
func TestRuntimeActorRequiresServerOwnedTypedContext(t *testing.T) {
	type clientActorKey string
	for _, ctx := range []context.Context{
		context.Background(),
		context.WithValue(context.Background(), clientActorKey("runtime_actor"), "client-supplied"),
		context.WithValue(context.Background(), runtimeActorKey{}, 42),
		ContextWithRuntimeActor(context.Background(), ""),
	} {
		if actor, err := runtimeActor(ctx); actor != "" || status.Code(err) != codes.Unauthenticated {
			t.Fatalf("untrusted actor scope accepted: %q %v", actor, err)
		}
	}
	parent := ContextWithRuntimeActor(context.Background(), "authenticated-a")
	child := ContextWithRuntimeActor(parent, "authenticated-b")
	if actor, err := runtimeActor(parent); err != nil || actor != "authenticated-a" {
		t.Fatal("child context mutated parent authentication scope")
	}
	if actor, err := runtimeActor(child); err != nil || actor != "authenticated-b" {
		t.Fatal("server actor scope did not propagate")
	}
}

func TestRuntimeRPCRejectsMissingActorBeforeReadingInstanceOrRequest(t *testing.T) {
	service := new(StartedService)
	ctx := context.Background()
	if _, err := service.GetRuntimeCapabilities(ctx, nil); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("capabilities authentication = %v", err)
	}
	if _, err := service.PlanRuntimeConfig(ctx, nil); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("plan authentication = %v", err)
	}
	if _, err := service.ApplyRuntimeConfig(ctx, nil); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("apply authentication = %v", err)
	}
	if _, err := service.GetRuntimeConfigStatus(ctx, nil); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("status authentication = %v", err)
	}
	ctx = ContextWithRuntimeActor(ctx, "authenticated-a")
	if _, err := service.GetRuntimeCapabilities(ctx, nil); status.Code(err) != codes.Unavailable {
		t.Fatalf("missing instance = %v", err)
	}
	if _, err := service.PlanRuntimeConfig(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil plan request = %v", err)
	}
	if _, err := service.ApplyRuntimeConfig(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil apply request = %v", err)
	}
	if _, err := service.GetRuntimeConfigStatus(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil status request = %v", err)
	}
}

func TestRuntimePlanRejectsUnknownImpactPolicyBeforeInstanceOrConfigPreparation(t *testing.T) {
	service := new(StartedService)
	request := &PlanRuntimeConfigRequest{ContractVersion: box.RuntimeConfigContractVersion, ClientImpactPolicyVersion: 2}
	if _, err := service.PlanRuntimeConfig(context.Background(), request); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("policy must not bypass server actor authentication: %v", err)
	}
	ctx := ContextWithRuntimeActor(context.Background(), "authenticated-a")
	if _, err := service.PlanRuntimeConfig(ctx, request); status.Code(err) != codes.InvalidArgument || status.Convert(err).Message() != "unsupported client impact policy version" {
		t.Fatalf("unknown policy was read as legacy or reached preparation: %v", err)
	}
}

func TestAuthorizePoolProbeRequiresCredentialedIngressAndBoundedRequest(t *testing.T) {
	service := new(StartedService)
	ctx := t.Context()
	owner := ContextWithRuntimeActor(ctx, "local-owner")
	credentialed := ContextWithPoolProbeAuthorization(owner)
	request := &AuthorizePoolProbeRequest{
		Graph:            strings.Repeat("a", 64) + "/1",
		MemberTag:        "member",
		ConnectAuthority: "probe.example:443",
	}
	if _, err := service.AuthorizePoolProbe(ContextWithPoolProbeAuthorization(ctx), request); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unidentified caller = %v", err)
	}
	if _, err := service.AuthorizePoolProbe(owner, request); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("uncredentialed local owner = %v", err)
	}
	if _, err := service.AuthorizePoolProbe(credentialed, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("missing request = %v", err)
	}
	if _, err := service.AuthorizePoolProbe(credentialed, request); status.Code(err) != codes.Unavailable {
		t.Fatalf("credentialed request with no runtime = %v", err)
	}
	request.ConnectAuthority = "http://probe.example:443"
	if _, err := service.AuthorizePoolProbe(credentialed, request); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("URL instead of authority = %v", err)
	}
}

func TestAuthorizePoolProbeUsesAdmittedGraphAndDoesNotSelect(t *testing.T) {
	inbounds := inbound.NewRegistry()
	boxHTTP.RegisterInbound(inbounds)
	outbounds := outbound.NewRegistry()
	direct.RegisterOutbound(outbounds)
	group.RegisterSelector(outbounds)
	transports := dns.NewTransportRegistry()
	transport.RegisterUDP(transports)
	ctx := box.Context(t.Context(), inbounds, outbounds, endpoint.NewRegistry(), transports, boxService.NewRegistry(), boxCertificate.NewRegistry())
	ctx = pause.WithDefaultManager(ctx)
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, &runtimeURLTestPlatform{})
	var options option.Options
	if err := json.UnmarshalContext(ctx, []byte(`{
		"log":{"disabled":true},
		"dns":{"servers":[{"type":"udp","tag":"resolver","server":"192.0.2.53"}],"final":"resolver"},
		"inbounds":[{"type":"http","tag":"probe-in-0","listen":"127.0.0.1"}],
		"outbounds":[{"type":"direct","tag":"direct"},{"type":"direct","tag":"probe"},
			{"type":"selector","tag":"probe-selector-0","outbounds":["direct","probe"],"default":"direct"}],
		"route":{"rules":[{"inbound":"probe-in-0","action":"route","outbound":"probe-selector-0"}],"final":"direct"}
	}`), &options); err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := instance.CloseWithResult(); err != nil {
			t.Error(err)
		}
	})
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	server := &StartedService{instance: &Instance{instance: instance, ctx: ctx}}
	transport := bufconn.Listen(64 * 1024)
	grpcServer := NewServer(server, "fixture-secret")
	go func() { _ = grpcServer.Serve(transport) }()
	t.Cleanup(grpcServer.Stop)
	client, err := grpc.NewClient("passthrough:///pool-probe-test", grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return transport.DialContext(ctx)
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	wire := NewRuntimeConfigServiceClient(client)
	wireContext := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer fixture-secret")
	owner := ContextWithRuntimeActor(ctx, "pool-probe-owner")
	credentialed := ContextWithPoolProbeAuthorization(owner)
	before, err := server.GetRuntimeCapabilities(credentialed, nil)
	if err != nil || before.PoolProbeTicketVersion != urltest.PoolProbeTicketVersion {
		t.Fatalf("capabilities did not advertise the authenticated ticket service: %v", err)
	}
	if uncredentialed, err := server.GetRuntimeCapabilities(owner, nil); err != nil || uncredentialed.PoolProbeTicketVersion != 0 {
		t.Fatalf("uncredentialed capabilities advertised ticket service: %v", err)
	}
	graph := before.Active.Incarnation + "/" + strconv.FormatUint(before.Active.AppliedRevision, 10)
	request := &AuthorizePoolProbeRequest{Graph: graph, MemberTag: "probe", ConnectAuthority: "192.0.2.10:443", Background: true}
	reply, err := wire.AuthorizePoolProbe(wireContext, request)
	if err != nil {
		t.Fatal(err)
	}
	if member, slot, ok := urltest.VerifyPoolProbeTicket(reply.Ticket, graph, sha256.Sum256([]byte("probe")), "192.0.2.10:443", true); !ok || member != "probe" || slot != 0 {
		t.Fatal("ticket did not bind the admitted member and slot")
	}
	request.Slot = 1
	if _, err := server.AuthorizePoolProbe(credentialed, request); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("missing probe slot = %v", err)
	}
	request.Slot, request.MemberTag = 0, "non-member"
	if _, err := server.AuthorizePoolProbe(credentialed, request); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("missing direct member = %v", err)
	}
	request.MemberTag, request.ConnectAuthority = "probe", "probe.example:443"
	var trailer metadata.MD
	if _, err := wire.AuthorizePoolProbe(wireContext, request, grpc.Trailer(&trailer)); status.Code(err) != codes.Unimplemented {
		t.Fatalf("direct member with domain resolution = %v", err)
	}
	if fallback := trailer.Get("x-polaris-pool-probe"); len(fallback) != 1 || fallback[0] != "legacy-member" {
		t.Fatal("known unsupported TCP member did not authorize compatibility fallback")
	}
	request.Graph = before.Active.Incarnation + "/" + strconv.FormatUint(before.Active.AppliedRevision+1, 10)
	trailer = nil
	if _, err := wire.AuthorizePoolProbe(wireContext, request, grpc.Trailer(&trailer)); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("different graph = %v", err)
	}
	if len(trailer.Get("x-polaris-pool-probe")) != 0 {
		t.Fatal("stale graph authorized compatibility fallback")
	}
	after, err := server.GetRuntimeCapabilities(credentialed, nil)
	if err != nil || before.ControlRevision != after.ControlRevision || before.Active.AppliedRevision != after.Active.AppliedRevision {
		t.Fatalf("issuing a ticket changed active or control revision: %v", err)
	}
}
