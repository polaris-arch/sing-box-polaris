package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"slices"
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
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/log"
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

type observedHostOOMKiller struct {
	boxService.Adapter
	options    option.OOMKillerServiceOptions
	stages     []adapter.StartStage
	closeCount int
	closeErr   error
}

func (s *observedHostOOMKiller) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	s.stages = append(s.stages, stage)
	if stage == adapter.StartStateStart {
		scope.Add(func() error { s.closeCount++; return s.closeErr })
	}
	return nil
}

func observeRuntimeHostOOMKiller(host *StartedService) *[]*observedHostOOMKiller {
	owners := new([]*observedHostOOMKiller)
	registry := service.FromContext[adapter.ServiceRegistry](host.ctx).(*boxService.Registry)
	boxService.Register[option.OOMKillerServiceOptions](registry, C.TypeOOMKiller, func(_ context.Context, _ log.ContextLogger, tag string, options option.OOMKillerServiceOptions) (adapter.Service, error) {
		owner := &observedHostOOMKiller{Adapter: boxService.NewAdapter(C.TypeOOMKiller, tag), options: options}
		*owners = append(*owners, owner)
		return owner, nil
	})
	return owners
}

func TestRuntimeHostOOMKillerStaysOwnedAcrossPublicationAndReplay(t *testing.T) {
	host, _ := retirementPureHost(t)
	observed := observeRuntimeHostOOMKiller(host)
	var persisted string
	ctx, err := ContextWithRuntimePersistenceMode(ContextWithRuntimeActor(t.Context(), "local-owner"), func(_ box.RuntimeIdentity, content []byte) error {
		persisted = string(content)
		return nil
	}, "exact_configuration_file")
	if err != nil {
		t.Fatal(err)
	}
	const initial = `{"log":{"disabled":true}}`
	const candidate = `{"log":{"disabled":true,"level":"warn"}}`
	const explicit = `{"log":{"disabled":true},"services":[{"type":"oom-killer"}]}`
	host.SetOOMKillerOptions(true, true, 123)
	if err := host.StartOrReloadService(ctx, initial, nil); err != nil {
		t.Fatal(err)
	}
	owners := *observed
	active := host.instance.instance.RuntimeCapabilities().Identity
	initialDigest := sha256.Sum256([]byte(initial))
	if active.Revision != 1 || active.EffectiveDigest != hex.EncodeToString(initialDigest[:]) {
		t.Fatalf("startup digest did not represent the profile: %+v", active)
	}
	if len(owners) != 1 || !owners[0].options.KillerDisabled || owners[0].options.MemoryLimitOverride != 123 || !slices.Equal(owners[0].stages, adapter.ListStartStages) || owners[0].closeCount != 0 {
		t.Fatalf("startup lost the OOM policy or lifecycle: %+v", owners)
	}
	plan := func(content string) *RuntimeConfigPlan {
		t.Helper()
		result, err := host.PlanRuntimeConfig(ctx, &PlanRuntimeConfigRequest{
			ContractVersion: box.RuntimeConfigContractVersion, ConfigContent: content,
			Expected: runtimeIdentity(active), ExpectedControlRevision: active.ControlRevision,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	for _, change := range []struct {
		enabled, reportOnly bool
		limit               uint64
		content             string
	}{
		{false, true, 123, candidate},
		{true, false, 123, candidate},
		{true, true, 456, candidate},
		{true, true, 123, explicit},
	} {
		host.SetOOMKillerOptions(change.enabled, change.reportOnly, change.limit)
		rejected := plan(change.content)
		if rejected.Applicable || len(rejected.Errors) != 1 || rejected.Errors[0].Code != "RESTART_REQUIRED" || rejected.Errors[0].EffectivePath != "services.oom-killer" {
			t.Fatalf("changed OOM policy was not classified as restart-only: %+v", rejected)
		}
	}
	host.SetOOMKillerOptions(true, true, 123)
	if result := plan(initial); !result.Applicable || !result.NoOp {
		t.Fatalf("host OOM changed the profile's no-op comparison: %+v", result)
	}
	planned := plan(candidate)
	if !planned.Applicable || planned.NoOp || len(planned.Errors) != 0 {
		t.Fatalf("plain profile change did not plan with host OOM: %+v", planned)
	}
	result, err := host.ApplyRuntimeConfig(ctx, &ApplyRuntimeConfigRequest{
		ContractVersion: box.RuntimeConfigContractVersion, Expected: runtimeIdentity(active), ExpectedControlRevision: active.ControlRevision,
		PlanId: planned.PlanId, TransactionId: planned.TransactionId, CandidateDigest: planned.CandidateDigest, AcceptedImpactDigest: planned.ImpactDigest,
	})
	if err != nil || result.State != RuntimeOperationState_COMMITTED || persisted != candidate {
		t.Fatalf("apply or persistence failed: %+v, %v; content = %q", result, err, persisted)
	}
	owners = *observed
	if len(owners) != 1 || !slices.Equal(owners[0].stages, adapter.ListStartStages) || owners[0].closeCount != 0 {
		t.Fatal("graph publication restarted or closed the host OOM service")
	}
	if err := host.StartOrReloadService(ctx, persisted, nil); err != nil {
		t.Fatal(err)
	}
	owners = *observed
	if len(owners) != 2 || owners[0].closeCount != 1 || !slices.Equal(owners[1].stages, adapter.ListStartStages) || owners[1].options != owners[0].options {
		t.Fatal("reload did not close and reapply the same host OOM policy")
	}
	if err := host.CloseService(); err != nil || owners[0].closeCount != 1 || owners[1].closeCount != 1 {
		t.Fatalf("host OOM close did not run exactly once per Box: %v", err)
	}
}

func TestRuntimeHostOOMKillerClosesWhenIngressCleanupFails(t *testing.T) {
	host, _ := retirementPureHost(t)
	owners := observeRuntimeHostOOMKiller(host)
	ingressFailure := errors.New("test ingress cleanup failure")
	oomFailure := errors.New("test host OOM cleanup failure")
	registry := service.FromContext[adapter.ServiceRegistry](host.ctx).(*boxService.Registry)
	boxService.Register[option.APIServiceOptions](registry, C.TypeAPI, func(context.Context, log.ContextLogger, string, option.APIServiceOptions) (adapter.Service, error) {
		return &failingTransientService{closeErr: ingressFailure}, nil
	})
	host.SetOOMKillerOptions(true, true, 123)
	config := `{"log":{"disabled":true},"services":[{"type":"api","listen":"127.0.0.1","secret":"local-test-secret"}]}`
	if err := host.StartOrReloadService(t.Context(), config, nil); err != nil {
		t.Fatal(err)
	}
	if !host.instance.instance.RuntimeCapabilities().Enabled || len(*owners) != 1 {
		t.Fatal("startup did not create a graph and its host OOM service")
	}
	owner := (*owners)[0]
	owner.closeErr = oomFailure
	for range 2 {
		err := host.CloseService()
		if !errors.Is(err, ingressFailure) || !errors.Is(err, oomFailure) || owner.closeCount != 1 {
			t.Fatalf("close lost a cleanup result or repeated OOM cleanup: count = %d, error = %v", owner.closeCount, err)
		}
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
