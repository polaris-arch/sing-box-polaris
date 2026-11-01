package api

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/daemon"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	health "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

// An existing daemon method is registered only in this fixture. Its real unary
// callback blocks under the production ingress interceptor; no OS proxy is read
// or changed, and no additional production RPC is introduced.
type blockingAPIManaged struct {
	daemon.UnimplementedManagedServiceServer
	entered, release chan struct{}
}

func (b *blockingAPIManaged) GetSystemProxyStatus(ctx context.Context, _ *emptypb.Empty) (*daemon.SystemProxyStatus, error) {
	close(b.entered)
	select {
	case <-b.release:
		return &daemon.SystemProxyStatus{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func apiApplyRequest(p *daemon.RuntimeConfigPlan) *daemon.ApplyRuntimeConfigRequest {
	return &daemon.ApplyRuntimeConfigRequest{ContractVersion: 1, PlanId: p.PlanId, TransactionId: p.TransactionId, Expected: p.Expected, ExpectedControlRevision: p.ExpectedControlRevision, CandidateDigest: p.CandidateDigest, AcceptedImpactDigest: p.ImpactDigest}
}

func TestRuntimeAPIPrepareJoinsRealOrdinaryRPCAndStreamBeforePublication(t *testing.T) {
	_, api, ctx, content := handoffBox(t, "old")
	origin := api.runtime.generations[0]
	held := &blockingAPIManaged{entered: make(chan struct{}), release: make(chan struct{})}
	daemon.RegisterManagedServiceServer(origin.grpc, held)
	connection, err := grpc.NewClient(origin.endpoint.listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithUnaryInterceptor(daemon.NewClientAuthUnaryInterceptor("old")))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	ordinary := make(chan error, 1)
	go func() {
		_, e := daemon.NewManagedServiceClient(connection).GetSystemProxyStatus(ctx, &emptypb.Empty{})
		ordinary <- e
	}()
	select {
	case <-held.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	watch, err := health.NewHealthClient(connection).Watch(metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer old"), &health.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = watch.Recv(); err != nil {
		t.Fatal(err)
	}
	streamDone := make(chan error, 1)
	go func() { _, e := watch.Recv(); streamDone <- e }()
	client := daemon.NewRuntimeConfigServiceClient(connection)
	plan := handoffPlan(t, ctx, client, strings.Replace(content, `"secret":"old"`, `"secret":"new"`, 1))
	applied := make(chan error, 1)
	go func() { _, e := client.ApplyRuntimeConfig(ctx, apiApplyRequest(plan)); applied <- e }()
	select {
	case <-origin.admissionChanged:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case e := <-streamDone:
		if e == nil {
			t.Fatal("old stream was not canceled")
		}
	case <-ctx.Done():
		t.Fatal("stream did not join", ctx.Err())
	}
	select {
	case e := <-applied:
		t.Fatal("published before the real ordinary callback returned", e)
	default:
	}
	if _, err = client.GetRuntimeCapabilities(ctx, &emptypb.Empty{}); err == nil {
		t.Fatal("ordinary admission reopened during prepare")
	}
	close(held.release)
	select {
	case e := <-ordinary:
		if e != nil {
			t.Fatal(e)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case e := <-applied:
		if e != nil {
			t.Fatal(e)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	origin.mu.Lock()
	count := origin.ordinary
	origin.mu.Unlock()
	if count != 0 {
		t.Fatal("publication retained ordinary borrower", count)
	}
}

func TestRuntimeAPICancelledPrepareRestoresOriginalWithoutReapplying(t *testing.T) {
	_, api, ctx, content := handoffBox(t, "old")
	origin := api.runtime.generations[0]
	held := &blockingAPIManaged{entered: make(chan struct{}), release: make(chan struct{})}
	daemon.RegisterManagedServiceServer(origin.grpc, held)
	connection, err := grpc.NewClient(origin.endpoint.listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithUnaryInterceptor(daemon.NewClientAuthUnaryInterceptor("old")))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	ordinary := make(chan error, 1)
	go func() {
		_, e := daemon.NewManagedServiceClient(connection).GetSystemProxyStatus(ctx, &emptypb.Empty{})
		ordinary <- e
	}()
	select {
	case <-held.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	client := daemon.NewRuntimeConfigServiceClient(connection)
	plan := handoffPlan(t, ctx, client, strings.Replace(content, `"secret":"old"`, `"secret":"new"`, 1))
	call, cancel := context.WithCancel(ctx)
	defer cancel()
	applied := make(chan error, 1)
	go func() { _, e := client.ApplyRuntimeConfig(call, apiApplyRequest(plan)); applied <- e }()
	select {
	case <-origin.admissionChanged:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	api.runtime.mu.Lock()
	pending := api.runtime.pending
	api.runtime.mu.Unlock()
	if pending == nil {
		t.Fatal("missing actual prepared claim")
	}
	cancel()
	select {
	case <-pending.done:
	case <-ctx.Done():
		t.Fatal("candidate abort did not actually finish", ctx.Err())
	}
	api.runtime.mu.Lock()
	revoked := pending.authExpired && pending.key == [32]byte{}
	api.runtime.mu.Unlock()
	if !revoked {
		t.Fatal("aborted prepare retained verifier authority")
	}
	if _, err = client.GetRuntimeCapabilities(ctx, &emptypb.Empty{}); err != nil {
		t.Fatal("original recovery/ordinary channel lost", err)
	}
	state, err := client.GetRuntimeConfigStatus(ctx, &daemon.RuntimeConfigStatusRequest{ContractVersion: 1, TransactionId: plan.TransactionId, RuntimeIncarnation: plan.Expected.Incarnation})
	if err != nil || state.Active.AppliedRevision != plan.Expected.AppliedRevision {
		t.Fatal("cancelled preparation published or lost status", state, err)
	}
	close(held.release)
	select {
	case <-ordinary:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case e := <-applied:
		if e == nil {
			t.Fatal("canceled RPC reported success")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestRuntimeAPIExclusiveClaimRejectsConcurrentOrdinaryBind(t *testing.T) {
	_, api, _, _ := handoffBox(t, "old")
	address := api.runtime.generations[0].endpoint.listener.Addr().String()
	rival, err := net.Listen("tcp", address)
	if err == nil {
		rival.Close()
		t.Fatal("another listener took an owned tuple")
	}
	if errors.Is(err, net.ErrClosed) {
		t.Fatal("fixture did not test a live claim", err)
	}
}
