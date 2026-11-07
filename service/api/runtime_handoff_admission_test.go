package api

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/daemon"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	health "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// An existing daemon method is registered only in this fixture. Its real unary
// callback blocks under the production ingress interceptor; no OS proxy is read
// or changed, and no additional production RPC is introduced.
type blockingAPIManaged struct {
	daemon.UnimplementedManagedServiceServer
	entered, release         chan struct{}
	returned                 chan struct{}
	cancelled, returnRelease chan struct{}
}

func (b *blockingAPIManaged) GetSystemProxyStatus(ctx context.Context, _ *emptypb.Empty) (*daemon.SystemProxyStatus, error) {
	close(b.entered)
	if b.returned != nil {
		defer close(b.returned)
	}
	select {
	case <-b.release:
		return &daemon.SystemProxyStatus{}, nil
	case <-ctx.Done():
		if b.cancelled != nil {
			close(b.cancelled)
		}
		if b.returnRelease != nil {
			<-b.returnRelease
		}
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

// Hold both the real RPC's cancellation tail and its HTTP dispatch tail.
// Observe held-work snapshots, then release both and verify complete shutdown.
// These snapshots do not prove entry into Stop's handler join or deterministically
// reject an implementation missing that join.
func TestRuntimeAPICloseJoinsHeldDispatchAfterCarrierShutdown(t *testing.T) {
	instance, api, ctx, _ := handoffBox(t, "old")
	origin := api.runtime.generations[0]
	endpoint := origin.endpoint
	held := &blockingAPIManaged{entered: make(chan struct{}), release: make(chan struct{}), returned: make(chan struct{}), cancelled: make(chan struct{}), returnRelease: make(chan struct{})}
	daemon.RegisterManagedServiceServer(origin.grpc, held)
	captured := make(chan *apiOwnedConn, 1)
	tailEntered := make(chan struct{})
	tailRelease := make(chan struct{})
	tailReturned := make(chan struct{})
	defer func() {
		for _, release := range []chan struct{}{tailRelease, held.returnRelease} {
			if !runtimeAPIChannelClosed(release) {
				close(release)
			}
		}
	}()
	original := origin.handler
	// Installed before any request exists; only this existing test method is
	// held, with the same production ingress and gRPC server underneath it.
	origin.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != daemon.ManagedService_GetSystemProxyStatus_FullMethodName {
			original.ServeHTTP(w, r)
			return
		}
		carrier, _ := r.Context().Value(apiConnContextKey{}).(*apiOwnedConn)
		captured <- carrier
		original.ServeHTTP(w, r)
		close(tailEntered)
		<-tailRelease
		close(tailReturned)
	})
	connection, err := grpc.NewClient(endpoint.listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithUnaryInterceptor(daemon.NewClientAuthUnaryInterceptor("old")), grpc.WithStreamInterceptor(daemon.NewClientAuthStreamInterceptor("old")))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	ordinary := make(chan error, 1)
	go func() {
		_, err := daemon.NewManagedServiceClient(connection).GetSystemProxyStatus(ctx, &emptypb.Empty{})
		ordinary <- err
	}()
	select {
	case <-held.entered:
	case <-ctx.Done():
		t.Fatal("real RPC never entered", ctx.Err())
	}
	var carrier *apiOwnedConn
	select {
	case carrier = <-captured:
	case <-ctx.Done():
		t.Fatal("RPC has no captured carrier", ctx.Err())
	}
	endpoint.mu.Lock()
	_, retained := endpoint.conns[carrier]
	owned := carrier != nil && carrier.generation == origin
	endpoint.mu.Unlock()
	if !retained || !owned {
		t.Fatal("controlled RPC did not use its actual generation-owned carrier")
	}
	stream, err := daemon.NewStartedServiceClient(connection).SubscribeOutbounds(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal("inventory did not enter the real attached graph", err)
	}
	streamDone := make(chan error, 1)
	readerReady := make(chan struct{})
	go func() {
		close(readerReady)
		for {
			if _, err := stream.Recv(); err != nil {
				streamDone <- err
				return
			}
		}
	}()
	select {
	case <-readerReady:
	case <-ctx.Done():
		t.Fatal("inventory terminal reader did not start", ctx.Err())
	}
	closeStarted := time.Now()
	closed := make(chan error, 1)
	go func() { closed <- instance.CloseWithResult() }()
	select {
	case <-tailEntered:
	case err := <-closed:
		t.Fatal("Close returned before held dispatch reached its cancellation tail", err)
	case <-ctx.Done():
		t.Fatalf("owner did not cancel the real RPC: %v; %s", ctx.Err(), runtimeAPICloseState(api))
	}
	select {
	case <-held.cancelled:
	case <-ctx.Done():
		t.Fatal("actual RPC callback did not observe owner cancellation", ctx.Err())
	}
	select {
	case err := <-ordinary:
		if err := runtimeAPISubscriptionTerminalError(ctx, err); err != nil {
			t.Fatal("ordinary RPC ended through client deadline/cancellation", err)
		}
	case <-ctx.Done():
		t.Fatal("ordinary client did not observe owner termination", ctx.Err())
	}
	select {
	case err := <-streamDone:
		if err := runtimeAPISubscriptionTerminalError(ctx, err); err != nil {
			t.Fatal("inventory ended through client deadline/cancellation", err)
		}
	case <-ctx.Done():
		t.Fatal("inventory client did not observe owner termination", ctx.Err())
	}
	// The map is removed only by the actual apiOwnedConn.Close. Check that
	// physical close independently of request-context cancellation. Poll only
	// within handoffBox's unchanged, single five-second overall context.
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		endpoint.mu.Lock()
		_, retained = endpoint.conns[carrier]
		closing := endpoint.closing
		endpoint.mu.Unlock()
		if !retained && closing {
			break
		}
		select {
		case err := <-closed:
			t.Fatal("Close returned before physical carrier shutdown and held-handler join", err)
		case <-tick.C:
		case <-ctx.Done():
			t.Fatalf("carrier shutdown missed total deadline: %v; %s", ctx.Err(), runtimeAPICloseState(api))
		}
	}
	select {
	case <-endpoint.serveDone:
	case <-ctx.Done():
		t.Fatal("endpoint Serve did not return", ctx.Err())
	}
	// Negative control: real transport termination has already occurred, but
	// it is not sufficient while one admitted HTTP handler remains held.
	if runtimeAPIChannelClosed(origin.done) || runtimeAPIChannelClosed(api.runtime.closeDone) {
		t.Fatalf("handler not joined before generation/owner completion; %s", runtimeAPICloseState(api))
	}
	select {
	case err := <-closed:
		t.Fatal("Box falsely completed while admitted dispatch was held", err)
	default:
	}
	t.Logf("carrier shutdown with dispatch still held after %s; %s", time.Since(closeStarted), runtimeAPICloseState(api))
	close(tailRelease)
	select {
	case <-tailReturned:
	case <-ctx.Done():
		t.Fatal("released HTTP dispatch tail did not return", ctx.Err())
	}
	// The endpoint is sealed and its physical carrier is already removed, so
	// no new dispatch can Add while this Wait joins the existing HTTP work.
	dispatchJoined := make(chan struct{})
	go func() { origin.requests.Wait(); close(dispatchJoined) }()
	select {
	case <-dispatchJoined:
	case <-ctx.Done():
		t.Fatal("released HTTP dispatch did not join", ctx.Err())
	}
	origin.mu.Lock()
	borrowers := origin.ordinary
	origin.mu.Unlock()
	if runtimeAPIChannelClosed(held.returned) || borrowers == 0 {
		t.Fatal("controlled cancelled RPC lost its deferred-release borrower", borrowers)
	}
	// Held-RPC snapshot only: HTTP work has joined, but owner close may still
	// be in endpoint cleanup. Open done channels do not prove that Stop has
	// reached its handler join, so this cannot deterministically reject a
	// missing RPC wait. The checks still reject premature completion if seen.
	if runtimeAPIChannelClosed(origin.done) || runtimeAPIChannelClosed(api.runtime.closeDone) {
		t.Fatalf("generation/owner completed before RPC release; %s", runtimeAPICloseState(api))
	}
	select {
	case err := <-closed:
		t.Fatal("Box falsely completed before cancelled RPC release", err)
	default:
	}
	t.Logf("HTTP joined with RPC release still held after %s; %s", time.Since(closeStarted), runtimeAPICloseState(api))
	close(held.returnRelease)
	select {
	case <-held.returned:
	case <-ctx.Done():
		t.Fatal("released real RPC callback did not return", ctx.Err())
	}
	select {
	case err := <-closed:
		if err != nil || ctx.Err() != nil {
			t.Fatalf("Close did not join dispatch and RPC release within total deadline: %v context=%v", err, ctx.Err())
		}
	case <-ctx.Done():
		t.Fatalf("RPC release did not join before total deadline: %v; %s", ctx.Err(), runtimeAPICloseState(api))
	}
	origin.mu.Lock()
	ordinaryCount := origin.ordinary
	origin.mu.Unlock()
	endpoint.mu.Lock()
	carrierCount := len(endpoint.conns)
	endpoint.mu.Unlock()
	if !runtimeAPIChannelClosed(origin.done) || !runtimeAPIChannelClosed(api.runtime.closeDone) || ordinaryCount != 0 || carrierCount != 0 {
		t.Fatalf("Close retained real handler/carrier/borrower; %s", runtimeAPICloseState(api))
	}
}

func TestRuntimeAPIClientCancellationDoesNotProveOwnerShutdown(t *testing.T) {
	_, api, ctx, _ := handoffBox(t, "old")
	origin := api.runtime.generations[0]
	connection, err := grpc.NewClient(origin.endpoint.listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithUnaryInterceptor(daemon.NewClientAuthUnaryInterceptor("old")), grpc.WithStreamInterceptor(daemon.NewClientAuthStreamInterceptor("old")))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	request, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := daemon.NewStartedServiceClient(connection).SubscribeOutbounds(request, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	cancel()
	terminal := make(chan error, 1)
	go func() {
		for {
			if _, err := stream.Recv(); err != nil {
				terminal <- err
				return
			}
		}
	}()
	select {
	case err := <-terminal:
		if status.Code(err) != codes.Canceled || !errors.Is(request.Err(), context.Canceled) {
			t.Fatalf("negative control did not reach actual client cancellation: %v context=%v", err, request.Err())
		}
		if rejected := runtimeAPISubscriptionTerminalError(request, err); rejected == nil || !strings.Contains(rejected.Error(), "request ended independently") {
			t.Fatalf("client cancellation was accepted as owner shutdown: %v", rejected)
		}
	case <-ctx.Done():
		t.Fatal("client cancellation did not actually terminate stream", ctx.Err())
	}
	if runtimeAPIChannelClosed(origin.done) || runtimeAPIChannelClosed(origin.endpoint.serveDone) || runtimeAPIChannelClosed(api.runtime.closeDone) {
		t.Fatal("negative control unexpectedly closed live API owner")
	}
	// A real successful public RPC proves the owner is still usable. Merely
	// inspecting open done channels would not establish the positive control.
	if _, err := daemon.NewRuntimeConfigServiceClient(connection).GetRuntimeCapabilities(ctx, &emptypb.Empty{}); err != nil {
		t.Fatal("client cancellation also destroyed live API owner", err)
	}
}

func TestRuntimeAPISubscriptionTerminalGuardRejectsDeadline(t *testing.T) {
	for name, terminal := range map[string]error{
		"RPC deadline":     status.Error(codes.DeadlineExceeded, "synthetic deadline negative control"),
		"context deadline": context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			err := runtimeAPISubscriptionTerminalError(context.Background(), terminal)
			if err == nil || !strings.Contains(err.Error(), "subscription reached deadline") {
				t.Fatalf("deadline was accepted as owner shutdown: %v", err)
			}
		})
	}
	if err := runtimeAPISubscriptionTerminalError(context.Background(), io.EOF); err != nil {
		t.Fatal("live-request transport EOF was rejected", err)
	}
	if err := runtimeAPISubscriptionTerminalError(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "no terminal error") {
		t.Fatal("missing terminal was accepted", err)
	}
}
