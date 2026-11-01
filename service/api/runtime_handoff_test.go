package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func newHandoffBox(t *testing.T, secret string, tlsOptions ...option.InboundTLSOptions) (*box.Box, *Service, string) {
	t.Helper()
	return newHandoffBoxWithLog(t, secret, nil, tlsOptions...)
}

func newHandoffBoxWithLog(t *testing.T, secret string, logOptions *option.LogOptions, tlsOptions ...option.InboundTLSOptions) (*box.Box, *Service, string) {
	t.Helper()
	out := outbound.NewRegistry()
	direct.RegisterOutbound(out)
	transports := dns.NewTransportRegistry()
	transport.RegisterUDP(transports)
	services := boxService.NewRegistry()
	RegisterService(services)
	ctx := box.Context(context.Background(), inbound.NewRegistry(), out, endpoint.NewRegistry(), transports, services, certificate.NewRegistry())
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, &runtimeAPIPlatform{})
	content := fmt.Sprintf(`{"log":{"disabled":true},"dns":{"servers":[{"type":"udp","tag":"resolver","server":"192.0.2.53"}],"final":"resolver"},"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"},"services":[{"type":"api","listen":"127.0.0.1","listen_port":0,"secret":%q}]}`, secret)
	if len(tlsOptions) != 0 {
		wire, err := json.Marshal(tlsOptions[0])
		if err != nil {
			t.Fatal(err)
		}
		content = strings.Replace(content, `"listen_port":0,`, `"listen_port":0,"tls":`+string(wire)+`,`, 1)
	}
	var options option.Options
	if err := json.UnmarshalContext(ctx, []byte(content), &options); err != nil {
		t.Fatal(err)
	}
	if logOptions != nil {
		options.Log = logOptions
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := instance.CloseWithResult(); err != nil {
			t.Errorf("API owner cleanup: %v", err)
		}
	})
	if len(tlsOptions) == 0 {
		if err = instance.BindRuntimePersistence(func(box.RuntimeIdentity, []byte) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	member, _ := service.FromContext[adapter.ServiceManager](ctx).Get("0")
	return instance, member.(*Service), content
}

func handoffBox(t *testing.T, secret string, tlsOptions ...option.InboundTLSOptions) (*box.Box, *Service, context.Context, string) {
	t.Helper()
	instance, api, content := newHandoffBox(t, secret, tlsOptions...)
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	call, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return instance, api, call, content
}

func handoffClient(t *testing.T, address, secret string) daemon.RuntimeConfigServiceClient {
	t.Helper()
	connection, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithUnaryInterceptor(daemon.NewClientAuthUnaryInterceptor(secret)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return daemon.NewRuntimeConfigServiceClient(connection)
}

func handoffPlan(t *testing.T, ctx context.Context, client daemon.RuntimeConfigServiceClient, content string) *daemon.RuntimeConfigPlan {
	t.Helper()
	caps, err := client.GetRuntimeCapabilities(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := client.PlanRuntimeConfig(ctx, &daemon.PlanRuntimeConfigRequest{ContractVersion: 1, Expected: caps.Active, ExpectedControlRevision: caps.ControlRevision, ConfigContent: content})
	if err != nil || !plan.GetApplicable() {
		t.Fatalf("API plan: %v %+v", err, plan)
	}
	return plan
}

func applyHandoff(t *testing.T, ctx context.Context, c daemon.RuntimeConfigServiceClient, p *daemon.RuntimeConfigPlan) *daemon.RuntimeConfigOperation {
	t.Helper()
	op, err := c.ApplyRuntimeConfig(ctx, &daemon.ApplyRuntimeConfigRequest{ContractVersion: 1, PlanId: p.PlanId, TransactionId: p.TransactionId, Expected: p.Expected, ExpectedControlRevision: p.ExpectedControlRevision, CandidateDigest: p.CandidateDigest, AcceptedImpactDigest: p.ImpactDigest})
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func testHandoffMAC(t *testing.T, key, kind, generation, transaction, endpoint, nonce string, response *daemon.RuntimeConfigStatus) string {
	t.Helper()
	secret, err := hex.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	digest := ""
	if kind == "proof" || kind == "accepted" {
		wire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(wire)
		digest = hex.EncodeToString(sum[:])
	}
	active := response.Active
	transcript := strings.Join([]string{"listener-handoff-hmac-v1", kind, generation, transaction, active.Incarnation, strconv.FormatUint(active.AppliedRevision, 10), active.EffectiveDigest, endpoint, nonce, digest}, "\n")
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(transcript))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestRuntimeAPIRealListenerHandoff(t *testing.T) {
	for _, variant := range []struct {
		old, next string
		move      bool
	}{{"old", "next", true}, {"old", "next", false}, {"", "next", true}, {"", "next", false}, {"old", "", true}, {"old", "", false}, {"same", "same", true}, {"", "", true}} {
		t.Run(fmt.Sprintf("old-empty=%t/new-empty=%t/move=%t", variant.old == "", variant.next == "", variant.move), func(t *testing.T) {
			_, api, ctx, content := handoffBox(t, variant.old)
			original := api.listener.TCPListener().Addr().String()
			old := handoffClient(t, original, variant.old)
			port := 0
			if variant.move {
				l, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				port = l.Addr().(*net.TCPAddr).Port
				_ = l.Close()
			}
			candidate := strings.Replace(content, fmt.Sprintf(`"secret":%q`, variant.old), fmt.Sprintf(`"secret":%q`, variant.next), 1)
			candidate = strings.Replace(candidate, `"listen_port":0`, fmt.Sprintf(`"listen_port":%d`, port), 1)
			plan := handoffPlan(t, ctx, old, candidate)
			op := applyHandoff(t, ctx, old, plan)
			if !apiCommitted(op) {
				t.Fatalf("real API handoff not committed: %+v", op)
			}
			if _, err := old.GetRuntimeCapabilities(ctx, &emptypb.Empty{}); err == nil {
				t.Fatal("old API retained ordinary mutation/capability authority")
			}
			if _, err := old.PlanRuntimeConfig(ctx, &daemon.PlanRuntimeConfigRequest{ContractVersion: 1}); err == nil {
				t.Fatal("old API accepted new Plan")
			}
			req := &daemon.RuntimeConfigStatusRequest{ContractVersion: 1, TransactionId: plan.TransactionId, RuntimeIncarnation: plan.Expected.Incarnation}
			// Expiring an unused Plan must not expire an already-published
			// transaction's retained channel/recovery custody.
			api.runtime.mu.Lock()
			record := api.runtime.plans[plan.TransactionId]
			record.expires = time.Now().Add(-time.Hour)
			api.runtime.plans[plan.TransactionId] = record
			api.runtime.mu.Unlock()
			var headers metadata.MD
			prior, err := old.GetRuntimeConfigStatus(ctx, req, grpc.Header(&headers))
			if err != nil {
				t.Fatal(err)
			}
			// The tuple/secret/transaction can be known to another local client;
			// only the already-bound original TCP carrier may receive the key.
			foreign := handoffClient(t, original, variant.old)
			var foreignHeaders metadata.MD
			_, foreignErr := foreign.GetRuntimeConfigStatus(ctx, req, grpc.Header(&foreignHeaders))
			if foreignErr == nil || len(foreignHeaders.Get(handoffPrefix+"key")) != 0 {
				t.Fatal("fresh carrier acquired original recovery authority")
			}
			key := headers.Get(handoffPrefix + "key")
			generation := headers.Get(handoffPrefix + "generation")
			endpoint := headers.Get(handoffPrefix + "endpoint")
			if len(key) != 1 || !validAPIHex(key[0], 64) || len(generation) != 1 || len(endpoint) != 1 {
				t.Fatalf("original channel lacks owned handoff material: %d fields", len(headers))
			}
			if prior.Operation.RetirementState == "DRAINED" {
				t.Fatal("graph retirement hid pending API socket ownership")
			}
			// A rival normal listener cannot claim the old or candidate tuple while
			// the real owner is retaining it; no close-then-probe custody gap exists.
			for _, address := range []string{original, endpoint[0]} {
				if rival, err := net.Listen("tcp", address); err == nil {
					_ = rival.Close()
					t.Fatal("owned API tuple could be rebound")
				}
			}
			next := handoffClient(t, endpoint[0], variant.next)
			nonce := strings.Repeat("42", 32)
			probeCtx := metadata.AppendToOutgoingContext(ctx, handoffPrefix+"challenge", nonce)
			headers = nil
			observed, err := next.GetRuntimeConfigStatus(probeCtx, req, grpc.Header(&headers))
			if err != nil {
				t.Fatal(err)
			}
			if len(headers.Get(handoffPrefix+"key")) != 0 {
				t.Fatal("new peer received the verifier key")
			}
			proof := headers.Get(handoffPrefix + "proof")
			if len(proof) != 1 || !hmac.Equal([]byte(proof[0]), []byte(testHandoffMAC(t, key[0], "proof", generation[0], plan.TransactionId, endpoint[0], nonce, observed))) {
				t.Fatal("new peer lacks original owner's body-bound proof")
			}
			bad := metadata.AppendToOutgoingContext(probeCtx, handoffPrefix+"ack", strings.Repeat("00", 32))
			if _, err := next.GetRuntimeConfigStatus(bad, req); err == nil {
				t.Fatal("bad handoff MAC retired original listener")
			}
			if _, err := old.GetRuntimeConfigStatus(ctx, req); err != nil {
				t.Fatal("bad proof lost original recovery", err)
			}
			ack := testHandoffMAC(t, key[0], "ack", generation[0], plan.TransactionId, endpoint[0], nonce, observed)
			ackCtx := metadata.AppendToOutgoingContext(probeCtx, handoffPrefix+"ack", ack)
			headers = nil
			accepted, err := next.GetRuntimeConfigStatus(ackCtx, req, grpc.Header(&headers))
			if err != nil {
				t.Fatal(err)
			}
			if len(headers.Get(handoffPrefix+"acknowledged")) != 1 || headers.Get(handoffPrefix + "acknowledged")[0] != "true" {
				t.Fatal("no API handoff acknowledgement")
			}
			proof = headers.Get(handoffPrefix + "proof")
			if len(proof) != 1 || !hmac.Equal([]byte(proof[0]), []byte(testHandoffMAC(t, key[0], "accepted", generation[0], plan.TransactionId, endpoint[0], nonce, accepted))) {
				t.Fatal("accepted status lacks distinct authenticated receipt")
			}
			api.runtime.mu.Lock()
			confirmed := api.runtime.generations[len(api.runtime.generations)-1].confirmed
			api.runtime.mu.Unlock()
			if confirmed == nil {
				t.Fatal("missing actual handoff lifecycle")
			}
			select {
			case <-confirmed.done:
			case <-ctx.Done():
				t.Fatal("old serve/handlers did not actually join")
			}
			complete, err := confirmed.Status()
			if !complete || err != nil {
				t.Fatalf("actual API cleanup: %t %v", complete, err)
			}
			if _, err = next.GetRuntimeCapabilities(ctx, &emptypb.Empty{}); err != nil {
				t.Fatal("new proven channel unavailable", err)
			}
			// A lost ACK response is recoverable through idempotent Status, not Apply.
			headers = nil
			if _, err = next.GetRuntimeConfigStatus(ackCtx, req, grpc.Header(&headers)); err != nil || len(headers.Get(handoffPrefix+"acknowledged")) != 1 {
				t.Fatal("ACK replay not observable", err)
			}
			freshNonce := strings.Repeat("43", 32)
			freshCtx := metadata.AppendToOutgoingContext(ctx, handoffPrefix+"challenge", freshNonce)
			headers = nil
			freshStatus, freshErr := next.GetRuntimeConfigStatus(freshCtx, req, grpc.Header(&headers))
			freshProof := headers.Get(handoffPrefix + "proof")
			if freshErr != nil || len(freshProof) != 1 || headers.Get(handoffPrefix + "acknowledged")[0] != "true" || !hmac.Equal([]byte(freshProof[0]), []byte(testHandoffMAC(t, key[0], "accepted", generation[0], plan.TransactionId, endpoint[0], freshNonce, freshStatus))) {
				t.Fatal("lost ACK response cannot be recovered with fresh proof", freshErr)
			}
			if accepted.Operation.TransactionId != plan.TransactionId {
				t.Fatal("handoff changed transaction")
			}
			if variant.move {
				if rebound, err := net.Listen("tcp", original); err != nil {
					t.Fatal("joined old listener still reserves tuple", err)
				} else {
					_ = rebound.Close()
				}
			}
		})
	}
}

func TestRuntimeAPIBindFailureKeepsOriginalChannel(t *testing.T) {
	_, api, ctx, content := handoffBox(t, "original")
	old := handoffClient(t, api.listener.TCPListener().Addr().String(), "original")
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	candidate := strings.Replace(content, `"listen_port":0`, fmt.Sprintf(`"listen_port":%d`, occupied.Addr().(*net.TCPAddr).Port), 1)
	p := handoffPlan(t, ctx, old, candidate)
	op := applyHandoff(t, ctx, old, p)
	if apiCommitted(op) {
		t.Fatal("occupied socket was published")
	}
	if _, err = old.GetRuntimeCapabilities(ctx, &emptypb.Empty{}); err != nil {
		t.Fatal("failed preparation lost old API", err)
	}
}

func TestRuntimeAPIKeyNeverEchoesClientActorOrUnknownTransaction(t *testing.T) {
	_, api, ctx, content := handoffBox(t, "old")
	old := handoffClient(t, api.listener.TCPListener().Addr().String(), "old")
	candidate := strings.Replace(content, `"secret":"old"`, `"secret":"new"`, 1)
	p := handoffPlan(t, ctx, old, candidate)
	if !apiCommitted(applyHandoff(t, ctx, old, p)) {
		t.Fatal("fixture publication failed")
	}
	forged := metadata.AppendToOutgoingContext(ctx, "x-polaris-api-owner", "api:local-owner:forged", handoffPrefix+"key", strings.Repeat("aa", 32))
	var headers metadata.MD
	_, err := old.GetRuntimeConfigStatus(forged, &daemon.RuntimeConfigStatusRequest{ContractVersion: 1, TransactionId: "not-issued-on-this-ingress", RuntimeIncarnation: p.Expected.Incarnation}, grpc.Header(&headers))
	if err == nil || len(headers.Get(handoffPrefix+"key")) != 0 {
		t.Fatal("client identity or transaction supplied owner authority")
	}
}

// The authority deadline is independent of Plan expiry, new Plan traffic and
// ACK state. Real Status RPCs consume the production clock and metadata paths.
func TestRuntimeAPIHandshakeAuthenticationExpiresInEveryPublishedState(t *testing.T) {
	for _, phase := range []string{"published", "key", "proof", "accepted"} {
		t.Run(phase, func(t *testing.T) {
			_, api, ctx, content := handoffBox(t, "old")
			old := handoffClient(t, api.listener.TCPListener().Addr().String(), "old")
			plan := handoffPlan(t, ctx, old, strings.Replace(content, `"secret":"old"`, `"secret":"new"`, 1))
			op := applyHandoff(t, ctx, old, plan)
			if !apiCommitted(op) {
				t.Fatal("not committed")
			}
			owner := api.runtime
			owner.mu.Lock()
			pending := owner.pending
			deadline := pending.authDeadline
			owner.mu.Unlock()
			req := &daemon.RuntimeConfigStatusRequest{ContractVersion: 1, TransactionId: plan.TransactionId, RuntimeIncarnation: plan.Expected.Incarnation}
			var keyHeaders metadata.MD
			if phase != "published" {
				if _, err := old.GetRuntimeConfigStatus(ctx, req, grpc.Header(&keyHeaders)); err != nil {
					t.Fatal(err)
				}
			}
			next := handoffClient(t, pending.next.endpoint.listener.Addr().String(), "new")
			nonce := strings.Repeat("46", 32)
			challenge := metadata.AppendToOutgoingContext(ctx, handoffPrefix+"challenge", nonce)
			var proof *daemon.RuntimeConfigStatus
			if phase == "proof" || phase == "accepted" {
				var err error
				proof, err = next.GetRuntimeConfigStatus(challenge, req)
				if err != nil {
					t.Fatal(err)
				}
			}
			ackCtx := challenge
			if proof != nil {
				ack := testHandoffMAC(t, keyHeaders.Get(handoffPrefix + "key")[0], "ack", pending.next.id, plan.TransactionId, pending.next.endpoint.listener.Addr().String(), nonce, proof)
				ackCtx = metadata.AppendToOutgoingContext(challenge, handoffPrefix+"ack", ack)
			}
			if phase == "accepted" {
				if _, err := next.GetRuntimeConfigStatus(ackCtx, req); err != nil {
					t.Fatal(err)
				}
				select {
				case <-pending.done:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			owner.mu.Lock()
			// time.Time preserves its monotonic component; no wall-clock jump,
			// next Plan, or unused Plan expiry drives this deadline.
			owner.now = func() time.Time { return deadline }
			owner.mu.Unlock()
			for _, clientAndCtx := range []struct {
				client daemon.RuntimeConfigServiceClient
				call   context.Context
			}{{old, ctx}, {next, challenge}, {next, ackCtx}} {
				var headers metadata.MD
				_, err := clientAndCtx.client.GetRuntimeConfigStatus(clientAndCtx.call, req, grpc.Header(&headers))
				if err == nil || len(headers.Get(handoffPrefix+"key")) != 0 || len(headers.Get(handoffPrefix+"proof")) != 0 || len(headers.Get(handoffPrefix+"acknowledged")) != 0 {
					t.Fatal("expired key/proof/ACK/accepted authentication survived", err)
				}
			}
			owner.mu.Lock()
			zero := pending.key == [32]byte{} && pending.authExpired
			debt := owner.pending == pending
			owner.mu.Unlock()
			if !zero {
				t.Fatal("expired material was not cleared")
			}
			if phase != "accepted" && !debt {
				t.Fatal("expiry falsely released socket cleanup debt")
			}
			current, err := owner.identity()
			if err != nil || current.Revision != op.Active.AppliedRevision || current.EffectiveDigest != op.Active.EffectiveDigest {
				t.Fatal("expiry changed the graph", err)
			}
			var ordinaryStatusHeaders metadata.MD
			if _, err := next.GetRuntimeConfigStatus(ctx, req, grpc.Header(&ordinaryStatusHeaders)); err != nil || len(ordinaryStatusHeaders.Get(handoffPrefix+"key")) != 0 || len(ordinaryStatusHeaders.Get(handoffPrefix+"proof")) != 0 || len(ordinaryStatusHeaders.Get(handoffPrefix+"acknowledged")) != 0 {
				t.Fatal("proof expiry broke ordinary current-API receipt observation", err)
			}
			if phase == "accepted" {
				currentContent := strings.Replace(content, `"secret":"old"`, `"secret":"new"`, 1)
				ordinaryPlan := handoffPlan(t, ctx, next, currentContent)
				ordinary := applyHandoff(t, ctx, next, ordinaryPlan)
				if !apiCommitted(ordinary) {
					t.Fatal("expired old proof poisoned ordinary API")
				}
				ordinaryReq := &daemon.RuntimeConfigStatusRequest{ContractVersion: 1, TransactionId: ordinaryPlan.TransactionId, RuntimeIncarnation: ordinaryPlan.Expected.Incarnation}
				var ordinaryHeaders metadata.MD
				if _, err := next.GetRuntimeConfigStatus(ctx, ordinaryReq, grpc.Header(&ordinaryHeaders)); err != nil || len(ordinaryHeaders.Get(handoffPrefix+"proof")) != 0 {
					t.Fatal("expired old proof poisoned a later ordinary transaction", err)
				}
			}
		})
	}
}

func TestRuntimeAPIIdleDeadlineTimerClearsKeyWithoutAnyRPCOrPlan(t *testing.T) {
	_, api, ctx, content := handoffBox(t, "old")
	old := handoffClient(t, api.listener.TCPListener().Addr().String(), "old")
	plan := handoffPlan(t, ctx, old, strings.Replace(content, `"secret":"old"`, `"secret":"new"`, 1))
	applyHandoff(t, ctx, old, plan)
	owner := api.runtime
	owner.mu.Lock()
	pending := owner.pending
	deadline := pending.authDeadline
	owner.now = func() time.Time { return deadline }
	// Drive the installed production timer, not a second expiry implementation.
	pending.authTimer.Reset(0)
	owner.mu.Unlock()
	for {
		owner.mu.Lock()
		expired := pending.authExpired && pending.key == [32]byte{}
		retained := owner.pending == pending
		owner.mu.Unlock()
		if expired {
			if !retained {
				t.Fatal("timer released unjoined ownership")
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("idle timer never revoked material")
		default:
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRuntimeAPIStopClearsPublishedAuthenticationMaterial(t *testing.T) {
	instance, api, ctx, content := handoffBox(t, "old")
	old := handoffClient(t, api.listener.TCPListener().Addr().String(), "old")
	plan := handoffPlan(t, ctx, old, strings.Replace(content, `"secret":"old"`, `"secret":"new"`, 1))
	applyHandoff(t, ctx, old, plan)
	owner := api.runtime
	owner.mu.Lock()
	pending := owner.pending
	owner.mu.Unlock()
	if err := instance.CloseWithResult(); err != nil {
		t.Fatal(err)
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if !pending.authExpired || pending.key != [32]byte{} || pending.authenticationLive() {
		t.Fatal("stop retained verifier authority")
	}
}
