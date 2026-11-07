package libbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/daemon"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// The native owner boundary accepts reload content on its first call. The
// existing publicRuntimeRegenerationOwner intentionally fails its first call,
// which would hide whether the real wrapper still requires the App's ACK.
type sourceRuntimeRegenerationOwner struct {
	access sync.Mutex
	calls  []publicRuntimePersistenceCall
}

func (*sourceRuntimeRegenerationOwner) RuntimePersistenceMode() string {
	return "app_authoritative_regeneration"
}

func (h *sourceRuntimeRegenerationOwner) PersistRuntimeConfiguration(incarnation string, revision int64, digest, content string) error {
	h.access.Lock()
	defer h.access.Unlock()
	h.calls = append(h.calls, publicRuntimePersistenceCall{incarnation, revision, digest, content})
	return nil
}

func (h *sourceRuntimeRegenerationOwner) snapshot() []publicRuntimePersistenceCall {
	h.access.Lock()
	defer h.access.Unlock()
	return append([]publicRuntimePersistenceCall(nil), h.calls...)
}

type sourceRuntimePublicFixture struct {
	client daemon.RuntimeConfigServiceClient
	other  daemon.RuntimeConfigServiceClient
	owner  *sourceRuntimeRegenerationOwner
	ctx    context.Context
	path   string
	config string
}

func sourceRuntimeReplace(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path+".next", content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".next", path); err != nil {
		t.Fatal(err)
	}
}

// No worker, private actor or source-proof entry is called by this fixture.
// These atomic replacements are observed by the real production fsnotify loop.
func (f *sourceRuntimePublicFixture) changeSource(t *testing.T, domain string) {
	t.Helper()
	sourceRuntimeReplace(t, f.path, []byte(fmt.Sprintf(
		"{\"version\":3,\"rules\":[{\"domain_suffix\":[%q]}]}", domain)))
}

func sourceRuntimeFixture(t *testing.T) *sourceRuntimePublicFixture {
	t.Helper()
	// As in the original public fixture, host callbacks are mocked but Darwin
	// dnsinfo and Windows power observers are native production lifecycles.
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only mocked platform fixture; Darwin DNS and Windows power watchers require separate native coverage")
	}
	transientTestSetup(t)
	secret, port, xpc := sCommandServerSecret, sCommandServerListenPort, sXPCDialer
	debug, oomEnabled := sDebug, sOOMKillerEnabled
	sCommandServerSecret = "synthetic-public-source-secret"
	sCommandServerListenPort, sXPCDialer = 0, nil
	sDebug, sOOMKillerEnabled = false, false
	t.Cleanup(func() {
		sCommandServerSecret, sCommandServerListenPort, sXPCDialer = secret, port, xpc
		sDebug, sOOMKillerEnabled = debug, oomEnabled
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	f := &sourceRuntimePublicFixture{
		ctx: ctx, owner: new(sourceRuntimeRegenerationOwner),
		path: filepath.Join(t.TempDir(), "sites.json"),
	}
	f.changeSource(t, "initial.example.test")
	// No TUN, listening inbound, remote source, traffic probe or direct network
	// operation. Both graph construction and persistence use production code.
	f.config = fmt.Sprintf("{\"log\":{\"disabled\":true},\"dns\":{\"servers\":[{\"type\":\"udp\",\"tag\":\"resolver\",\"server\":\"192.0.2.53\"}],\"final\":\"resolver\"},\"outbounds\":[{\"type\":\"socks\",\"tag\":\"proxy\",\"server\":\"192.0.2.1\",\"server_port\":1080,\"version\":\"5\"}],\"route\":{\"final\":\"proxy\",\"rules\":[{\"rule_set\":\"sites\",\"action\":\"route\",\"outbound\":\"proxy\"}],\"rule_set\":[{\"type\":\"local\",\"tag\":\"sites\",\"format\":\"source\",\"path\":%q}]}}", f.path)
	server, err := NewStrictCommandServer(nil, transientTestPlatform{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	if err := server.StartOrReloadServiceWithRetryableRuntimePersistence(f.config, &OverrideOptions{}, f.owner); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.CloseService(); err != nil {
			t.Errorf("close actual source service: %v", err)
		}
	})
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	target, dialer := dialTarget()
	connection, err := grpc.NewClient(target, localDialOptions(dialer)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	f.client = daemon.NewRuntimeConfigServiceClient(connection)

	// The second real authenticated production ingress has a different actor:
	// daemon:shared-credential rather than libbox:command-owner. Transport is
	// in-memory; neither actor nor RuntimeIngress is injected by the test.
	listener := bufconn.Listen(64 * 1024)
	const otherSecret = "synthetic-distinct-daemon-source-secret"
	otherServer := daemon.NewServer(server.StartedService, otherSecret)
	served := make(chan error, 1)
	go func() { served <- otherServer.Serve(listener) }()
	t.Cleanup(func() {
		otherServer.Stop()
		_ = listener.Close()
		select {
		case err := <-served:
			if err != nil && err != grpc.ErrServerStopped {
				t.Errorf("close second production RPC ingress: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("second production RPC ingress did not stop")
		}
	})
	otherConnection, err := grpc.NewClient("passthrough:///source-other-owner",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpc.WithUnaryInterceptor(func(ctx context.Context, method string, request, reply any, cc *grpc.ClientConn, invoke grpc.UnaryInvoker, options ...grpc.CallOption) error {
			return invoke(metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+otherSecret), method, request, reply, cc, options...)
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = otherConnection.Close() })
	f.other = daemon.NewRuntimeConfigServiceClient(otherConnection)
	ready, err := f.client.GetRuntimeCapabilities(ctx, &emptypb.Empty{})
	if err != nil || ready.GetContractVersion() != box.RuntimeConfigContractVersion ||
		!ready.GetConnectedHotEnabled() || ready.GetFullEffectiveSchemaSupported() ||
		ready.GetActive().GetIncarnation() == "" || ready.GetActive().GetAppliedRevision() != 1 ||
		ready.GetImplementationManifestDigest() == "" {
		t.Fatalf("real public source startup was not ready: %+v / %v", ready, err)
	}
	otherReady, err := f.other.GetRuntimeCapabilities(ctx, &emptypb.Empty{})
	if err != nil || !proto.Equal(otherReady.GetActive(), ready.Active) {
		t.Fatalf("second authenticated ingress is not observing the same actual instance: %+v / %v", otherReady, err)
	}
	f.requireCalls(t, 0)
	return f
}

func (f *sourceRuntimePublicFixture) requireCalls(t *testing.T, count int) {
	t.Helper()
	if calls := f.owner.snapshot(); len(calls) != count {
		t.Fatalf("real runtimeHostPersistence owner calls = %d, want %d", len(calls), count)
	}
}

func (f *sourceRuntimePublicFixture) readStatus(t *testing.T, transaction string) *daemon.RuntimeConfigStatus {
	t.Helper()
	current, err := f.client.GetRuntimeConfigStatus(f.ctx, &daemon.RuntimeConfigStatusRequest{
		ContractVersion: box.RuntimeConfigContractVersion, TransactionId: transaction,
	})
	if err != nil || current.GetContractVersion() != box.RuntimeConfigContractVersion ||
		current.GetPersistenceMode() != f.owner.RuntimePersistenceMode() ||
		current.GetActive().GetIncarnation() == "" {
		t.Fatalf("public original-binding status unavailable: %+v / %v", current, err)
	}
	if transaction == "" && (current.LookupState != daemon.RuntimeLookupState_ACTIVE_ONLY || current.Operation != nil) {
		t.Fatalf("active-only status fabricated an operation: %+v", current)
	}
	if transaction != "" && (current.LookupState != daemon.RuntimeLookupState_FOUND || current.GetOperation().GetTransactionId() != transaction) {
		t.Fatalf("original actor receipt missing: %+v", current)
	}
	return current
}

func sourceRuntimeRequireUnknown(t *testing.T, current *daemon.RuntimeConfigStatus) {
	t.Helper()
	if current.DurableAppliedDigest != "" || current.DurableDesiredStateDigest != "" ||
		current.DurableDesiredStateRevision != "" || current.DurableOwnerReloadAcknowledged {
		t.Fatalf("unproven cold configuration acquired positive durability: %+v", current)
	}
}

func (f *sourceRuntimePublicFixture) plan(t *testing.T, content string) *daemon.RuntimeConfigPlan {
	t.Helper()
	current := f.readStatus(t, "")
	plan, err := f.client.PlanRuntimeConfig(f.ctx, &daemon.PlanRuntimeConfigRequest{
		ContractVersion: box.RuntimeConfigContractVersion, Expected: current.Active,
		ExpectedControlRevision: current.ControlRevision, ConfigContent: content,
		ClientImpactPolicyVersion: uint32(box.RuntimeClientImpactPolicyExplicit),
	})
	if err != nil || !plan.GetApplicable() || len(plan.GetErrors()) != 0 ||
		plan.PlanId == "" || plan.TransactionId == "" || plan.CandidateDigest == "" ||
		!proto.Equal(plan.Expected, current.Active) || plan.ExpectedControlRevision != current.ControlRevision ||
		plan.ClientImpactPolicyVersion != uint32(box.RuntimeClientImpactPolicyExplicit) {
		t.Fatalf("actual public plan failed: %+v / %v", plan, err)
	}
	return plan
}

func sourceRuntimeApplyRequest(plan *daemon.RuntimeConfigPlan) *daemon.ApplyRuntimeConfigRequest {
	return &daemon.ApplyRuntimeConfigRequest{
		ContractVersion: box.RuntimeConfigContractVersion, TransactionId: plan.TransactionId,
		PlanId: plan.PlanId, Expected: plan.Expected, ExpectedControlRevision: plan.ExpectedControlRevision,
		CandidateDigest: plan.CandidateDigest, AcceptedImpactDigest: plan.ImpactDigest,
	}
}

// Publication can be visible before the synchronous source operation's final
// preparation fence drops. Re-submit only the same public NoOp request after
// a definite precondition rejection, with unchanged public identity/control;
// never retry an unknown RPC outcome or execute a private source worker.
func (f *sourceRuntimePublicFixture) noOp(t *testing.T, content string) *daemon.RuntimeConfigOperation {
	t.Helper()
	plan := f.plan(t, content)
	if !plan.NoOp {
		t.Fatalf("unchanged accepted configuration was not NoOp: %+v", plan)
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		op, err := f.client.ApplyRuntimeConfig(f.ctx, sourceRuntimeApplyRequest(plan))
		if err == nil {
			if op.TransactionId != plan.TransactionId || !proto.Equal(op.Active, plan.Expected) ||
				!proto.Equal(op.Before, plan.Expected) || op.ControlRevision != plan.ExpectedControlRevision ||
				op.CandidateDigest != plan.CandidateDigest || op.PersistenceMode != f.owner.RuntimePersistenceMode() {
				t.Fatalf("public NoOp changed active identity/binding: %+v", op)
			}
			return op
		}
		if status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != "runtime plan precondition changed" {
			t.Fatalf("NoOp outcome was not a definite busy-fence rejection: %v", err)
		}
		current := f.readStatus(t, "")
		if !proto.Equal(current.Active, plan.Expected) || current.ControlRevision != plan.ExpectedControlRevision {
			t.Fatalf("NoOp raced an unexpected publication/control change: %+v", current)
		}
		select {
		case <-ticker.C:
		case <-f.ctx.Done():
			t.Fatalf("source preparation fence did not settle: %v", f.ctx.Err())
		}
	}
}

func (f *sourceRuntimePublicFixture) waitSource(t *testing.T, before *daemon.RuntimeConfigStatus, content string, calls int) *daemon.RuntimeConfigStatus {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		current := f.readStatus(t, "")
		if current.Active.Incarnation != before.Active.Incarnation ||
			current.Active.EffectiveDigest != before.Active.EffectiveDigest ||
			current.ControlRevision != before.ControlRevision ||
			current.Active.AppliedRevision > before.Active.AppliedRevision+1 {
			t.Fatalf("source changed canonical digest/instance/control or skipped a revision: before=%+v after=%+v", before, current)
		}
		if current.Active.AppliedRevision == before.Active.AppliedRevision+1 {
			f.noOp(t, content)
			f.requireCalls(t, calls)
			return f.readStatus(t, "")
		}
		if current.Active.AppliedRevision != before.Active.AppliedRevision {
			t.Fatalf("source revision regressed: %+v", current)
		}
		select {
		case <-ticker.C:
		case <-f.ctx.Done():
			t.Fatalf("real watched source event did not publish: %v; status=%+v", f.ctx.Err(), current)
		}
	}
}

// This is a test owner declaration from an actual on-disk desired file, not a
// claim that a Swift reload receipt or the diagnostic snapshot proves Rust D.
// ConfigManager's production lock/cache/disk checks have their own semantic tests.
func sourceRuntimeDesiredEvidence(t *testing.T, path, content string, operation *daemon.RuntimeConfigOperation) *daemon.RuntimePersistenceAcknowledgementRequest {
	t.Helper()
	sourceRuntimeReplace(t, path, []byte(content))
	actual, err := os.ReadFile(path)
	if err != nil || string(actual) != content {
		t.Fatalf("fixture desired file was not written/read back: %v", err)
	}
	sum := sha256.Sum256(actual)
	digest := hex.EncodeToString(sum[:])
	return &daemon.RuntimePersistenceAcknowledgementRequest{
		ContractVersion: box.RuntimeConfigContractVersion, TransactionId: operation.TransactionId,
		Active: proto.Clone(operation.Active).(*daemon.RuntimeIdentity), ControlRevision: operation.ControlRevision,
		PersistenceMode: "app_authoritative_regeneration", DesiredStateDigest: digest,
		DesiredStateRevision: "file-sha256:" + digest,
	}
}

func (f *sourceRuntimePublicFixture) ordinaryPending(t *testing.T, content string) *daemon.RuntimeConfigOperation {
	t.Helper()
	before := f.readStatus(t, "")
	plan := f.plan(t, content)
	if plan.NoOp || plan.CandidateDigest == before.Active.EffectiveDigest {
		t.Fatal("ordinary fixture did not change real canonical configuration")
	}
	op, err := f.client.ApplyRuntimeConfig(f.ctx, sourceRuntimeApplyRequest(plan))
	if err != nil || op.GetState() != daemon.RuntimeOperationState_COMMITTED_DURABILITY_PENDING ||
		op.GetDurable() || !op.GetOwnerReloadAcknowledged() ||
		op.GetPersistenceMode() != f.owner.RuntimePersistenceMode() ||
		op.GetTransactionId() != plan.TransactionId || !proto.Equal(op.Before, before.Active) ||
		op.GetActive().GetIncarnation() != before.Active.Incarnation ||
		op.GetActive().GetAppliedRevision() != before.Active.AppliedRevision+1 ||
		op.GetActive().GetEffectiveDigest() != plan.CandidateDigest ||
		op.ControlRevision != before.ControlRevision ||
		op.DesiredStateDigest != "" || op.DesiredStateRevision != "" ||
		len(op.Errors) != 1 || op.Errors[0].Code != "OWNER_ACKNOWLEDGEMENT_REQUIRED" {
		t.Fatalf("ordinary public Apply bypassed real wrapper/owner ACK: %+v / %v", op, err)
	}
	f.requireCalls(t, 1)
	call := f.owner.snapshot()[0]
	sum := sha256.Sum256([]byte(call.content))
	if call.incarnation != op.Active.Incarnation || call.revision != int64(op.Active.AppliedRevision) ||
		call.digest != op.Active.EffectiveDigest || hex.EncodeToString(sum[:]) != call.digest ||
		!strings.Contains(call.content, "\"server_port\":1081") {
		t.Fatal("actual wrapper callback lost committed canonical identity/content")
	}
	// Retirement is an independent asynchronous leg. Wait for its public
	// terminal before later exact receipt comparisons rather than treating
	// a legitimate PENDING -> DRAINED transition as an ownership mutation.
	settled := proto.Clone(op).(*daemon.RuntimeConfigOperation)
	settled.RetirementState = "DRAINED"
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		current := f.readStatus(t, op.TransactionId)
		if current.Operation.RetirementState == "DRAINED" {
			if !proto.Equal(current.Operation, settled) {
				t.Fatalf("ordinary receipt changed while its resources retired: %+v", current.Operation)
			}
			return current.Operation
		}
		if current.Operation.RetirementState != "PENDING" {
			t.Fatalf("ordinary original resource retirement is not known: %+v", current.Operation)
		}
		select {
		case <-ticker.C:
		case <-f.ctx.Done():
			t.Fatalf("ordinary original resources did not retire: %v", f.ctx.Err())
		}
	}
}

func (f *sourceRuntimePublicFixture) acknowledge(t *testing.T, ack *daemon.RuntimePersistenceAcknowledgementRequest) *daemon.RuntimeConfigOperation {
	t.Helper()
	op, err := f.client.AcknowledgeRuntimePersistence(f.ctx, ack)
	if err != nil || op.GetTransactionId() != ack.TransactionId ||
		op.GetState() != daemon.RuntimeOperationState_COMMITTED || !op.GetDurable() ||
		!op.GetOwnerReloadAcknowledged() || op.PersistenceMode != ack.PersistenceMode ||
		!proto.Equal(op.Active, ack.Active) || op.ControlRevision != ack.ControlRevision ||
		op.DesiredStateDigest != ack.DesiredStateDigest || op.DesiredStateRevision != ack.DesiredStateRevision ||
		len(op.Errors) != 0 {
		t.Fatalf("real original-owner ACK did not settle its own transaction: %+v / %v", op, err)
	}
	f.requireCalls(t, 1)
	return op
}

func TestRuntimePublicSourceColdUnknownDoesNotReplaceOriginalAppOwner(t *testing.T) {
	// Globals belong to the actual libbox host; do not t.Parallel this fixture.
	f := sourceRuntimeFixture(t)
	current := f.readStatus(t, "")
	sourceRuntimeRequireUnknown(t, current)
	raw, err := os.ReadFile(configSnapshotPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"cold-one.example.test", "cold-two.example.test"} {
		before := current
		f.changeSource(t, domain)
		current = f.waitSource(t, before, f.config, 0)
		sourceRuntimeRequireUnknown(t, current)
		after, err := os.ReadFile(configSnapshotPath())
		if err != nil || !bytes.Equal(raw, after) {
			t.Fatal("source event rewrote the native diagnostic raw configuration", err)
		}
	}
	if current.Active.AppliedRevision != 3 {
		t.Fatalf("two actual cold source publications missing: %+v", current)
	}

	candidate := strings.Replace(f.config, "\"server_port\":1080", "\"server_port\":1081", 1)
	pending := f.ordinaryPending(t, candidate)
	sourceRuntimeRequireUnknown(t, f.readStatus(t, ""))
	ack := sourceRuntimeDesiredEvidence(t, filepath.Join(t.TempDir(), "desired.json"),
		"{\"selected\":\"fixture-v1\",\"theme\":\"light\"}", pending)
	original := f.readStatus(t, pending.TransactionId)
	if !proto.Equal(original.Operation, pending) {
		t.Fatal("ordinary original receipt changed before owner ACK")
	}
	retry := &daemon.RuntimePersistenceRetryRequest{
		ContractVersion: box.RuntimeConfigContractVersion, TransactionId: pending.TransactionId,
		Active: pending.Active, ControlRevision: pending.ControlRevision, PersistenceMode: pending.PersistenceMode,
	}
	// The original reload already returned. Retry observes that same receipt;
	// it cannot turn provider acceptance into desired-state durability.
	reloaded, err := f.client.RetryRuntimePersistence(f.ctx, retry)
	if err != nil || !proto.Equal(reloaded, pending) {
		t.Fatalf("ordinary Retry replaced the original owner receipt: %+v / %v", reloaded, err)
	}
	f.requireCalls(t, 1)

	wrongSecret := metadata.AppendToOutgoingContext(f.ctx, "x-command-secret", "wrong-source-owner-secret")
	if _, err := f.client.AcknowledgeRuntimePersistence(wrongSecret, ack); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong command authentication ACK = %v, want Unauthenticated", err)
	}
	hidden, err := f.other.GetRuntimeConfigStatus(f.ctx, &daemon.RuntimeConfigStatusRequest{
		ContractVersion: box.RuntimeConfigContractVersion, TransactionId: pending.TransactionId,
		RuntimeIncarnation: pending.Active.Incarnation,
	})
	if err != nil || hidden.GetLookupState() != daemon.RuntimeLookupState_UNKNOWN_OR_EXPIRED || hidden.GetOperation() != nil {
		t.Fatalf("different authenticated actor observed original transaction: %+v / %v", hidden, err)
	}
	if _, err := f.other.AcknowledgeRuntimePersistence(f.ctx, ack); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("different authenticated actor ACK = %v, want FailedPrecondition", err)
	}
	if _, err := f.other.RetryRuntimePersistence(f.ctx, retry); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("different authenticated actor Retry = %v, want FailedPrecondition", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*daemon.RuntimePersistenceAcknowledgementRequest)
	}{
		{"old revision", func(r *daemon.RuntimePersistenceAcknowledgementRequest) {
			r.Active = proto.Clone(current.Active).(*daemon.RuntimeIdentity)
		}},
		{"foreign incarnation", func(r *daemon.RuntimePersistenceAcknowledgementRequest) {
			r.Active.Incarnation = "foreign-source-instance"
		}},
		{"wrong control", func(r *daemon.RuntimePersistenceAcknowledgementRequest) { r.ControlRevision++ }},
		{"wrong transaction", func(r *daemon.RuntimePersistenceAcknowledgementRequest) {
			r.TransactionId = "not-an-original-transaction"
		}},
		{"wrong mode", func(r *daemon.RuntimePersistenceAcknowledgementRequest) {
			r.PersistenceMode = "source_only_unchanged_configuration"
		}},
		{"invalid desired evidence", func(r *daemon.RuntimePersistenceAcknowledgementRequest) { r.DesiredStateDigest = "not-a-digest" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			bad := proto.Clone(ack).(*daemon.RuntimePersistenceAcknowledgementRequest)
			test.mutate(bad)
			if _, err := f.client.AcknowledgeRuntimePersistence(f.ctx, bad); status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("foreign/stale owner ACK = %v, want FailedPrecondition", err)
			}
			retained := f.readStatus(t, pending.TransactionId)
			if !proto.Equal(retained.Operation, pending) {
				t.Fatal("rejected ACK changed the original pending owner")
			}
			sourceRuntimeRequireUnknown(t, retained)
			f.requireCalls(t, 1)
		})
	}
	noOp := f.noOp(t, candidate)
	if noOp.TransactionId == pending.TransactionId || noOp.Durable || noOp.OwnerReloadAcknowledged ||
		noOp.State != daemon.RuntimeOperationState_COMMITTED_DURABILITY_PENDING ||
		noOp.DesiredStateDigest != "" || noOp.DesiredStateRevision != "" {
		t.Fatalf("NoOp borrowed a different transaction's owner proof: %+v", noOp)
	}
	noOpAck := proto.Clone(ack).(*daemon.RuntimePersistenceAcknowledgementRequest)
	noOpAck.TransactionId = noOp.TransactionId
	if _, err := f.client.AcknowledgeRuntimePersistence(f.ctx, noOpAck); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("NoOp manufactured an owner ACK tail: %v", err)
	}
	noOpRetry := proto.Clone(retry).(*daemon.RuntimePersistenceRetryRequest)
	noOpRetry.TransactionId = noOp.TransactionId
	if _, err := f.client.RetryRuntimePersistence(f.ctx, noOpRetry); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("NoOp manufactured a replayable owner callback: %v", err)
	}
	retained := f.readStatus(t, pending.TransactionId)
	if !proto.Equal(retained.Operation, pending) {
		t.Fatal("NoOp/rejected cross-tail completion replaced the ordinary original tail")
	}
	sourceRuntimeRequireUnknown(t, retained)
	f.requireCalls(t, 1)
	f.acknowledge(t, ack)
	final := f.readStatus(t, pending.TransactionId)
	if final.DurableAppliedDigest != pending.Active.EffectiveDigest ||
		final.DurableDesiredStateDigest != ack.DesiredStateDigest ||
		final.DurableDesiredStateRevision != ack.DesiredStateRevision || !final.DurableOwnerReloadAcknowledged {
		t.Fatalf("actual original ACK evidence missing: %+v", final)
	}
}

func TestRuntimePublicSourceInheritsOnlyActualHistoricalOwnerEvidence(t *testing.T) {
	f := sourceRuntimeFixture(t)
	candidate := strings.Replace(f.config, "\"server_port\":1080", "\"server_port\":1081", 1)
	pending := f.ordinaryPending(t, candidate)
	desiredPath := filepath.Join(t.TempDir(), "desired.json")
	ack := sourceRuntimeDesiredEvidence(t, desiredPath,
		"{\"selected\":\"fixture-v1\",\"theme\":\"light\"}", pending)
	base := f.acknowledge(t, ack)
	callback := f.owner.snapshot()[0]

	// A later file save is deliberately NOT communicated as a new Core intent.
	// Core may retain only historical accepted-D evidence; it cannot certify the
	// new current file or infer another App ACK from an equal canonical digest.
	sourceRuntimeReplace(t, desiredPath, []byte("{\"selected\":\"fixture-v1\",\"theme\":\"dark\"}"))
	newDesired, err := os.ReadFile(desiredPath)
	if err != nil {
		t.Fatal(err)
	}
	newSum := sha256.Sum256(newDesired)
	newDigest := hex.EncodeToString(newSum[:])
	if newDigest == ack.DesiredStateDigest {
		t.Fatal("later desired save did not change real on-disk bytes")
	}
	current := f.readStatus(t, "")
	for _, domain := range []string{"settled-one.example.test", "settled-two.example.test"} {
		before := current
		f.changeSource(t, domain)
		current = f.waitSource(t, before, candidate, 1)
		if current.DurableAppliedDigest != base.Active.EffectiveDigest ||
			current.DurableDesiredStateDigest != ack.DesiredStateDigest ||
			current.DurableDesiredStateRevision != ack.DesiredStateRevision ||
			!current.DurableOwnerReloadAcknowledged ||
			current.DurableDesiredStateDigest == newDigest {
			t.Fatalf("source fabricated fresh/current desired evidence or lost original history: %+v", current)
		}
		if f.owner.snapshot()[0] != callback {
			t.Fatal("source replaced the native owner's original accepted reload content")
		}
	}
	if current.Active.AppliedRevision != base.Active.AppliedRevision+2 {
		t.Fatalf("settled source lineage did not publish twice: %+v", current)
	}
	// Even with byte-identical effective configuration, a newer source identity
	// cannot be substituted into the original App acknowledgement.
	fresh := proto.Clone(ack).(*daemon.RuntimePersistenceAcknowledgementRequest)
	fresh.Active = proto.Clone(current.Active).(*daemon.RuntimeIdentity)
	if _, err := f.client.AcknowledgeRuntimePersistence(f.ctx, fresh); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("historical original ACK accepted a newer source identity: %v", err)
	}
	old := f.readStatus(t, base.TransactionId)
	if old.Operation.State != daemon.RuntimeOperationState_COMMITTED || !old.Operation.Durable ||
		!old.Operation.OwnerReloadAcknowledged || !proto.Equal(old.Operation.Active, base.Active) ||
		old.Operation.DesiredStateDigest != ack.DesiredStateDigest ||
		old.Operation.DesiredStateRevision != ack.DesiredStateRevision {
		t.Fatalf("source repurposed the original ordinary owner receipt: %+v", old.Operation)
	}
	f.requireCalls(t, 1)
}
