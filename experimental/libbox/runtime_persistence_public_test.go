package libbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/daemon"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type publicRuntimePersistenceCall struct {
	incarnation string
	revision    int64
	digest      string
	content     string
}

// Only the native owner is a fixture. Returning nil acknowledges provider
// reload; runtimeHostPersistence must still require the separate desired-state
// acknowledgement through the authenticated public RPC.
type publicRuntimeRegenerationOwner struct {
	access sync.Mutex
	calls  []publicRuntimePersistenceCall
}

func (*publicRuntimeRegenerationOwner) RuntimePersistenceMode() string {
	return "app_authoritative_regeneration"
}

func (h *publicRuntimeRegenerationOwner) PersistRuntimeConfiguration(incarnation string, revision int64, digest, content string) error {
	h.access.Lock()
	defer h.access.Unlock()
	h.calls = append(h.calls, publicRuntimePersistenceCall{incarnation, revision, digest, content})
	if len(h.calls) == 1 {
		return errors.New("synthetic transient owner reload failure")
	}
	return nil
}

func (h *publicRuntimeRegenerationOwner) snapshot() []publicRuntimePersistenceCall {
	h.access.Lock()
	defer h.access.Unlock()
	return append([]publicRuntimePersistenceCall(nil), h.calls...)
}

// Use the real libbox host, socket, generated client and x-command-secret
// interceptors. The platform boundary and owner are mocked, not graph
// construction or transaction admission. No TUN, listening inbound, automatic
// routing, remote rule-set or traffic probe is configured.
func TestRuntimePublicCommandRegenerationPersistenceChain(t *testing.T) {
	// transientTestPlatform mocks the host callbacks, but the production
	// platformDefaultInterfaceMonitor.Start still opens dnsinfo.NewWatcher on
	// Darwin, and NetworkManager.Start opens winpowrprof on Windows. Keep those
	// native observer lifecycles outside this Linux-only socket fixture.
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only mocked platform fixture; Darwin DNS and Windows power watchers require separate native coverage")
	}
	transientTestSetup(t)
	// These host settings are process-global, so this fixture is not parallel.
	secret, port, xpc := sCommandServerSecret, sCommandServerListenPort, sXPCDialer
	debug, oomEnabled := sDebug, sOOMKillerEnabled
	sCommandServerSecret = "synthetic-public-regeneration-secret"
	sCommandServerListenPort = 0
	sXPCDialer = nil
	sDebug, sOOMKillerEnabled = false, false
	t.Cleanup(func() {
		sCommandServerSecret, sCommandServerListenPort, sXPCDialer = secret, port, xpc
		sDebug, sOOMKillerEnabled = debug, oomEnabled
	})
	server, err := NewStrictCommandServer(nil, transientTestPlatform{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	owner := new(publicRuntimeRegenerationOwner)
	const content = `{"log":{"disabled":true},"dns":{"servers":[{"type":"udp","tag":"resolver","server":"192.0.2.53"}],"final":"resolver"},"outbounds":[{"type":"socks","tag":"proxy","server":"192.0.2.1","server_port":1080,"version":"5"}],"route":{"final":"proxy","rule_set":[{"type":"inline","tag":"sites","rules":[{"domain_suffix":["before.example.test"]}]}]}}`
	if err := server.StartOrReloadServiceWithRetryableRuntimePersistence(content, &OverrideOptions{}, owner); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := server.CloseService(); err != nil {
			t.Errorf("close runtime service: %v", err)
		}
	}()
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	target, dialer := dialTarget()
	connection, err := grpc.NewClient(target, localDialOptions(dialer)...)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	client := daemon.NewRuntimeConfigServiceClient(connection)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	capabilities, err := client.GetRuntimeCapabilities(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if capabilities.ContractVersion != box.RuntimeConfigContractVersion || !capabilities.ConnectedHotEnabled || capabilities.FullEffectiveSchemaSupported || capabilities.ImplementationManifestDigest == "" || capabilities.GetActive().GetIncarnation() == "" || capabilities.GetActive().GetAppliedRevision() != 1 {
		t.Fatalf("public ready capability mismatch: %+v", capabilities)
	}
	if len(owner.snapshot()) != 0 {
		t.Fatal("startup performed an unrequested persistence callback")
	}
	plan, err := client.PlanRuntimeConfig(ctx, &daemon.PlanRuntimeConfigRequest{
		ContractVersion:         capabilities.ContractVersion,
		Expected:                capabilities.Active,
		ExpectedControlRevision: capabilities.ControlRevision,
		ConfigContent:           strings.Replace(content, "before.example.test", "after.example.test", 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Applicable || plan.NoOp || len(plan.Errors) != 0 || plan.PlanId == "" || plan.TransactionId == "" || plan.CandidateDigest == capabilities.Active.EffectiveDigest || !proto.Equal(plan.Expected, capabilities.Active) {
		t.Fatalf("changed graph was not publicly plannable: %+v", plan)
	}
	apply := &daemon.ApplyRuntimeConfigRequest{
		ContractVersion:         capabilities.ContractVersion,
		TransactionId:           plan.TransactionId,
		PlanId:                  plan.PlanId,
		Expected:                plan.Expected,
		ExpectedControlRevision: plan.ExpectedControlRevision,
		CandidateDigest:         plan.CandidateDigest,
		AcceptedImpactDigest:    plan.ImpactDigest,
	}
	operation, err := client.ApplyRuntimeConfig(ctx, apply)
	if err != nil {
		t.Fatal(err)
	}
	if operation.GetActive().GetIncarnation() != capabilities.Active.Incarnation || operation.GetActive().GetAppliedRevision() != capabilities.Active.AppliedRevision+1 || operation.GetActive().GetEffectiveDigest() != plan.CandidateDigest || !proto.Equal(operation.Before, capabilities.Active) || operation.ControlRevision != capabilities.ControlRevision {
		t.Fatalf("Apply did not publish exactly one new graph on the original instance: %+v", operation)
	}
	active := proto.Clone(operation.Active).(*daemon.RuntimeIdentity)
	control := operation.ControlRevision
	assertOperation := func(got *daemon.RuntimeConfigOperation, durable, reload bool, calls int) {
		t.Helper()
		state := daemon.RuntimeOperationState_COMMITTED_DURABILITY_PENDING
		if durable {
			state = daemon.RuntimeOperationState_COMMITTED
		}
		if got == nil || got.ContractVersion != capabilities.ContractVersion || got.TransactionId != plan.TransactionId || got.State != state || got.Durable != durable || got.OwnerReloadAcknowledged != reload || got.PersistenceMode != owner.RuntimePersistenceMode() || !proto.Equal(got.Active, active) || !proto.Equal(got.Before, capabilities.Active) || got.ControlRevision != control || got.CandidateDigest != plan.CandidateDigest || got.ImpactDigest != plan.ImpactDigest {
			t.Fatalf("original transaction changed or durability was misreported: %+v", got)
		}
		if actual := len(owner.snapshot()); actual != calls {
			t.Fatalf("owner callback count = %d, want %d", actual, calls)
		}
	}
	assertOperation(operation, false, false, 1)
	if len(operation.Errors) != 1 || operation.Errors[0].Code != "PERSISTENCE_FAILED" {
		t.Fatalf("transient failure did not remain visible: %+v", operation.Errors)
	}
	first := owner.snapshot()[0]
	sum := sha256.Sum256([]byte(first.content))
	if first.incarnation != active.Incarnation || first.revision != int64(active.AppliedRevision) || first.digest != active.EffectiveDigest || hex.EncodeToString(sum[:]) != first.digest || !strings.Contains(first.content, "after.example.test") || strings.Contains(first.content, "before.example.test") {
		t.Fatal("host callback did not capture the committed canonical identity/content")
	}
	statusRequest := &daemon.RuntimeConfigStatusRequest{ContractVersion: capabilities.ContractVersion, TransactionId: plan.TransactionId, RuntimeIncarnation: active.Incarnation}
	readStatus := func(durable, reload bool, calls int) *daemon.RuntimeConfigStatus {
		t.Helper()
		current, err := client.GetRuntimeConfigStatus(ctx, statusRequest)
		if err != nil {
			t.Fatal(err)
		}
		if current.LookupState != daemon.RuntimeLookupState_FOUND || !proto.Equal(current.Active, active) || current.ControlRevision != control || current.PersistenceMode != owner.RuntimePersistenceMode() {
			t.Fatalf("original public receipt was not found: %+v", current)
		}
		assertOperation(current.Operation, durable, reload, calls)
		if !durable && (current.DurableAppliedDigest == active.EffectiveDigest || current.DurableDesiredStateDigest != "" || current.DurableDesiredStateRevision != "" || current.DurableOwnerReloadAcknowledged) {
			t.Fatalf("pending operation was reported durable by Status: %+v", current)
		}
		return current
	}
	readStatus(false, false, 1)
	replay, err := client.ApplyRuntimeConfig(ctx, apply)
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(replay, false, false, 1)
	retry := &daemon.RuntimePersistenceRetryRequest{ContractVersion: capabilities.ContractVersion, TransactionId: plan.TransactionId, Active: active, ControlRevision: control, PersistenceMode: owner.RuntimePersistenceMode()}
	// localDialOptions appends the real secret; the forged first value must not
	// be replaced or admitted by a different daemon authentication interceptor.
	wrongSecret := metadata.AppendToOutgoingContext(ctx, "x-command-secret", "wrong-owner-secret")
	if _, err := client.RetryRuntimePersistence(wrongSecret, retry); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong command owner authentication = %v, want Unauthenticated", err)
	}
	wrongIncarnation := proto.Clone(statusRequest).(*daemon.RuntimeConfigStatusRequest)
	wrongIncarnation.RuntimeIncarnation = "other-instance"
	wrongStatus, err := client.GetRuntimeConfigStatus(ctx, wrongIncarnation)
	if err != nil || wrongStatus.GetLookupState() != daemon.RuntimeLookupState_WRONG_INCARNATION || wrongStatus.GetOperation() != nil {
		t.Fatalf("wrong incarnation exposed an original receipt: %+v, %v", wrongStatus, err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*daemon.RuntimePersistenceRetryRequest)
	}{
		{"stale graph", func(r *daemon.RuntimePersistenceRetryRequest) { r.Active = capabilities.Active }},
		{"stale control", func(r *daemon.RuntimePersistenceRetryRequest) { r.ControlRevision++ }},
		{"wrong mode", func(r *daemon.RuntimePersistenceRetryRequest) { r.PersistenceMode = "exact_configuration_file" }},
		{"wrong transaction", func(r *daemon.RuntimePersistenceRetryRequest) { r.TransactionId = "other-transaction" }},
	} {
		bad := proto.Clone(retry).(*daemon.RuntimePersistenceRetryRequest)
		test.mutate(bad)
		if _, err := client.RetryRuntimePersistence(ctx, bad); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("%s Retry = %v, want FailedPrecondition", test.name, err)
		}
	}
	// This is owner desired-state evidence, deliberately separate from the
	// kernel's effective configuration digest.
	desiredSum := sha256.Sum256([]byte("synthetic-authoritative-desired-generation-2"))
	ack := &daemon.RuntimePersistenceAcknowledgementRequest{ContractVersion: capabilities.ContractVersion, TransactionId: plan.TransactionId, Active: active, ControlRevision: control, PersistenceMode: owner.RuntimePersistenceMode(), DesiredStateDigest: hex.EncodeToString(desiredSum[:]), DesiredStateRevision: "desired-generation-2"}
	if _, err := client.AcknowledgeRuntimePersistence(ctx, ack); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Ack before provider reload = %v, want FailedPrecondition", err)
	}
	readStatus(false, false, 1)
	operation, err = client.RetryRuntimePersistence(ctx, retry)
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(operation, false, true, 2)
	if len(operation.Errors) != 1 || operation.Errors[0].Code != "OWNER_ACKNOWLEDGEMENT_REQUIRED" || owner.snapshot()[1] != first {
		t.Fatal("Retry lost the original callback bytes/identity or treated reload as durability")
	}
	readStatus(false, true, 2)
	// A repeat Retry after reload acceptance is observational, even while the
	// owner's separate durable desired-state acknowledgement is still pending.
	operation, err = client.RetryRuntimePersistence(ctx, retry)
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(operation, false, true, 2)
	badAck := proto.Clone(ack).(*daemon.RuntimePersistenceAcknowledgementRequest)
	badAck.Active = capabilities.Active
	if _, err := client.AcknowledgeRuntimePersistence(ctx, badAck); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stale Ack = %v, want FailedPrecondition", err)
	}
	badAck = proto.Clone(ack).(*daemon.RuntimePersistenceAcknowledgementRequest)
	badAck.DesiredStateDigest = "invalid-desired-digest"
	if _, err := client.AcknowledgeRuntimePersistence(ctx, badAck); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("invalid desired-state Ack = %v, want FailedPrecondition", err)
	}
	for range 2 {
		operation, err = client.AcknowledgeRuntimePersistence(ctx, ack)
		if err != nil {
			t.Fatal(err)
		}
		assertOperation(operation, true, true, 2)
		if len(operation.Errors) != 0 || operation.DesiredStateDigest != ack.DesiredStateDigest || operation.DesiredStateRevision != ack.DesiredStateRevision {
			t.Fatalf("owner desired-state acknowledgement was not retained: %+v", operation)
		}
	}
	badAck = proto.Clone(ack).(*daemon.RuntimePersistenceAcknowledgementRequest)
	badAck.DesiredStateRevision = "different-desired-generation"
	if _, err := client.AcknowledgeRuntimePersistence(ctx, badAck); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("conflicting Ack replay = %v, want FailedPrecondition", err)
	}
	operation, err = client.RetryRuntimePersistence(ctx, retry)
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(operation, true, true, 2)
	replay, err = client.ApplyRuntimeConfig(ctx, apply)
	if err != nil {
		t.Fatal(err)
	}
	assertOperation(replay, true, true, 2)
	current := readStatus(true, true, 2)
	if current.DurableAppliedDigest != active.EffectiveDigest || current.DurableDesiredStateDigest != ack.DesiredStateDigest || current.DurableDesiredStateRevision != ack.DesiredStateRevision || !current.DurableOwnerReloadAcknowledged {
		t.Fatalf("Status lost final durability evidence: %+v", current)
	}
	final, err := client.GetRuntimeCapabilities(ctx, &emptypb.Empty{})
	if err != nil || !final.GetConnectedHotEnabled() || !proto.Equal(final.GetActive(), active) || final.GetControlRevision() != control || final.GetImplementationManifestDigest() != capabilities.ImplementationManifestDigest {
		t.Fatalf("persistence/replay changed the published graph or manifest: %+v, %v", final, err)
	}
}
