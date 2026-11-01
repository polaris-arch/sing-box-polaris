package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/daemon"

	"google.golang.org/protobuf/proto"
)

// The same byte fixture is decoded by the Rust Status codec and authenticated
// by its real HMAC implementation. This assertion binds it to Go's actual
// outgoing serializer, including presence, repeated empty messages and uint64.
func TestRuntimeAPIStatusWireCrossLanguage(t *testing.T) {
	max := ^uint64(0)
	active := &daemon.RuntimeIdentity{Incarnation: "incarnation-A", AppliedRevision: max, EffectiveDigest: strings.Repeat("3", 64)}
	value := &daemon.RuntimeConfigStatus{
		ContractVersion: 1, Active: active,
		Operation: &daemon.RuntimeConfigOperation{
			ContractVersion: 1, TransactionId: strings.Repeat("22", 16), State: 4,
			Before: &daemon.RuntimeIdentity{Incarnation: "incarnation-A", AppliedRevision: max - 1, EffectiveDigest: strings.Repeat("2", 64)}, Active: active,
			CandidateDigest: active.EffectiveDigest, ImpactDigest: strings.Repeat("5", 64),
			Impacts: []*daemon.RuntimeImpact{{ResourceId: "api:control", EffectivePath: "services[0]", UpdateClass: 2, Reason: "real listener handoff", AffectedSessionClasses: []string{"tcp", "udp"}, ReconnectRequired: true}, {}},
			Errors:  []*daemon.RuntimePlanError{{Code: "FIXTURE", EffectivePath: "services[0]", DependencyPath: []string{"http.default", "outbound.direct"}, Message: "诊断\nsafe"}, {}},
			Durable: true, RetirementState: "DRAINING", ControlRevision: max, PersistenceMode: "owner-regeneration-v1", OwnerReloadAcknowledged: true, DesiredStateDigest: strings.Repeat("a", 64), DesiredStateRevision: "D:9",
		},
		LookupState: 1, DurableAppliedDigest: strings.Repeat("b", 64), ControlRevision: max, PersistenceMode: "owner-regeneration-v1", DurableDesiredStateDigest: strings.Repeat("c", 64), DurableDesiredStateRevision: "r:\n9", DurableOwnerReloadAcknowledged: true,
	}
	text, err := os.ReadFile("testdata/runtime_handoff_status.hex")
	if err != nil {
		t.Fatal(err)
	}
	golden, err := hex.DecodeString(strings.TrimSpace(string(text)))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := (apiWireCodec{}).Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, golden) {
		t.Fatalf("actual Go wire differs from shared Rust fixture: %x", wire)
	}
	var decoded daemon.RuntimeConfigStatus
	if err = (apiWireCodec{}).Unmarshal(golden, &decoded); err != nil || !proto.Equal(&decoded, value) {
		t.Fatal("wire lost status fields/presence", err)
	}
	h := &apiHandoff{active: active, transaction: strings.Repeat("22", 16), next: &apiGeneration{id: strings.Repeat("11", 16), endpoint: &apiEndpoint{listener: apiAddrOnly{}}}}
	for i := range h.key {
		h.key[i] = byte(i)
	}
	body := apiStatusWireHash(t, value)
	if got := h.mac("proof", strings.Repeat("44", 32), body); got != "5629cc88b2e018dea1c4c419fc2c78f3a8510cac8bd8e65cc3cbf51472921287" {
		t.Fatal("cross-language full-body proof differs", got)
	}
	if got := h.mac("ack", strings.Repeat("44", 32), ""); got != "7ca7710b3d40664b6f6af3cb9e73ece6880c4682998d839d5a77cfb354d2d1e4" {
		t.Fatal("domain-separated ack differs", got)
	}
	for _, change := range []func(*daemon.RuntimeConfigStatus){func(v *daemon.RuntimeConfigStatus) { v.Operation.DesiredStateRevision = "D:8" }, func(v *daemon.RuntimeConfigStatus) { v.Operation.State = 3 }, func(v *daemon.RuntimeConfigStatus) { v.Operation.Errors[0].Message = "altered" }, func(v *daemon.RuntimeConfigStatus) { v.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01}) }} {
		altered := proto.Clone(value).(*daemon.RuntimeConfigStatus)
		change(altered)
		if !proto.Equal(altered.Active, value.Active) {
			t.Fatal("negative changed identity instead of receipt")
		}
		if apiStatusWireHash(t, altered) == body {
			t.Fatal("receipt/body change escaped hash")
		}
	}
	// Explicit empty message presence is not equivalent to no operation.
	absent, _ := (apiWireCodec{}).Marshal(&daemon.RuntimeConfigStatus{})
	present, _ := (apiWireCodec{}).Marshal(&daemon.RuntimeConfigStatus{Active: &daemon.RuntimeIdentity{}, Operation: &daemon.RuntimeConfigOperation{}})
	if bytes.Equal(absent, present) || !bytes.Equal(present, []byte{0x12, 0, 0x1a, 0}) {
		t.Fatal("optional/default presence changed", present)
	}
}

func apiStatusWireHash(t *testing.T, value proto.Message) string {
	t.Helper()
	wire, err := (apiWireCodec{}).Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

// No socket is opened by the transcript vector. Binding/custody is covered by
// the separate actual listener tests.
type apiAddrOnly struct{}

func (apiAddrOnly) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (apiAddrOnly) Close() error              { return nil }
func (apiAddrOnly) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 39001} }
