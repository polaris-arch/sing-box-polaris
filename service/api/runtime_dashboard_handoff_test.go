package api

import (
	"context"
	"crypto/hmac"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

func dashboardPolicyPlan(t *testing.T, ctx context.Context, client daemon.RuntimeConfigServiceClient, content string, policy uint32) *daemon.RuntimeConfigPlan {
	t.Helper()
	caps, err := client.GetRuntimeCapabilities(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := client.PlanRuntimeConfig(ctx, &daemon.PlanRuntimeConfigRequest{
		ContractVersion: 1, Expected: caps.Active, ExpectedControlRevision: caps.ControlRevision,
		ConfigContent: content, ClientImpactPolicyVersion: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func dashboardCandidate(content, path string, enabled bool) string {
	if !enabled {
		return content
	}
	return strings.Replace(content, `"secret":"same"`, fmt.Sprintf(`"secret":"same","dashboard":{"enabled":true,"path":%q,"http_client":{"detour":"direct"}}`, path), 1)
}

func dashboardConfirmHandoff(t *testing.T, ctx context.Context, api *Service, original, next daemon.RuntimeConfigServiceClient, plan *daemon.RuntimeConfigPlan) {
	t.Helper()
	req := &daemon.RuntimeConfigStatusRequest{ContractVersion: 1, TransactionId: plan.TransactionId, RuntimeIncarnation: plan.Expected.Incarnation}
	var header metadata.MD
	prior, err := original.GetRuntimeConfigStatus(ctx, req, grpc.Header(&header))
	if err != nil || prior.Operation == nil {
		t.Fatal("old owned recovery", err)
	}
	keys, generations, endpoints := header.Get(handoffPrefix+"key"), header.Get(handoffPrefix+"generation"), header.Get(handoffPrefix+"endpoint")
	if len(keys) != 1 || len(generations) != 1 || len(endpoints) != 1 {
		t.Fatal("missing captured handoff owner")
	}
	nonce := strings.Repeat("73", 32)
	probe := metadata.AppendToOutgoingContext(ctx, handoffPrefix+"challenge", nonce)
	header = nil
	observed, err := next.GetRuntimeConfigStatus(probe, req, grpc.Header(&header))
	if err != nil {
		t.Fatal(err)
	}
	if len(header.Get(handoffPrefix+"key")) != 0 {
		t.Fatal("fresh same-secret carrier obtained original owner key")
	}
	proof := header.Get(handoffPrefix + "proof")
	if len(proof) != 1 || !hmac.Equal([]byte(proof[0]), []byte(testHandoffMAC(t, keys[0], "proof", generations[0], plan.TransactionId, endpoints[0], nonce, observed))) {
		t.Fatal("fresh same-endpoint generation did not prove custody")
	}
	bad := metadata.AppendToOutgoingContext(probe, handoffPrefix+"ack", strings.Repeat("00", 32))
	if _, err := next.GetRuntimeConfigStatus(bad, req); err == nil {
		t.Fatal("bad ACK retired old generation")
	}
	api.runtime.mu.Lock()
	pending := api.runtime.pending
	api.runtime.mu.Unlock()
	if pending == nil {
		t.Fatal("handoff prematurely lost owner")
	}
	select {
	case <-pending.origin.done:
		t.Fatal("old generation closed before valid ACK")
	default:
	}
	ack := testHandoffMAC(t, keys[0], "ack", generations[0], plan.TransactionId, endpoints[0], nonce, observed)
	header = nil
	accepted, err := next.GetRuntimeConfigStatus(metadata.AppendToOutgoingContext(probe, handoffPrefix+"ack", ack), req, grpc.Header(&header))
	if err != nil || accepted.Operation == nil {
		t.Fatal("valid same-endpoint ACK", err)
	}
	acceptedProof := header.Get(handoffPrefix + "proof")
	if len(header.Get(handoffPrefix+"acknowledged")) != 1 || header.Get(handoffPrefix + "acknowledged")[0] != "true" || len(acceptedProof) != 1 || !hmac.Equal([]byte(acceptedProof[0]), []byte(testHandoffMAC(t, keys[0], "accepted", generations[0], plan.TransactionId, endpoints[0], nonce, accepted))) {
		t.Fatal("ACK lacks fresh generation-bound accepted verifier")
	}
	dashboardWait(t, pending.done, "old API/dashboard generation retired")
}

// This uses real Box, daemon RPC, loopback HTTP/2 carriers and original HMAC
// recovery. It does not simulate a native device or claim full-schema support.
func TestRuntimeDashboardPolicyToggleUsesFreshSameEndpointGeneration(t *testing.T) {
	instance, api, _, content := handoffBox(t, "same")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	address := api.listener.TCPListener().Addr().String()
	current := handoffClient(t, address, "same")
	path := t.TempDir()
	if err := os.WriteFile(filepath.Join(path, "index.html"), []byte("client-dashboard"), 0o600); err != nil {
		t.Fatal(err)
	}
	var previousGeneration string
	for _, enabled := range []bool{true, false, true} {
		candidate := dashboardCandidate(content, path, enabled)
		legacy := dashboardPolicyPlan(t, ctx, current, candidate, 0)
		if legacy.Applicable {
			t.Fatal("legacy consumer lost original dashboard guard")
		}
		plan := dashboardPolicyPlan(t, ctx, current, candidate, 1)
		if !plan.Applicable || plan.ClientImpactPolicyVersion != 1 || !plan.ImpactConfirmationRequired {
			t.Fatalf("policy-v1 client toggle rejected/unconfirmed: %+v", plan)
		}
		impactFound := false
		for _, impact := range plan.Impacts {
			if impact.EffectivePath != "services" {
				continue
			}
			machine, streams, worker := false, false, false
			for _, class := range impact.AffectedSessionClasses {
				machine = machine || class == "api_generation_handoff_v1"
				streams = streams || class == "API streams on the replaced ingress"
				worker = worker || class == "dashboard updater"
			}
			impactFound = impact.UpdateClass == daemon.RuntimeUpdateClass_LOCAL_REPLACE && impact.ReconnectRequired && machine && streams && worker
		}
		if !impactFound {
			t.Fatal("same-endpoint reset lacks exact negotiated impact")
		}
		op := applyHandoff(t, ctx, current, plan)
		if !apiCommitted(op) {
			t.Fatalf("dashboard toggle not committed: %+v", op)
		}
		if _, err := current.GetRuntimeCapabilities(ctx, &emptypb.Empty{}); err == nil {
			t.Fatal("old same-secret carrier retained ordinary authority")
		}
		next := handoffClient(t, address, "same")
		if _, err := next.GetRuntimeCapabilities(ctx, &emptypb.Empty{}); err != nil {
			t.Fatal("fresh carrier did not select published generation", err)
		}
		api.runtime.mu.Lock()
		var active *apiGeneration
		if api.runtime.pending != nil {
			active = api.runtime.pending.next
		}
		api.runtime.mu.Unlock()
		if active == nil || active.id == previousGeneration || (active.dashboard != nil) != enabled {
			t.Fatal("historical digest selected an old generation")
		}
		previousGeneration = active.id
		if enabled {
			response, err := http.Get("http://" + address + "/dashboard/index.html")
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(response.Body)
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil || response.StatusCode != 200 || string(body) != "client-dashboard" {
				t.Fatalf("real handler %d %q %v %v", response.StatusCode, body, readErr, closeErr)
			}
		}
		dashboardConfirmHandoff(t, ctx, api, current, next, plan)
		current = next
	}
	if instance.RuntimeCapabilities().FullConfiguration {
		t.Fatal("finite dashboard migration advertised full schema")
	}
}

func TestRuntimeDashboardPrepareFailuresDoNotAdvanceRevision(t *testing.T) {
	for _, mode := range []string{"handler", "listener"} {
		t.Run(mode, func(t *testing.T) {
			_, api, ctx, content := handoffBox(t, "same")
			address := api.listener.TCPListener().Addr().String()
			client := handoffClient(t, address, "same")
			before, err := client.GetRuntimeCapabilities(ctx, &emptypb.Empty{})
			if err != nil {
				t.Fatal(err)
			}
			path := t.TempDir()
			if mode == "handler" {
				path = filepath.Join(path, "not-directory")
				if err := os.WriteFile(path, []byte("file"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			candidate := dashboardCandidate(content, path, true)
			var occupied net.Listener
			if mode == "listener" {
				occupied, err = net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer occupied.Close()
				candidate = strings.Replace(candidate, `"listen_port":0`, fmt.Sprintf(`"listen_port":%d`, occupied.Addr().(*net.TCPAddr).Port), 1)
			}
			plan := dashboardPolicyPlan(t, ctx, client, candidate, 1)
			if !plan.Applicable {
				t.Fatalf("failure fixture blocked before real preparation: %+v", plan.Errors)
			}
			op := applyHandoff(t, ctx, client, plan)
			if apiCommitted(op) {
				t.Fatal("failed preparation committed")
			}
			after, err := client.GetRuntimeCapabilities(ctx, &emptypb.Empty{})
			if err != nil || after.Active.AppliedRevision != before.Active.AppliedRevision || after.Active.EffectiveDigest != before.Active.EffectiveDigest {
				t.Fatal("failed preparation advanced R", err)
			}
			api.runtime.mu.Lock()
			pending := api.runtime.pending
			var active *apiGeneration
			if len(api.runtime.generations) == 1 {
				active = api.runtime.generations[0]
			}
			api.runtime.mu.Unlock()
			if active == nil || active.dashboard != nil || pending != nil {
				t.Fatal("failed candidate leaked publication/worker owner")
			}
		})
	}
}

type runtimePolicyLogWriter struct {
	sync.Mutex
	messages []string
}

func (w *runtimePolicyLogWriter) WriteMessage(_ log.Level, message string) {
	w.Lock()
	defer w.Unlock()
	w.messages = append(w.messages, message)
}

func (w *runtimePolicyLogWriter) contains(message string) bool {
	w.Lock()
	defer w.Unlock()
	for _, item := range w.messages {
		if strings.Contains(item, message) {
			return true
		}
	}
	return false
}

func TestRuntimeLogPolicyReusesColdDisabledComponentLoggerAcrossApply(t *testing.T) {
	instance, api, _, content := handoffBox(t, "same")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := handoffClient(t, api.listener.TCPListener().Addr().String(), "same")
	writer := new(runtimePolicyLogWriter)
	instance.LogFactory().AttachPlatformWriter(writer)
	retained := instance.LogFactory().NewLogger("captured-cold")
	retained.Info("cold-NOP-marker")
	if writer.contains("cold-NOP-marker") {
		t.Fatal("cold disabled logger emitted")
	}
	for index, enabled := range []bool{true, false, true} {
		candidate := content
		if enabled {
			candidate = strings.Replace(content, `"disabled":true`, `"disabled":false`, 1)
		}
		legacy := dashboardPolicyPlan(t, ctx, client, candidate, 0)
		if legacy.Applicable {
			t.Fatal("legacy consumer acquired disabled variant")
		}
		plan := dashboardPolicyPlan(t, ctx, client, candidate, 1)
		if !plan.Applicable {
			t.Fatalf("bounded logger variant rejected: %+v", plan.Errors)
		}
		for _, impact := range plan.Impacts {
			if impact.EffectivePath == "log" && (impact.ReconnectRequired || impact.UpdateClass != daemon.RuntimeUpdateClass_IN_PLACE) {
				t.Fatal("logger switch falsely resets network")
			}
		}
		if op := applyHandoff(t, ctx, client, plan); !apiCommitted(op) {
			t.Fatalf("logger apply %+v", op)
		}
		marker := fmt.Sprintf("retained-log-%d", index)
		retained.Info(marker)
		if writer.contains(marker) != enabled {
			t.Fatal("captured logger stranded or disabled emission escaped")
		}
		if _, err := client.GetRuntimeCapabilities(ctx, &emptypb.Empty{}); err != nil {
			t.Fatal("logger-only apply changed API ingress", err)
		}
	}
}

func TestRuntimeLogFailedBoundOutputPreparationDoesNotAdvanceRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-created.log")
	instance, api, content := newHandoffBoxWithLog(t, "same", &option.LogOptions{Disabled: true, Output: path})
	content = strings.Replace(content, `"disabled":true`, fmt.Sprintf(`"disabled":true,"output":%q`, path), 1)
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := handoffClient(t, api.listener.TCPListener().Addr().String(), "same")
	before, err := client.GetRuntimeCapabilities(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	candidate := strings.Replace(content, `"disabled":true`, `"disabled":false`, 1)
	plan := dashboardPolicyPlan(t, ctx, client, candidate, 1)
	if !plan.Applicable {
		t.Fatalf("output failure never reached real preparation: %+v", plan.Errors)
	}
	if op := applyHandoff(t, ctx, client, plan); apiCommitted(op) {
		t.Fatal("unprepared output committed")
	}
	after, err := client.GetRuntimeCapabilities(ctx, &emptypb.Empty{})
	if err != nil || after.Active.AppliedRevision != before.Active.AppliedRevision || after.Active.EffectiveDigest != before.Active.EffectiveDigest {
		t.Fatal("failed logger preparation advanced R", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("hot preparation created a new bound file", err)
	}
}

func TestRuntimeLogColdDisabledSubscribeLogSurvivesSameProcessEnableDisableEnable(t *testing.T) {
	instance, api, _, content := handoffBox(t, "same")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	address := api.listener.TCPListener().Addr().String()
	control := handoffClient(t, address, "same")
	captured := instance.LogFactory().NewLogger("cold-existing-component")
	captured.Info("cold-disabled-must-not-appear")
	connection, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithStreamInterceptor(daemon.NewClientAuthStreamInterceptor("same")))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	stream, err := daemon.NewStartedServiceClient(connection).SubscribeLog(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := stream.Recv()
	if err != nil || !initial.GetReset_() || len(initial.Messages) != 0 {
		t.Fatalf("cold disabled wire reset %+v %v", initial, err)
	}
	before, err := control.GetRuntimeCapabilities(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	enable := strings.Replace(content, `"disabled":true`, `"disabled":false`, 1)
	apply := func(candidate string) {
		t.Helper()
		plan := dashboardPolicyPlan(t, ctx, control, candidate, 1)
		if !plan.Applicable {
			t.Fatalf("actual log plan %+v", plan.Errors)
		}
		if operation := applyHandoff(t, ctx, control, plan); !apiCommitted(operation) {
			t.Fatalf("actual log apply %+v", operation)
		}
	}
	receiveMarker := func(marker string) {
		t.Helper()
		for {
			frame, err := stream.Recv()
			if err != nil {
				t.Fatal("existing SubscribeLog stream was replaced", err)
			}
			for _, message := range frame.Messages {
				if strings.Contains(message.Message, "cold-disabled-must-not-appear") || strings.Contains(message.Message, "disabled-must-not-appear") {
					t.Fatal("disabled log escaped stable owner", message.Message)
				}
				if strings.Contains(message.Message, marker) {
					return
				}
			}
		}
	}
	apply(enable)
	captured.Info("first-enable-real-wire")
	receiveMarker("first-enable-real-wire")
	apply(content)
	captured.Info("disabled-must-not-appear")
	apply(enable)
	captured.Info("second-enable-real-wire")
	receiveMarker("second-enable-real-wire")
	after, err := control.GetRuntimeCapabilities(ctx, &emptypb.Empty{})
	if err != nil || after.Active.Incarnation != before.Active.Incarnation || after.Active.AppliedRevision != before.Active.AppliedRevision+3 {
		t.Fatal("log toggle replaced runtime or failed to advance exact R", err)
	}
	// A genuine API generation change ends the old stream. The attached
	// daemon retains history; the App must skip this replay on its new epoch.
	path := t.TempDir()
	if err := os.WriteFile(filepath.Join(path, "index.html"), []byte("dashboard"), 0o600); err != nil {
		t.Fatal(err)
	}
	apiPlan := dashboardPolicyPlan(t, ctx, control, dashboardCandidate(enable, path, true), 1)
	if !apiPlan.Applicable {
		t.Fatalf("API rebind fixture never reached handoff: %+v", apiPlan.Errors)
	}
	if operation := applyHandoff(t, ctx, control, apiPlan); !apiCommitted(operation) {
		t.Fatalf("API handoff %+v", operation)
	}
	for {
		if _, err := stream.Recv(); err != nil {
			break
		}
	}
	nextControl := handoffClient(t, address, "same")
	dashboardConfirmHandoff(t, ctx, api, control, nextControl, apiPlan)
	nextConnection, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithStreamInterceptor(daemon.NewClientAuthStreamInterceptor("same")))
	if err != nil {
		t.Fatal(err)
	}
	defer nextConnection.Close()
	nextStream, err := daemon.NewStartedServiceClient(nextConnection).SubscribeLog(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	history, err := nextStream.Recv()
	if err != nil || !history.GetReset_() {
		t.Fatal("new API epoch lacks real retained history", err)
	}
	foundPrior := false
	for _, message := range history.Messages {
		foundPrior = foundPrior || strings.Contains(message.Message, "second-enable-real-wire")
	}
	if !foundPrior {
		t.Fatal("retained history premise not established")
	}
	captured.Info("after-api-generation-real-wire")
	for {
		frame, err := nextStream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, message := range frame.Messages {
			found = found || strings.Contains(message.Message, "after-api-generation-real-wire")
		}
		if found {
			break
		}
	}
}
