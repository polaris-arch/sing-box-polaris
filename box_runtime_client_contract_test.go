package box

import (
	"context"
	stdjson "encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

func runtimeClientPlan(t *testing.T, f *runtimeTestFixture, content []byte) (RuntimeConfigPlan, RuntimeConfigApply) {
	t.Helper()
	plan, err := f.box.PlanRuntimeConfigWithClientImpactPolicy(context.Background(), "actor-a", f.identity(), content, nil, RuntimeClientImpactPolicyExplicit)
	if err != nil || !plan.Applicable || len(plan.Errors) != 0 {
		t.Fatal("explicit candidate not planned", plan, err)
	}
	return plan, RuntimeConfigApply{ContractVersion: 1, PlanID: plan.PlanID, TransactionID: plan.TransactionID, Expected: plan.Expected, CandidateDigest: plan.CandidateDigest, AcceptedImpactDigest: plan.ImpactDigest}
}

func TestRuntimeClientLoggerPublicTogglePreservesReferencesAndAbort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var root map[string]stdjson.RawMessage
	if err := stdjson.Unmarshal(runtimeTestConfig(1080, "log.test"), &root); err != nil {
		t.Fatal(err)
	}
	encode := func(disabled bool, level string) []byte {
		root["log"], _ = stdjson.Marshal(option.LogOptions{Disabled: disabled, Output: path, Level: level})
		content, err := stdjson.Marshal(root)
		if err != nil {
			t.Fatal(err)
		}
		return content
	}
	f := newRuntimeTestFixture(t, encode(true, "info"), nil)
	f.start(t)
	factory := f.box.logFactory
	retained := factory.NewLogger("retained-before-toggle")
	enabled := encode(false, "debug")
	legacy, err := f.box.PlanRuntimeConfig(context.Background(), "actor-a", f.identity(), enabled)
	if err != nil || legacy.Applicable {
		t.Fatal("legacy logger structure guard relaxed", legacy, err)
	}
	plan, request := runtimeClientPlan(t, f, enabled)
	if plan.ImpactConfirmationRequired || len(plan.Impacts) != 1 || plan.Impacts[0].UpdateClass != "IN_PLACE" {
		t.Fatal("logger toggle falsely reset network sessions", plan)
	}
	operation, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || operation.Active.Revision != request.Expected.Revision+1 || f.box.logFactory != factory || factory.Level() != log.LevelDebug {
		t.Fatal("stable logger not published", operation, err)
	}
	retained.Info("first-enabled")
	bytes, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(bytes), "first-enabled") {
		t.Fatal("retained logger stranded on old disabled generation", err)
	}
	_, disable := runtimeClientPlan(t, f, encode(true, "info"))
	if _, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", disable); err != nil {
		t.Fatal(err)
	}
	retained.Info("must-not-emit")
	bytes, err = os.ReadFile(path)
	if err != nil || strings.Contains(string(bytes), "must-not-emit") {
		t.Fatal("disabled publication kept emitting", err)
	}
	// A compound candidate fails after the typed log generation is prepared.
	// Abort must release that candidate and leave the committed disabled owner.
	var next option.Options
	if err := json.UnmarshalContext(f.ctx, runtimeTestConfig(1081, "log.test"), &next); err != nil {
		t.Fatal(err)
	}
	next.Log = &option.LogOptions{Output: path, Level: "info"}
	content, _ := json.MarshalContext(f.ctx, next)
	_, failed := runtimeClientPlan(t, f, content)
	f.setConstructorHook(func(*runtimeTestSocks) error { return errors.New("constructor rejected") })
	failedOperation, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", failed)
	if err != nil || failedOperation.Active != failed.Expected {
		t.Fatal("failed candidate changed active graph", failedOperation, err)
	}
	retained.Info("aborted-candidate-must-not-emit")
	bytes, _ = os.ReadFile(path)
	if strings.Contains(string(bytes), "aborted-candidate-must-not-emit") {
		t.Fatal("aborted log generation became visible")
	}
	f.setConstructorHook(nil)
	_, retry := runtimeClientPlan(t, f, encode(false, "info"))
	if _, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", retry); err != nil {
		t.Fatal("abort left logger prepare fence held", err)
	}
	retained.Info("enabled-after-abort")
	bytes, _ = os.ReadFile(path)
	if !strings.Contains(string(bytes), "enabled-after-abort") {
		t.Fatal("logger owner did not recover after abort")
	}
}

type runtimeClientAPIObserver struct {
	boxService.Adapter
	published atomic.Int32
	aborted   atomic.Int32
}

func (*runtimeClientAPIObserver) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (s *runtimeClientAPIObserver) PrepareRuntimeAPI(context.Context, option.APIServiceOptions) (adapter.RuntimeAPIHandoff, error) {
	return s, nil
}
func (s *runtimeClientAPIObserver) PublishRuntimeAPI()  { s.published.Add(1) }
func (s *runtimeClientAPIObserver) Abort() error        { s.aborted.Add(1); return nil }
func (*runtimeClientAPIObserver) Status() (bool, error) { return true, nil }

func TestRuntimeClientDashboardPublicPlanBindsGenerationImpactAndPublication(t *testing.T) {
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "dashboard.test"), nil)
	registry := service.FromContext[adapter.ServiceRegistry](f.ctx).(*boxService.Registry)
	observer := &runtimeClientAPIObserver{Adapter: boxService.NewAdapter(C.TypeAPI, "control")}
	boxService.Register[option.APIServiceOptions](registry, C.TypeAPI, func(context.Context, log.ContextLogger, string, option.APIServiceOptions) (adapter.Service, error) {
		return observer, nil
	})
	var initial option.APIServiceOptions
	if err := json.Unmarshal([]byte(`{"listen":"127.0.0.1","listen_port":3001,"secret":"same"}`), &initial); err != nil {
		t.Fatal(err)
	}
	options.Services = []option.Service{{Type: C.TypeAPI, Tag: "control", Options: &initial}}
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.box = instance
	t.Cleanup(func() { _ = instance.CloseWithResult() })
	f.start(t)
	next := initial
	next.Dashboard = &option.APIDashboardOptions{Enabled: true, Path: t.TempDir(), HTTPClient: &option.HTTPClientOptions{Detour: "select"}}
	candidate := options.Options
	candidate.Services = append([]option.Service(nil), options.Services...)
	candidate.Services[0].Options = &next
	content, _ := json.MarshalContext(f.ctx, candidate)
	legacy, err := instance.PlanRuntimeConfig(context.Background(), "actor-a", f.identity(), content)
	if err != nil || legacy.Applicable {
		t.Fatal("legacy dashboard structure guard relaxed", legacy, err)
	}
	plan, request := runtimeClientPlan(t, f, content)
	marker := false
	for _, impact := range plan.Impacts {
		if impact.Path == "services" && impact.UpdateClass == "LOCAL_REPLACE" && impact.ReconnectRequired {
			for _, class := range impact.AffectedSessionClasses {
				marker = marker || class == "api_generation_handoff_v1"
			}
		}
	}
	if !plan.ImpactConfirmationRequired || !marker {
		t.Fatal("same-endpoint dashboard toggle lost API generation handoff", plan)
	}
	operation, err := instance.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || operation.Active.Revision != request.Expected.Revision+1 || observer.published.Load() != 1 || observer.aborted.Load() != 0 {
		t.Fatal("API publication hook missing from atomic graph publication", operation, err)
	}
	replayed, err := instance.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || replayed.Active != operation.Active || observer.published.Load() != 1 {
		t.Fatal("replay reactivated dashboard worker", replayed, err)
	}
	next.Dashboard = &option.APIDashboardOptions{Enabled: true, Path: "different", HTTPClient: &option.HTTPClientOptions{Detour: "a"}}
	candidate.Services[0].Options = &next
	content, _ = json.MarshalContext(f.ctx, candidate)
	unsupported, err := instance.PlanRuntimeConfigWithClientImpactPolicy(context.Background(), "actor-a", f.identity(), content, nil, RuntimeClientImpactPolicyExplicit)
	if err != nil || unsupported.Applicable || unsupported.ImpactConfirmationRequired {
		t.Fatal("policy opened arbitrary enabled dashboard edits", unsupported, err)
	}
}

func TestRuntimeClientStoredPolicyDoesNotReplaceExpiryAndCAS(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "guards.test"), nil)
	f.start(t)
	_, request := runtimeClientPlan(t, f, runtimeTestConfig(1081, "guards.test"))
	stale := request
	stale.Expected.Revision++
	if _, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", stale); err == nil {
		t.Fatal("policy capability bypassed CAS")
	}
	record := f.box.runtime.plans[request.TransactionID]
	f.box.runtime.now = func() time.Time { return time.UnixMilli(record.plan.ExpiresAtUnixMilli) }
	if _, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request); err == nil {
		t.Fatal("policy capability bypassed exact expiry")
	}
	if record.consumed || f.count("a") != 1 || f.identity() != request.Expected {
		t.Fatal("guard rejection constructed or consumed candidate")
	}
	f.box.runtime.now = time.Now
	if runtimeClientImpactPolicyFromContext(context.Background()) != RuntimeClientImpactPolicyLegacy {
		t.Fatal("missing stored policy inferred explicit authority")
	}
}

func TestRuntimeClientLoggerKeepsExplicitCLIDisableColorAcrossPublicPlan(t *testing.T) {
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "cli-log.test"), nil)
	options.Log.DisableColor = true // same existing create() startup override
	options.Context = ContextWithRuntimeLogDisableColor(options.Context)
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.box = instance
	t.Cleanup(func() { _ = instance.CloseWithResult() })
	f.start(t)
	// The generator omits disable_color, but the explicit CLI override is
	// still effective. Its omission must not manufacture a structural edit.
	legacy, err := instance.PlanRuntimeConfig(context.Background(), "actor-a", f.identity(), runtimeTestConfig(1081, "cli-log.test"))
	if err != nil || !legacy.Applicable {
		t.Fatal("explicit CLI override broke an ordinary existing update", legacy, err)
	}
	var candidate option.Options
	if err := json.UnmarshalContext(f.ctx, runtimeTestConfig(1080, "cli-log.test"), &candidate); err != nil {
		t.Fatal(err)
	}
	candidate.Log = &option.LogOptions{Level: "info"}
	content, _ := json.MarshalContext(f.ctx, candidate)
	plan, request := runtimeClientPlan(t, f, content)
	stored := instance.runtime.plans[plan.TransactionID]
	if stored.options.Log == nil || !stored.options.Log.DisableColor || strings.Contains(string(stored.canonical), "disable_color") || plan.CandidateDigest != runtimeDigest(stored.canonical) {
		t.Fatal("CLI override not bound to the actual effective candidate")
	}
	operation, err := instance.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || operation.Active.Revision != request.Expected.Revision+1 {
		t.Fatal("CLI-normalized logger toggle did not publish", operation, err)
	}
}
