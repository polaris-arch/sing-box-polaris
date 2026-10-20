package box

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func TestRuntimePlanDependencyDigestBindsCandidateGraph(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	f.start(t)
	first, _ := f.plan(t, runtimeTestConfig(1081, "example.org"))
	same, _ := f.plan(t, runtimeTestConfig(1081, "example.org"))
	changed, _ := f.plan(t, runtimeTestConfig(1082, "example.org"))
	if first.DependencyDigest == "" || first.DependencyDigest != same.DependencyDigest {
		t.Fatal("identical candidate dependency graph has unstable identity")
	}
	if first.DependencyDigest == changed.DependencyDigest {
		t.Fatal("dependency receipt omitted constructor configuration")
	}
}

func TestRuntimeDependencyDigestRejectsMissingDependencyAndBindsSources(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	var options option.Options
	if err := json.UnmarshalContext(f.box.runtime.ctx, runtimeTestConfig(1080, "example.org"), &options); err != nil {
		t.Fatal(err)
	}
	first, err := runtimePlannedDependencyDigest(f.box.runtime.ctx, options, "source-one")
	if err != nil {
		t.Fatal(err)
	}
	second, err := runtimePlannedDependencyDigest(f.box.runtime.ctx, options, "source-two")
	if err != nil || first == second {
		t.Fatalf("source binding missing: %v", err)
	}
	for i := range options.Outbounds {
		if selector, ok := options.Outbounds[i].Options.(*option.SelectorOutboundOptions); ok {
			selector.Outbounds = []string{"missing"}
		}
	}
	if _, err := runtimePlannedDependencyDigest(f.box.runtime.ctx, options, "source-one"); err == nil {
		t.Fatal("missing captured dependency admitted")
	}
}

func TestRuntimePlanRejectsMissingDefaultBeforeConstruction(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	f.start(t)
	for _, field := range []string{`"final":"select"`, `"final":"resolver"`} {
		content := strings.Replace(string(runtimeTestConfig(1080, "example.org")), field, `"final":"missing"`, 1)
		plan, err := f.box.planRuntimeConfig(context.Background(), "actor-a", f.identity(), []byte(content))
		if err != nil {
			t.Fatal(err)
		}
		if plan.Applicable || len(plan.Errors) != 1 || plan.Errors[0].Code != "INVALID_DEPENDENCY_GRAPH" {
			t.Fatalf("missing default admitted: %+v", plan)
		}
	}
	if f.count("a") != 1 || f.count("b") != 1 {
		t.Fatal("planning constructed a candidate")
	}
}
