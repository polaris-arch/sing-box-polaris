package box

import (
	"context"
	"testing"
)

func TestRuntimeClientImpactPolicyPlansBindOriginalApplyAndKeepLegacyIngress(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	f.start(t)
	before := f.identity()
	content := []byte(runtimeTestConfig(1081, "example.org"))
	legacy, legacyApply := f.plan(t, content)
	plan, err := f.box.PlanRuntimeConfigWithClientImpactPolicy(context.Background(), "actor-a", before, content, nil, RuntimeClientImpactPolicyExplicit)
	if err != nil || !plan.Applicable || plan.NoOp || len(plan.Errors) != 0 {
		t.Fatalf("explicit consumer could not use the actual planner: %+v, %v", plan, err)
	}
	if legacy.ClientImpactPolicyVersion != RuntimeClientImpactPolicyLegacy || legacy.ImpactConfirmationRequired || plan.ClientImpactPolicyVersion != RuntimeClientImpactPolicyExplicit || legacy.CandidateDigest != plan.CandidateDigest || legacy.DependencyDigest != plan.DependencyDigest || legacy.ImpactDigest == plan.ImpactDigest {
		t.Fatal("consumer policy was not bound independently of the candidate and legacy ingress")
	}
	stored := f.box.runtime.plans[plan.TransactionID]
	if stored == nil || stored.plan.ClientImpactPolicyVersion != RuntimeClientImpactPolicyExplicit || stored.plan.ImpactDigest != plan.ImpactDigest {
		t.Fatal("the executable private plan lost its negotiated policy")
	}
	request := RuntimeConfigApply{ContractVersion: RuntimeConfigContractVersion, TransactionID: plan.TransactionID, PlanID: plan.PlanID, Expected: plan.Expected, CandidateDigest: plan.CandidateDigest, AcceptedImpactDigest: plan.ImpactDigest}
	crossPolicy := request
	crossPolicy.AcceptedImpactDigest = legacyApply.AcceptedImpactDigest
	if _, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", crossPolicy); err == nil {
		t.Fatal("legacy acknowledgement was accepted for the explicit-consumer plan")
	}
	if _, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-b", request); err == nil {
		t.Fatal("consumer capability replaced the authenticated actor scope")
	}
	if f.identity() != before || f.count("a") != 1 || stored.consumed {
		t.Fatal("rejected acknowledgement published, constructed, or consumed the original plan")
	}
	// Mutating the caller's returned plan cannot lower the server-owned policy.
	plan.ClientImpactPolicyVersion = RuntimeClientImpactPolicyLegacy
	plan.ImpactConfirmationRequired = !stored.plan.ImpactConfirmationRequired
	operation, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || operation.Active.Revision != before.Revision+1 || operation.ImpactDigest != request.AcceptedImpactDigest {
		t.Fatalf("original exact acknowledgement did not publish once: %+v, %v", operation, err)
	}
	replayed, err := f.box.ApplyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || replayed.Active != operation.Active || f.count("a") != 2 {
		t.Fatal("explicit acknowledgement changed original transaction replay semantics")
	}
}

func TestRuntimeUnknownClientImpactPolicyDoesNotAllocateOrConstruct(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	f.start(t)
	before := f.identity()
	for _, version := range []RuntimeClientImpactPolicyVersion{2, ^RuntimeClientImpactPolicyVersion(0)} {
		_, err := f.box.PlanRuntimeConfigWithClientImpactPolicy(context.Background(), "actor-a", before, []byte(runtimeTestConfig(1081, "example.org")), nil, version)
		if err == nil || f.identity() != before || len(f.box.runtime.plans) != 0 || f.count("a") != 1 {
			t.Fatal("unknown consumer policy was treated as legacy or caused transaction effects")
		}
	}
}
