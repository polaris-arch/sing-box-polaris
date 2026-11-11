package daemon

import (
	"context"
	"testing"

	box "github.com/sagernet/sing-box"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// These authentication-entry tests deliberately make no generated-message or
// wire compatibility claim. Descriptor/serialization tests must be added after
// the separately authorized protobuf output has been generated and inspected.
func TestRuntimeActorRequiresServerOwnedTypedContext(t *testing.T) {
	type clientActorKey string
	for _, ctx := range []context.Context{
		context.Background(),
		context.WithValue(context.Background(), clientActorKey("runtime_actor"), "client-supplied"),
		context.WithValue(context.Background(), runtimeActorKey{}, 42),
		ContextWithRuntimeActor(context.Background(), ""),
	} {
		if actor, err := runtimeActor(ctx); actor != "" || status.Code(err) != codes.Unauthenticated {
			t.Fatalf("untrusted actor scope accepted: %q %v", actor, err)
		}
	}
	parent := ContextWithRuntimeActor(context.Background(), "authenticated-a")
	child := ContextWithRuntimeActor(parent, "authenticated-b")
	if actor, err := runtimeActor(parent); err != nil || actor != "authenticated-a" {
		t.Fatal("child context mutated parent authentication scope")
	}
	if actor, err := runtimeActor(child); err != nil || actor != "authenticated-b" {
		t.Fatal("server actor scope did not propagate")
	}
}

func TestRuntimeRPCRejectsMissingActorBeforeReadingInstanceOrRequest(t *testing.T) {
	service := new(StartedService)
	ctx := context.Background()
	if _, err := service.GetRuntimeCapabilities(ctx, nil); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("capabilities authentication = %v", err)
	}
	if _, err := service.PlanRuntimeConfig(ctx, nil); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("plan authentication = %v", err)
	}
	if _, err := service.ApplyRuntimeConfig(ctx, nil); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("apply authentication = %v", err)
	}
	if _, err := service.GetRuntimeConfigStatus(ctx, nil); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("status authentication = %v", err)
	}
	ctx = ContextWithRuntimeActor(ctx, "authenticated-a")
	if _, err := service.GetRuntimeCapabilities(ctx, nil); status.Code(err) != codes.Unavailable {
		t.Fatalf("missing instance = %v", err)
	}
	if _, err := service.PlanRuntimeConfig(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil plan request = %v", err)
	}
	if _, err := service.ApplyRuntimeConfig(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil apply request = %v", err)
	}
	if _, err := service.GetRuntimeConfigStatus(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil status request = %v", err)
	}
}

func TestRuntimePlanRejectsUnknownImpactPolicyBeforeInstanceOrConfigPreparation(t *testing.T) {
	service := new(StartedService)
	request := &PlanRuntimeConfigRequest{ContractVersion: box.RuntimeConfigContractVersion, ClientImpactPolicyVersion: 2}
	if _, err := service.PlanRuntimeConfig(context.Background(), request); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("policy must not bypass server actor authentication: %v", err)
	}
	ctx := ContextWithRuntimeActor(context.Background(), "authenticated-a")
	if _, err := service.PlanRuntimeConfig(ctx, request); status.Code(err) != codes.InvalidArgument || status.Convert(err).Message() != "unsupported client impact policy version" {
		t.Fatalf("unknown policy was read as legacy or reached preparation: %v", err)
	}
}
