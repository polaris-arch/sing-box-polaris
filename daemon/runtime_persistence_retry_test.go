package daemon

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRuntimePersistenceRetryAuthenticatesFirst(t *testing.T) {
	s := new(StartedService)
	if _, err := s.RetryRuntimePersistence(context.Background(), nil); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("authentication: %v", err)
	}
	ctx := ContextWithRuntimeActor(context.Background(), "owner")
	if _, err := s.RetryRuntimePersistence(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil request: %v", err)
	}
	if runtimePersistenceRetrySafeForRequest(ctx) {
		t.Fatal("generic owner implicitly opted into replay")
	}
	bound, err := ContextWithRuntimePersistenceOptions(ctx, nil, "exact_configuration_file", true)
	if err != nil || !runtimePersistenceRetrySafeForRequest(bound) || runtimePersistenceRetrySafeForRequest(ctx) {
		t.Fatal("repeat-safety binding escaped request", err)
	}
}
