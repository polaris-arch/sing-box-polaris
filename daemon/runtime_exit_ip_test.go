package daemon

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRuntimeExitIPRequiresAuthenticatedBoundRequest(t *testing.T) {
	service := new(StartedService)
	valid := &ProbeExitIPRequest{
		Version:                 1,
		Expected:                &RuntimeIdentity{Incarnation: "instance", AppliedRevision: 1, EffectiveDigest: "digest"},
		ExpectedControlRevision: 1,
		LeafTag:                 "selected",
	}
	anonymous := context.Background()
	authenticated := ContextWithRuntimeActor(anonymous, "fixture")
	for _, check := range []struct {
		name    string
		ctx     context.Context
		request *ProbeExitIPRequest
		want    codes.Code
	}{
		{"unauthenticated", anonymous, valid, codes.Unauthenticated},
		{"invalid-contract", authenticated, &ProbeExitIPRequest{Version: 2}, codes.InvalidArgument},
		{"missing-identity", authenticated, &ProbeExitIPRequest{Version: 1, LeafTag: "selected"}, codes.InvalidArgument},
		{"oversize-tag", authenticated, &ProbeExitIPRequest{Version: 1, Expected: valid.Expected, LeafTag: strings.Repeat("x", 513)}, codes.InvalidArgument},
		{"oversize-payload", authenticated, &ProbeExitIPRequest{Version: 1, Expected: &RuntimeIdentity{EffectiveDigest: strings.Repeat("x", 2048)}, LeafTag: "selected"}, codes.InvalidArgument},
		{"stopped-runtime", authenticated, valid, codes.FailedPrecondition},
	} {
		t.Run(check.name, func(t *testing.T) {
			result, err := service.ProbeExitIP(check.ctx, check.request)
			if result != nil || status.Code(err) != check.want {
				t.Fatalf("unexpected result: err=%v", err)
			}
		})
	}
}
