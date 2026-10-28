package box

import (
	"context"
	"errors"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestRuntimeCleanupObserverDeadlineSurvivesScopeFilter(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "example.org"), nil)
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		scope := adapter.NewScope(context.Background(), f.box.logger)
		scope.Add(func() error { return runtimeCleanupResult(cause) })
		err := scope.Close()
		if err == nil || !errors.Is(err, errRuntimeCleanupIncomplete) {
			t.Fatalf("cleanup uncertainty filtered as success: %v", err)
		}
	}
	cause := errors.New("original cleanup failure")
	for _, original := range []error{cause, errors.Join(context.Canceled, cause)} {
		scope := adapter.NewScope(context.Background(), f.box.logger)
		scope.Add(func() error { return runtimeCleanupResult(original) })
		err := scope.Close()
		if !errors.Is(err, errRuntimeCleanupIncomplete) || !errors.Is(err, cause) {
			t.Fatalf("cleanup lost sentinel or original cause: %v", err)
		}
	}
	if runtimeCleanupResult(nil) != nil {
		t.Fatal("confirmed cleanup manufactured uncertainty")
	}
}
