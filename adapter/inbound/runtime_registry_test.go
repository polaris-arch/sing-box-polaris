package inbound

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

func TestRuntimeRegistryInvokesConstructorsOutsideRegistryLock(t *testing.T) {
	registry := NewRegistry()
	registry.register("fixture", func() any {
		registry.OptionTypes()
		return new(struct{})
	}, func(context.Context, adapter.Router, log.ContextLogger, string, any) (adapter.Inbound, error) {
		registry.OptionTypes()
		registry.CreateOptions("fixture")
		return &preparedInboundFixture{tag: "fixture"}, nil
	})
	done := make(chan error, 1)
	go func() { _, err := registry.Create(context.Background(), nil, nil, "fixture", "fixture", nil); done <- err }()
	select {
	case err := <-done: if err != nil { t.Fatal(err) }
	case <-time.After(5*time.Second): t.Fatal("registry constructor reentry deadlocked")
	}
}
