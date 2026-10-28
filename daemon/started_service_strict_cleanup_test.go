package daemon

import (
	"context"
	"errors"
	"os"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	boxCertificate "github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
)

type failingTransientService struct {
	startErr error
	closeErr error
}

func (s *failingTransientService) Type() string { return "test-failing-close" }
func (s *failingTransientService) Tag() string  { return "probe" }
func (s *failingTransientService) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		scope.Add(func() error { return s.closeErr })
	case adapter.StartStateStart:
		return s.startErr
	}
	return nil
}

func TestStrictTransientEarlyStartCleanupFailureBecomesSticky(t *testing.T) {
	t.Chdir(t.TempDir())
	dnsRegistry := dns.NewTransportRegistry()
	local.RegisterTransport(dnsRegistry)
	ctx := box.Context(context.Background(), inbound.NewRegistry(), outbound.NewRegistry(), endpoint.NewRegistry(), dnsRegistry, boxService.NewRegistry(), boxCertificate.NewRegistry())
	registry := service.FromContext[adapter.ServiceRegistry](ctx).(*boxService.Registry)
	startFailure := errors.New("synthetic transient service start failed")
	closeFailure := errors.New("synthetic transient service close failed")
	boxService.Register[struct{}](registry, "test-failing-close", func(context.Context, log.ContextLogger, string, struct{}) (adapter.Service, error) {
		return &failingTransientService{startErr: startFailure, closeErr: closeFailure}, nil
	})
	host := NewStartedService(ServiceOptions{Context: ctx, StrictCleanup: true, KeepDefaultLogger: true})
	defer host.Close()
	err := host.StartOrReloadService(context.Background(), `{"services":[{"type":"test-failing-close","tag":"probe"}]}`, &OverrideOptions{})
	if !errors.Is(err, startFailure) || !errors.Is(err, closeFailure) {
		t.Fatalf("failed start did not propagate both original errors: %v", err)
	}
	for range 2 {
		if err := host.CloseService(); !errors.Is(err, closeFailure) {
			t.Fatalf("repeated close cleared real cleanup failure: %v", err)
		}
	}
	if err := host.StartOrReloadService(context.Background(), `{}`, &OverrideOptions{}); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("late start after CloseService = %v, want terminal ErrClosed", err)
	}
}

func TestStrictTransientCloseIsTerminalBeforeStart(t *testing.T) {
	service := NewStartedService(ServiceOptions{Context: context.Background(), StrictCleanup: true})
	defer service.Close()
	if err := service.CloseService(); err != nil {
		t.Fatal(err)
	}
	if err := service.StartOrReloadService(context.Background(), `{}`, &OverrideOptions{}); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("late start after close = %v, want ErrClosed", err)
	}
}

func TestStrictTransientCleanupFailureStaysStickyAfterIdle(t *testing.T) {
	service := NewStartedService(ServiceOptions{Context: context.Background(), StrictCleanup: true})
	defer service.Close()
	failed := errors.New("synthetic endpoint close failure")
	service.cleanupErr = failed
	if err := service.StartOrReloadService(context.Background(), `{}`, &OverrideOptions{}); !errors.Is(err, failed) {
		t.Fatalf("start after cleanup failure = %v", err)
	}
	for range 2 {
		if err := service.CloseService(); !errors.Is(err, failed) {
			t.Fatalf("repeated close cleared cleanup failure: %v", err)
		}
	}
}
