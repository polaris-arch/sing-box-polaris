package box

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxCertificate "github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
)

type failingCloseService struct {
	startErr error
	closeErr error
	entered  chan struct{}
	release  chan struct{}
}

func (s *failingCloseService) Name() string { return "failing-close" }

func (s *failingCloseService) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	scope.Add(s.close)
	return s.startErr
}

func (s *failingCloseService) close() error {
	if s.entered != nil {
		close(s.entered)
		<-s.release
	}
	return s.closeErr
}

func testContext() context.Context {
	dnsRegistry := dns.NewTransportRegistry()
	local.RegisterTransport(dnsRegistry)
	outboundRegistry := outbound.NewRegistry()
	direct.RegisterOutbound(outboundRegistry)
	return Context(context.Background(), inbound.NewRegistry(), outboundRegistry, endpoint.NewRegistry(), dnsRegistry, boxService.NewRegistry(), boxCertificate.NewRegistry())
}

func testBoxWithService(t *testing.T, extra *failingCloseService) *Box {
	t.Helper()
	instance, err := New(Options{Context: testContext(), Options: option.Options{}})
	if err != nil {
		t.Fatal(err)
	}
	// Internal services start before every other component, so a failing
	// one stops Start before anything touches the host.
	instance.internalService = append([]adapter.LifecycleService{extra}, instance.internalService...)
	return instance
}

func TestCloseReturnsFirstCloseResultOnce(t *testing.T) {
	closeFailure := errors.New("synthetic cleanup failure")
	instance := testBoxWithService(t, &failingCloseService{})
	instance.scope.Add(func() error { return closeFailure })
	err := instance.Close()
	if !errors.Is(err, closeFailure) {
		t.Fatalf("first Close = %v, want cleanup failure", err)
	}
	err = instance.Close()
	if err != nil {
		t.Fatalf("duplicate Close = %v, want nil", err)
	}
	err = instance.CloseWithResult()
	if !errors.Is(err, closeFailure) {
		t.Fatalf("CloseWithResult after Close = %v, want cleanup failure", err)
	}
}

func TestStartFailureRetainsFirstCloseFailure(t *testing.T) {
	startFailure := errors.New("synthetic initialize failure")
	closeFailure := errors.New("synthetic cleanup failure")
	instance := testBoxWithService(t, &failingCloseService{startErr: startFailure, closeErr: closeFailure})
	err := instance.Start()
	if !errors.Is(err, startFailure) {
		t.Fatalf("Start = %v, want injected start failure", err)
	}
	err = instance.CloseWithResult()
	if !errors.Is(err, closeFailure) {
		t.Fatalf("CloseWithResult after automatic close = %v, want original cleanup failure", err)
	}
	err = instance.Close()
	if err != nil {
		t.Fatalf("duplicate Close = %v, want nil", err)
	}
}

func TestDuplicateCloseReturnsBeforeFirstCloseCompletes(t *testing.T) {
	closeFailure := errors.New("synthetic cleanup failure")
	blocking := &failingCloseService{closeErr: closeFailure, entered: make(chan struct{}), release: make(chan struct{})}
	instance := testBoxWithService(t, &failingCloseService{})
	instance.scope.Add(blocking.close)
	first := make(chan error, 1)
	go func() { first <- instance.Close() }()
	<-blocking.entered
	quick := make(chan error, 1)
	go func() { quick <- instance.Close() }()
	select {
	case err := <-quick:
		if err != nil {
			t.Fatalf("duplicate Close = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("duplicate Close waited for the first close")
	}
	var waiters sync.WaitGroup
	results := make(chan error, 4)
	for range 4 {
		waiters.Go(func() {
			results <- instance.CloseWithResult()
		})
	}
	select {
	case err := <-results:
		t.Fatalf("CloseWithResult returned %v before the first close completed", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(blocking.release)
	err := <-first
	if !errors.Is(err, closeFailure) {
		t.Fatalf("first Close = %v, want cleanup failure", err)
	}
	waiters.Wait()
	close(results)
	for err := range results {
		if !errors.Is(err, closeFailure) {
			t.Fatalf("concurrent CloseWithResult = %v, want cleanup failure", err)
		}
	}
}

func TestCloseResultReportsCleanupPanic(t *testing.T) {
	instance := testBoxWithService(t, &failingCloseService{})
	instance.scope.Add(func() error { panic("synthetic cleanup panic") })
	err := instance.Close()
	if err == nil || !strings.Contains(err.Error(), "synthetic cleanup panic") {
		t.Fatalf("Close = %v, want the cleanup panic as an error", err)
	}
	again := instance.CloseWithResult()
	if again == nil || again.Error() != err.Error() {
		t.Fatalf("CloseWithResult = %v, want the first close result %v", again, err)
	}
}

type countingLogFactory struct {
	log.Factory
	closed int
	started int
}

func (f *countingLogFactory) Start() error {
 f.started++
 return f.Factory.Start()
}

func (f *countingLogFactory) Close() error {
	f.closed++
	return f.Factory.Close()
}

func TestStartFailureAfterCloseRunsLateRegistrations(t *testing.T) {
 // This assertion covers the legacy late-registration path. Runtime startup
 // rejects a closed instance before touching the logger (covered separately).
 instance, constructErr := New(Options{Context: testContext(), Options: option.Options{Certificate: &option.CertificateOptions{}}})
 if constructErr != nil { t.Fatal(constructErr) }
 if instance.runtime != nil { t.Fatal("legacy fixture selected runtime startup") }
	factory := &countingLogFactory{Factory: instance.logFactory}
	instance.logFactory = factory
	err := instance.Close()
	if err != nil {
		t.Fatal(err)
	}
	// The scope is closed, so the start fails at the first component, but only
	// after it started the log factory and registered its close.
	err = instance.Start()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Start after Close = %v, want context canceled", err)
	}
	if factory.started != 1 { t.Fatalf("legacy start count = %d, want 1",factory.started) }
	if factory.closed != 1 {
		t.Fatalf("log factory started by the failed start was closed %d times, want 1", factory.closed)
	}
}

func TestRuntimeStartAfterCloseDoesNotRestartLogger(t *testing.T) {
 instance := testBoxWithService(t, &failingCloseService{})
 if instance.runtime == nil { t.Fatal("runtime fixture selected legacy startup") }
 factory := &countingLogFactory{Factory: instance.logFactory}
 instance.logFactory = factory
 if err := instance.Close(); err != nil { t.Fatal(err) }
 if err := instance.Start(); err == nil { t.Fatal("closed runtime restarted") }
 if factory.started != 0 { t.Fatalf("closed runtime restarted logger %d times",factory.started) }
 if factory.closed != 0 { t.Fatalf("closed runtime touched logger lifecycle: %d", factory.closed) }
}
