package box

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxCertificate "github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

type constructedService struct {
	boxService.Adapter
}

func (s *constructedService) Start(adapter.StartStage, *adapter.Scope) error { return nil }

// constructionProbe registers a service type whose constructor acquires a
// fake resource and registers its release in the construction scope.
type constructionProbe struct {
	registry    *boxService.Registry
	constructed int
	released    []int
	construct   func(ctx context.Context, index int) error
}

func newConstructionProbe() *constructionProbe {
	probe := &constructionProbe{registry: boxService.NewRegistry()}
	boxService.Register[struct{}](probe.registry, "construction-probe", func(ctx context.Context, _ log.ContextLogger, tag string, _ struct{}) (adapter.Service, error) {
		index := probe.constructed
		probe.constructed++
		probe.released = append(probe.released, 0)
		err := adapter.DeferConstructionCleanup(ctx, func() error {
			probe.released[index]++
			return nil
		})
		if err != nil {
			return nil, err
		}
		if probe.construct != nil {
			err = probe.construct(ctx, index)
			if err != nil {
				return nil, err
			}
		}
		return &constructedService{Adapter: boxService.NewAdapter("construction-probe", tag)}, nil
	})
	return probe
}

func (p *constructionProbe) options(tags ...string) Options {
	ctx := Context(context.Background(), inbound.NewRegistry(), outbound.NewRegistry(), endpoint.NewRegistry(), dns.NewTransportRegistry(), p.registry, boxCertificate.NewRegistry())
	options := option.Options{Log: &option.LogOptions{Disabled: true}}
	for _, tag := range tags {
		options.Services = append(options.Services, option.Service{Type: "construction-probe", Tag: tag, Options: &struct{}{}})
	}
	return Options{Context: ctx, Options: options}
}

// Keep programmatic fixtures equivalent to parsed options: the Windows reserved-
// path admission check serializes all service options before construction.
func TestConstructionProbeOptionsRoundTrip(t *testing.T) {
	probe := newConstructionProbe()
	options := probe.options("one")
	content, err := json.MarshalContext(options.Context, options.Options)
	if err != nil {
		t.Fatal(err)
	}
	var decoded option.Options
	if err = json.UnmarshalContext(options.Context, content, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Services) != 1 || decoded.Services[0].Type != "construction-probe" || decoded.Services[0].Tag != "one" {
		t.Fatalf("service fixture changed during JSON round trip: %+v", decoded.Services)
	}
	if _, ok := decoded.Services[0].Options.(*struct{}); !ok {
		t.Fatalf("service fixture lost its registered options type: %T", decoded.Services[0].Options)
	}
}

func TestNewPropagatesErrorOrPanicWithoutWaitingForRollback(t *testing.T) {
	for _, panicConstructor := range []bool{false, true} {
		t.Run(strconv.FormatBool(panicConstructor), func(t *testing.T) {
			entered, release, disposed := make(chan struct{}), make(chan struct{}), make(chan struct{})
			failure := errors.New("ordinary constructor failure")
			probe := newConstructionProbe()
			probe.construct = func(ctx context.Context, _ int) error {
				err := adapter.DeferConstructionCleanup(ctx, func() error {
					close(entered)
					<-release
					close(disposed)
					return nil
				})
				if err != nil {
					return err
				}
				if panicConstructor {
					panic("ordinary constructor panic")
				}
				return failure
			}
			done := make(chan any, 1)
			go func() {
				defer func() {
					recovered := recover()
					if recovered != nil {
						done <- recovered
					}
				}()
				_, err := New(probe.options("one"))
				done <- err
			}()
			select {
			case result := <-done:
				if panicConstructor {
					if result != "ordinary constructor panic" {
						t.Fatalf("panic changed: %v", result)
					}
				} else if err, isError := result.(error); !isError || !errors.Is(err, failure) {
					t.Fatalf("error changed: %v", result)
				}
			case <-time.After(time.Second):
				close(release)
				t.Fatal("New waited for blocked cleanup")
			}
			select {
			case <-entered:
			case <-time.After(time.Second):
				close(release)
				t.Fatal("rollback lost the acquired resource")
			}
			close(release)
			select {
			case <-disposed:
			case <-time.After(time.Second):
				t.Fatal("rollback failed to complete after release")
			}
		})
	}
}

func TestNewRollbackAtEveryServiceConstructor(t *testing.T) {
	for nth := range 4 {
		t.Run(strconv.Itoa(nth), func(t *testing.T) {
			failure := errors.New("injected constructor failure")
			cleanupFailure := errors.New("injected cleanup failure")
			probe := newConstructionProbe()
			probe.construct = func(ctx context.Context, index int) error {
				if index != nth {
					return nil
				}
				err := adapter.DeferConstructionCleanup(ctx, func() error { return cleanupFailure })
				if err != nil {
					return err
				}
				return failure
			}
			instance, err, report := NewWithConstructionReport(probe.options("0", "1", "2", "3"))
			if instance != nil || !errors.Is(err, failure) {
				t.Fatalf("New = %v, %v", instance, err)
			}
			if !report.Attempted || !errors.Is(report.CleanupError, cleanupFailure) {
				t.Fatalf("report = %+v", report)
			}
			if probe.constructed != nth+1 {
				t.Fatalf("constructed %d services, want %d", probe.constructed, nth+1)
			}
			for index, released := range probe.released {
				if released != 1 {
					t.Fatalf("service %d released %d times, want 1", index, released)
				}
			}
		})
	}
}

func TestNewRollbackAfterDuplicateTagReleasesRejectedObject(t *testing.T) {
	probe := newConstructionProbe()
	instance, err, report := NewWithConstructionReport(probe.options("same", "same"))
	if instance != nil || err == nil {
		t.Fatalf("New = %v, %v; want duplicate tag failure", instance, err)
	}
	if !report.Attempted || report.CleanupError != nil {
		t.Fatalf("report = %+v", report)
	}
	if len(probe.released) != 2 || probe.released[0] != 1 || probe.released[1] != 1 {
		t.Fatalf("released = %v, want both the accepted and the rejected object exactly once", probe.released)
	}
}

func TestNewRollbackAfterConstructorPanic(t *testing.T) {
	probe := newConstructionProbe()
	probe.construct = func(_ context.Context, index int) error {
		if index == 1 {
			panic("injected construction panic")
		}
		return nil
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("constructor panic disappeared")
			}
		}()
		NewWithConstructionReport(probe.options("first", "second", "never"))
	}()
	if len(probe.released) != 2 || probe.released[0] != 1 || probe.released[1] != 1 {
		t.Fatalf("released = %v, want both constructed services exactly once", probe.released)
	}
}

func TestCloseReleasesUnstartedConstruction(t *testing.T) {
	probe := newConstructionProbe()
	instance, err, report := NewWithConstructionReport(probe.options("one"))
	if err != nil {
		t.Fatal(err)
	}
	if !report.Attempted || report.CleanupError != nil {
		t.Fatalf("report = %+v", report)
	}
	if probe.released[0] != 0 {
		t.Fatal("resource released while the box still owns it")
	}
	err = instance.CloseWithResult()
	if err != nil {
		t.Fatal(err)
	}
	if probe.released[0] != 1 {
		t.Fatalf("unstarted service released %d times, want 1", probe.released[0])
	}
	err = instance.Close()
	if err != nil || probe.released[0] != 1 {
		t.Fatalf("second close = %v, released %d times", err, probe.released[0])
	}
}

func TestCloseReleasesRuntimeBeforeConstruction(t *testing.T) {
	probe := newConstructionProbe()
	var order []string
	probe.construct = func(ctx context.Context, _ int) error {
		return adapter.DeferConstructionCleanup(ctx, func() error {
			order = append(order, "construction")
			return nil
		})
	}
	startFailure := errors.New("synthetic initialize failure")
	instance, err := New(probe.options("one"))
	if err != nil {
		t.Fatal(err)
	}
	runtime := &failingCloseService{startErr: startFailure}
	instance.internalService = append([]adapter.LifecycleService{orderedService{runtime, &order}}, instance.internalService...)
	err = instance.Start()
	if !errors.Is(err, startFailure) {
		t.Fatalf("Start = %v, want injected start failure", err)
	}
	if len(order) != 2 || order[0] != "runtime" || order[1] != "construction" {
		t.Fatalf("cleanup order = %v, want [runtime construction]", order)
	}
}

type orderedService struct {
	*failingCloseService
	order *[]string
}

func (s orderedService) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		scope.Add(func() error {
			*s.order = append(*s.order, "runtime")
			return nil
		})
	}
	return s.failingCloseService.Start(stage, scope)
}

func TestRollbackContainsCleanupPanic(t *testing.T) {
	failure := errors.New("injected constructor failure")
	newProbe := func(entered chan struct{}) *constructionProbe {
		probe := newConstructionProbe()
		probe.construct = func(ctx context.Context, _ int) error {
			err := adapter.DeferConstructionCleanup(ctx, func() error {
				if entered != nil {
					close(entered)
				}
				panic("synthetic rollback panic")
			})
			if err != nil {
				return err
			}
			return failure
		}
		return probe
	}
	t.Run("report", func(t *testing.T) {
		instance, err, report := NewWithConstructionReport(newProbe(nil).options("one"))
		if instance != nil || !errors.Is(err, failure) {
			t.Fatalf("New = %v, %v", instance, err)
		}
		if report.CleanupError == nil || !strings.Contains(report.CleanupError.Error(), "synthetic rollback panic") {
			t.Fatalf("report = %+v, want the cleanup panic as the cleanup error", report)
		}
	})
	t.Run("background", func(t *testing.T) {
		entered := make(chan struct{})
		_, err := New(newProbe(entered).options("one"))
		if !errors.Is(err, failure) {
			t.Fatalf("New = %v", err)
		}
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("rollback did not run")
		}
		// An unrecovered panic in the rollback goroutine would crash the
		// process right after the cleanup was entered.
		time.Sleep(100 * time.Millisecond)
	})
}
