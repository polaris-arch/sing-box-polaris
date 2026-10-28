package daemon

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

func TestAttachedInstanceBindsOriginalBox(t *testing.T) {
	owner := &box.Box{}
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegisterPtr(ctx, owner)
	overrides := &OverrideOptions{AutoRedirect: true, IncludePackage: []string{"example.app"}}
	ctx = context.WithValue(ctx, runtimeStartupOverridesKey{}, overrides)
	instance := attachInstance(ctx)
	if instance.instance != owner {
		t.Fatal("attached API lost its owning Box")
	}
	if instance.runtimeOverrides == overrides || !instance.runtimeOverrides.AutoRedirect || instance.runtimeOverrides.IncludePackage[0] != "example.app" {
		t.Fatal("attached API lost its detached startup override projection")
	}
	overrides.IncludePackage[0] = "mutated"
	if instance.runtimeOverrides.IncludePackage[0] != "example.app" {
		t.Fatal("attached startup overrides share mutable caller state")
	}
	snapshot, changed, release, err := instance.runtimeSnapshot()
	defer release()
	if err != nil || snapshot != instance || changed != nil {
		t.Fatal("legacy attachment was retargeted")
	}
}

type apiStatusEndpoint struct {
	adapter.Endpoint
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (*apiStatusEndpoint) Type() string { return "api-test" }
func (e *apiStatusEndpoint) StatusUpdated() <-chan struct{} {
	e.once.Do(func() { close(e.entered) })
	<-e.release
	return make(chan struct{})
}

type apiEndpointManager struct {
	adapter.EndpointManager
	endpoint adapter.Endpoint
}

func (m *apiEndpointManager) Endpoints() []adapter.Endpoint {
	return []adapter.Endpoint{m.endpoint}
}

func TestEndpointSubscriptionJoinsBlockedWatcherAfterSendFailure(t *testing.T) {
	s := admissionTestService(t)
	endpoint := &apiStatusEndpoint{entered: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(endpoint.release) }) }
	t.Cleanup(release)
	s.instance = &Instance{ctx: context.Background(), endpointManager: &apiEndpointManager{endpoint: endpoint}}
	s.serviceStatus = &ServiceStatus{Status: ServiceStatus_STARTED}
	failure := errors.New("send failed")
	sent := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- subscribeEndpointStatus(context.Background(), s, "api-test", func([]*apiStatusEndpoint) error {
			<-endpoint.entered
			close(sent)
			return failure
		})
	}()
	runtimeURLTestWait(t, sent)
	select {
	case <-result:
		t.Fatal("subscription returned before its last provider call joined")
	default:
	}
	release()
	if err := admissionAwait(t, result); !errors.Is(err, failure) {
		t.Fatalf("send result changed: %v", err)
	}
}

func TestTaggedSubscriptionJoinsProviderOnInitialSendFailure(t *testing.T) {
	canceled := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	finish := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(finish)
	failure := errors.New("initial send failed")
	result := make(chan error, 1)
	go func() {
		result <- streamTaggedStatus(context.Background(), []taggedStatusSource[int]{{
			tag: "one",
			subscribe: func(ctx context.Context, send func(int)) {
				send(1)
				<-ctx.Done()
				close(canceled)
				<-release
			},
		}}, func(map[string]int) error { return failure })
	}()
	runtimeURLTestWait(t, canceled)
	select {
	case <-result:
		t.Fatal("initial send failure dropped live provider work")
	default:
	}
	finish()
	if err := admissionAwait(t, result); !errors.Is(err, failure) {
		t.Fatalf("send result changed: %v", err)
	}
}

func TestRuntimeAPIInventoryWakesOnGraphWithoutHistoryOrControl(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := &StartedService{ctx: context.Background()}
	changed := make(chan struct{})
	// Publication may finish during serialization or a blocked transport Send.
	// No history, lifecycle, selector or URL-test event is supplied.
	close(changed)
	if stop, err := s.waitRuntimeAPIUpdate(ctx, changed, nil, nil, nil, nil); stop || err != nil {
		t.Fatalf("graph-only inventory wake lost: stop=%v err=%v", stop, err)
	}
}
