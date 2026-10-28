package httpclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func legacyTestManagedTransport(t *testing.T, inner *runtimeTestInner) *ManagedTransport {
	t.Helper()
	managed := &ManagedTransport{factory: func() (innerTransport, error) { return inner, nil }}
	managed.epoch.Store(&transportEpoch{transport: inner})
	if err := managed.initializeRuntime(context.Background()); err != nil {
		t.Fatal(err)
	}
	return managed
}

func TestLegacyHTTPStartDoesNotResolveUnusedDefault(t *testing.T) {
	for _, constructionOwned := range []bool{false, true} {
		name := "lifecycle-owned"
		if constructionOwned {
			name = "construction-owned"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
			if constructionOwned {
				ctx = adapter.ContextWithConstructionScope(ctx, scope)
			}
			manager := NewManager(ctx, log.NewNOPFactory().Logger(), nil, "")
			defer manager.RuntimeCloseAndWait()
			var calls atomic.Int32
			unwanted := errors.New("unused implicit HTTP fallback was constructed")
			manager.Initialize(func() (*ManagedTransport, error) {
				calls.Add(1)
				return nil, unwanted
			})
			for _, stage := range adapter.ListStartStages {
				if err := manager.Start(stage, scope); err != nil {
					t.Fatalf("legacy %s: %v", stage, err)
				}
			}
			if calls.Load() != 0 || manager.defaultTransport != nil || manager.prepared || manager.frozen {
				t.Fatal("ordinary startup performed connected-graph preparation")
			}
			// A real consumer still sees the existing fallback error. Startup must
			// defer the policy, not suppress it or synthesize a working client.
			request, _ := http.NewRequest(http.MethodGet, "https://example.invalid", nil)
			if _, err := manager.DefaultTransport().RoundTrip(request); !errors.Is(err, unwanted) {
				t.Fatalf("default consumer error: %v", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("fallback calls after actual demand: %d", calls.Load())
			}
			if err := scope.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := manager.DefaultTransport().RoundTrip(request); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("scope did not close the manager: %v", err)
			}
			if calls.Load() != 1 {
				t.Fatal("closed manager invoked fallback again")
			}
		})
	}
}

func TestLegacyHTTPDefaultIsLazySharedAndScoped(t *testing.T) {
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	manager := NewManager(context.Background(), log.NewNOPFactory().Logger(), nil, "")
	defer manager.RuntimeCloseAndWait()
	inner := new(runtimeTestInner)
	var calls atomic.Int32
	manager.Initialize(func() (*ManagedTransport, error) {
		calls.Add(1)
		return legacyTestManagedTransport(t, inner), nil
	})
	if err := manager.Start(adapter.StartStateStart, scope); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("startup resolved an unused implicit default")
	}
	first, second := manager.DefaultTransport(), manager.DefaultTransport()
	if calls.Load() != 1 {
		t.Fatalf("sequential consumers did not share default: %d", calls.Load())
	}
	request, _ := http.NewRequest(http.MethodGet, "https://example.invalid", nil)
	response, err := first.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	first.CloseIdleConnections()
	second.CloseIdleConnections()
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if err := manager.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
	if inner.closed.Load() != 1 {
		t.Fatalf("scoped/repeated close count: %d", inner.closed.Load())
	}
}

func TestLegacyHTTPStartValidatesConfiguredDefault(t *testing.T) {
	t.Run("already resolved explicit default", func(t *testing.T) {
		scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
		manager := NewManager(context.Background(), log.NewNOPFactory().Logger(), nil, "explicit")
		defer manager.RuntimeCloseAndWait()
		inner := new(runtimeTestInner)
		managed := legacyTestManagedTransport(t, inner)
		shared := &sharedManagedTransport{managed: managed, shared: &sharedState{}}
		manager.sharedTransports["explicit"] = shared
		manager.managedTransports = append(manager.managedTransports, managed)
		manager.Initialize(func() (*ManagedTransport, error) {
			t.Fatal("explicit default used implicit fallback")
			return nil, nil
		})
		if err := manager.Start(adapter.StartStateStart, scope); err != nil {
			t.Fatal(err)
		}
		if manager.defaultTransport != shared || manager.prepared || manager.frozen {
			t.Fatal("configured legacy default was not selected independently of graph preparation")
		}
		if err := scope.Close(); err != nil {
			t.Fatal(err)
		}
		if inner.closed.Load() != 1 {
			t.Fatal("explicit default escaped scoped cleanup")
		}
	})
	t.Run("missing explicit default", func(t *testing.T) {
		manager := NewManager(context.Background(), log.NewNOPFactory().Logger(), nil, "missing")
		defer manager.RuntimeCloseAndWait()
		err := manager.Start(adapter.StartStateStart, adapter.NewScope(context.Background(), log.NewNOPFactory().Logger()))
		if err == nil || !strings.Contains(err.Error(), "http_client not found: missing") {
			t.Fatalf("unknown explicit default was accepted: %v", err)
		}
	})
	t.Run("setup error", func(t *testing.T) {
		manager := NewManager(context.Background(), log.NewNOPFactory().Logger(), nil, "")
		defer manager.RuntimeCloseAndWait()
		setupErr := errors.New("client options could not be cloned")
		manager.setupErr = setupErr
		if err := manager.Start(adapter.StartStateStart, adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())); !errors.Is(err, setupErr) {
			t.Fatalf("setup error hidden: %v", err)
		}
	})
	t.Run("closed manager", func(t *testing.T) {
		manager := NewManager(context.Background(), log.NewNOPFactory().Logger(), nil, "")
		if err := manager.RuntimeCloseAndWait(); err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(adapter.StartStateStart, adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed manager started: %v", err)
		}
	})
}

func TestRuntimeHTTPPreparationRemainsEagerAndFrozen(t *testing.T) {
	manager := NewManager(context.Background(), log.NewNOPFactory().Logger(), nil, "")
	defer manager.RuntimeCloseAndWait()
	inner := new(runtimeTestInner)
	var calls atomic.Int32
	if err := manager.PrepareRuntime(func() (*ManagedTransport, error) {
		calls.Add(1)
		return legacyTestManagedTransport(t, inner), nil
	}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || !manager.prepared || manager.frozen {
		t.Fatal("candidate preparation was made lazy with legacy startup")
	}
	if _, err := manager.RuntimePreparedTransport(""); err == nil {
		t.Fatal("unfrozen inventory was exposed")
	}
	if err := manager.FreezeRuntime(); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.RuntimePreparedTransport(""); err != nil {
		t.Fatal(err)
	}
	if err := manager.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ResolveTransport(context.Background(), log.NewNOPFactory().Logger(), option.HTTPClientOptions{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed graph accepted a transport: %v", err)
	}
}
