package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

type standaloneTailscaleSource struct{}

func (standaloneTailscaleSource) ID() adapter.RuntimeResourceID {
	return adapter.RuntimeResourceID{Incarnation: "standalone-fixture", Sequence: 1}
}

func (standaloneTailscaleSource) Acquire() (adapter.RuntimeResourceLease, error) {
	return nil, errors.New("registration must not acquire a physical resource")
}

const standaloneTailscaleConfig = `{"endpoints":[{"type":"tailscale","tag":"child","state_directory":"fixture-state","taildrop_directory":"fixture-taildrop"}]}`

func standaloneTailscaleContext() context.Context {
	registry := endpoint.NewRegistry()
	endpoint.Register[option.TailscaleEndpointOptions](registry, C.TypeTailscale, func(context.Context, adapter.Router, log.ContextLogger, string, option.TailscaleEndpointOptions) (adapter.Endpoint, error) {
		panic("registration-only fixture must not construct a native child")
	})
	ctx := service.ContextWith[option.EndpointOptionsRegistry](context.Background(), registry)
	ctx = adapter.ContextWithRuntimeResourceSource(ctx, standaloneTailscaleSource{})
	return adapter.ContextWithRuntimeTailscaleConfiguration(ctx, []byte(standaloneTailscaleConfig))
}

func standaloneTailscaleRequest(t *testing.T) adapter.RuntimeTailscaleChildRequest {
	t.Helper()
	constructionDone, closeDone := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(constructionDone); close(closeDone) })
	return adapter.RuntimeTailscaleChildRequest{
		ResourceID: standaloneTailscaleSource{}.ID(), Generation: 1, Tag: "child",
		StateDirectory: "fixture-state", TaildropDirectory: "fixture-taildrop",
		ConstructionDone: constructionDone, CloseDone: closeDone,
		ConstructionResult: func() error { return errors.New("native construction deliberately not performed") },
		CloseResult:        func() error { return nil },
		StoreScopes:        func() []adapter.TailscaleStoreNode { return nil },
		DirectoryScopes:    func() []adapter.TailscaleDirectoryNode { return nil },
	}
}

func TestStandaloneTailscaleRegistryPreservesOriginalBindingAndBase(t *testing.T) {
	ctx := ContextWithRuntimeTailscaleChildren(standaloneTailscaleContext())
	logical, cancelLogical := context.WithCancel(ctx)
	stable, cancelStable := context.WithCancel(context.Background())
	defer cancelStable()
	request := standaloneTailscaleRequest(t)
	registration, err := adapter.RegisterRuntimeTailscaleChild(adapter.ContextWithRuntimeTailscaleChildBase(logical, stable), request)
	if err != nil {
		t.Fatal(err)
	}
	child := registration.(*runtimeTailscaleChild)
	digest := sha256.Sum256([]byte(standaloneTailscaleConfig))
	binding := service.PtrFromContext[adapter.TailscaleStoreRunBinding](child.Context())
	if binding == nil || len(binding.RunNonce) != 64 || binding.ConfigDigest != hex.EncodeToString(digest[:]) {
		t.Fatal("standalone registry did not bind the original whole configuration")
	}
	if child.run.closeFinished != request.CloseDone || child.request.ConstructionDone != request.ConstructionDone {
		t.Fatal("standalone registry substituted child-owned completion signals")
	}
	cancelLogical()
	if child.Context().Err() != nil {
		t.Fatal("physical child inherited logical cancellation instead of its stable base")
	}
	if err := child.Constructed(); err == nil {
		t.Fatal("registration certified a constructor that has not returned")
	}
	if err := child.Abort(); err == nil {
		t.Fatal("registration aborted a live constructor binding")
	}
	cancelStable()
	if !errors.Is(child.Context().Err(), context.Canceled) {
		t.Fatal("standalone registry detached physical-base cancellation")
	}
}

func TestStandaloneTailscaleRegistryKeepsAdmissionFailClosed(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(context.Context, *adapter.RuntimeTailscaleChildRequest) context.Context
		want   string
	}{
		{"missing registrar", func(ctx context.Context, _ *adapter.RuntimeTailscaleChildRequest) context.Context {
			return adapter.ContextWithRuntimeTailscaleChildRegistrar(ctx, nil)
		}, "registration unavailable"},
		{"missing original evidence", func(ctx context.Context, request *adapter.RuntimeTailscaleChildRequest) context.Context {
			request.CloseResult = nil
			return ctx
		}, "incomplete original Tailscale child evidence"},
		{"wrong owner", func(ctx context.Context, request *adapter.RuntimeTailscaleChildRequest) context.Context {
			request.ResourceID.Sequence++
			return ctx
		}, "does not match constructor owner"},
		{"missing captured configuration", func(ctx context.Context, _ *adapter.RuntimeTailscaleChildRequest) context.Context {
			return adapter.ContextWithRuntimeTailscaleConfiguration(ctx, nil)
		}, "lacks captured whole configuration"},
		{"wrong original path", func(ctx context.Context, request *adapter.RuntimeTailscaleChildRequest) context.Context {
			request.StateDirectory = "unrelated-state"
			return ctx
		}, "paths differ from captured configuration"},
		{"unconfigured child", func(ctx context.Context, request *adapter.RuntimeTailscaleChildRequest) context.Context {
			request.Tag = "unconfigured"
			return ctx
		}, "absent from captured configuration"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := ContextWithRuntimeTailscaleChildren(standaloneTailscaleContext())
			request := standaloneTailscaleRequest(t)
			ctx = test.change(ctx, &request)
			registration, err := adapter.RegisterRuntimeTailscaleChild(ctx, request)
			if registration != nil || err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("admission did not preserve its rejection: %v", err)
			}
		})
	}
}

func TestStandaloneTailscaleRegistryRetainsCensusAcrossDerivedContexts(t *testing.T) {
	ctx := ContextWithRuntimeTailscaleChildren(standaloneTailscaleContext())
	var children []*runtimeTailscaleChild
	// Register this cleanup first so request cleanups close their original
	// channels before it waits for the existing asynchronous close observers.
	t.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for _, child := range children {
			for {
				child.run.access.Lock()
				done := child.run.originalCloseSucceeded
				child.run.access.Unlock()
				if done {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("original close observer did not finish")
				}
				time.Sleep(time.Millisecond)
			}
		}
	})
	for index := range maxTailscaleRetirementRuns {
		derived, cancel := context.WithCancel(service.ExtendContext(ctx))
		request := standaloneTailscaleRequest(t)
		request.Generation = uint64(index + 1)
		registration, err := adapter.RegisterRuntimeTailscaleChild(derived, request)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		children = append(children, registration.(*runtimeTailscaleChild))
	}
	// Cancellation of the containing context is not actual child completion.
	if registration, err := adapter.RegisterRuntimeTailscaleChild(service.ExtendContext(ctx), standaloneTailscaleRequest(t)); registration != nil || err == nil || !strings.Contains(err.Error(), "census capacity reached") {
		t.Fatalf("derived context reset the retained original census: %v", err)
	}
	other := ContextWithRuntimeTailscaleChildren(standaloneTailscaleContext())
	registration, err := adapter.RegisterRuntimeTailscaleChild(other, standaloneTailscaleRequest(t))
	if err != nil {
		t.Fatal("independent CLI lifecycle inherited another census", err)
	}
	children = append(children, registration.(*runtimeTailscaleChild))
}
