package box

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

type runtimeInboundFixture struct {
	tag    string
	stages atomic.Int32
	closed atomic.Int32
}

func (i *runtimeInboundFixture) Type() string { return C.TypeSOCKS }
func (i *runtimeInboundFixture) Tag() string  { return i.tag }
func (i *runtimeInboundFixture) Start(adapter.StartStage, *adapter.Scope) error {
	panic("legacy inbound Start invoked")
}
func (i *runtimeInboundFixture) RuntimeValidate() error { return nil }
func (i *runtimeInboundFixture) PrepareRuntime(adapter.StartStage, *adapter.Scope) error {
	i.stages.Add(1)
	return nil
}
func (i *runtimeInboundFixture) RuntimeListeners() []*listener.Listener { return nil }

func TestRuntimeInboundInventoryPreservesUnchangedReceiver(t *testing.T) {
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "example.test"), nil)
	registry := service.FromContext[adapter.InboundRegistry](f.ctx).(*inbound.Registry)
	var objects []*runtimeInboundFixture
	inbound.Register[option.SocksInboundOptions](registry, C.TypeSOCKS, func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ option.SocksInboundOptions) (adapter.Inbound, error) {
		instance := &runtimeInboundFixture{tag: tag}
		objects = append(objects, instance)
		if err := adapter.DeferConstructionCleanup(ctx, func() error { instance.closed.Add(1); return nil }); err != nil {
			return nil, err
		}
		return instance, nil
	})
	options.Inbounds = []option.Inbound{{Type: C.TypeSOCKS, Tag: "ingress", Options: &option.SocksInboundOptions{}}}
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.box = instance
	t.Cleanup(func() {
		if err := instance.closeRuntimeResourcesContext(runtimeTestContext(t)); err != nil {
			t.Error(err)
		}
		if err := instance.CloseWithResult(); err != nil {
			t.Error(err)
		}
	})
	f.start(t)
	oldLease, oldView := f.acquire(t)
	member, ok := oldView.inbounds.Get("ingress")
	if !ok || member != objects[0] {
		t.Fatal("initial graph lacks exact inbound")
	}
	if objects[0].stages.Load() != int32(len(adapter.ListStartStages)) {
		t.Fatal("initial inbound stages not run")
	}
	routeCopy := *options.Route
	options.Route = &routeCopy
	options.Route.Final = "a"
	encoded, err := json.MarshalContext(f.ctx, options.Options)
	if err != nil {
		t.Fatal(err)
	}
	_, request := f.plan(t, encoded)
	result, err := instance.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Active.Revision != request.Expected.Revision+1 {
		t.Fatalf("not committed: %+v", result)
	}
	newLease, newView := f.acquire(t)
	defer newLease.Release()
	current, ok := newView.inbounds.Get("ingress")
	if !ok || current != member || len(objects) != 1 {
		t.Fatal("route edit restarted unaffected inbound")
	}
	if objects[0].stages.Load() != int32(len(adapter.ListStartStages)) {
		t.Fatal("borrowed inbound restarted")
	}
	oldLease.Release()
}
