package box

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxCertificate "github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

type retirementEndpoint struct {
	adapter.Endpoint
	tag     string
	retired int
	writer  string
	events  *[]string
}

func (*retirementEndpoint) Type() string  { return C.TypeTailscale }
func (e *retirementEndpoint) Tag() string { return e.tag }

func (e *retirementEndpoint) TailscaleStateStoreScope() adapter.TailscaleStoreNode {
	return adapter.TailscaleStoreNode{Tag: e.tag, StateFile: "/original/" + e.tag + "/tailscaled.state", WriterState: "Unknown"}
}

func (e *retirementEndpoint) RetireTailscaleStateStore(time.Time) adapter.TailscaleStoreNode {
	e.retired++
	if e.events != nil {
		*e.events = append(*e.events, "retire "+e.tag)
	}
	node := e.TailscaleStateStoreScope()
	node.WriterState = e.writer
	return node
}

// retirementRegistry registers a Tailscale endpoint type that behaves like the
// real one towards the box: its state store is retired by the box before the
// scope is closed, and its construction cleanup reports an unknown writer.
func retirementRegistry(created map[string]*retirementEndpoint, writer string, events *[]string) *endpoint.Registry {
	registry := endpoint.NewRegistry()
	endpoint.Register[struct{}](registry, C.TypeTailscale, func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ struct{}) (adapter.Endpoint, error) {
		e := &retirementEndpoint{tag: tag, writer: writer, events: events}
		created[tag] = e
		err := adapter.DeferConstructionCleanup(ctx, func() error {
			if events != nil {
				*events = append(*events, "cleanup "+tag)
			}
			if e.RetireTailscaleStateStore(time.Time{}).WriterState == "Unknown" {
				return errors.New("Tailscale state writer retirement unknown")
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return e, nil
	})
	return registry
}

func TestTailscaleStoreCensusRetainsOriginalAndSealsLateEndpoint(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	created := map[string]*retirementEndpoint{}
	scope := adapter.NewScope(context.Background(), logger)
	ctx := adapter.ContextWithConstructionScope(context.Background(), scope)
	manager := endpoint.NewManager(retirementRegistry(created, "NoStoreConstruction", nil))
	err := manager.Create(ctx, nil, logger, "original", C.TypeTailscale, &struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	original := created["original"]
	box := &Box{endpoint: manager, scope: scope}
	scopes := box.TailscaleStateStoreScopes()
	if len(scopes) != 1 || scopes[0].Tag != "original" || original.retired != 0 {
		t.Fatal("readonly capture retired or lost original")
	}
	err = manager.Create(ctx, nil, logger, "late", C.TypeTailscale, &struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	late := created["late"]
	box.retireTailscaleStateStores()
	if original.retired != 1 || late.retired != 1 {
		t.Fatal("original or late writer escaped sealing")
	}
	nodes := box.TailscaleStoreRetirement()
	if len(nodes) != 2 || nodes[0].Tag != "original" || nodes[1].Tag != "late" {
		t.Fatalf("final census omitted a writer: %+v", nodes)
	}
	nodes[0].WriterState = "mutated"
	if box.TailscaleStoreRetirement()[0].WriterState != "NoStoreConstruction" {
		t.Fatal("caller changed immutable snapshot")
	}
}

func retirementOptions(registry *endpoint.Registry, tags ...string) Options {
	ctx := Context(context.Background(), inbound.NewRegistry(), outbound.NewRegistry(), registry, dns.NewTransportRegistry(), boxService.NewRegistry(), boxCertificate.NewRegistry())
	options := option.Options{Log: &option.LogOptions{Disabled: true}}
	for _, tag := range tags {
		options.Endpoints = append(options.Endpoints, option.Endpoint{Type: C.TypeTailscale, Tag: tag, Options: &struct{}{}})
	}
	return Options{Context: ctx, Options: options}
}

func TestCloseRetiresTailscaleStoresBeforeClosingScope(t *testing.T) {
	created := map[string]*retirementEndpoint{}
	var events []string
	instance, err := New(retirementOptions(retirementRegistry(created, "NoStoreConstruction", &events), "ts"))
	if err != nil {
		t.Fatal(err)
	}
	instance.scope.Add(func() error {
		events = append(events, "runtime")
		return nil
	})
	if len(events) != 0 {
		t.Fatalf("construction retired the store: %v", events)
	}
	err = instance.CloseWithResult()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 3 || events[0] != "retire ts" || events[1] != "runtime" || events[2] != "cleanup ts" {
		t.Fatalf("close order = %v, want the store retired before the scope is closed", events)
	}
	nodes := instance.TailscaleStoreRetirement()
	if len(nodes) != 1 || nodes[0].Tag != "ts" || nodes[0].WriterState != "NoStoreConstruction" {
		t.Fatalf("retirement census = %+v", nodes)
	}
}

func TestCloseResultReportsUnknownTailscaleWriter(t *testing.T) {
	created := map[string]*retirementEndpoint{}
	instance, err := New(retirementOptions(retirementRegistry(created, "Unknown", nil), "ts"))
	if err != nil {
		t.Fatal(err)
	}
	err = instance.CloseWithResult()
	if err == nil || err.Error() != "Tailscale state writer retirement unknown" {
		t.Fatalf("CloseWithResult = %v, want unknown writer retirement", err)
	}
}

func TestFailedConstructionRetiresTailscaleStore(t *testing.T) {
	created := map[string]*retirementEndpoint{}
	instance, err, report := NewWithConstructionReport(retirementOptions(retirementRegistry(created, "NoStoreConstruction", nil), "ts", "ts"))
	if instance != nil || err == nil {
		t.Fatalf("New = %v, %v; want duplicate tag failure", instance, err)
	}
	if report.CleanupError != nil {
		t.Fatalf("report = %+v", report)
	}
	if created["ts"].retired != 1 {
		t.Fatalf("rejected endpoint retired %d times, want 1", created["ts"].retired)
	}
}
