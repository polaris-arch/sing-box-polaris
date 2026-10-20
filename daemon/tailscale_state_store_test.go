package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	boxCertificate "github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing/service"
)

type retirementTestEndpoint struct {
	adapter.Endpoint
	node     adapter.TailscaleStoreNode
	disposed int
	retired  int
}

func (*retirementTestEndpoint) Type() string  { return C.TypeTailscale }
func (e *retirementTestEndpoint) Tag() string { return e.node.Tag }

func (*retirementTestEndpoint) Start(adapter.StartStage, *adapter.Scope) error {
	panic("pure constructor test must not start runtime")
}

func (e *retirementTestEndpoint) TailscaleStateStoreScope() adapter.TailscaleStoreNode { return e.node }

func (e *retirementTestEndpoint) RetireTailscaleStateStore(time.Time) adapter.TailscaleStoreNode {
	e.retired++
	node := e.node
	node.WriterState = "NoStoreConstruction"
	node.StateFileState = "Missing"
	node.ProfileState = "None"
	return node
}

func retirementPureHost(t *testing.T) (*StartedService, *[]*retirementTestEndpoint) {
	t.Helper()
	t.Chdir(t.TempDir())
	dnsRegistry := dns.NewTransportRegistry()
	local.RegisterTransport(dnsRegistry)
	endpoints := endpoint.NewRegistry()
	outbounds := outbound.NewRegistry()
	direct.RegisterOutbound(outbounds)
	ctx := box.Context(context.Background(), inbound.NewRegistry(), outbounds, endpoints, dnsRegistry, boxService.NewRegistry(), boxCertificate.NewRegistry())
	created := new([]*retirementTestEndpoint)
	endpoint.Register[struct{}](endpoints, C.TypeTailscale, func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ struct{}) (adapter.Endpoint, error) {
		binding := service.PtrFromContext[adapter.TailscaleStoreRunBinding](ctx)
		if binding == nil {
			t.Fatal("guard created before original run binding")
		}
		directory := filepath.Join(t.TempDir(), tag)
		e := &retirementTestEndpoint{node: adapter.TailscaleStoreNode{RunNonce: binding.RunNonce, ConfigDigest: binding.ConfigDigest, Tag: tag, StateDirectory: directory, StateFile: filepath.Join(directory, "tailscaled.state"), WriterState: "Unknown", StateFileState: "Unknown", ProfileState: "Unknown"}}
		*created = append(*created, e)
		// Like the real endpoint, release the store through the construction scope.
		err := adapter.DeferConstructionCleanup(ctx, func() error { e.disposed++; return nil })
		if err != nil {
			return nil, err
		}
		return e, nil
	})
	endpoint.Register[struct{}](endpoints, "test-constructor-failure", func(context.Context, adapter.Router, log.ContextLogger, string, struct{}) (adapter.Endpoint, error) {
		return nil, errors.New("original partial constructor failure")
	})
	host := NewStartedService(ServiceOptions{Context: ctx, StrictCleanup: true, KeepDefaultLogger: true})
	t.Cleanup(func() { host.Close() })
	return host, created
}

func TestTailscaleStoreActualInstanceUnstartedExportAndRetainedRuns(t *testing.T) {
	host, created := retirementPureHost(t)
	// Keep the synthetic physical store owner on the existing legacy path.
	content := `{"certificate":{},"endpoints":[{"type":"tailscale","tag":"a"},{"type":"tailscale","tag":"b"}]}`
	for range 2 {
		host.lifecycleAccess.Lock()
		instance, err := host.newInstance(context.Background(), content, nil, false)
		host.lifecycleAccess.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		active := host.tailscaleRetirementRuns[len(host.tailscaleRetirementRuns)-1].snapshot()
		digest := sha256.Sum256([]byte(content))
		if len(active.RunNonce) != 64 || active.ConfigDigest != hex.EncodeToString(digest[:]) || len(active.Nodes) != 2 || active.Terminal != "Unknown" || active.CensusComplete {
			t.Fatalf("active original metadata invalid: %+v", active)
		}
		if active.Nodes[0].StateDirectory == "" || active.Nodes[0].WriterState != "Unknown" {
			t.Fatal("missing actual active scope")
		}
		first := host.ExportTailscaleStoreRetirement()
		if first != host.ExportTailscaleStoreRetirement() {
			t.Fatal("readonly export mutated instance")
		}
		if err := instance.CloseWithResult(); err != nil {
			t.Fatal(err)
		}
		terminal := instance.tailscaleRetirement.snapshot()
		if terminal.Terminal != "NoStoreConstruction" || !terminal.CensusComplete || len(terminal.Nodes) != 2 {
			t.Fatalf("unstarted full census missing: %+v", terminal)
		}
		for range 2 {
			if err := instance.CloseWithResult(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(*created) != 4 {
		t.Fatal("unexpected constructor count")
	}
	for _, e := range *created {
		if e.retired != 1 || e.disposed != 1 {
			t.Fatalf("unstarted lifecycle not covered exactly: %+v", e)
		}
	}
	var export struct {
		ContractVersion, GlobalCleanupEvidence string
		Instances                              []tailscaleRetirementInstance
	}
	payload := host.ExportTailscaleStoreRetirement()
	if err := json.Unmarshal([]byte(payload), &export); err != nil {
		t.Fatal(err)
	}
	if export.ContractVersion != tailscaleStoreRetirementVersion || export.GlobalCleanupEvidence != "CleanupUnknown" || len(export.Instances) != 2 {
		t.Fatalf("lost original run/export boundary: %s", payload)
	}
	if export.Instances[0].RunNonce == export.Instances[1].RunNonce {
		t.Fatal("reload reused original nonce")
	}
}

func TestTailscaleStoreFailedConstructionCannotUpgrade(t *testing.T) {
	host, _ := retirementPureHost(t)
	content := `{"endpoints":[{"type":"tailscale","tag":"constructed"},{"type":"test-constructor-failure","tag":"fails"}]}`
	host.lifecycleAccess.Lock()
	instance, err := host.newInstance(context.Background(), content, nil, false)
	host.lifecycleAccess.Unlock()
	if err == nil || instance != nil {
		t.Fatal("partial construction did not fail")
	}
	if len(host.tailscaleRetirementRuns) != 1 {
		t.Fatal("partial run silently omitted")
	}
	run := host.tailscaleRetirementRuns[0]
	initial := run.snapshot()
	if initial.Terminal != "Unknown" || initial.CensusComplete {
		t.Fatalf("partial constructor promoted: %+v", initial)
	}
	run.freeze(nil, true)
	if !reflect.DeepEqual(initial, run.snapshot()) {
		t.Fatal("late finalizer upgraded partial construction")
	}
}

func TestTailscaleStoreWrongCensusBindingAndStickyClose(t *testing.T) {
	options := option.Options{Endpoints: []option.Endpoint{{Type: C.TypeTailscale, Tag: "a"}, {Type: C.TypeTailscale, Tag: "b"}}}
	for _, kind := range []string{"complete", "missing", "extra", "duplicate-tag", "duplicate-path", "wrong-nonce", "wrong-config", "unknown", "constructor-partial"} {
		t.Run(kind, func(t *testing.T) {
			run, err := newTailscaleRetirementRun("actual-profile", options)
			if err != nil {
				t.Fatal(err)
			}
			nodes := []adapter.TailscaleStoreNode{}
			for _, tag := range []string{"a", "b"} {
				nodes = append(nodes, adapter.TailscaleStoreNode{Tag: tag, StateDirectory: "/scope/" + tag, StateFile: "/scope/" + tag + "/tailscaled.state", WriterState: "SealedDrained", RunNonce: run.binding.RunNonce, ConfigDigest: run.binding.ConfigDigest})
			}
			constructed := true
			switch kind {
			case "missing":
				nodes = nodes[:1]
			case "extra":
				nodes = append(nodes, nodes[0])
				nodes[2].Tag = "c"
			case "duplicate-tag":
				nodes[1].Tag = "a"
			case "duplicate-path":
				nodes[1].StateFile = nodes[0].StateFile
			case "wrong-nonce":
				nodes[0].RunNonce = "caller-supplied"
			case "wrong-config":
				nodes[0].ConfigDigest = "old-config"
			case "unknown":
				nodes[0].WriterState = "Unknown"
			case "constructor-partial":
				constructed = false
			}
			run.freeze(nodes, constructed)
			result := run.snapshot()
			if kind == "complete" {
				if result.Terminal != "SealedDrained" || !result.CensusComplete {
					t.Fatal("complete census rejected")
				}
			} else if result.Terminal != "Unknown" || result.CensusComplete {
				t.Fatalf("%s accepted: %+v", kind, result)
			}
			frozen := run.snapshot()
			nodes[0].Tag = "mutated"
			run.freeze(nil, true)
			if !reflect.DeepEqual(frozen, run.snapshot()) {
				t.Fatal("terminal overwritten")
			}
			failure := errors.New("original operational close failure")
			host := NewStartedService(ServiceOptions{Context: context.Background(), StrictCleanup: true})
			defer host.Close()
			host.cleanupErr = failure
			host.tailscaleRetirementRuns = []*tailscaleRetirementRun{run}
			if err := host.CloseService(); !errors.Is(err, failure) {
				t.Fatal("export cleared sticky close failure", err)
			}
			payload := host.ExportTailscaleStoreRetirement()
			if !strings.Contains(payload, `"globalCleanupEvidence":"CleanupUnknown"`) || strings.Contains(payload, "private") || strings.Contains(payload, "caller-supplied") {
				t.Fatal("payload boundary invalid", payload)
			}
			if err := host.StartOrReloadService(context.Background(), `{}`, &OverrideOptions{}); !errors.Is(err, os.ErrClosed) {
				t.Fatal("late start accepted", err)
			}
		})
	}
}
