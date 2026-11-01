package box

import (
	"bytes"
	"context"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// The local API is a stable control-plane ingress. It captures no graph leaf:
// daemon operations and supported dashboard downloads explicitly borrow current
// graph snapshots. Other dashboard clients and TLS retain the legacy path.
func runtimeStableAPIService(item option.Service) bool {
	options, ok := item.Options.(*option.APIServiceOptions)
	if item.Type != C.TypeAPI || !ok || options.Listen == nil || (!netip.Addr(*options.Listen).Unmap().IsLoopback() || netip.Addr(*options.Listen).Zone() != "") {
		return false
	}
	return options.TLS == nil && runtimeStableDashboard(options.Dashboard) &&
		options.Detour == "" && options.NetNs == "" && options.BindInterface == "" &&
		options.RoutingMark == 0 && !options.ReuseAddr && !options.TCPFastOpen && !options.TCPMultiPath
}

// AcquireRuntimeAPI transfers a current graph reservation plus its publication
// change signal in the same admission epoch. Callers must join all work using
// the view before Release. A legacy Box returns connected=false.
func (s *Box) AcquireRuntimeAPI() (lease adapter.RuntimeLease, changed <-chan struct{}, connected bool, err error) {
	if s == nil || s.runtime == nil {
		return nil, nil, false, nil
	}
	lease, changed, err = s.runtime.store.AcquireWithChanges()
	return lease, changed, true, err
}

// Only the App's explicit inline detour-only client has a stable adapter. Check
// the complete structure, including fields deliberately omitted from JSON.
func runtimeStableDashboard(options *option.APIDashboardOptions) bool {
	if options == nil || !options.Enabled {
		return true
	}
	if options.HTTPClient == nil || options.HTTPClient.Detour == "" {
		return false
	}
	client := *options.HTTPClient
	client.Detour = ""
	return reflect.ValueOf(client).IsZero()
}

// This key lives outside the public named/default HTTP client namespace.
type runtimeDashboardHTTPKey struct {
	ServiceTag string
}

type runtimeDashboardHTTPConfig struct {
	Key     runtimeDashboardHTTPKey
	Options option.HTTPClientOptions
}

func runtimeDashboardHTTPConfigs(options option.Options) ([]runtimeDashboardHTTPConfig, error) {
	var clients []runtimeDashboardHTTPConfig
	seen := make(map[string]bool)
	for index, item := range options.Services {
		if !runtimeStableAPIService(item) {
			continue
		}
		tag := item.Tag
		if tag == "" {
			tag = fmt.Sprint(index)
		}
		if seen[tag] {
			return nil, fmt.Errorf("duplicate stable API service tag: %s", tag)
		}
		seen[tag] = true
		options := item.Options.(*option.APIServiceOptions).Dashboard
		if options != nil && options.Enabled {
			clients = append(clients, runtimeDashboardHTTPConfig{runtimeDashboardHTTPKey{tag}, *options.HTTPClient})
		}
	}
	return clients, nil
}

type runtimeDashboardHTTPLease struct {
	ctx       context.Context
	transport adapter.HTTPTransport
	lease     adapter.RuntimeLease
	once      sync.Once
}

func (l *runtimeDashboardHTTPLease) Context() context.Context         { return l.ctx }
func (l *runtimeDashboardHTTPLease) Transport() adapter.HTTPTransport { return l.transport }
func (l *runtimeDashboardHTTPLease) Release()                         { l.once.Do(l.lease.Release) }

func (s *Box) AcquireDashboardHTTP(ctx context.Context, serviceTag string) (adapter.RuntimeDashboardHTTPLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lease, _, connected, err := s.AcquireRuntimeAPI()
	if err != nil {
		return nil, err
	}
	if !connected {
		return nil, errors.New("dashboard runtime admission unavailable")
	}
	view, ok := lease.View().(*runtimeView)
	if !ok {
		lease.Release()
		return nil, errors.New("dashboard runtime view unavailable")
	}
	transport := view.dashboardHTTP[runtimeDashboardHTTPKey{serviceTag}]
	if transport == nil {
		lease.Release()
		return nil, errors.New("dashboard HTTP client was not prepared")
	}
	return &runtimeDashboardHTTPLease{ctx: adapter.ContextWithRuntimeLease(ctx, lease), transport: transport, lease: lease}, nil
}

// Only address/port/secret changes share the stable control-plane owner. Tag,
// cardinality, TLS, dashboard HTTP and every socket option remain structural.
func runtimeAPIHandoffChanges(before, after stdjson.RawMessage) bool {
	var left, right []map[string]stdjson.RawMessage
	if stdjson.Unmarshal(before, &left) != nil || stdjson.Unmarshal(after, &right) != nil || len(left) != 1 || len(left) != len(right) {
		return false
	}
	for i := range left {
		if string(left[i]["type"]) != `"api"` || string(right[i]["type"]) != `"api"` {
			return false
		}
		for _, key := range []string{"listen", "listen_port", "secret"} {
			delete(left[i], key)
			delete(right[i], key)
		}
		a, _ := stdjson.Marshal(left[i])
		b, _ := stdjson.Marshal(right[i])
		if !bytes.Equal(a, b) {
			return false
		}
	}
	return true
}

func runtimeAPIIdentities(options option.Options, identity RuntimeIdentity) (map[string]adapter.RuntimeAPIIdentity, error) {
	result := make(map[string]adapter.RuntimeAPIIdentity)
	for i, item := range options.Services {
		if !runtimeStableAPIService(item) {
			continue
		}
		tag := item.Tag
		if tag == "" {
			tag = fmt.Sprint(i)
		}
		digest, err := adapter.RuntimeAPIConfigDigest(*item.Options.(*option.APIServiceOptions))
		if err != nil {
			return nil, err
		}
		result[tag] = adapter.RuntimeAPIIdentity{Incarnation: identity.Incarnation, Revision: identity.Revision, EffectiveDigest: identity.EffectiveDigest, ConfigurationDigest: digest}
	}
	return result, nil
}

func (s *Box) RuntimeAPIIngressIdentity(tag string) (adapter.RuntimeAPIIdentity, error) {
	lease, changed, connected, err := s.AcquireRuntimeAPI()
	if err != nil {
		return adapter.RuntimeAPIIdentity{}, err
	}
	if !connected {
		return adapter.RuntimeAPIIdentity{}, errors.New("API graph unavailable")
	}
	defer lease.Release()
	view, ok := lease.View().(*runtimeView)
	if !ok {
		return adapter.RuntimeAPIIdentity{}, errors.New("API graph view unavailable")
	}
	value, ok := view.apiIdentities[tag]
	if !ok {
		return adapter.RuntimeAPIIdentity{}, errors.New("API ingress is not in the active graph")
	}
	value.Changed = changed
	return value, nil
}

func (s *Box) prepareRuntimeAPI(ctx context.Context, graph *preparedRuntimeGraph) error {
	s.runtime.access.Lock()
	previous := s.runtime.options
	s.runtime.access.Unlock()
	for i, item := range graph.options.Services {
		if !runtimeStableAPIService(item) || i >= len(previous.Services) {
			return errors.New("unsupported API service handoff")
		}
		tag := item.Tag
		if tag == "" {
			tag = fmt.Sprint(i)
		}
		next := *item.Options.(*option.APIServiceOptions)
		digest, err := adapter.RuntimeAPIConfigDigest(next)
		if err != nil {
			return err
		}
		old, ok := previous.Services[i].Options.(*option.APIServiceOptions)
		if !ok {
			return errors.New("API service type changed")
		}
		oldDigest, err := adapter.RuntimeAPIConfigDigest(*old)
		if err != nil {
			return err
		}
		if digest == oldDigest {
			continue
		}
		member, ok := s.service.Get(tag)
		if !ok {
			return errors.New("API service owner unavailable")
		}
		owner, ok := member.(adapter.RuntimeAPIService)
		if !ok {
			return errors.New("API service has no listener handoff adapter")
		}
		handoff, err := owner.PrepareRuntimeAPI(ctx, next)
		if handoff != nil {
			graph.apiHandoffs = append(graph.apiHandoffs, handoff)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
