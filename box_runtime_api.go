package box

import (
	"context"
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
	if item.Type != C.TypeAPI || !ok || options.Listen == nil || !netip.Addr(*options.Listen).IsLoopback() {
		return false
	}
	return options.TLS == nil && runtimeStableDashboard(options.Dashboard) &&
		options.Detour == "" && options.NetNs == "" && options.BindInterface == "" &&
		options.RoutingMark == 0 && !options.TCPFastOpen && !options.TCPMultiPath
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
