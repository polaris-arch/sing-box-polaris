package boxruntime

import (
	"context"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

type RuntimeAPI interface {
	adapter.RuntimeAPIProvider
	adapter.RuntimeDashboardHTTPProvider
}

// Host binds the instance to the public Box type and its upstream platform
// entry points. The same binding is used for legacy and graph-backed instances.
type Host struct {
	PrepareDirectory func(context.Context, option.Options) (context.Context, error)
	CheckDebug       func(option.DebugOptions) error
	StartDebug       func(option.DebugOptions) (*http.Server, error)
	Register         func(context.Context, *Box) RuntimeAPI
}

func (h *Host) register(ctx context.Context, instance *Box) RuntimeAPI {
	if h != nil {
		return h.Register(ctx, instance)
	}
	service.MustRegisterPtr(ctx, instance)
	return instance
}

func (s *Box) startDebug() (*http.Server, error) {
	if s.host == nil {
		return nil, nil
	}
	return s.host.StartDebug(s.debugOptions)
}
