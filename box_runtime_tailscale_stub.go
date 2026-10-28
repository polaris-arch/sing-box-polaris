//go:build !with_tailscale

package box

import (
	"context"

	"github.com/sagernet/sing-box/option"
)

type runtimeTailscaleEndpointTransaction struct{}

func (s *Box) stageRuntimeTailscaleEndpoints(context.Context, *preparedRuntimeGraph, []*runtimeResource, []*runtimeResource) (*runtimeTailscaleEndpointTransaction, error) {
	return nil, nil
}
func (t *runtimeTailscaleEndpointTransaction) preparePublication() error        { return nil }
func (t *runtimeTailscaleEndpointTransaction) publish()                         {}
func (t *runtimeTailscaleEndpointTransaction) compensate(context.Context) error { return nil }
func (s *Box) preflightRuntimeTailscaleEndpoints(context.Context, option.Options, []RuntimeSelectorIntent, [32]byte) error {
	return nil
}
