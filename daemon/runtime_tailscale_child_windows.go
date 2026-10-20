//go:build windows && with_tailscale

package daemon

import (
	"context"
	"errors"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/directorywindows"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/tailscale"
)

func prepareRuntimeChildDirectories(ctx context.Context, options option.Options, selected option.Endpoint) (context.Context, runtimeChildDirectoryPlan, error) {
	if options.PolarisWindowsDirectory == nil {
		if adapter.TailscaleDirectoryDomainFromContext(ctx) != nil || adapter.TailscaleDirectoryMappingFromContext(ctx) != nil {
			return nil, nil, errors.New("physical child inherited managed Windows authority without activation envelope")
		}
		if err := directorywindows.RejectReservedPaths(options.RawMessage); err != nil {
			return nil, nil, err
		}
		return ctx, nil, nil
	}
	prepared, err := directorywindows.PreparePhysicalChildActivation(ctx, options, tailscale.PoisonDirectoryDomain)
	if err != nil {
		return nil, nil, err
	}
	// Full graph projection was validated above; acquire only this exact original
	// physical child's directory, never every logical endpoint in the graph.
	plan, err := tailscale.NewPreparedDirectoryLeases(prepared, option.Options{Endpoints: []option.Endpoint{selected}})
	if err != nil {
		return nil, nil, err
	}
	return plan.Context(), plan, nil
}
