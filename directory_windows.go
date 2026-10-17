//go:build windows && with_tailscale

package box

import (
	"context"

	"github.com/sagernet/sing-box/experimental/directorywindows"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/tailscale"
)

// Runs before box resources and before any endpoint/SDK filesystem constructor.
func prepareWindowsDirectoryDomain(ctx context.Context, options option.Options) (context.Context, error) {
	return directorywindows.Prepare(ctx, options, tailscale.PoisonDirectoryDomain)
}
