//go:build !windows || !with_tailscale

package box

import (
	"context"
	"fmt"

	"github.com/sagernet/sing-box/option"
)

func prepareWindowsDirectoryDomain(ctx context.Context, options option.Options) (context.Context, error) {
	if options.PolarisWindowsDirectory != nil {
		//nolint:staticcheck // ST1005: Windows is a proper noun; preserve the stable error contract.
		return nil, fmt.Errorf("Windows directory protocol requires Windows and with_tailscale")
	}
	return ctx, nil
}
