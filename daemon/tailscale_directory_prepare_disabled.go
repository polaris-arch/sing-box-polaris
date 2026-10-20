//go:build !windows || !with_tailscale

package daemon

import "context"

func (s *StartedService) prepareManagedDirectories(_ context.Context, _ *preparedInstance) error { return nil }
