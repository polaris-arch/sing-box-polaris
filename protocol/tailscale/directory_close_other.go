//go:build with_tailscale && !windows

package tailscale

func prepareDirectoryLeaseClose(_ *directoryLease, _ error) error { return nil }
