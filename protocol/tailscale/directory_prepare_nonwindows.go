//go:build !windows && with_tailscale

package tailscale

// Non-Windows builds do not expose the mapped-directory acquisition entrypoint.
type preparedDirectoryPlatform struct{}
