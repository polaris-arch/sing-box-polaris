//go:build !windows

package listener

import "syscall"

// On these targets Go's normal TCP bind does not opt into SO_REUSEPORT. Keep
// ordinary TIME_WAIT/SO_REUSEADDR behavior; callers prohibit user port sharing
// and wildcard addresses instead of changing all protocol listeners.
func apiExclusiveControl(_, _ string, _ syscall.RawConn) error { return nil }
