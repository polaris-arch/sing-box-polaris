//go:build !windows && with_tailscale

package tailscale

import (
	"context"
	"sync"
)

// PreparedDirectoryLeases retains the original leases through construction.
// Only the Windows validated preparation entrypoint creates populated plans.
// Abort is lifecycle-owned and must run after Box construction has unwound.
type PreparedDirectoryLeases struct {
	mu        sync.Mutex
	ctx       context.Context
	entries   []*preparedDirectoryEntry
	aborted   bool
	committed bool
	validated bool
}
