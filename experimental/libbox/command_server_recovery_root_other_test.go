//go:build !windows

package libbox

import (
	"os"
	"path/filepath"
	"testing"
)

// The original short parent owns removal after the primary's deferred close.
func commandServerPrivateRecoveryRoot(t *testing.T, parent string) string {
	t.Helper()
	root := filepath.Join(parent, "recovery-root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal("create private recovery root:", err)
	}
	return root
}
