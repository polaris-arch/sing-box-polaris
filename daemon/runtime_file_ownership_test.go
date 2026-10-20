//go:build linux || darwin

package daemon

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRuntimeReplacementPreservesOriginalOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	original := before.Sys().(*syscall.Stat_t)
	committed, err := writeRuntimeOwnedFile(path, []byte("before"), []byte("after"))
	if err != nil || !committed {
		t.Fatalf("replace: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	owner := after.Sys().(*syscall.Stat_t)
	if owner.Uid != original.Uid || owner.Gid != original.Gid || after.Mode() != before.Mode() {
		t.Fatal("source ownership or mode changed")
	}
}
