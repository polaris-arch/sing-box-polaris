package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestRuntimeCLIRecoveryRootRequiresExplicitResolvedDirectory(t *testing.T) {
	for _, absent := range []string{"", ".", "relative-state"} {
		if _, present := adapter.RuntimeRecoveryRootFromContext(runtimeCLIRecoveryContext(context.Background(), absent)); present {
			t.Fatal("implicit cwd/config path became a recovery root")
		}
	}
	root := t.TempDir()
	ctx := runtimeCLIRecoveryContext(context.Background(), root)
	if value, present := adapter.RuntimeRecoveryRootFromContext(ctx); !present || value != filepath.Clean(root) {
		t.Fatal("explicit host-selected state root was lost", value)
	}
}
