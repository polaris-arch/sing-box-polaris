//go:build !windows

package cachefile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

func TestRuntimeUnusableRecoveryRootPreservesColdStartButCannotIgnoreJournal(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })
	ctx := adapter.ContextWithRuntimeRecoveryRoot(context.Background(), root)
	if ready, err := FakeIPRuntimeRecoveryRootReady(ctx); ready || err != nil {
		t.Fatal("new custody requirement broke legacy startup without recovery evidence", ready, err)
	}
	path := filepath.Join(root, fakeIPRuntimeJournalName)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("readiness inspection created journal", err)
	}
	if err := os.WriteFile(path, []byte("existing recovery evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ready, err := FakeIPRuntimeRecoveryRootReady(ctx); ready || err == nil {
		t.Fatal("existing journal was ignored after custody failure", ready, err)
	}
}

func TestRuntimeUnixJournalReopenKeepsPermissionBoundary(t *testing.T) {
	root := t.TempDir()
	ctx := adapter.ContextWithRuntimeRecoveryRoot(context.Background(), root)
	journal, err := OpenFakeIPRuntimeJournal(ctx, log.NewNOPFactory().Logger())
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, fakeIPRuntimeJournalName)
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0600) })
	if opened, err := OpenFakeIPRuntimeJournal(ctx, log.NewNOPFactory().Logger()); !errors.Is(err, ErrFakeIPRecoveryCustody) || opened != nil {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatal("platform dispatch relaxed Unix file permissions", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	journal, err = OpenFakeIPRuntimeJournal(ctx, log.NewNOPFactory().Logger())
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
}
