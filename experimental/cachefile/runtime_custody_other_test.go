//go:build !windows

package cachefile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if opened, err := OpenFakeIPRuntimeJournal(ctx, log.NewNOPFactory().Logger()); !errors.Is(err, ErrFakeIPRecoveryCustody) || opened != nil || !strings.Contains(err.Error(), "unix.inspect.kind-or-permissions") {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatal("platform dispatch relaxed Unix file permissions", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
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

// The Unix creator remains exactly exclusive OpenFile with 0600. A nil root
// argument intentionally adds no new authority requirement to that OS helper.
func TestRuntimeUnixActualCreatorKeepsExclusive0600Contract(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creator.db")
	file, err := createRuntimeJournalFile(nil, path)
	if err != nil {
		t.Fatal("original Unix exclusive creation contract changed")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatal("fresh Unix creator did not retain regular private 0600 mode")
	}
	const payload = "existing Unix creator evidence"
	if n, err := file.WriteAt([]byte(payload), 0); err != nil || n != len(payload) {
		t.Fatal("Unix creation handle could not write")
	}
	if err := file.Sync(); err != nil {
		t.Fatal("Unix creation handle could not sync")
	}
	duplicate, err := createRuntimeJournalFile(nil, path)
	if duplicate != nil {
		_ = duplicate.Close()
	}
	if duplicate != nil || !errors.Is(err, os.ErrExist) {
		t.Fatal("Unix exclusive create lost EEXIST classification")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, after) || after.Mode().Perm() != 0o600 {
		t.Fatal("Unix EEXIST changed the original object or permissions")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != payload {
		t.Fatal("Unix EEXIST truncated or changed original evidence")
	}
	if err := file.Close(); err != nil {
		t.Fatal("Unix creation handle did not close")
	}
	missing := filepath.Join(t.TempDir(), "absent", "child.db")
	if file, err := createRuntimeJournalFile(nil, missing); file != nil || !errors.Is(err, os.ErrNotExist) {
		if file != nil {
			_ = file.Close()
		}
		t.Fatal("Unix creator lost its original missing-parent error")
	}
}

func TestRuntimeUnixProductionNewJournalKeeps0600AndDatabaseIdentity(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, fakeIPRuntimeJournalName)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("production Unix NEW journal premise is not absent")
	}
	ctx := adapter.ContextWithRuntimeRecoveryRoot(context.Background(), root)
	journal, err := OpenFakeIPRuntimeJournal(ctx, log.NewNOPFactory().Logger())
	if err != nil {
		t.Fatal("production Unix fresh journal did not open")
	}
	defer journal.Close()
	first, err := journal.RuntimeDescriptor(ctx)
	if err != nil || first.DatabaseID == "" {
		t.Fatal("production Unix journal has no database identity")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatal("production Unix NEW journal lost 0600")
	}
	before, err := os.ReadFile(path)
	if err != nil || len(before) == 0 {
		t.Fatal("production Unix journal has no persisted bytes")
	}
	duplicate, err := createRuntimeJournalFile(nil, path)
	if duplicate != nil {
		_ = duplicate.Close()
	}
	if duplicate != nil || !errors.Is(err, os.ErrExist) {
		t.Fatal("production Unix journal lost exclusive-create protection")
	}
	if after, err := os.ReadFile(path); err != nil || string(after) != string(before) {
		t.Fatal("Unix duplicate creation changed real database bytes")
	}
	if err := journal.Close(); err != nil {
		t.Fatal("production Unix journal did not close")
	}
	journal, err = OpenFakeIPRuntimeJournal(ctx, log.NewNOPFactory().Logger())
	if err != nil {
		t.Fatal("production Unix journal did not reopen")
	}
	defer journal.Close()
	second, err := journal.RuntimeDescriptor(ctx)
	if err != nil || second != first {
		t.Fatal("Unix reopen changed the exact database descriptor")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, after) || after.Mode().Perm() != 0o600 {
		t.Fatal("Unix reopen replaced the original private database object")
	}
}
