package usagepersist

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

func TestUsageFileLeaseProcess(t *testing.T) {
	path := os.Getenv("USAGE_LEASE_TEST_PATH")
	if path == "" {
		return
	}
	lease, err := AcquireFile(context.Background(), path)
	if os.Getenv("USAGE_LEASE_EXPECT_BUSY") == "1" {
		if !errors.Is(err, ErrFileInUse) {
			t.Fatalf("other process acquired live owner's file: %v", err)
		}
	} else {
		if err != nil {
			t.Fatal(err)
		}
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUsageFileLeaseExcludesOtherInstancesAndProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	first, err := AcquireFile(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := AcquireFile(context.Background(), path); !errors.Is(err, ErrFileInUse) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("duplicate owner: %v", err)
	}
	run := func(busy string) {
		t.Helper()
		child := exec.Command(os.Args[0], "-test.run=^TestUsageFileLeaseProcess$")
		child.Env = append(os.Environ(), "USAGE_LEASE_TEST_PATH="+path, "USAGE_LEASE_EXPECT_BUSY="+busy)
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("child lease: %v %s", err, output)
		}
	}
	run("1")
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	run("0")
	if _, err := os.Stat(path + ".lock"); err != nil {
		t.Fatal("stable sidecar was removed", err)
	}
}

func TestUsageFileLeaseResolvesDirectoryAliases(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "actual")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Skip("symlinks unavailable", err)
	}
	first, err := AcquireFile(context.Background(), filepath.Join(target, "usage.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := AcquireFile(context.Background(), filepath.Join(alias, "usage.json")); !errors.Is(err, ErrFileInUse) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("alias bypass: %v", err)
	}
}

// Emulate a manager which always prefixes its base, including native absolute
// paths. This catches the Windows default-manager contract on every test host.
type prefixingUsageManager struct {
	filemanager.Manager
	root string
}

func (m prefixingUsageManager) BasePath(name string) string {
	return filepath.Join(m.root, strings.TrimLeft(name, "/\\"))
}

func (m prefixingUsageManager) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(m.BasePath(name), flag, perm)
}

func TestUsageLeasePreservesManagerLogicalPath(t *testing.T) {
	root := t.TempDir()
	physicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(physicalRoot, "usage.json")
	for _, forcePrefix := range []bool{false, true} {
		ctx := filemanager.WithDefault(context.Background(), root, "", os.Getuid(), os.Getgid())
		if forcePrefix {
			manager := service.FromContext[filemanager.Manager](ctx)
			ctx = service.ContextWith[filemanager.Manager](ctx, prefixingUsageManager{Manager: manager, root: root})
		}
		lease, err := AcquireFile(ctx, "usage.json")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = lease.Close() })
		if lease.Path != want {
			t.Fatalf("physical path = %q, want %q", lease.Path, want)
		}
		// The same managed name used by tracker Load/Save must resolve only once.
		if err := filemanager.WriteFile(ctx, lease.ManagedPath, []byte("snapshot"), 0o600); err != nil {
			t.Fatal(err)
		}
		contents, err := os.ReadFile(filepath.Join(root, "usage.json"))
		if err != nil || string(contents) != "snapshot" {
			t.Fatalf("manager duplicated base: %q %v", contents, err)
		}
		other, err := AcquireFile(ctx, "usage.json")
		if !errors.Is(err, ErrFileInUse) {
			if other != nil {
				other.Close()
			}
			t.Fatal("manager alias bypassed lease", err)
		}
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
