package cachefile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"golang.org/x/sys/windows"
)

// Test actual Windows descriptor decoding/GetAce, without permission changes.
func TestRuntimeWindowsJournalCustodyUsesDACLInsteadOfUnixMode(t *testing.T) {
	const owner = "S-1-5-21-1-2-3-1001"
	for _, row := range []struct {
		sddl  string
		valid bool
	}{
		{"O:" + owner + "D:P(A;;FA;;;" + owner + ")(A;;FA;;;SY)(A;;FA;;;BA)", true},
		{"O:" + owner + "D:(A;OICI;FA;;;" + owner + ")(A;OICI;FA;;;SY)", true},
		{"O:" + owner + "D:P(A;;FA;;;" + owner + ")(A;;FR;;;WD)", false},
		{"O:" + owner + "D:P(A;;FA;;;" + owner + ")(A;;FW;;;AU)", false},
		{"O:" + owner + "D:P(D;;FW;;;WD)(A;;FA;;;" + owner + ")", false},
		{"O:" + owner + "D:NO_ACCESS_CONTROL", false},
	} {
		sd, err := windows.SecurityDescriptorFromString(row.sddl)
		if err != nil {
			t.Fatal(err)
		}
		if got := requireRuntimeWindowsDescriptor(sd, owner) == nil; got != row.valid {
			t.Fatal("native DACL boundary", row.sddl, got)
		}
		if requireRuntimeWindowsDescriptor(sd, "S-1-5-21-1-2-3-2002") == nil {
			t.Fatal("another account adopted owner custody")
		}
	}
}

// The production helper must retain actual native object identity, not only
// decode an ACL. All objects are new children of this isolated test directory.
func TestRuntimeWindowsJournalCustodyPinsNativeRootAndFile(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	owner := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + owner + "D:P(A;OICI;FA;;;" + owner + ")(A;OICI;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	root := filepath.Join(t.TempDir(), "private-root")
	rootName, _ := windows.UTF16PtrFromString(root)
	if err := windows.CreateDirectory(rootName, &sa); err != nil {
		t.Fatal(err)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	releaseRoot, err := requireRuntimeJournalCustody(root, rootInfo, true)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseRoot()
	path := filepath.Join(root, "journal.db")
	create := func() {
		name, _ := windows.UTF16PtrFromString(path)
		handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.CloseHandle(handle); err != nil {
			t.Fatal(err)
		}
	}
	create()
	fileInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	releaseFile, err := requireRuntimeJournalCustody(path, fileInfo, false)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseFile()
	if err := os.Rename(path, path+".moved"); err == nil {
		t.Fatal("live journal custody allowed delete/replace")
	}
	if err := os.Rename(root, root+".moved"); err == nil {
		t.Fatal("live root custody allowed delete/replace")
	}
	if err := releaseFile(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal("native file handle did not release", err)
	}
	create()
	if release, err := requireRuntimeJournalCustody(path, fileInfo, false); err == nil {
		_ = release()
		t.Fatal("new object borrowed the previous journal identity")
	}
}

func TestRuntimeWindowsJournalChildRetainsOnlyVerifiedRootPrincipal(t *testing.T) {
	const user = "S-1-5-21-1-2-3-1001"
	const foreign = "S-1-5-21-1-2-3-2002"
	root, err := windows.SecurityDescriptorFromString("O:" + user + "D:P(A;OICI;FA;;;" + user + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := runtimeWindowsDescriptorPrincipal(root, "S-1-5-18", "")
	if err != nil || principal != user {
		t.Fatal("SYSTEM did not verify the user-owned root", principal, err)
	}
	for _, row := range []struct {
		name, owner, grants, current string
		valid                        bool
	}{
		{"system-default-owner", "SY", user, "S-1-5-18", true},
		{"administrators-default-owner", "BA", user, "S-1-5-18", true},
		{"user-default-owner", user, user, "S-1-5-18", true},
		{"foreign-owner", foreign, user, "S-1-5-18", false},
		{"foreign-inherited-ACE", "SY", foreign, "S-1-5-18", false},
		{"everyone", "SY", "WD", "S-1-5-18", false},
		{"users", "SY", "BU", "S-1-5-18", false},
		{"authenticated-users", "SY", "AU", "S-1-5-18", false},
		{"foreign-current", "SY", user, foreign, false},
		{"user-cannot-adopt-system-child", "SY", user, user, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			child, err := windows.SecurityDescriptorFromString("O:" + row.owner + "D:P(A;ID;FA;;;" + row.grants + ")(A;ID;FA;;;SY)(A;ID;FA;;;BA)")
			if err != nil {
				t.Fatal(err)
			}
			_, err = runtimeWindowsDescriptorPrincipal(child, row.current, principal)
			if (err == nil) != row.valid {
				t.Fatal("bound root child descriptor", row, err)
			}
			if row.valid && row.owner != user {
				if requireRuntimeWindowsDescriptor(child, row.current) == nil {
					t.Fatal("unbound file adopted a user principal from nowhere")
				}
			}
		})
	}
	broad, err := windows.SecurityDescriptorFromString("O:" + user + "D:P(A;;FA;;;" + user + ")(A;;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtimeWindowsDescriptorPrincipal(broad, "S-1-5-18", ""); err == nil {
		t.Fatal("broad root minted a custody principal")
	}
}

func runtimeWindowsJournalPrivateRoot(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	owner := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + owner + "D:P(A;OICI;FA;;;" + owner + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	root := filepath.Join(t.TempDir(), "journal-private-root")
	name, _ := windows.UTF16PtrFromString(root)
	if err := windows.CreateDirectory(name, &sa); err != nil {
		t.Fatal(err)
	}
	return root
}
func TestRuntimeWindowsJournalRealOpenCloseReopen(t *testing.T) {
	root := runtimeWindowsJournalPrivateRoot(t)
	ctx := adapter.ContextWithRuntimeRecoveryRoot(context.Background(), root)
	journal, err := OpenFakeIPRuntimeJournal(ctx, log.NewNOPFactory().Logger())
	if err != nil {
		t.Fatal(err)
	}
	first, err := journal.RuntimeDescriptor(ctx)
	if err != nil {
		_ = journal.Close()
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	// Real Windows writable files report 0666; reopening must use native DACL
	// custody rather than the shared Unix permission-bit shortcut.
	info, err := os.Lstat(filepath.Join(root, fakeIPRuntimeJournalName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 == 0 {
		t.Fatal("fixture did not exercise Windows Unix-mode mismatch", info.Mode())
	}
	journal, err = OpenFakeIPRuntimeJournal(ctx, log.NewNOPFactory().Logger())
	if err != nil {
		t.Fatal("actual existing-file branch rejected valid DACL", err)
	}
	defer journal.Close()
	second, err := journal.RuntimeDescriptor(ctx)
	if err != nil || second != first {
		t.Fatal("reopen lost exact database identity", first, second, err)
	}
}
func TestRuntimeWindowsJournalCanceledOpenAndClosedRootCannotAdoptChild(t *testing.T) {
	root := runtimeWindowsJournalPrivateRoot(t)
	ctx, cancel := context.WithCancel(adapter.ContextWithRuntimeRecoveryRoot(context.Background(), root))
	cancel()
	if journal, err := OpenFakeIPRuntimeJournal(ctx, log.NewNOPFactory().Logger()); !errors.Is(err, context.Canceled) || journal != nil {
		t.Fatal(journal, err)
	}
	if _, err := os.Lstat(filepath.Join(root, fakeIPRuntimeJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("canceled ingress created a journal", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := requireRuntimeJournalRootCustody(root, info)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(runtimeWindowsJournalPrivateRoot(t), "outside.db")
	if err := os.WriteFile(outside, nil, 0600); err != nil {
		t.Fatal(err)
	}
	outsideInfo, err := os.Lstat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if release, err := custody.RequireFile(outside, outsideInfo); !errors.Is(err, ErrFakeIPRecoveryCustody) || release != nil {
		t.Fatal("root token adopted an unrelated parent", err)
	}
	if err := custody.Close(); err != nil {
		t.Fatal(err)
	}
	if release, err := custody.RequireFile(filepath.Join(root, "absent"), nil); !errors.Is(err, ErrFakeIPRecoveryClosed) || release != nil {
		t.Fatal("released root token granted child authority", err)
	}
}
