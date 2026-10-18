//go:build with_tailscale && windows

package tailscale

import (
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func windowsTestPrivateDescriptor(t *testing.T, sd *windows.SECURITY_DESCRIPTOR, owner string, directory bool) {
	t.Helper()
	actual, _, err := sd.Owner()
	if err != nil || actual == nil || actual.String() != owner {
		t.Fatalf("private descriptor owner mismatch: %v", err)
	}
	control, _, err := sd.Control()
	if err != nil || control&(windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED) != windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED {
		t.Fatalf("private descriptor must remain present and protected: %v", err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		t.Fatalf("missing private descriptor DACL: %v", err)
	}
	count := uint16(2)
	if owner == windowsSystemSID {
		count = 1
	}
	if acl.AceCount != count {
		t.Fatalf("private ACE count=%d, want %d", acl.AceCount, count)
	}
	flags := uint8(0)
	if directory {
		flags = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}
	for i := range uint32(count) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask != windowsFileAllAccess || ace.Header.AceFlags != flags {
			t.Fatalf("private ACE %d differs: type=%#x mask=%#x flags=%#x, want flags=%#x", i, ace.Header.AceType, ace.Mask, ace.Header.AceFlags, flags)
		}
		wantSID := owner
		if i != 0 {
			wantSID = windowsSystemSID
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || sid.String() != wantSID {
			t.Fatalf("private ACE %d principal/order mismatch", i)
		}
	}
}

func TestWindowsDirectoryPrivateDescriptorObjectType(t *testing.T) {
	for _, tc := range []struct {
		name      string
		owner     string
		directory bool
	}{
		{"user-file", "S-1-5-21-1-2-3-1001", false},
		{"user-directory", "S-1-5-21-1-2-3-1001", true},
		{"system-file", windowsSystemSID, false},
		{"system-directory", windowsSystemSID, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windowsPrivateDescriptor(tc.owner, tc.directory)
			if err != nil {
				t.Fatal(err)
			}
			windowsTestPrivateDescriptor(t, sd, tc.owner, tc.directory)
		})
	}
}

func TestWindowsDirectoryNativePrivateACLObjectType(t *testing.T) {
	l, err := acquireDirectoryLease(filepath.Join(t.TempDir(), "tailscale-windows-v1", "node"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.releaseHandles()
	for _, tc := range []struct {
		name      string
		handle    windows.Handle
		directory bool
	}{
		{"root", l.root, true},
		{"control", l.control, true},
		{"target", l.target, true},
		{"admission", l.admission, false},
		{"lifetime", l.lifetime, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := windowsInspect(tc.handle, tc.directory); err != nil {
				t.Fatalf("native object type: %v", err)
			}
			if err := windowsRequirePrivate(tc.handle, l.ownerSID); err != nil {
				t.Fatal(err)
			}
			sd, err := windows.GetSecurityInfo(tc.handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			windowsTestPrivateDescriptor(t, sd, l.ownerSID, tc.directory)
		})
	}
}

func TestWindowsDirectoryLegacyFileACLRemainsUnchanged(t *testing.T) {
	l, err := openDirectoryAdmission(filepath.Join(t.TempDir(), "tailscale-windows-v1"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.releaseHandles()
	// Reproduce the old descriptor on a leaf file. Reopening must validate
	// it without repairing or migrating its inherited-ACE flags.
	legacy, err := windowsPrivateDescriptor(l.ownerSID, true)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windowsOpenAt(l.control, "legacy.lock", false, windows.FILE_CREATE, true, legacy)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	original, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	windowsTestPrivateDescriptor(t, original, l.ownerSID, true)
	originalControl, _, err := original.Control()
	if err != nil {
		t.Fatal(err)
	}
	for _, disposition := range []uint32{windows.FILE_OPEN, windows.FILE_OPEN_IF} {
		reopened, err := l.openPrivate(l.control, "legacy.lock", false, disposition, true)
		if err != nil {
			t.Fatalf("reopen legacy file with disposition %d: %v", disposition, err)
		}
		sd, readErr := windows.GetSecurityInfo(reopened, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		closeErr := windows.CloseHandle(reopened)
		if readErr != nil || closeErr != nil {
			t.Fatalf("inspect reopened legacy file: read=%v close=%v", readErr, closeErr)
		}
		if err := windowsTestRestoredDACL(original, sd); err != nil {
			t.Fatalf("reopening migrated legacy ACL: %v", err)
		}
		control, _, err := sd.Control()
		if err != nil || control != originalControl {
			t.Fatalf("reopening changed legacy descriptor control: %v", err)
		}
		windowsTestPrivateDescriptor(t, sd, l.ownerSID, true)
	}
}
