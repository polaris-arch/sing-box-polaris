//go:build with_tailscale && windows

package tailscale

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func windowsTestMarker() directoryLeaseMarker {
	return directoryLeaseMarker{Version: 1, Platform: windowsDirectoryPlatform, ServerID: "node", Incarnation: strings.Repeat("1", 32), DirectoryEpoch: strings.Repeat("2", 32), RootVolume: 1, RootFileID: strings.Repeat("3", 32), DirectoryVolume: 1, DirectoryFileID: strings.Repeat("4", 32), Phase: "Open"}
}

func windowsTestMarkerLine(t *testing.T, m directoryLeaseMarker) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func TestWindowsDirectoryMarkerStrictHistory(t *testing.T) {
	first := windowsTestMarker()
	data := windowsTestMarkerLine(t, first)
	second := first
	second.DirectoryEpoch = strings.Repeat("5", 32)
	data = append(data, windowsTestMarkerLine(t, second)...)
	deleting := second
	deleting.Phase = "Deleting"
	deleting.DeleteIntentNonce = strings.Repeat("6", 32)
	data = append(data, windowsTestMarkerLine(t, deleting)...)
	data = append(data, windowsTestMarkerLine(t, deleting)...)
	deleted := deleting
	deleted.Phase = "Deleted"
	data = append(data, windowsTestMarkerLine(t, deleted)...)
	fresh := first
	fresh.Incarnation = strings.Repeat("7", 32)
	fresh.DirectoryEpoch = strings.Repeat("8", 32)
	data = append(data, windowsTestMarkerLine(t, fresh)...)
	got, err := windowsDecodeMarkerLog(data)
	if err != nil || *got != fresh {
		t.Fatalf("valid complete snapshots failed: %v", err)
	}
	for _, bad := range [][]byte{nil, data[:len(data)-1], append(data, []byte("{\n")...), append(windowsTestMarkerLine(t, first), windowsTestMarkerLine(t, first)...), []byte(strings.Replace(string(windowsTestMarkerLine(t, first)), `"version":1`, `"version":1,"version":1`, 1)), []byte(strings.Replace(string(windowsTestMarkerLine(t, first)), `"phase":"Open"`, `"phase":null`, 1)), []byte(strings.Repeat("x", windowsMarkerLimit+1))} {
		if _, err := windowsDecodeMarkerLog(bad); err == nil {
			t.Fatal("invalid log accepted")
		}
	}
}

func TestWindowsDirectoryNamesAndIdentity(t *testing.T) {
	for _, name := range []string{"", "..", "node.", "node ", "a/b", "a\\b", "C:node", "NUL", "com1", "LPT²", "node\x00"} {
		if validDirectoryServerID(name) {
			t.Fatalf("unsafe component %q", name)
		}
	}
	if !validDirectoryServerID("节点-1") {
		t.Fatal("valid UTF-8 name rejected")
	}
	root := windowsDirectoryID{Volume: 1, FileID: [16]byte{1}}
	target := windowsDirectoryID{Volume: 2, FileID: [16]byte{2}}
	if got := windowsDirectoryIdentity(root, target); got != "windows-ntfs-v1:1:01000000000000000000000000000000:2:02000000000000000000000000000000" {
		t.Fatal(got)
	}
}

func TestWindowsDirectoryLegacyAndUnmarkedRemainUnmanaged(t *testing.T) {
	base := t.TempDir()
	logical := filepath.Join(base, "tailscale", "node")
	physical := filepath.Join(base, "tailscale-windows-v1", "node")
	if err := os.MkdirAll(logical, 0o700); err != nil {
		t.Fatal(err)
	}
	actual, l, err := acquireMappedDirectory(logical, physical)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if actual != logical || l.Managed || l.Identity != "" {
		t.Fatal("legacy adopted")
	}
	if _, err := os.Stat(filepath.Dir(physical)); !os.IsNotExist(err) {
		t.Fatal("legacy selection created physical root")
	}
	if err := os.Mkdir(filepath.Dir(physical), 0o700); err != nil {
		t.Fatal(err)
	}
	if l, err := acquireDirectoryLease(physical); err == nil {
		_ = l.Close()
		t.Fatal("unmarked physical root adopted")
	}
}

func TestWindowsDirectoryPoisonAndFailedDrainPersist(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tailscale-windows-v1")
	path := filepath.Join(root, "node")
	l, err := acquireDirectoryLease(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.releaseHandles()
	if err := prepareDirectoryLeaseClose(l, errors.New("SDK failure")); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err == nil {
		t.Fatal("poisoned close reported success")
	}
	if l.target != 0 || l.lifetime != 0 {
		t.Fatal("durably revoked drained close did not release")
	}
	if next, err := acquireDirectoryLease(path); err == nil {
		_ = next.Close()
		t.Fatal("revoked domain reopened")
	}
}

func TestWindowsDirectoryTornLogNeverRepaired(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tailscale-windows-v1")
	path := filepath.Join(root, "node")
	l, err := acquireDirectoryLease(path)
	if err != nil {
		t.Fatal(err)
	}
	control, name := l.controlName, l.markerName
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(filepath.Dir(root), control, name)
	before, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	torn := append(before, []byte("{\"version\":")...)
	if err := os.WriteFile(logPath, torn, 0o600); err != nil {
		t.Fatal(err)
	}
	if l, err := acquireDirectoryLease(path); err == nil {
		_ = l.Close()
		t.Fatal("torn tail repaired")
	}
	after, err := os.ReadFile(logPath)
	if err != nil || string(after) != string(torn) {
		t.Fatal("torn marker changed", err)
	}
}

func TestWindowsDirectoryNativeSharedAndDeleteExclusion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailscale-windows-v1", "node")
	a, err := acquireDirectoryLease(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.releaseHandles()
	b, err := acquireDirectoryLease(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.releaseHandles()
	if a.Incarnation != b.Incarnation || a.Epoch == b.Epoch {
		t.Fatal("generation/epoch contract")
	}
	h, err := a.openPrivate(a.control, a.lockName, false, windows.FILE_OPEN, true)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if err := windowsLock(h, true); err == nil {
		_ = windowsUnlock(h)
		t.Fatal("exclusive lifetime passed writers")
	}
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	target, err := windows.CreateFile(wide, windows.DELETE|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err == nil {
		windows.CloseHandle(target)
		t.Fatal("DELETE handle passed no-delete-share writer")
	}
}
