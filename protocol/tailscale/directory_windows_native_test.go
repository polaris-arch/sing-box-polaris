//go:build with_tailscale && windows

package tailscale

import (
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsDirectoryReadNamesReopensRetainedControl(t *testing.T) {
	// Bootstrap stops before findMarker, isolating the native enumeration
	// boundary from writer activation and process-handshake fixtures.
	l, err := openDirectoryAdmission(filepath.Join(t.TempDir(), "tailscale-windows-v1"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.releaseHandles()
	want := []string{"domain.json", "root.admission.lock"}
	for pass := range 3 {
		if pass == 2 {
			if err := l.writeNew(l.control, "enumeration-probe", []byte("probe")); err != nil {
				t.Fatal(err)
			}
			want = append(want, "enumeration-probe")
		}
		names, err := windowsReadNames(l.control)
		if err != nil {
			t.Fatalf("enumeration %d: %v", pass, err)
		}
		slices.Sort(names)
		slices.Sort(want)
		if !slices.Equal(names, want) {
			t.Fatalf("enumeration %d: got %q, want %q", pass, names, want)
		}
		id, err := windowsInspect(l.control, true)
		if err != nil || id != l.controlID {
			t.Fatalf("enumeration lost retained control custody: %v", err)
		}
		if err := windowsRequirePrivate(l.control, l.ownerSID); err != nil {
			t.Fatal(err)
		}
	}
	// Enumeration must not release the independently held admission lock.
	other, err := l.openPrivate(l.control, "root.admission.lock", false, windows.FILE_OPEN, true)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(other)
	if err := windowsLock(other, true); err == nil {
		_ = windowsUnlock(other)
		t.Fatal("enumeration released admission custody")
	}
}

func TestWindowsDirectoryReadNamesDoesNotRelaxComponentChecks(t *testing.T) {
	l, err := openDirectoryAdmission(filepath.Join(t.TempDir(), "tailscale-windows-v1"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.releaseHandles()
	// The empty NT name is internal to reopening an already retained handle.
	// Caller-supplied components still cannot select self, ancestors or paths.
	for _, name := range []string{"", ".", "..", `child\..`, `C:\other`, "child/other", "child:stream", "child.", "NUL"} {
		if h, err := windowsOpenAt(l.control, name, true, windows.FILE_OPEN, false, nil); err == nil {
			_ = windows.CloseHandle(h)
			t.Fatalf("unsafe component %q accepted", name)
		}
	}
	if _, err := windowsReadNames(l.admission); err == nil {
		t.Fatal("protocol file accepted as enumeration directory")
	}
	if _, err := windowsReadNames(windows.InvalidHandle); err == nil {
		t.Fatal("invalid directory handle accepted")
	}
}
