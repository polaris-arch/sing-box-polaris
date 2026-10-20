package cachefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestRuntimeWindowsCreationFlushesAndCloses(t *testing.T) {
	var events []string
	err := syncRuntimeWindowsCreation("fixture.db", func(path string) (windows.Handle, error) {
		if path != "fixture.db" {
			t.Fatal("path changed")
		}
		events = append(events, "open")
		return windows.Handle(42), nil
	}, func(handle windows.Handle) error {
		if handle != 42 {
			t.Fatal("handle changed")
		}
		events = append(events, "flush")
		return nil
	}, func(handle windows.Handle) error {
		if handle != 42 {
			t.Fatal("handle changed")
		}
		events = append(events, "close")
		return nil
	})
	if err != nil || len(events) != 3 || events[0] != "open" || events[1] != "flush" || events[2] != "close" {
		t.Fatal("creation flush order", events, err)
	}
}

func TestRuntimeWindowsCreationOpenErrorIsNotSuppressed(t *testing.T) {
	failure := errors.New("open denied")
	err := syncRuntimeWindowsCreation("fixture.db", func(string) (windows.Handle, error) { return windows.InvalidHandle, failure }, func(windows.Handle) error { t.Fatal("flush after failed open"); return nil }, func(windows.Handle) error { t.Fatal("close after failed open"); return nil })
	if !errors.Is(err, failure) {
		t.Fatal("open failure lost", err)
	}
}

func TestRuntimeWindowsCreationFlushAndCloseErrorsRemainVisible(t *testing.T) {
	flushFailure := errors.New("flush failed")
	closeFailure := errors.New("close failed")
	closed := false
	err := syncRuntimeWindowsCreation("fixture.db", func(string) (windows.Handle, error) { return windows.Handle(42), nil }, func(windows.Handle) error { return flushFailure }, func(windows.Handle) error { closed = true; return closeFailure })
	if !closed || !errors.Is(err, flushFailure) || !errors.Is(err, closeFailure) {
		t.Fatal("cleanup errors lost", err)
	}
}

// Native Windows regression fixture, authored only; it is not run by the source
// preparation workflow. The initial file is synced exactly as production does.
func TestRuntimeWindowsCreatedFileDurability(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write([]byte("owned-cache")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err = errors.Join(file.Sync(), file.Close()); err != nil {
		t.Fatal(err)
	}
	if err = syncRuntimeFileCreation(path); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "owned-cache" {
		t.Fatal("flush modified configured file", err)
	}
}
