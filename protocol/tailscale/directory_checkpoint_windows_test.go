//go:build with_tailscale && windows

package tailscale

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsCheckpointTerminalEquivalence(t *testing.T) {
	first := windowsTestMarker()
	last := first
	last.DirectoryEpoch = strings.Repeat("5", 32)
	original := append(windowsTestMarkerLine(t, first), windowsTestMarkerLine(t, last)...)
	before := bytes.Clone(original)
	got, compact, err := windowsCheckpointOpenJournal(original)
	if err != nil || got != last || !bytes.Equal(compact, windowsTestMarkerLine(t, last)) {
		t.Fatalf("terminal checkpoint mismatch: %v", err)
	}
	if !bytes.Equal(original, before) {
		t.Fatal("modified source history")
	}
	next := last
	next.DirectoryEpoch = strings.Repeat("6", 32)
	got, compact, err = windowsCheckpointOpenJournal(append(compact, windowsTestMarkerLine(t, next)...))
	if err != nil || got != next || !bytes.Equal(compact, windowsTestMarkerLine(t, next)) {
		t.Fatalf("second checkpoint mismatch: %v", err)
	}
	bad := map[string][]byte{"empty": nil, "torn": before[:len(before)-1], "oversize": bytes.Repeat([]byte{'x'}, windowsMarkerLimit+1)}
	for _, phase := range []string{"Deleting", "Deleted", "Unknown"} {
		m := last
		m.Phase, m.DeleteIntentNonce = phase, strings.Repeat("7", 32)
		bad[phase] = append(bytes.Clone(before), windowsTestMarkerLine(t, m)...)
	}
	for _, field := range []string{"incarnation", "root", "directory", "server"} {
		m := last
		m.DirectoryEpoch = strings.Repeat("8", 32)
		switch field {
		case "incarnation":
			m.Incarnation = strings.Repeat("9", 32)
		case "root":
			m.RootVolume++
		case "directory":
			m.DirectoryVolume++
		case "server":
			m.ServerID = "other"
		}
		bad[field] = append(bytes.Clone(before), windowsTestMarkerLine(t, m)...)
	}
	// This is valid protocol history, but must not be reduced across deletion
	// and recreation even though its terminal phase is Open.
	deleting := last
	deleting.Phase, deleting.DeleteIntentNonce = "Deleting", strings.Repeat("a", 32)
	deleted := deleting
	deleted.Phase = "Deleted"
	fresh := first
	fresh.Incarnation, fresh.DirectoryEpoch = strings.Repeat("b", 32), strings.Repeat("c", 32)
	mixed := append(bytes.Clone(before), windowsTestMarkerLine(t, deleting)...)
	mixed = append(mixed, windowsTestMarkerLine(t, deleted)...)
	mixed = append(mixed, windowsTestMarkerLine(t, fresh)...)
	if _, err := windowsDecodeMarkerLog(mixed); err != nil {
		t.Fatalf("invalid mixed fixture: %v", err)
	}
	bad["valid mixed history"] = mixed
	for name, data := range bad {
		t.Run(name, func(t *testing.T) {
			if _, _, err := windowsCheckpointOpenJournal(data); err == nil {
				t.Fatal("unsafe checkpoint accepted")
			}
		})
	}
}

func TestWindowsCheckpointDeletionReserveBoundary(t *testing.T) {
	for _, name := range []string{"node", "节点&\u2028\u2029", strings.Repeat("n", 100)} {
		m := windowsTestMarker()
		m.ServerID, m.RootVolume, m.DirectoryVolume = name, ^uint64(0), ^uint64(0)
		required, err := windowsMarkerAdmissionBytes(m)
		if err != nil {
			t.Fatal(err)
		}
		deleting := m
		deleting.Phase, deleting.DeleteIntentNonce = "Deleting", strings.Repeat("f", 32)
		deleted := deleting
		deleted.Phase = "Deleted"
		want := len(windowsTestMarkerLine(t, m)) + len(windowsTestMarkerLine(t, deleting)) + len(windowsTestMarkerLine(t, deleted))
		if required != want {
			t.Fatalf("reserve %d != serialized %d", required, want)
		}
		for _, item := range []struct {
			retained int
			want     bool
		}{{windowsMarkerLimit - required, true}, {windowsMarkerLimit - required + 1, false}, {-1, false}, {windowsMarkerLimit + 1, false}} {
			got, err := windowsMarkerAdmissionFits(item.retained, m)
			if err != nil || got != item.want {
				t.Fatalf("boundary %d: %v, %v", item.retained, got, err)
			}
		}
	}
}

func TestWindowsCheckpointPublicationOwnership(t *testing.T) {
	failure := errors.New("injected")
	for _, item := range []struct {
		fail string
		want []string
	}{
		{"", []string{"write", "rename", "flush", "close", "verify"}},
		{"write", []string{"write", "dispose", "close"}},
		{"rename", []string{"write", "rename", "close"}},
		{"flush", []string{"write", "rename", "flush", "close"}},
		{"close", []string{"write", "rename", "flush", "close"}},
		{"verify", []string{"write", "rename", "flush", "close", "verify"}},
	} {
		t.Run("failure-"+item.fail, func(t *testing.T) {
			var calls []string
			step := func(name string) func() error {
				return func() error {
					calls = append(calls, name)
					if name == item.fail {
						return failure
					}
					return nil
				}
			}
			err := windowsPublishCheckpoint(step("write"), step("rename"), step("flush"), step("close"), step("verify"), step("dispose"))
			if (item.fail == "") != (err == nil) || (err != nil && !errors.Is(err, failure)) {
				t.Fatalf("error %v", err)
			}
			if !reflect.DeepEqual(calls, item.want) {
				t.Fatalf("calls %v, want %v", calls, item.want)
			}
		})
	}
	disposeFailure, closeFailure := errors.New("dispose"), errors.New("close")
	err := windowsPublishCheckpoint(func() error { return failure }, nil, nil, func() error { return closeFailure }, nil, func() error { return disposeFailure })
	for _, want := range []error{failure, disposeFailure, closeFailure} {
		if !errors.Is(err, want) {
			t.Fatalf("lost cleanup failure %v", want)
		}
	}
}

func TestWindowsCheckpointRenameLayout(t *testing.T) {
	name := directoryControlStem("node") + ".jsonl"
	root := windows.Handle(123)
	data, err := windowsCheckpointRenameBuffer(root, name)
	if err != nil {
		t.Fatal(err)
	}
	type layout struct {
		Replace byte
		Root    windows.Handle
		Length  uint32
		Name    [1]uint16
	}
	var shape layout
	info := (*layout)(unsafe.Pointer(&data[0]))
	if info.Replace != 1 || info.Root != root || info.Length != uint32(len(name)*2) {
		t.Fatal("invalid rename header")
	}
	wide := unsafe.Slice((*uint16)(unsafe.Pointer(&data[unsafe.Offsetof(shape.Name)])), len(name))
	if windows.UTF16ToString(wide) != name {
		t.Fatal("invalid UTF-16 destination")
	}
	wantOffset := uintptr(12)
	if unsafe.Sizeof(root) == 8 {
		wantOffset = 20
	}
	if unsafe.Offsetof(shape.Name) != wantOffset {
		t.Fatalf("unexpected native layout %d", unsafe.Offsetof(shape.Name))
	}
	for _, bad := range []string{"", "../" + name, "SHA256-" + name[7:], name + "x", ".checkpoint-" + name} {
		if _, err := windowsCheckpointRenameBuffer(root, bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
