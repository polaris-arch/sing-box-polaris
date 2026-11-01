//go:build with_purego && linux && !android

package cronet

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStoreLeaseSelectorRejectsInvalidOrWrongObjects(t *testing.T) {
	if got := captureStoreLease("", false); got.err != nil || got.file != nil {
		t.Fatal("absent selector must not invent occupancy")
	}
	for _, value := range []string{"", "0", "1", "2", "-1", "+3", "3 ", "2147483648", "999999"} {
		if got := captureStoreLease(value, true); got.err == nil || got.file != nil {
			t.Fatalf("invalid lease selector %q accepted", value)
		}
	}
	file, err := os.CreateTemp(t.TempDir(), "not-empty")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString("not a lease"); err != nil {
		t.Fatal(err)
	}
	if got := captureStoreLease(strconv.Itoa(int(file.Fd())), true); got.err == nil || got.file != nil {
		t.Fatal("nonempty object accepted as occupancy lease")
	}
}

func TestStoreLeaseRetainsSameLockAndDoesNotLeakToExecDescendants(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "lease")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := unix.Flock(int(file.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	// Model the dedicated FD immediately after the Core exec.
	if _, err := unix.FcntlInt(file.Fd(), unix.F_SETFD, 0); err != nil {
		t.Fatal(err)
	}
	selection := captureStoreLease(strconv.Itoa(int(file.Fd())), true)
	if selection.err != nil {
		t.Fatal(selection.err)
	}
	defer selection.file.Close()
	for _, fd := range []uintptr{file.Fd(), selection.file.Fd()} {
		flags, err := unix.FcntlInt(fd, unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatal("Core-owned lease leaks across another exec")
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestStoreLeaseExecProbe$")
	command.Env = append(os.Environ(),
		"POLARIS_LEASE_EXEC_PROBE="+strconv.Itoa(int(file.Fd()))+","+strconv.Itoa(int(selection.file.Fd()))+","+strconv.FormatUint(uint64(stat.Dev), 10)+","+strconv.FormatUint(stat.Ino, 10))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("descendant inherited occupancy: %v %s", err, output)
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	runtime.GC()
	if err := unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != unix.EWOULDBLOCK {
		t.Fatalf("original description lost after borrowed fd closed: %v", err)
	}
	if err := selection.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("final close did not release occupancy: %v", err)
	}
}

func TestStoreLeaseExecProbe(t *testing.T) {
	value := os.Getenv("POLARIS_LEASE_EXEC_PROBE")
	if value == "" {
		return
	}
	fields := strings.Split(value, ",")
	if len(fields) != 4 {
		t.Fatal("malformed controlled probe")
	}
	dev, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	ino, err := strconv.ParseUint(fields[3], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range fields[:2] {
		fd, err := strconv.Atoi(value)
		if err != nil {
			t.Fatal(err)
		}
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) == nil && uint64(stat.Dev) == dev && stat.Ino == ino {
			t.Fatal("store lease survived unrelated descendant exec")
		}
	}
}
