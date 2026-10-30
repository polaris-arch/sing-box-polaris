//go:build with_purego && linux && !android

package cronet

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestExplicitSelectorPresenceIsFailClosed(t *testing.T) {
	if got := captureLibraryFD("", false); got.present || got.err != nil {
		t.Fatal("absent selector must retain standalone mode")
	}
	for _, value := range []string{"", "0", "1", "2", "-1", "+3", "3 ", "/tmp/libcronet.so", "2147483648", "999999"} {
		got := captureLibraryFD(value, true)
		if !got.present || got.err == nil || got.path != "" || got.file != nil {
			t.Fatalf("explicit invalid selector %q admitted", value)
		}
	}
}

func TestExplicitFDRejectsMutableAndNonELF(t *testing.T) {
	fd, err := unix.MemfdCreate("cronet-test", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "cronet-test")
	defer file.Close()
	if _, err := file.Write([]byte("not ELF")); err != nil {
		t.Fatal(err)
	}
	value := strconv.Itoa(fd)
	if got := captureLibraryFD(value, true); got.err == nil {
		t.Fatal("unsealed file admitted")
	}
	const seals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		t.Fatal(err)
	}
	if got := captureLibraryFD(value, true); got.err == nil {
		t.Fatal("sealed non-ELF admitted")
	}
}

func TestExplicitLoadFailureNeverSearches(t *testing.T) {
	previous := explicitLibrary
	defer func() { explicitLibrary = previous }()
	explicitLibrary = captureLibraryFD("", true)
	// A caller-supplied valid-looking path cannot override an explicit failure.
	if err := doLoadLibrary("/usr/lib/libcronet.so"); err == nil {
		t.Fatal("explicit failure bypassed")
	}
}

func TestExplicitFDHoldsSealedObjectUntilLazyUse(t *testing.T) {
	file, data := sealedLibraryFixture(t)
	defer file.Close()
	fd := int(file.Fd())
	// The actual producer clears CLOEXEC for the Core exec. Begin with precisely
	// that incoming state, rather than an already-CLOEXEC fixture.
	if _, err := unix.FcntlInt(file.Fd(), unix.F_SETFD, 0); err != nil {
		t.Fatal(err)
	}
	selection := captureLibraryFD(strconv.Itoa(fd), true)
	if selection.err != nil {
		t.Fatal(selection.err)
	}
	defer selection.file.Close()
	for _, held := range []uintptr{file.Fd(), selection.file.Fd()} {
		flags, err := unix.FcntlInt(held, unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatal("incoming and owned descriptors must both remain CLOEXEC")
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestExplicitFDExecProbe$")
	command.Env = append(os.Environ(), "POLARIS_CRONET_EXEC_PROBE="+fmt.Sprintf("%d,%d,%d,%d", fd, selection.file.Fd(), uint64(stat.Dev), stat.Ino))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("descendant inherited sealed library: %v %s", err, output)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	actual, err := os.ReadFile(selection.path)
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatalf("retained FD lost before lazy load: %v", err)
	}
	if _, err := selection.file.WriteAt([]byte{0}, 0); err == nil {
		t.Fatal("sealed source became writable")
	}
}

func sealedLibraryFixture(t *testing.T) (*os.File, []byte) {
	t.Helper()
	// Minimal host-class ET_DYN fixture validates the FD/format contract. Actual
	// Cronet symbols and dependency loading remain a final-package native gate.
	data := make([]byte, 64)
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	data[16] = 3 // ET_DYN
	machine := uint16(0)
	switch runtime.GOARCH {
	case "amd64":
		machine = 62
	case "arm64":
		machine = 183
	default:
		t.Skip("64-bit fixture; other targets covered by fail-closed format tests")
	}
	binary.LittleEndian.PutUint16(data[18:20], machine)
	binary.LittleEndian.PutUint32(data[20:24], 1)
	binary.LittleEndian.PutUint16(data[52:54], 64)
	fd, err := unix.MemfdCreate("cronet-lifetime", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "cronet-lifetime")
	t.Cleanup(func() { _ = file.Close() })
	if _, err := file.Write(data); err != nil {
		t.Fatal(err)
	}
	const seals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		t.Fatal(err)
	}
	return file, data
}

func TestExplicitFDExecProbe(t *testing.T) {
	value := os.Getenv("POLARIS_CRONET_EXEC_PROBE")
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
			t.Fatal("sealed library survived unrelated descendant exec")
		}
	}
}

func TestExplicitFDFcntlFailureClosesDuplicate(t *testing.T) {
	for _, failCommand := range []int{unix.F_GETFD, unix.F_SETFD} {
		t.Run(strconv.Itoa(failCommand), func(t *testing.T) {
			file, _ := sealedLibraryFixture(t)
			defer file.Close()
			owned := -1
			failure := errors.New("incoming descriptor flag operation failed")
			selection := captureLibraryFDWithFcntl(strconv.Itoa(int(file.Fd())), true, func(fd uintptr, cmd, value int) (int, error) {
				if cmd == failCommand {
					return -1, failure
				}
				result, err := unix.FcntlInt(fd, cmd, value)
				if cmd == unix.F_DUPFD_CLOEXEC && err == nil {
					owned = result
				}
				return result, err
			})
			if !selection.present || !errors.Is(selection.err, failure) || selection.file != nil || selection.path != "" || owned < 3 {
				t.Fatalf("failed flag operation did not reject capture: %+v", selection)
			}
			if _, err := unix.FcntlInt(uintptr(owned), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				t.Fatalf("failed capture leaked its duplicate: %v", err)
			}
		})
	}
}

func TestSelectedObservationUsesHeldObjectAndRejectsConflictingPaths(t *testing.T) {
	file, data := sealedLibraryFixture(t)
	selection := captureLibraryFD(strconv.Itoa(int(file.Fd())), true)
	if selection.err != nil {
		t.Fatal(selection.err)
	}
	defer selection.file.Close()
	previous := explicitLibrary
	explicitLibrary = selection
	defer func() { explicitLibrary = previous }()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	// This selector is deliberately no longer valid. Observation must use the
	// captured os.File, never this reusable environment string or descriptor.
	t.Setenv(cronetLibraryFDEnvironment, "999999")
	observed, present, err := ObserveSelectedLibrary("")
	if err != nil || !present || observed.Path != selection.path || observed.Bytes != int64(len(data)) || observed.SHA256 != fmt.Sprintf("%x", sha256.Sum256(data)) {
		t.Fatalf("observation lost held byte identity: %+v %v %v", observed, present, err)
	}
	if _, _, err := ObserveSelectedLibrary(selection.path); err != nil {
		t.Fatal("matching captured descriptor rejected", err)
	}
	foreign, _ := sealedLibraryFixture(t)
	defer foreign.Close()
	foreignPath := "/proc/self/fd/" + strconv.Itoa(int(foreign.Fd()))
	// Even identical bytes are a different object and cannot assert selection.
	if _, _, err := ObserveSelectedLibrary(foreignPath); err == nil {
		t.Fatal("different object accepted as the captured selection")
	}
	if err := LoadLibrary(foreignPath); err == nil {
		t.Fatal("explicit conflict reached lazy loader")
	}
	explicitLibrary = captureLibraryFD("", true)
	if _, present, err := ObserveSelectedLibrary(selection.path); !present || err == nil {
		t.Fatal("invalid captured selector fell back to a path")
	}
	explicitLibrary = captureLibraryFD("", false)
	if got, present, err := ObserveSelectedLibrary("missing"); present || err != nil || got != (LibraryObservation{}) {
		t.Fatal("absent selector performed path observation", got, err)
	}
}
