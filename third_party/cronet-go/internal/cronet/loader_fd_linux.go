//go:build with_purego && linux && !android

package cronet

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"
)

const cronetLibraryFDEnvironment = "POLARIS_CRONET_LIBRARY_FD"

// The selector chooses only a loader input. The parent must separately admit
// the complete selected cohort; an environment string is not that authority.
type explicitLibrarySelection struct {
	present bool
	path    string
	file    *os.File // retained for the process lifetime, including lazy loads
	err     error
}

func captureExplicitLibrary() explicitLibrarySelection {
	value, present := os.LookupEnv(cronetLibraryFDEnvironment)
	return captureLibraryFD(value, present)
}

func captureLibraryFD(value string, present bool) explicitLibrarySelection {
	return captureLibraryFDWithFcntl(value, present, unix.FcntlInt)
}

func captureLibraryFDWithFcntl(value string, present bool, fcntl func(uintptr, int, int) (int, error)) explicitLibrarySelection {
	selection := explicitLibrarySelection{present: present}
	if !present {
		return selection // standalone tools keep their separately scoped search
	}
	reject := func(err error) explicitLibrarySelection {
		selection.err = fmt.Errorf("cronet: explicit sealed library FD rejected: %w", err)
		return selection
	}
	if value == "" {
		return reject(fmt.Errorf("empty selector"))
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return reject(fmt.Errorf("invalid descriptor"))
		}
	}
	fd, err := strconv.ParseUint(value, 10, 31)
	if err != nil || fd < 3 {
		return reject(fmt.Errorf("invalid descriptor"))
	}
	// Retain our own CLOEXEC descriptor. Never clear the parent's CLOEXEC bit,
	// and never rely on a borrowed descriptor remaining open until first use.
	owned, err := fcntl(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return reject(err)
	}
	file := os.NewFile(uintptr(owned), "polaris-sealed-cronet")
	fail := func(err error) explicitLibrarySelection {
		_ = file.Close()
		return reject(err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(owned, &st); err != nil {
		return fail(err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size <= 0 || st.Size > 96*1024*1024 {
		return fail(fmt.Errorf("not a bounded regular ELF object"))
	}
	seals, err := fcntl(file.Fd(), unix.F_GET_SEALS, 0)
	const required = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if err != nil || seals&required != required {
		return fail(fmt.Errorf("immutable seals unavailable"))
	}
	image, err := elf.NewFile(file)
	if err != nil {
		return fail(fmt.Errorf("invalid ELF: %w", err))
	}
	machine := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64, "386": elf.EM_386, "arm": elf.EM_ARM}[runtime.GOARCH]
	class := elf.ELFCLASS64
	if runtime.GOARCH == "386" || runtime.GOARCH == "arm" {
		class = elf.ELFCLASS32
	}
	if machine == elf.EM_NONE || image.Machine != machine || image.Class != class || image.Type != elf.ET_DYN || image.Data != elf.ELFDATA2LSB {
		return fail(fmt.Errorf("foreign ELF architecture or non-shared object"))
	}
	// The incoming descriptor crossed the Core exec with CLOEXEC cleared. Only
	// this child's descriptor table is changed; the parent's flags and the open
	// file description are untouched. Neither reference may reach another exec.
	flags, err := fcntl(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		return fail(err)
	}
	if _, err = fcntl(uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC); err != nil {
		return fail(err)
	}
	selection.file = file
	selection.path = "/proc/self/fd/" + strconv.Itoa(owned)
	return selection
}

func (s explicitLibrarySelection) resolvePath(path string) (string, error) {
	if !s.present {
		return path, nil
	}
	if s.err != nil {
		return "", s.err
	}
	if path != "" {
		selected, err := s.file.Stat()
		if err != nil {
			return "", err
		}
		requested, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		if !os.SameFile(selected, requested) {
			return "", fmt.Errorf("cronet: requested library conflicts with the captured sealed object")
		}
	}
	return s.path, nil
}

func (s explicitLibrarySelection) observe(path string) (LibraryObservation, bool, error) {
	selected, err := s.resolvePath(path)
	if !s.present || err != nil {
		return LibraryObservation{}, s.present, err
	}
	info, err := s.file.Stat()
	if err != nil {
		return LibraryObservation{}, true, err
	}
	// ReaderAt hashes the held immutable object without changing its offset,
	// reopening a path, or consulting a now-reusable incoming descriptor number.
	digest := sha256.New()
	if _, err = io.Copy(digest, io.NewSectionReader(s.file, 0, info.Size())); err != nil {
		return LibraryObservation{}, true, err
	}
	return LibraryObservation{Path: selected, Bytes: info.Size(), SHA256: hex.EncodeToString(digest.Sum(nil))}, true, nil
}
