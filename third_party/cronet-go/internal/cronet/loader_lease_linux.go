//go:build with_purego && linux && !android

package cronet

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

const coreStoreLeaseFDEnvironment = "POLARIS_CORE_STORE_LEASE_FD"

type storeLeaseSelection struct {
	file *os.File
	err  error
}

// A Helper supplies a dedicated duplicate of its already-locked shared lease.
// This is occupancy data, never proof authorizing a Core or library image.
// Retain the same open-file-description independently of the Helper lifetime.
var inheritedStoreLease = captureStoreLease(os.LookupEnv(coreStoreLeaseFDEnvironment))

func init() {
	if inheritedStoreLease.err != nil {
		panic(inheritedStoreLease.err)
	}
}

func captureStoreLease(value string, present bool) storeLeaseSelection {
	if !present {
		return storeLeaseSelection{} // direct App/standalone runs have no store lease
	}
	reject := func(err error) storeLeaseSelection {
		return storeLeaseSelection{err: fmt.Errorf("core: explicit store lease FD rejected: %w", err)}
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
	owned, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return reject(err)
	}
	file := os.NewFile(uintptr(owned), "polaris-core-store-lease")
	fail := func(err error) storeLeaseSelection {
		_ = file.Close()
		return reject(err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(owned, &st); err != nil {
		return fail(err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size != 0 || st.Nlink != 1 {
		return fail(fmt.Errorf("not an empty single-link regular lease"))
	}
	// The incoming dedicated descriptor survived this exec. Mark it CLOEXEC in
	// this child only, so unrelated descendants cannot prolong store occupancy.
	// Do not unlock or reopen: flock is tied to the shared open-file-description.
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		return fail(err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC); err != nil {
		return fail(err)
	}
	return storeLeaseSelection{file: file}
}
