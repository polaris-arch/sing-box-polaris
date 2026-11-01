//go:build darwin && !generate

package main

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

const darwinStoreLeaseEnvironment = "POLARIS_CORE_STORE_LEASE_FD"

type darwinStoreLease struct {
	file *os.File
	err  error
}

// Occupancy only, not executable admission. The Helper has already admitted
// the private Core and supplies a dedicated duplicate of its shared store
// lease. Keep that same open file description for the entire Core lifetime.
var inheritedDarwinStoreLease = captureDarwinStoreLease(os.LookupEnv(darwinStoreLeaseEnvironment))

func init() {
	if inheritedDarwinStoreLease.err != nil {
		panic(inheritedDarwinStoreLease.err)
	}
	if inheritedDarwinStoreLease.file != nil {
		// A later exec must neither inherit this descriptor nor interpret its
		// stale selector as one of the later child's own descriptors.
		if err := os.Unsetenv(darwinStoreLeaseEnvironment); err != nil {
			panic(err)
		}
	}
}

func captureDarwinStoreLease(value string, present bool) darwinStoreLease {
	if !present {
		return darwinStoreLease{}
	}
	reject := func(err error) darwinStoreLease {
		return darwinStoreLease{err: fmt.Errorf("core: explicit Darwin store lease rejected: %w", err)}
	}
	if value == "" {
		return reject(fmt.Errorf("empty descriptor"))
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
	file := os.NewFile(uintptr(owned), "polaris-darwin-core-store-lease")
	fail := func(err error) darwinStoreLease {
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
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		return fail(err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC); err != nil {
		return fail(err)
	}
	return darwinStoreLease{file: file}
}
