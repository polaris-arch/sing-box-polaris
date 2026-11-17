package tun

import (
	"errors"
	"os"
	"testing"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

func TestNativeConstructorConfigureFailureClosesOwnedFile(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "constructor-source")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	fd, err := unix.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("injected configure failure")
	var configured *NativeTun
	value, err := newNativeTun(Options{Name: "test"}, func(string, bool, bool) (int, bool, error) {
		return fd, false, nil
	}, func(string) (netlink.Link, error) {
		return nil, nil
	}, func(native *NativeTun, _ netlink.Link) error {
		configured = native
		return failure
	})
	if value != nil || !errors.Is(err, failure) || configured == nil {
		t.Fatalf("constructor failure not preserved: value=%v err=%v", value, err)
	}
	if _, err := configured.tunFile.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("constructor bypassed os.File.Close: %v", err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("owned descriptor remains open: %v", err)
	}
}

func TestNativeConstructorLookupFailureClosesRawDescriptor(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "constructor-source")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	fd, err := unix.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("injected lookup failure")
	_, err = newNativeTun(Options{}, func(string, bool, bool) (int, bool, error) {
		return fd, false, nil
	}, func(string) (netlink.Link, error) {
		return nil, failure
	}, func(*NativeTun, netlink.Link) error {
		t.Fatal("configure called after lookup failure")
		return nil
	})
	if !errors.Is(err, failure) {
		t.Fatalf("lookup failure lost: %v", err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("raw descriptor remains open: %v", err)
	}
}
