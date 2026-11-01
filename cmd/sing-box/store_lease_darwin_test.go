//go:build darwin && !generate

package main

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDarwinStoreLeaseRejectsInvalidSelectors(t *testing.T) {
	if captureDarwinStoreLease("", false).err != nil {
		t.Fatal("absent optional lease was rejected")
	}
	for _, value := range []string{"", "0", "1", "2", "-1", "+3", " 3", "3x", "2147483648", "999999"} {
		if result := captureDarwinStoreLease(value, true); result.err == nil {
			if result.file != nil {
				_ = result.file.Close()
			}
			t.Fatalf("accepted invalid selector %q", value)
		}
	}
}

func TestDarwinStoreLeaseRejectsNonemptyAndHardlinkedData(t *testing.T) {
	for _, hardlink := range []bool{false, true} {
		root := t.TempDir()
		path := filepath.Join(root, "lease")
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if hardlink {
			err = os.Link(path, filepath.Join(root, "alias"))
		} else {
			_, err = f.Write([]byte("not a lease"))
		}
		if err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		result := captureDarwinStoreLease(strconv.FormatUint(uint64(f.Fd()), 10), true)
		_ = f.Close()
		if result.err == nil {
			_ = result.file.Close()
			t.Fatal("accepted invalid lease object")
		}
	}
}

func TestDarwinStoreLeaseKeepsSameDescriptionAndClosesOnExec(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	result := captureDarwinStoreLease(strconv.FormatUint(uint64(f.Fd()), 10), true)
	if result.err != nil {
		t.Fatal(result.err)
	}
	defer result.file.Close()
	for _, fd := range []uintptr{f.Fd(), result.file.Fd()} {
		flags, err := unix.FcntlInt(fd, unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("lease not CLOEXEC: %v", err)
		}
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err = unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != unix.EWOULDBLOCK {
		t.Fatalf("duplicate lost occupancy: %v", err)
	}
	// An ordinary exec receives neither lease FD. This checks the inherited
	// occupancy mechanism only, not root/private execution or formal policy.
	cmd := exec.Command("/bin/sh", "-c", "test ! -e /dev/fd/"+strconv.FormatUint(uint64(result.file.Fd()), 10))
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("unrelated exec inherited lease: %v %s", err, output)
	}
	if err = result.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err = unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("closed duplicate retained occupancy: %v", err)
	}
}

func TestDarwinStoreLeaseSurvivesClosingTheLauncherDescriptor(t *testing.T) {
	if os.Getenv("POLARIS_DARWIN_LEASE_TEST_CHILD") == "1" {
		if inheritedDarwinStoreLease.file == nil || inheritedDarwinStoreLease.err != nil {
			t.Fatal("native child did not capture the inherited shared lease")
		}
		if _, present := os.LookupEnv(darwinStoreLeaseEnvironment); present {
			t.Fatal("stale lease selector would reach unrelated descendants")
		}
		if _, err := os.Stdout.Write([]byte("READY\n")); err != nil {
			t.Fatal(err)
		}
		var byte [1]byte
		_, _ = os.Stdin.Read(byte[:])
		return
	}
	path := filepath.Join(t.TempDir(), "lease")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, "-test.run=^TestDarwinStoreLeaseSurvivesClosingTheLauncherDescriptor$")
	cmd.ExtraFiles = []*os.File{f}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "POLARIS_DARWIN_LEASE_TEST_CHILD=1", darwinStoreLeaseEnvironment + "=3"}
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		_ = input.Close()
		if !waited {
			_ = cmd.Wait()
		}
	}()
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || line != "READY\n" {
		t.Fatalf("native capture failed: %q %v", line, err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	probe, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if err = unix.Flock(int(probe.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != unix.EWOULDBLOCK {
		t.Fatalf("launcher close lost child lease: %v", err)
	}
	_ = input.Close()
	err = cmd.Wait()
	waited = true
	if err != nil {
		t.Fatalf("actual child wait failed: %v", err)
	}
	if err = unix.Flock(int(probe.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("reaped child retained lease: %v", err)
	}
}
