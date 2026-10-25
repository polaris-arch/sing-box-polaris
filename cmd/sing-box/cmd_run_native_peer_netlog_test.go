//go:build linux && with_naive_outbound

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/cronet-go"
)

type peerNetLogFake struct {
	calls      []string
	start      bool
	shutdown   cronet.Result
	panicStop  bool
	mutate     func(string)
	onShutdown func()
	onDestroy  func()
}

func (f *peerNetLogFake) StartNetLogToFile(path string, all bool) bool {
	if all {
		panic("unexpected sensitive logging")
	}
	f.calls = append(f.calls, "start")
	if f.mutate != nil {
		f.mutate(path)
	}
	return f.start
}
func (f *peerNetLogFake) StopNetLog() {
	f.calls = append(f.calls, "stop")
	if f.panicStop {
		panic("PRIVATE")
	}
}
func (f *peerNetLogFake) Shutdown() cronet.Result {
	f.calls = append(f.calls, "shutdown")
	if f.onShutdown != nil {
		f.onShutdown()
	}
	return f.shutdown
}
func (f *peerNetLogFake) Destroy() {
	f.calls = append(f.calls, "destroy")
	if f.onDestroy != nil {
		f.onDestroy()
	}
}
func peerNetLogTestDir(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if err := os.Chmod(p, 0700); err != nil {
		t.Fatal(err)
	}
	return p
}
func peerNetLogStart(t *testing.T, path string, f *peerNetLogFake) (func() error, error) {
	t.Helper()
	return startNativePeerNetLogWith(path, func() (nativePeerNetLogEngine, error) { return f, nil }, func() error { return nil })
}

func TestNativePeerNetLogDefaultAndPartialFlags(t *testing.T) {
	old := []string{nativePeerNetLogPath, nativePeerNetLogLibrary, nativePeerNetLogDigest, nativePeerNetLogVersion}
	defer func() {
		nativePeerNetLogPath, nativePeerNetLogLibrary, nativePeerNetLogDigest, nativePeerNetLogVersion = old[0], old[1], old[2], old[3]
	}()
	nativePeerNetLogPath, nativePeerNetLogLibrary, nativePeerNetLogDigest, nativePeerNetLogVersion = "", "", "", ""
	finish, err := startNativePeerNetLog()
	if err != nil {
		t.Fatal(err)
	}
	if finish != nil {
		t.Fatal("default observation allocated cleanup")
	}
	nativePeerNetLogVersion = "unexpected"
	if _, err = startNativePeerNetLog(); err == nil {
		t.Fatal("partial opt-in admitted")
	}
}
func TestNativePeerNetLogPrivatePathAdmission(t *testing.T) {
	root := peerNetLogTestDir(t)
	bad := filepath.Join(root, "bad")
	if err := os.Mkdir(bad, 0755); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(root, "existing")
	if err := os.WriteFile(existing, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative", existing, filepath.Join(bad, "new"), filepath.Join(link, "new")} {
		f := &peerNetLogFake{start: true}
		if _, err := peerNetLogStart(t, path, f); err == nil {
			t.Fatal("invalid path admitted")
		}
		if len(f.calls) != 0 {
			t.Fatal("native started before path validation")
		}
	}
	b, err := os.ReadFile(existing)
	if err != nil || string(b) != "preserve" {
		t.Fatal("existing private file modified")
	}
}
func TestNativePeerNetLogLifecycleAndIdempotence(t *testing.T) {
	f := &peerNetLogFake{start: true}
	path := filepath.Join(peerNetLogTestDir(t), "netlog")
	finish, err := peerNetLogStart(t, path, f)
	if err != nil {
		t.Fatal(err)
	}
	if err = finish(); err != nil {
		t.Fatal(err)
	}
	if err = finish(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.calls, []string{"start", "stop", "shutdown", "destroy"}) {
		t.Fatal(f.calls)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private mode")
	}
}
func TestNativePeerNetLogStartupFailuresAreClosed(t *testing.T) {
	f := &peerNetLogFake{start: false}
	if _, err := peerNetLogStart(t, filepath.Join(peerNetLogTestDir(t), "netlog"), f); err == nil {
		t.Fatal("failed start admitted")
	}
	if !reflect.DeepEqual(f.calls, []string{"start", "shutdown", "destroy"}) {
		t.Fatal(f.calls)
	}
	called := false
	_, err := startNativePeerNetLogWith(filepath.Join(peerNetLogTestDir(t), "netlog"), func() (nativePeerNetLogEngine, error) { called = true; return nil, errors.New("PRIVATE") }, func() error { return errors.New("PRIVATE") })
	if err == nil || called || err.Error() != "native peer private observation failed" {
		t.Fatal("limit failure masked or native called")
	}
}
func TestNativePeerNetLogChangedIdentityAndBoundReject(t *testing.T) {
	for _, mutate := range []func(string){func(path string) {
		if err := os.Chmod(path, 0644); err != nil {
			panic(err)
		}
	}, func(path string) {
		if err := os.Remove(path); err != nil {
			panic(err)
		}
		if err := os.WriteFile(path, nil, 0600); err != nil {
			panic(err)
		}
	}, func(path string) {
		if err := os.Truncate(path, nativePeerNetLogMaximum+1); err != nil {
			panic(err)
		}
	}} {
		path := filepath.Join(peerNetLogTestDir(t), "netlog")
		f := &peerNetLogFake{start: true, mutate: func(string) { mutate(path) }}
		if _, err := peerNetLogStart(t, path, f); err == nil {
			t.Fatal("changed or oversized file admitted")
		}
		if !reflect.DeepEqual(f.calls, []string{"start", "stop", "shutdown", "destroy"}) {
			t.Fatal(f.calls)
		}
	}
}
func TestNativePeerNetLogUncertainFlushNeverDestroysOrSucceeds(t *testing.T) {
	if mode := os.Getenv("POLARIS_NETLOG_UNKNOWN_UNIT_CHILD"); mode != "" {
		f := &peerNetLogFake{start: true, panicStop: mode == "finish", onDestroy: func() { fmt.Fprint(os.Stderr, "UNEXPECTED") }}
		if mode == "finish" {
			f.onShutdown = func() { fmt.Fprint(os.Stderr, "UNEXPECTED") }
		}
		if mode == "shutdown" {
			f.shutdown = cronet.Result(-1)
		}
		finish, err := peerNetLogStart(t, filepath.Join(os.Getenv("POLARIS_NETLOG_UNKNOWN_DIRECTORY"), "netlog"), f)
		if err != nil {
			t.Fatal(err)
		}
		_ = finish()
		t.Fatal("unknown native finish returned")
	}
	for _, mode := range []string{"finish", "shutdown"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativePeerNetLogUncertainFlushNeverDestroysOrSucceeds$")
		cmd.Env = append(os.Environ(), "POLARIS_NETLOG_UNKNOWN_UNIT_CHILD="+mode, "POLARIS_NETLOG_UNKNOWN_DIRECTORY="+peerNetLogTestDir(t))
		output, err := cmd.CombinedOutput()
		cancel()
		exitError, ok := err.(*exec.ExitError)
		if !ok || exitError.ExitCode() != 1 || string(output) != "native peer private observation unknown: "+mode+"\n" {
			t.Fatalf("unknown native path was not fixed fail-fast: %v %s", err, output)
		}
	}
}

func TestNativePeerNetLogFileLimitBound(t *testing.T) {
	if mode := os.Getenv("POLARIS_NETLOG_LIMIT_UNIT_CHILD"); mode != "" {
		if mode == "low" {
			var old syscall.Rlimit
			if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
				t.Fatal(err)
			}
			old.Cur = 0
			if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
				t.Fatal(err)
			}
			if err := capNativePeerNetLogFiles(); err == nil {
				t.Fatal("insufficient inherited limit admitted")
			}
			return
		}
		if err := capNativePeerNetLogFiles(); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(peerNetLogTestDir(t), "bounded")
		err := os.WriteFile(path, make([]byte, nativePeerNetLogMaximum+1), 0600)
		if err == nil {
			t.Fatal("file size limit did not reject")
		}
		info, statErr := os.Stat(path)
		if statErr != nil || info.Size() > nativePeerNetLogMaximum {
			t.Fatal("file grew beyond hard bound")
		}
		return
	}
	for _, mode := range []string{"bound", "low"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativePeerNetLogFileLimitBound$")
		cmd.Env = append(os.Environ(), "POLARIS_NETLOG_LIMIT_UNIT_CHILD="+mode)
		output, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("owned limit child failed: %v %s", err, output)
		}
	}
}

func TestNativePeerNetLogStartupPanicsArePrivateAndClosed(t *testing.T) {
	if mode := os.Getenv("POLARIS_NETLOG_STARTUP_UNIT_CHILD"); mode != "" {
		path := filepath.Join(os.Getenv("POLARIS_NETLOG_UNKNOWN_DIRECTORY"), "netlog")
		f := &peerNetLogFake{start: true, mutate: func(string) { panic("PRIVATE") }, onShutdown: func() { fmt.Fprint(os.Stderr, "UNEXPECTED") }, onDestroy: func() { fmt.Fprint(os.Stderr, "UNEXPECTED") }}
		open := func() (nativePeerNetLogEngine, error) {
			if mode == "open" {
				panic("PRIVATE")
			}
			return f, nil
		}
		_, _ = startNativePeerNetLogWith(path, open, func() error { return nil })
		t.Fatal("unknown startup returned")
	}
	for _, mode := range []string{"open", "start"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativePeerNetLogStartupPanicsArePrivateAndClosed$")
		cmd.Env = append(os.Environ(), "POLARIS_NETLOG_STARTUP_UNIT_CHILD="+mode, "POLARIS_NETLOG_UNKNOWN_DIRECTORY="+peerNetLogTestDir(t))
		output, err := cmd.CombinedOutput()
		cancel()
		exitError, ok := err.(*exec.ExitError)
		if !ok || exitError.ExitCode() != 1 || string(output) != "native peer private observation unknown: startup\n" {
			t.Fatalf("startup unknown was not fixed fail-fast: %v %s", err, output)
		}
	}
}
