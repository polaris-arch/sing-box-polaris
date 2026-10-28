//go:build linux && with_naive_outbound

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"github.com/sagernet/cronet-go"
)

const nativePeerNetLogMaximum = 8 * 1024 * 1024

var nativePeerNetLogPath, nativePeerNetLogLibrary, nativePeerNetLogDigest, nativePeerNetLogVersion string

func init() {
	commandRun.Flags().StringVar(&nativePeerNetLogPath, "native-peer-netlog", "", "Private controlled native-peer diagnostic output")
	commandRun.Flags().StringVar(&nativePeerNetLogLibrary, "native-peer-netlog-library", "", "Exact controlled native library")
	commandRun.Flags().StringVar(&nativePeerNetLogDigest, "native-peer-netlog-sha256", "", "Exact controlled native library digest")
	commandRun.Flags().StringVar(&nativePeerNetLogVersion, "native-peer-netlog-version", "", "Exact controlled native library version")
	for _, name := range []string{"native-peer-netlog", "native-peer-netlog-library", "native-peer-netlog-sha256", "native-peer-netlog-version"} {
		_ = commandRun.Flags().MarkHidden(name)
	}
}

// This idle engine owns observation only: no requests, proxy, dialer, trust
// override or Box resource graph entry. Native NetLog observes all live engines.
type nativePeerNetLogEngine interface {
	StartNetLogToFile(string, bool) bool
	StopNetLog()
	Shutdown() cronet.Result
	Destroy()
}

func nativePeerNetLogFailure() error { return errors.New("native peer private observation failed") }

func nativePeerNetLogUnknown(phase string) {
	// Only fixed phase literals enter here. An unknown native operation may still
	// hold/use procfd paths: do not close/reuse them or force a native destructor.
	// The opted-in process exits nonzero; the CI owner records non-graceful FAIL.
	_, _ = fmt.Fprintln(os.Stderr, "native peer private observation unknown: "+phase)
	os.Exit(1)
}

func openNativePeerNetLogEngine() (nativePeerNetLogEngine, error) {
	if _, _, err := prepareCronetLibrary(nativePeerNetLogLibrary, nativePeerNetLogDigest); err != nil {
		return nil, nativePeerNetLogFailure()
	}
	engine := cronet.NewEngine()
	if engine.Version() != nativePeerNetLogVersion {
		engine.Destroy()
		return nil, nativePeerNetLogFailure()
	}
	params := cronet.NewEngineParams()
	params.SetEnableQuic(false)
	params.SetEnableHTTP2(false)
	result := engine.StartWithParams(params)
	params.Destroy()
	if result != cronet.ResultSuccess {
		if engine.Shutdown() == cronet.ResultSuccess {
			engine.Destroy()
		}
		return nil, nativePeerNetLogFailure()
	}
	return engine, nil
}

func capNativePeerNetLogFiles() error {
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
		return nativePeerNetLogFailure()
	}
	if limit.Cur == 0 {
		return nativePeerNetLogFailure()
	}
	if limit.Cur > nativePeerNetLogMaximum {
		limit.Cur = nativePeerNetLogMaximum
	}
	// Only the explicitly opted-in process is restricted; never raise a limit.
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
		return nativePeerNetLogFailure()
	}
	return nil
}

func startNativePeerNetLog() (func() error, error) {
	if nativePeerNetLogPath == "" {
		if nativePeerNetLogLibrary != "" || nativePeerNetLogDigest != "" || nativePeerNetLogVersion != "" {
			return nil, nativePeerNetLogFailure()
		}
		return nil, nil
	}
	if nativePeerNetLogVersion == "" {
		return nil, nativePeerNetLogFailure()
	}
	return startNativePeerNetLogWith(nativePeerNetLogPath, openNativePeerNetLogEngine, capNativePeerNetLogFiles)
}

func startNativePeerNetLogWith(path string, openEngine func() (nativePeerNetLogEngine, error), capFiles func() error) (finishResult func() error, startErr error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, nativePeerNetLogFailure()
	}
	parent := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return nil, nativePeerNetLogFailure()
	}
	dir, err := os.Lstat(parent)
	if err != nil || !dir.IsDir() || dir.Mode().Perm() != 0o700 {
		return nil, nativePeerNetLogFailure()
	}
	dirStat, ok := dir.Sys().(*syscall.Stat_t)
	if !ok || dirStat.Uid != uint32(os.Geteuid()) {
		return nil, nativePeerNetLogFailure()
	}
	directoryFD, err := syscall.Open(parent, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nativePeerNetLogFailure()
	}
	directoryFile := os.NewFile(uintptr(directoryFD), parent)
	heldDir, err := directoryFile.Stat()
	if err != nil || !os.SameFile(dir, heldDir) {
		_ = directoryFile.Close()
		return nil, nativePeerNetLogFailure()
	}
	fd, err := syscall.Openat(directoryFD, filepath.Base(path), syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	_ = directoryFile.Close()
	if err != nil {
		return nil, nativePeerNetLogFailure()
	}
	file := os.NewFile(uintptr(fd), path)
	var cleanup func() error
	transferred := false
	nativeBoundary := false
	defer func() {
		if recover() != nil {
			if nativeBoundary {
				nativePeerNetLogUnknown("startup")
			}
			if cleanup != nil {
				_ = cleanup()
			}
			finishResult = nil
			startErr = nativePeerNetLogFailure()
		}
		if !transferred {
			_ = file.Close()
		}
	}()

	original, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nativePeerNetLogFailure()
	}
	valid := func() bool {
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > nativePeerNetLogMaximum || !os.SameFile(original, info) {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
	}
	if !valid() {
		_ = file.Close()
		return nil, nativePeerNetLogFailure()
	}
	if err = capFiles(); err != nil {
		_ = file.Close()
		return nil, nativePeerNetLogFailure()
	}
	nativeBoundary = true
	engine, err := openEngine()
	nativeBoundary = false
	if err != nil {
		_ = file.Close()
		return nil, nativePeerNetLogFailure()
	}
	started := false
	var once sync.Once
	var closeErr error
	finish := func() (result error) {
		defer func() {
			if recover() != nil {
				nativePeerNetLogUnknown("finish")
			}
		}()
		once.Do(func() {
			// Synchronous native flush/shutdown is joined by this process. The existing
			// exact-PID CI deadline treats a stuck/forced process as FAIL, never success.
			if started {
				engine.StopNetLog()
			}
			if engine.Shutdown() != cronet.ResultSuccess {
				nativePeerNetLogUnknown("shutdown")
			}
			engine.Destroy()
			if !valid() {
				closeErr = nativePeerNetLogFailure()
			}
			if file.Close() != nil {
				closeErr = nativePeerNetLogFailure()
			}
		})
		return closeErr
	}
	cleanup = finish
	// Native reopens the held file, never an attacker-replaceable pathname.
	// Install cleanup before Start: Shutdown also stops a partially started log.
	nativeBoundary = true
	started = engine.StartNetLogToFile("/proc/self/fd/"+strconv.FormatUint(uint64(file.Fd()), 10), false)
	nativeBoundary = false
	if !started || !valid() {
		_ = finish()
		return nil, nativePeerNetLogFailure()
	}
	transferred = true
	return finish, nil
}
