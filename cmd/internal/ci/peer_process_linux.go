package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type peerProcessIdentity struct {
	PID        int    `json:"pid"`
	Group      int    `json:"pgrp"`
	Session    int    `json:"session"`
	StartTicks uint64 `json:"startTicks"`
}

type peerProcRow struct {
	peerProcessIdentity
	parent int
}

func readPeerProc(pid int) (peerProcRow, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return peerProcRow{}, err
	}
	end := bytes.LastIndexByte(raw, ')')
	if end < 0 {
		return peerProcRow{}, fmt.Errorf("invalid proc stat")
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) <= 19 {
		return peerProcRow{}, fmt.Errorf("incomplete proc stat")
	}
	parent, parentErr := strconv.Atoi(fields[1])
	group, groupErr := strconv.Atoi(fields[2])
	session, sessionErr := strconv.Atoi(fields[3])
	ticks, ticksErr := strconv.ParseUint(fields[19], 10, 64)
	if err := errors.Join(parentErr, groupErr, sessionErr, ticksErr); err != nil {
		return peerProcRow{}, fmt.Errorf("invalid proc stat identity: %w", err)
	}
	return peerProcRow{peerProcessIdentity{pid, group, session, ticks}, parent}, nil
}

func peerProcSnapshot() (map[int]peerProcRow, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	rows := make(map[int]peerProcRow, len(entries))
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		row, err := readPeerProc(pid)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil {
			return nil, err
		}
		rows[pid] = row
	}
	return rows, nil
}

func peerDescendants(snapshot map[int]peerProcRow, parent int) map[int]peerProcRow {
	descendants := make(map[int]peerProcRow)
	for changed := true; changed; {
		changed = false
		for pid, row := range snapshot {
			_, parentOwned := descendants[row.parent]
			if _, owned := descendants[pid]; !owned && pid != parent && (row.parent == parent || parentOwned) {
				descendants[pid], changed = row, true
			}
		}
	}
	return descendants
}

type peerProcessScope struct {
	previous uint32
	owners   map[int]*peerNativeProcess
	active   bool
}

// Subreaper admission and restoration apply to the host process as a whole.
var peerSubreaperScope sync.Mutex

func openPeerProcessScope() (_ *peerProcessScope, err error) {
	if !peerSubreaperScope.TryLock() {
		return nil, fmt.Errorf("controlled peer child scope is already active")
	}
	defer func() {
		if err != nil {
			peerSubreaperScope.Unlock()
		}
	}()
	rows, err := peerProcSnapshot()
	if err != nil {
		return nil, err
	}
	if len(peerDescendants(rows, os.Getpid())) != 0 {
		return nil, fmt.Errorf("runner already has unknown children; ownership scope rejected")
	}
	var previous uint32
	if _, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&previous)), 0, 0, 0, 0); errno != 0 {
		return nil, errno
	}
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return nil, err
	}
	return &peerProcessScope{previous, make(map[int]*peerNativeProcess), true}, nil
}

type peerNativeProcess struct {
	role     string
	identity peerProcessIdentity
	core     string
	pidfd    int
	command  *exec.Cmd
	log      *os.File
	done     chan struct{}
	waitErr  error

	// A bounded identity inspection and signals use the same process gate.
	// Waiting and closing resources never hold it.
	gate       chan struct{}
	termSignal *peerSignalFact
	result     *peerProcessCleanup
	cleanupErr error
}

func (scope *peerProcessScope) start(binary, role, privateLog, expectedHash string, args ...string) (*peerNativeProcess, error) {
	if !scope.active {
		return nil, fmt.Errorf("controlled peer child scope is closed")
	}
	binary, err := regularSource(filepath.Dir(binary), filepath.Base(binary))
	if err != nil {
		return nil, err
	}
	hash, err := fileSHA256(binary)
	if err != nil {
		return nil, err
	}
	if hash != expectedHash {
		return nil, fmt.Errorf("native executable bytes changed before process spawn")
	}

	log, err := os.OpenFile(privateLog, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	command := exec.Command(binary, args...)
	command.Dir = filepath.Dir(binary)
	command.Env = peerCoreEnvironment(filepath.Dir(privateLog), role)
	process := &peerNativeProcess{
		role: role, command: command, log: log, pidfd: -1,
		done: make(chan struct{}), gate: make(chan struct{}, 1),
	}
	// Birth into a new session yields PID == PGID == SID. The pidfd is
	// obtained at birth when supported, with a still-unreaped child fallback.
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, PidFD: &process.pidfd}
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		return nil, errors.Join(err, log.Close())
	}
	pid := command.Process.Pid
	scope.owners[pid] = process
	if process.pidfd < 0 {
		process.pidfd, err = unix.PidfdOpen(pid, 0)
	}
	if err == nil {
		row, identityErr := readPeerProc(pid)
		err = identityErr
		if err == nil && (row.parent != os.Getpid() || row.Group != pid || row.Session != pid) {
			err = fmt.Errorf("new child session identity unavailable")
		}
		if err == nil {
			process.identity = row.peerProcessIdentity
			actual, hashErr := fileSHA256(fmt.Sprintf("/proc/%d/exe", pid))
			err = hashErr
			if err == nil && actual != expectedHash {
				err = fmt.Errorf("actual process ELF hash differs")
			}
			if err == nil {
				process.core = expectedHash
			}
		}
	}
	go func() {
		process.waitErr = command.Wait()
		close(process.done)
	}()
	if err != nil {
		_, stopErr := process.close()
		return nil, errors.Join(err, stopErr)
	}
	return process, nil
}

func peerCoreEnvironment(privateDirectory, role string) []string {
	path := os.Getenv("PATH")
	if path == "" {
		path = "/usr/bin:/bin"
	}
	environment := []string{"PATH=" + path, "HOME=" + privateDirectory, "TMPDIR=" + privateDirectory, "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	if role == "peer" {
		environment = append(environment, "QUIC_GO_LOG_LEVEL=error")
	}
	return environment
}

type peerSignalFact struct {
	Stage        string  `json:"stage"`
	Signal       string  `json:"signal"`
	PIDFDBound   bool    `json:"pidfdBound"`
	PID          int     `json:"pid,omitempty"`
	StartTicks   uint64  `json:"startTicks,omitempty"`
	CoreSHA256   string  `json:"coreSHA256,omitempty"`
	MonotonicSec float64 `json:"monotonicSeconds,omitempty"`
}

type peerProcessCleanup struct {
	Role                        string               `json:"role"`
	PID                         int                  `json:"pid"`
	StartIdentity               *peerProcessIdentity `json:"startIdentity"`
	ExitCode                    *int                 `json:"exitCode"`
	ForcedKill                  bool                 `json:"forcedKill"`
	BoundCoreSHA256             *string              `json:"boundCoreSHA256"`
	ExitBeforeTerminate         *int                 `json:"exitBeforeTerminate"`
	TerminationActions          []peerSignalFact     `json:"terminationActions"`
	CloseOperationFailure       map[string]any       `json:"closeOperationFailure"`
	ResourceCloseErrors         []string             `json:"resourceCloseErrors"`
	PrivateLogObservedAfterExit bool                 `json:"privateLogObservedAfterExit"`
	RemainingGroup              []int                `json:"remainingGroup"`
	CleanupErrorLog             bool                 `json:"cleanupErrorLog"`
	PrivateLogSHA256            *string              `json:"privateLogSHA256"`
	PrivateLogBytes             *int                 `json:"privateLogBytes"`
	GracefulCleanupProven       bool                 `json:"gracefulCleanupProven"`
}

func (process *peerNativeProcess) exited() *int {
	select {
	case <-process.done:
		state := process.command.ProcessState
		if state == nil {
			return nil
		}
		exit := state.ExitCode()
		if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			exit = -int(status.Signal())
		}
		return &exit
	default:
		return nil
	}
}

func (process *peerNativeProcess) await(limit time.Duration) bool {
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-process.done:
		return true
	case <-timer.C:
		return false
	}
}

func (process *peerNativeProcess) inspect() (func(), error) {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case process.gate <- struct{}{}:
		return func() { <-process.gate }, nil
	case <-timer.C:
		return nil, fmt.Errorf("owned process inspection and signal ordering unavailable")
	}
}

func (process *peerNativeProcess) terminate() (peerSignalFact, string, error) {
	unlock, err := process.inspect()
	if err != nil {
		return peerSignalFact{}, "inspection_gate", err
	}
	defer unlock()

	row, err := readPeerProc(process.command.Process.Pid)
	if err != nil {
		return peerSignalFact{}, "owner_identity", err
	}
	if row.peerProcessIdentity != process.identity || process.pidfd < 0 {
		return peerSignalFact{}, "owner_identity", fmt.Errorf("owned process identity changed; no signal sent")
	}
	if err := unix.PidfdSendSignal(process.pidfd, unix.SIGTERM, nil, 0); err != nil {
		return peerSignalFact{}, "sigterm", err
	}
	var at unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &at); err != nil {
		return peerSignalFact{}, "sigterm", err
	}
	fact := peerSignalFact{
		Stage: process.role + ".process.signal", Signal: "SIGTERM", PIDFDBound: true, PID: process.identity.PID, StartTicks: process.identity.StartTicks,
		CoreSHA256: process.core, MonotonicSec: float64(at.Sec) + float64(at.Nsec)/1e9,
	}
	process.termSignal = &fact
	return fact, "", nil
}

func (process *peerNativeProcess) close() (*peerProcessCleanup, error) {
	if process.result != nil {
		return process.result, process.cleanupErr
	}
	result := &peerProcessCleanup{
		Role: process.role, PID: process.command.Process.Pid, TerminationActions: []peerSignalFact{}, ResourceCloseErrors: []string{},
	}
	if process.identity.PID != 0 {
		result.StartIdentity = &process.identity
	}
	if process.core != "" {
		result.BoundCoreSHA256 = &process.core
	}
	// pidfd can report exit before the Cmd.Wait goroutine has been scheduled.
	if process.pidfd >= 0 {
		fds := []unix.PollFd{{Fd: int32(process.pidfd), Events: unix.POLLIN}}
		if ready, err := unix.Poll(fds, 0); err == nil && ready != 0 {
			process.await(5 * time.Second)
		}
	}
	result.ExitBeforeTerminate = process.exited()

	fail := func(stage, category string, err error) {
		var number any
		var errno syscall.Errno
		if errors.As(err, &errno) {
			number = int(errno)
		}
		result.CloseOperationFailure = map[string]any{"stage": stage, "category": category, "errno": number}
	}
	if result.ExitBeforeTerminate == nil {
		fact, stage, err := process.terminate()
		if err != nil {
			category := "os_error"
			if stage == "owner_identity" || stage == "inspection_gate" {
				category = "identity"
			}
			fail(stage, category, err)
		} else {
			result.TerminationActions = append(result.TerminationActions, fact)
			if !process.await(15 * time.Second) {
				result.ForcedKill = true
				if err := unix.PidfdSendSignal(process.pidfd, unix.SIGKILL, nil, 0); err != nil {
					fail("sigkill", "os_error", err)
				} else {
					result.TerminationActions = append(result.TerminationActions, peerSignalFact{Stage: process.role + ".process.signal", Signal: "SIGKILL", PIDFDBound: true})
					if !process.await(5 * time.Second) {
						fail("wait_sigkill", "timeout", nil)
					}
				}
			}
		}
	}
	if err := process.log.Close(); err != nil {
		result.ResourceCloseErrors = append(result.ResourceCloseErrors, "private_log_close")
	}
	if process.pidfd >= 0 {
		if err := unix.Close(process.pidfd); err != nil {
			result.ResourceCloseErrors = append(result.ResourceCloseErrors, "pidfd_close")
		}
		process.pidfd = -1
	}
	snapshot, err := peerProcSnapshot()
	if err != nil {
		result.ResourceCloseErrors = append(result.ResourceCloseErrors, "owned_group_observation")
	} else {
		result.RemainingGroup = []int{}
		for pid, row := range snapshot {
			if row.Group == result.PID {
				result.RemainingGroup = append(result.RemainingGroup, pid)
			}
		}
		slices.Sort(result.RemainingGroup)
	}
	result.PrivateLogObservedAfterExit = process.exited() != nil
	raw, err := readPeerLog(process.log.Name())
	if err != nil {
		result.ResourceCloseErrors = append(result.ResourceCloseErrors, "private_log_read")
	} else {
		hash, length := sha256Hex(raw), len(raw)
		result.PrivateLogSHA256, result.PrivateLogBytes = &hash, &length
		lower := peerASCIILower(raw)
		for _, marker := range []string{"did not closed properly", "close timeout", "close timed out", "panic:", "fatal"} {
			if bytes.Contains(lower, []byte(marker)) {
				result.CleanupErrorLog = true
				break
			}
		}
	}
	result.ExitCode = process.exited()
	result.GracefulCleanupProven = result.ExitCode != nil && *result.ExitCode == 0 && process.waitErr == nil &&
		result.CloseOperationFailure == nil && len(result.ResourceCloseErrors) == 0 && !result.ForcedKill &&
		len(result.RemainingGroup) == 0 && !result.CleanupErrorLog
	process.result = result
	if !result.GracefulCleanupProven {
		process.cleanupErr = fmt.Errorf("core graceful cleanup not proven")
	}
	return result, process.cleanupErr
}

type peerDescendantRetirement struct {
	Remaining  []int            `json:"remaining"`
	ForcedKill bool             `json:"forcedKill"`
	Retired    []map[string]any `json:"retired"`
}

func (scope *peerProcessScope) drain() (retirement peerDescendantRetirement, err error) {
	retirement.Retired = []map[string]any{}
	root := os.Getpid()
	handles := make(map[peerProcessIdentity]int)
	defer func() {
		for _, fd := range handles {
			err = errors.Join(err, unix.Close(fd))
		}
	}()
	deadline := time.Now().Add(15 * time.Second)
	finalDeadline := deadline.Add(5 * time.Second)
	for {
		snapshot, err := peerProcSnapshot()
		if err != nil {
			retirement.Remaining = nil
			return retirement, err
		}
		rows := peerDescendants(snapshot, root)
		retirement.Remaining = make([]int, 0, len(rows))
		if len(rows) == 0 {
			return retirement, nil
		}
		for pid := range rows {
			retirement.Remaining = append(retirement.Remaining, pid)
		}
		slices.Sort(retirement.Remaining)
		for pid, row := range rows {
			identity := row.peerProcessIdentity
			fd, seen := handles[identity]
			if !seen {
				fd, err = unix.PidfdOpen(pid, 0)
				if errors.Is(err, unix.ESRCH) {
					continue
				}
				if err != nil {
					return retirement, err
				}
				current, err := peerProcSnapshot()
				if err != nil {
					return retirement, errors.Join(err, unix.Close(fd))
				}
				found, owned := peerDescendants(current, root)[pid]
				if !owned || found.peerProcessIdentity != identity {
					return retirement, errors.Join(fmt.Errorf("descendant identity changed; unknown process not signaled"), unix.Close(fd))
				}
				handles[identity] = fd
				retirement.Retired = append(retirement.Retired, map[string]any{
					"pid": pid, "startTicks": identity.StartTicks, "source": "own-descendant-or-subreaper-adoption",
				})
				if err := unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
					return retirement, err
				}
			}
			if time.Now().After(deadline) {
				retirement.ForcedKill = true
				if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
					return retirement, err
				}
			}
			owner := scope.owners[pid]
			// Only adopted children are reaped here. Cmd.Wait owns the
			// original child, even if it is concurrently exiting.
			if row.parent == root && (owner == nil || owner.exited() != nil) {
				var status unix.Siginfo
				if err := unix.Waitid(unix.P_PIDFD, fd, &status, unix.WEXITED|unix.WNOHANG, nil); err != nil && !errors.Is(err, unix.ECHILD) {
					return retirement, err
				}
			}
		}
		if time.Now().After(finalDeadline) {
			return retirement, fmt.Errorf("owned descendant retirement deadline exceeded")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (scope *peerProcessScope) close() (peerDescendantRetirement, error) {
	if !scope.active {
		return peerDescendantRetirement{}, fmt.Errorf("controlled peer child scope is already closed")
	}
	scope.active = false
	defer peerSubreaperScope.Unlock()
	var err error
	for _, owner := range scope.owners {
		_, closeErr := owner.close()
		err = errors.Join(err, closeErr)
	}
	retirement, drainErr := scope.drain()
	if len(retirement.Retired) != 0 || retirement.ForcedKill {
		err = errors.Join(err, fmt.Errorf("core left descendants; recovered but graceful cleanup failed"))
	}
	restoreErr := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, uintptr(scope.previous), 0, 0, 0)
	return retirement, errors.Join(err, drainErr, restoreErr)
}
