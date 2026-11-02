//go:build windows && amd64

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

const outputBound = 262144
const memoryImageType uint32 = 0x01000000 // MEM_IMAGE, observed through VirtualQueryEx

type boundedOutput struct {
	bytes.Buffer
	truncated bool
}

func (b *boundedOutput) Write(data []byte) (int, error) {
	available := outputBound - b.Len()
	if len(data) > available {
		b.Buffer.Write(data[:available])
		b.truncated = true
		return available, errors.New("native child output byte bound")
	}
	return b.Buffer.Write(data)
}

type jobAccounting struct {
	Times                                                            [4]int64
	PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses uint32
}
type nativeChild struct {
	process, thread, job  windows.Handle
	pid                   uint32
	stdin, stdout, stderr *os.File
	actor                 actorFact
	image                 string
	mitigation            uint32
}

func nativeBool(proc *windows.LazyProc, args ...uintptr) error {
	result, _, err := proc.Call(args...)
	if result == 0 {
		return fmt.Errorf("native %s failed: %w", proc.Name, err)
	}
	return nil
}

var kernel = windows.NewLazySystemDLL("kernel32.dll")

func (c *nativeChild) interrupt() error {
	return windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, c.pid)
}
func actualImage(process windows.Handle) (string, error) {
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(process, 1, &buffer[0], &size); err != nil {
		return "", err
	}
	if size == 0 || size >= uint32(len(buffer)) {
		return "", errors.New("native child image name bound")
	}
	return windows.UTF16ToString(buffer[:size]), nil
}
func jobActive(job windows.Handle) (uint32, error) {
	var info jobAccounting
	err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil)
	return info.ActiveProcesses, err
}

func (c *cohort) start(args []string) (child *nativeChild, failure error) {
	child = &nativeChild{}
	defer func() {
		if failure != nil {
			failure = errors.Join(failure, child.abort())
		}
	}()
	if c.custody == nil {
		return child, errors.New("durable native custody owner required before child creation")
	}
	job, err := c.custody.newJob()
	if err != nil {
		return child, err
	}
	child.job = job
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return child, err
	}
	var inputRead, inputWrite, outputRead, outputWrite, errorRead, errorWrite windows.Handle
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	var childEnds []windows.Handle
	defer func() {
		for _, handle := range childEnds {
			if handle != 0 {
				failure = errors.Join(failure, windows.CloseHandle(handle))
			}
		}
	}()
	if err = windows.CreatePipe(&inputRead, &inputWrite, &attributes, 0); err != nil {
		return child, err
	}
	childEnds = append(childEnds, inputRead)
	child.stdin = os.NewFile(uintptr(inputWrite), "native-stdin")
	if err = windows.SetHandleInformation(inputWrite, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		return child, err
	}
	if err = windows.CreatePipe(&outputRead, &outputWrite, &attributes, 0); err != nil {
		return child, err
	}
	childEnds = append(childEnds, outputWrite)
	child.stdout = os.NewFile(uintptr(outputRead), "native-stdout")
	if err = windows.SetHandleInformation(outputRead, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		return child, err
	}
	if err = windows.CreatePipe(&errorRead, &errorWrite, &attributes, 0); err != nil {
		return child, err
	}
	childEnds = append(childEnds, errorWrite)
	child.stderr = os.NewFile(uintptr(errorRead), "native-stderr")
	if err = windows.SetHandleInformation(errorRead, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		return child, err
	}
	list, err := windows.NewProcThreadAttributeList(3)
	if err != nil {
		return child, err
	}
	defer list.Delete()
	handles := [3]windows.Handle{inputRead, outputWrite, errorWrite}
	if err = list.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), unsafe.Sizeof(handles)); err != nil {
		return child, err
	}
	// JOB_LIST makes assignment atomic with creation; no suspended/AssignJob gap.
	if err = list.Update(0x0002000d, unsafe.Pointer(&job), unsafe.Sizeof(job)); err != nil {
		return child, err
	}
	mitigation := uint64(1<<52 | 1<<56 | 1<<60)
	if err = list.Update(windows.PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, unsafe.Pointer(&mitigation), unsafe.Sizeof(mitigation)); err != nil {
		return child, err
	}
	startup := windows.StartupInfoEx{}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.Flags = windows.STARTF_USESTDHANDLES
	startup.StdInput = inputRead
	startup.StdOutput = outputWrite
	startup.StdErr = errorWrite
	startup.ProcThreadAttributeList = list.List()
	application, err := utf16(c.coreFact.Path)
	if err != nil {
		return child, err
	}
	command, err := utf16(windows.ComposeCommandLine(append([]string{c.coreFact.Path}, args...)))
	if err != nil {
		return child, err
	}
	winDir, err := windows.GetWindowsDirectory()
	if err != nil {
		return child, err
	}
	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		return child, err
	}
	// A closed, sorted environment block; never inherit PATH, loader overrides,
	// credentials, Go runtime switches, or caller-controlled configuration.
	var environment []uint16
	for _, entry := range []string{"PATH=" + systemDir, "POLARIS_CRONET_LIBRARY_PATH=" + c.sidecarFact.Path, "SystemRoot=" + winDir} {
		encoded, e := windows.UTF16FromString(entry)
		if e != nil {
			return child, e
		}
		environment = append(environment, encoded...)
	}
	environment = append(environment, 0)
	directory, err := utf16(c.fact.Path)
	if err != nil {
		return child, err
	}
	var info windows.ProcessInformation
	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT)
	if err = windows.CreateProcess(application, command, nil, nil, true, flags, &environment[0], directory, &startup.StartupInfo, &info); err != nil {
		return child, err
	}
	child.process = info.Process
	child.thread = info.Thread
	child.pid = info.ProcessId
	c.children++
	var assigned int32
	if err = nativeBool(kernel.NewProc("IsProcessInJob"), uintptr(child.process), uintptr(job), uintptr(unsafe.Pointer(&assigned))); err != nil || assigned != 1 {
		return child, errors.Join(err, errors.New("native child lacks atomic job custody"))
	}
	child.actor, err = actorFor(child.process, child.thread, child.pid)
	if err != nil {
		return child, err
	}
	child.image, err = actualImage(child.process)
	if err != nil {
		return child, err
	}
	if !strings.EqualFold(child.image, c.coreFact.NativePath) {
		return child, errors.New("actual child image differs from held Core")
	}
	if err = nativeBool(kernel.NewProc("GetProcessMitigationPolicy"), uintptr(child.process), 10, uintptr(unsafe.Pointer(&child.mitigation)), unsafe.Sizeof(child.mitigation)); err != nil {
		return child, err
	}
	if child.mitigation != 7 {
		return child, errors.New("actual child image-load mitigation differs")
	}
	if _, err = windows.ResumeThread(child.thread); err != nil {
		return child, err
	}
	return child, nil
}

func (child *nativeChild) abort() error {
	var failures []error
	if child.process != 0 {
		if child.job != 0 {
			failures = append(failures, windows.TerminateJobObject(child.job, 1))
		}
		status, err := windows.WaitForSingleObject(child.process, 5000)
		failures = append(failures, err)
		if status != windows.WAIT_OBJECT_0 {
			failures = append(failures, errors.New("native abort actual wait incomplete"))
		}
	}
	for _, file := range []*os.File{child.stdin, child.stdout, child.stderr} {
		if file != nil {
			failures = append(failures, file.Close())
		}
	}
	for _, handle := range []windows.Handle{child.thread, child.process, child.job} {
		if handle != 0 {
			failures = append(failures, windows.CloseHandle(handle))
		}
	}
	return errors.Join(failures...)
}

func (c *cohort) execute(purpose string, args []string, input []byte, live func(*nativeChild) error) (record processFact, failure error) {
	if len(input) > 8<<20 {
		return record, errors.New("native child stdin bound")
	}
	if c.ctx != nil && c.ctx.Err() != nil {
		return record, c.ctx.Err()
	}
	child, err := c.start(args)
	if err != nil {
		c.forced = true
		return record, err
	}
	record = processFact{Purpose: purpose, Argv: args, StdinSHA256: digest(input), StdinBytes: len(input), ProcessID: child.pid, CreationTime: child.actor.CreationTime, Actor: child.actor, ImageNativePath: child.image, ImageLoadPolicy: child.mitigation, InheritedHandleCount: 3, JobAssignedAtCreation: true}
	var out, stderr boundedOutput
	var readers sync.WaitGroup
	var outErr, errErr error
	readers.Add(2)
	go func() { defer readers.Done(); _, outErr = io.Copy(&out, child.stdout) }()
	go func() { defer readers.Done(); _, errErr = io.Copy(&stderr, child.stderr) }()
	inputResult := make(chan error, 1)
	go func() {
		n, err := child.stdin.Write(input)
		if n != len(input) {
			err = errors.Join(err, io.ErrShortWrite)
		}
		inputResult <- errors.Join(err, child.stdin.Close())
	}()
	if live != nil {
		failure = live(child)
	}
	if failure != nil {
		record.ForcedKill = true
		c.forced = true
		failure = errors.Join(failure, windows.TerminateJobObject(child.job, 1))
	}
	status := uint32(windows.WAIT_TIMEOUT)
	var waitErr error
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if c.ctx != nil && c.ctx.Err() != nil {
			failure = errors.Join(failure, c.ctx.Err())
			break
		}
		status, waitErr = windows.WaitForSingleObject(child.process, 100)
		if waitErr != nil || status != windows.WAIT_TIMEOUT {
			break
		}
	}
	if waitErr != nil || status != windows.WAIT_OBJECT_0 {
		record.TimedOut = status == windows.WAIT_TIMEOUT && !time.Now().Before(deadline)
		record.ForcedKill = true
		c.forced = true
		failure = errors.Join(failure, waitErr, errors.New("native child did not finish within its wait bound"), windows.TerminateJobObject(child.job, 1))
		status, waitErr = windows.WaitForSingleObject(child.process, 5000)
	}
	record.ActualWait = waitErr == nil && status == windows.WAIT_OBJECT_0
	if record.ActualWait {
		c.waited++
	} else {
		failure = errors.Join(failure, waitErr, errors.New("native child actual wait incomplete"))
	}
	active, jobErr := jobActive(child.job)
	record.JobActiveAfterWait = active
	c.active = active
	failure = errors.Join(failure, jobErr)
	if active != 0 {
		c.forced = true
		record.ForcedKill = true
		failure = errors.Join(failure, errors.New("job descendants remain after Core wait"), windows.TerminateJobObject(child.job, 1))
		deadline := time.Now().Add(5 * time.Second)
		for active != 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
			active, jobErr = jobActive(child.job)
			if jobErr != nil {
				break
			}
		}
		c.active = active
		failure = errors.Join(failure, jobErr)
	}
	// Closing inherited child pipe handles occurs inside start before it returns.
	// Only after process+job completion can EOF and reader completion be evidence.
	readersDone := make(chan struct{})
	go func() { readers.Wait(); close(readersDone) }()
	select {
	case <-readersDone:
		c.joined++
	case <-time.After(5 * time.Second):
		failure = errors.Join(failure, errors.New("native output readers failed to join"))
		child.stdout.Close()
		child.stderr.Close()
		<-readersDone
	}
	select {
	case inputErr := <-inputResult:
		failure = errors.Join(failure, inputErr)
	case <-time.After(time.Second):
		child.stdin.Close()
		failure = errors.Join(failure, errors.New("native stdin writer failed to join"))
		<-inputResult
	}
	record.StdoutEOF = outErr == nil
	record.StderrEOF = errErr == nil
	record.OutputTruncated = out.truncated || stderr.truncated
	if !utf8.Valid(out.Bytes()) || !utf8.Valid(stderr.Bytes()) {
		failure = errors.Join(failure, errors.New("native child emitted non-UTF8 output"))
	}
	record.Stdout = out.String()
	record.Stderr = stderr.String()
	failure = errors.Join(failure, outErr, errErr, windows.GetExitCodeProcess(child.process, &record.ExitCode))
	var closeErrors []error
	for _, file := range []*os.File{child.stdout, child.stderr} {
		closeErrors = append(closeErrors, file.Close())
	}
	for _, handle := range []windows.Handle{child.thread, child.process, child.job} {
		closeErrors = append(closeErrors, windows.CloseHandle(handle))
	}
	record.HandlesClosed = errors.Join(closeErrors...) == nil
	failure = errors.Join(failure, errors.Join(closeErrors...))
	return record, failure
}

func listenerOwnedBy(port int, pid uint32) (bool, error) {
	proc := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")
	size := uint32(0)
	status, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, 3, 0)
	if status != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) || size < 4 || size > 4<<20 {
		return false, errors.New("native TCP table size query failed")
	}
	var buffer []byte
	for attempt := 0; attempt < 3; attempt++ {
		if size < 4 || size > 4<<20 {
			return false, errors.New("native TCP table byte bound")
		}
		buffer = make([]byte, size)
		status, _, _ = proc.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, 3, 0)
		if status != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			break
		}
	}
	if status != 0 {
		return false, fmt.Errorf("native TCP table query status %d", status)
	}
	count := binary.LittleEndian.Uint32(buffer[:4])
	if size < 4 || size > uint32(len(buffer)) || uint64(count)*24+4 > uint64(size) {
		return false, errors.New("native TCP table shape bound")
	}
	matches := 0
	for i := uint32(0); i < count; i++ {
		row := buffer[4+i*24 : 4+(i+1)*24]
		if binary.LittleEndian.Uint32(row[:4]) == 2 && binary.LittleEndian.Uint32(row[4:8]) == 0x0100007f && int(binary.BigEndian.Uint16(row[8:10])) == port {
			if binary.LittleEndian.Uint32(row[20:24]) != pid {
				return false, errors.New("RunMain endpoint belongs to another process")
			}
			matches++
		}
	}
	return matches == 1, nil
}

func mappedDLL(process windows.Handle, expected string) (mappingFact, error) {
	modules := make([]windows.Handle, 1024)
	var needed uint32
	if err := windows.EnumProcessModulesEx(process, &modules[0], uint32(len(modules))*uint32(unsafe.Sizeof(modules[0])), &needed, 3); err != nil {
		return mappingFact{}, err
	}
	if needed == 0 || needed > uint32(len(modules))*uint32(unsafe.Sizeof(modules[0])) {
		return mappingFact{}, errors.New("native module count bound")
	}
	var result mappingFact
	matches := 0
	for _, module := range modules[:needed/uint32(unsafe.Sizeof(modules[0]))] {
		var memory windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(process, uintptr(module), &memory, unsafe.Sizeof(memory)); err != nil {
			return mappingFact{}, err
		}
		if memory.Type != memoryImageType || memory.AllocationBase != uintptr(module) {
			return mappingFact{}, errors.New("enumerated module is not a native image mapping")
		}
		buffer := make([]uint16, 32768)
		n, _, err := kernel.NewProc("K32GetMappedFileNameW").Call(uintptr(process), uintptr(module), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
		if n == 0 || n >= uintptr(len(buffer)) {
			return mappingFact{}, fmt.Errorf("actual module mapping query: %w", err)
		}
		native := windows.UTF16ToString(buffer[:n])
		if strings.EqualFold(filepath.Clean(native), filepath.Clean(expected)) {
			matches++
			result = mappingFact{native, fmt.Sprintf("%016x", uintptr(module)), memory.Type}
		}
	}
	if matches != 1 {
		return mappingFact{}, errors.New("held DLL does not match exactly one actual loaded image")
	}
	return result, nil
}
