package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"time"
)

type sourceOutput struct {
	data     bytes.Buffer
	limit    int
	overflow bool
}

func (output *sourceOutput) Write(data []byte) (int, error) {
	if len(data) > output.limit-output.data.Len() {
		output.overflow = true
		return 0, fmt.Errorf("source command diagnostic exceeds byte bound")
	}
	return output.data.Write(data)
}

// The caller owns output writers until both the process and its pipes retire.
func runSourceProcess(ctx context.Context, command *exec.Cmd) (*int, error) {
	sourceProcessGroup(command)
	var escalation *time.Timer
	escalated := make(chan struct{})
	command.Cancel = func() error {
		if runtime.GOOS == "windows" {
			return terminateSourceProcess(command, true)
		}
		err := terminateSourceProcess(command, false)
		escalation = time.AfterFunc(5*time.Second, func() {
			defer close(escalated)
			_ = terminateSourceProcess(command, true)
		})
		return err
	}
	command.WaitDelay = 15 * time.Second
	err := command.Run()
	if escalation != nil && !escalation.Stop() {
		<-escalated
	}
	if ctx.Err() != nil {
		if command.Process != nil && runtime.GOOS != "windows" {
			if cleanup := terminateSourceProcess(command, true); cleanup != nil && !errors.Is(cleanup, os.ErrProcessDone) {
				return nil, errors.Join(ctx.Err(), err, cleanup)
			}
		}
		return nil, errors.Join(ctx.Err(), err)
	}
	var failed *exec.ExitError
	if err != nil && !errors.As(err, &failed) {
		return nil, err
	}
	code := command.ProcessState.ExitCode()
	return &code, nil
}

func sourceCommandOutput(ctx context.Context, directory string, environment []string, limit int, args ...string) (string, string, *int, error) {
	command := exec.CommandContext(ctx, args[0], args[1:]...)
	command.Dir, command.Env = directory, environment
	return sourceCaptureOutput(ctx, command, limit)
}

func sourceCaptureOutput(ctx context.Context, command *exec.Cmd, limit int) (string, string, *int, error) {
	stdout, stderr := &sourceOutput{limit: limit}, &sourceOutput{limit: limit}
	command.Stdout, command.Stderr = stdout, stderr
	code, err := runSourceProcess(ctx, command)
	if stdout.overflow || stderr.overflow || stdout.data.Len()+stderr.data.Len() > limit {
		err = errors.Join(err, fmt.Errorf("source command diagnostic exceeds byte bound"))
	}
	return stdout.data.String(), stderr.data.String(), code, err
}

func sourceCombinedOutput(ctx context.Context, directory string, environment []string, limit int, args ...string) (string, *int, error) {
	command := exec.CommandContext(ctx, args[0], args[1:]...)
	command.Dir, command.Env = directory, environment
	return sourceCaptureCombined(ctx, command, limit)
}

func sourceCaptureCombined(ctx context.Context, command *exec.Cmd, limit int) (string, *int, error) {
	output := &sourceOutput{limit: limit}
	command.Stdout, command.Stderr = output, output
	code, err := runSourceProcess(ctx, command)
	if output.overflow {
		err = errors.Join(err, fmt.Errorf("source command diagnostic exceeds byte bound"))
	}
	return output.data.String(), code, err
}

func sourceLogged(ctx context.Context, directory string, environment []string, logfile string, args ...string) (code *int, err error) {
	stream, err := os.OpenFile(logfile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, stream.Close()) }()
	command := exec.CommandContext(ctx, args[0], args[1:]...)
	command.Dir, command.Env = directory, environment
	command.Stdout, command.Stderr = stream, stream
	return runSourceProcess(ctx, command)
}

func sourceReceipt(filename string, document any, exclusive bool, limit int) error {
	var raw bytes.Buffer
	if err := writeJSON(&raw, document); err != nil {
		return err
	}
	if raw.Len() > limit {
		return fmt.Errorf("source receipt exceeds byte bound")
	}
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if exclusive {
		flags = os.O_CREATE | os.O_WRONLY | os.O_EXCL
	}
	file, err := os.OpenFile(filename, flags, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(file, &raw)
	return errors.Join(err, file.Close())
}
