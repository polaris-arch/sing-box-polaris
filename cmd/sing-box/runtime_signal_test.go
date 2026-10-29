package main

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
)

func TestRunSignalCloseControlsRestartAndError(t *testing.T) {
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP} {
		for _, fail := range []bool{false, true} {
			signals := make(chan os.Signal, 1)
			signals <- sig
			canceled, closes, creates, checks := false, 0, 1, 0
			closeErr := errors.New("runtime cleanup incomplete")
			reload, err := runUntilSignal(signals, func() error { checks++; return nil }, func() { canceled = true }, func() error {
				closes++
				if fail {
					return closeErr
				}
				return nil
			}, func() any { return map[string]any{"done": false} })
			if reload {
				creates++
			}
			if !canceled || closes != 1 {
				t.Fatal("signal did not cancel and close exactly once")
			}
			if fail && (!errors.Is(err, closeErr) || reload || creates != 1) {
				t.Fatalf("failed close restarted or was swallowed: %v", err)
			}
			if !fail && (err != nil || reload != (sig == syscall.SIGHUP)) {
				t.Fatalf("successful close: reload=%v err=%v", reload, err)
			}
			if checks != map[bool]int{true: 1, false: 0}[sig == syscall.SIGHUP] {
				t.Fatal("reload validation bypassed")
			}
		}
	}
}

func TestRunSignalInvalidReloadKeepsCurrentOwner(t *testing.T) {
	signals := make(chan os.Signal, 2)
	signals <- syscall.SIGHUP
	signals <- syscall.SIGTERM
	checks, closes := 0, 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reload, err := runUntilSignal(signals, func() error { checks++; return errors.New("invalid configuration") }, cancel, func() error { closes++; return nil }, func() any { return nil })
	if err != nil || reload || checks != 1 || closes != 1 || ctx.Err() == nil {
		t.Fatal("invalid reload changed current owner")
	}
}
