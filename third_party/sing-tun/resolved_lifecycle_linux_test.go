package tun

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestResolvedCloseCancelsSetup(t *testing.T) {
	var lifecycle resolvedLifecycle
	entered := make(chan struct{})
	var commands []string
	run := func(ctx context.Context, args ...string) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("command has no deadline")
		}
		commands = append(commands, args[0])
		if args[0] == "dns" {
			close(entered)
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}
	done := make(chan error, 1)
	go func() {
		done <- lifecycle.configure(run, "tun-test", []string{"192.0.2.1"})
	}()
	<-entered
	if err := lifecycle.close(run, "tun-test"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("setup was not canceled: %v", err)
	}
	if want := []string{"dns", "revert"}; !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands = %v, want %v", commands, want)
	}
	if err := lifecycle.configure(run, "tun-test", nil); err == nil {
		t.Fatal("setup after close accepted")
	}
	if err := lifecycle.close(run, "tun-test"); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 2 {
		t.Fatal("successful revert repeated")
	}
}

func TestResolvedFailureReportedAndPartialSetupReverted(t *testing.T) {
	var lifecycle resolvedLifecycle
	failure := errors.New("resolver unavailable")
	var commands []string
	run := func(_ context.Context, args ...string) error {
		commands = append(commands, args[0])
		if args[0] == "domain" {
			return failure
		}
		return nil
	}
	if err := lifecycle.configure(run, "tun-test", nil); !errors.Is(err, failure) {
		t.Fatalf("lost setup error: %v", err)
	}
	if err := lifecycle.close(run, "tun-test"); err != nil {
		t.Fatal(err)
	}
	if want := []string{"dns", "domain", "revert"}; !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands = %v", commands)
	}
}

func TestResolvedUnstartedCloseDoesNotRevert(t *testing.T) {
	var lifecycle resolvedLifecycle
	run := func(context.Context, ...string) error {
		t.Fatal("unowned resolver mutation")
		return nil
	}
	if err := lifecycle.close(run, "tun-test"); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.configure(run, "tun-test", nil); err == nil {
		t.Fatal("setup after close accepted")
	}
}

func TestResolvedFailedRevertCanRetry(t *testing.T) {
	var lifecycle resolvedLifecycle
	run := func(context.Context, ...string) error { return nil }
	if err := lifecycle.configure(run, "tun-test", nil); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.close(func(context.Context, ...string) error {
		return errors.New("failed")
	}, "tun-test"); err == nil {
		t.Fatal("lost revert error")
	}
	if err := lifecycle.close(run, "tun-test"); err != nil {
		t.Fatal(err)
	}
}

func TestResolvedRevertUsesShortShutdownBudget(t *testing.T) {
	var lifecycle resolvedLifecycle
	if err := lifecycle.configure(func(context.Context, ...string) error { return nil }, "tun-test", nil); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := lifecycle.close(func(ctx context.Context, args ...string) error {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > time.Second {
			t.Fatal("revert exceeds one-second shutdown budget")
		}
		<-ctx.Done()
		return ctx.Err()
	}, "tun-test")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("revert timeout was not reported: %v", err)
	}
	if time.Since(start) >= 3*time.Second {
		t.Fatal("resolver cleanup consumed helper's five-second grace")
	}
}
