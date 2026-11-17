package tun

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
)

func TestResolvedCloseWaitsForSetup(t *testing.T) {
	var lifecycle resolvedLifecycle
	entered, release := make(chan struct{}), make(chan struct{})
	var commands []string
	run := func(ctx context.Context, args ...string) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("command has no deadline")
		}
		commands = append(commands, args[0])
		if args[0] == "dns" {
			close(entered)
			<-release
		}
		return nil
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := lifecycle.configure(run, "tun-test", []string{"192.0.2.1"}); err != nil {
			t.Error(err)
		}
	}()
	<-entered
	go func() {
		defer wg.Done()
		if err := lifecycle.close(run, "tun-test"); err != nil {
			t.Error(err)
		}
	}()
	close(release)
	wg.Wait()
	if want := []string{"dns", "domain", "default-route", "revert"}; !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands = %v, want %v", commands, want)
	}
	if err := lifecycle.configure(run, "tun-test", nil); err == nil {
		t.Fatal("setup after close accepted")
	}
	if err := lifecycle.close(run, "tun-test"); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 4 {
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
