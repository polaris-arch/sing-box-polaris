package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"slices"
	"syscall"
	"testing"
	"time"
)

func TestPeerNativeProcessFixture(t *testing.T) {
	i := slices.Index(os.Args, "--")
	if i == -1 || i+1 == len(os.Args) {
		return
	}
	mode := os.Args[i+1]
	switch mode {
	case "single", "parent", "descendant":
		if os.Getenv("GH_TOKEN") != "" {
			t.Fatal("repository credentials inherited by the fixture")
		}
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM)
		if mode == "parent" {
			child := exec.Command(os.Args[0], "-test.run=^TestPeerNativeProcessFixture$", "--", "descendant")
			child.Stdout, child.Stderr = os.Stdout, os.Stderr
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
		}
		fmt.Println(mode + "-ready")
		<-signals
		os.Exit(0)
	default:
		t.Fatalf("unknown fixture mode: %s", mode)
	}
}

func TestPeerNativeProcessCustody(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := fileSHA256(binary)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GH_TOKEN", "inert-test-credential")
	for _, mode := range []string{"single", "parent"} {
		t.Run(mode, func(t *testing.T) {
			scope, err := openPeerProcessScope()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if scope.active {
					_, _ = scope.close()
				}
			})
			dir := t.TempDir()
			args := []string{"-test.run=^TestPeerNativeProcessFixture$", "--", mode}
			if _, err := scope.start(binary, "peer", filepath.Join(dir, "mismatched.log"), "wrong", args...); err == nil || len(scope.owners) != 0 {
				t.Fatalf("executable with the wrong digest was started: %v", err)
			}
			log := filepath.Join(dir, "peer.private.log")
			owner, err := scope.start(binary, "peer", log, hash, args...)
			if err != nil {
				t.Fatal(err)
			}
			ready := mode + "-ready"
			if mode == "parent" {
				ready = "descendant-ready"
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				raw, err := os.ReadFile(log)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(raw, []byte(ready)) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("owner did not reach readiness, log: %q", raw)
				}
				time.Sleep(10 * time.Millisecond)
			}
			observed, closeErr := owner.close()
			success := mode == "single"
			if observed.GracefulCleanupProven != success || (closeErr == nil) != success ||
				observed.ExitCode == nil || *observed.ExitCode != 0 || observed.ExitBeforeTerminate != nil ||
				observed.ForcedKill || !observed.PrivateLogObservedAfterExit ||
				observed.PrivateLogSHA256 == nil || observed.PrivateLogBytes == nil {
				t.Fatalf("incorrect process cleanup evidence: %+v, %v", observed, closeErr)
			}
			pid, identity := owner.command.Process.Pid, observed.StartIdentity
			signals := observed.TerminationActions
			if identity == nil || identity.PID != pid || identity.Group != pid || identity.Session != pid ||
				len(signals) != 1 || signals[0].Signal != "SIGTERM" || !signals[0].PIDFDBound ||
				signals[0].PID != pid || signals[0].StartTicks != identity.StartTicks || signals[0].CoreSHA256 != hash {
				t.Fatalf("incorrect process identity/signal: %+v, %+v", identity, signals)
			}
			again, againErr := owner.close()
			if !reflect.DeepEqual(again, observed) || !reflect.DeepEqual(againErr, closeErr) {
				t.Fatalf("repeat close changed evidence: %+v, %v", again, againErr)
			}
			retirement, err := scope.close()
			if (err == nil) != success || retirement.ForcedKill || len(retirement.Remaining) != 0 {
				t.Fatalf("incorrect descendant retirement: %+v, %v", retirement, err)
			}
			if success {
				if len(observed.RemainingGroup) != 0 || len(retirement.Retired) != 0 {
					t.Fatalf("graceful close retained descendants: %+v", retirement)
				}
			} else if len(observed.RemainingGroup) != 1 || len(retirement.Retired) != 1 ||
				retirement.Retired[0]["pid"] != observed.RemainingGroup[0] {
				t.Fatalf("adopted descendant not identified and reaped: %+v, %+v", observed.RemainingGroup, retirement)
			}
		})
	}
}
