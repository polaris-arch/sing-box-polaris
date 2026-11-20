package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

type startupFailureService struct {
	boxService.Adapter
	cleanup func() error
}

func (s *startupFailureService) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		scope.Add(s.cleanup)
		return context.Canceled
	}
	return nil
}

func TestCreateReportsStartupCleanupFailure(t *testing.T) {
	for _, test := range []struct {
		name     string
		closeErr error
	}{
		{name: "clean"},
		{name: "failed", closeErr: errors.New("injected startup cleanup failure")},
	} {
		t.Run(test.name, func(t *testing.T) {
			oldContext, oldLogger := globalCtx, log.StdLogger()
			t.Cleanup(func() {
				globalCtx = oldContext
				log.SetStdLogger(oldLogger)
			})
			var output bytes.Buffer
			logger := log.NewDefaultFactory(context.Background(), log.Formatter{DisableColors: true}, &output, "", nil, false)
			if err := logger.Start(); err != nil {
				t.Fatal(err)
			}
			log.SetStdLogger(logger.Logger())
			globalCtx = include.Context(context.Background())
			registry := service.FromContext[adapter.ServiceRegistry](globalCtx).(*boxService.Registry)
			const fixtureType = "startup-fixture"
			closes := 0
			boxService.Register(registry, fixtureType, func(_ context.Context, _ log.ContextLogger, tag string, _ struct{}) (adapter.Service, error) {
				return &startupFailureService{Adapter: boxService.NewAdapter(fixtureType, tag), cleanup: func() error {
					closes++
					return test.closeErr
				}}, nil
			})
			instance, cancel, err := create(option.Options{
				Log:         &option.LogOptions{Disabled: true},
				Certificate: &option.CertificateOptions{Store: C.CertificateStoreNone},
				Services:    []option.Service{{Type: fixtureType, Tag: fixtureType, Options: &struct{}{}}},
			}, nil)
			if instance != nil || cancel != nil || !errors.Is(err, context.Canceled) || closes != 1 {
				t.Fatalf("create startup failure = %v, cleanup calls = %d", err, closes)
			}
			if test.closeErr == nil {
				if output.Len() != 0 || strings.Contains(err.Error(), "sing-box did not close properly") {
					t.Fatalf("clean startup rollback reported a failure: %v, log = %q", err, output.String())
				}
			} else if !errors.Is(err, test.closeErr) || !strings.Contains(output.String(), `runtime cleanup snapshot: {"schema":"runtime-cleanup-v1"`) {
				t.Fatalf("startup cleanup result or diagnostic was lost: %v, log = %q", err, output.String())
			}
		})
	}
}

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
