package log

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/observable"
)

type runtimeLogBuffer struct {
	sync.Mutex
	bytes.Buffer
}

func (b *runtimeLogBuffer) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.Buffer.Write(p)
}
func (b *runtimeLogBuffer) text() string { b.Lock(); defer b.Unlock(); return b.Buffer.String() }

func runtimeLogPublish(t *testing.T, f Factory, next option.LogOptions) *RuntimeOptionsChange {
	t.Helper()
	change, err := PrepareRuntimeOptions(f, next)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := change.PreparePublication()
	if err != nil {
		t.Fatal(err)
	}
	publication.Publish()
	publication.Finish()
	return change
}

func TestRuntimeLogColdDisabledRetainedLoggerAndSubscriptions(t *testing.T) {
	var output runtimeLogBuffer
	value, err := New(Options{Context: context.Background(), Options: option.LogOptions{Disabled: true}, Observable: true, DefaultWriter: &output})
	if err != nil {
		t.Fatal(err)
	}
	f := value.(*runtimeFactory)
	defer f.Close()
	logger := f.NewLogger("retained-before-start")
	logger.Info("cold-disabled")
	logger.Panic("disabled-panic-is-NOP")
	if _, err := PrepareRuntimeOptions(f, option.LogOptions{}); err == nil {
		t.Fatal("variant prepared before runtime owner started")
	}
	if err := f.Start(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.Subscribe(); !errors.Is(err, os.ErrInvalid) {
		t.Fatal("disabled Subscribe", err)
	}
	enable := runtimeLogPublish(t, f, option.LogOptions{Level: "info"})
	if err := enable.Retire(context.Background()); err != nil {
		t.Fatal(err)
	}
	sub, done, err := f.Subscribe()
	if err != nil {
		t.Fatal(err)
	}
	defer f.UnSubscribe(sub)
	logger.Info("first-enabled")
	entry := runtimeLogEntry(t, sub)
	if !strings.Contains(entry.Message, "first-enabled") {
		t.Fatal(entry)
	}
	disable := runtimeLogPublish(t, f, option.LogOptions{Disabled: true, Level: "info"})
	if err := disable.Retire(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := output.text()
	logger.Error("disabled-error")
	logger.Panic("disabled-panic")
	if output.text() != before || strings.Contains(before, "cold-disabled") {
		t.Fatal("disabled logger emitted")
	}
	if _, _, err := f.Subscribe(); !errors.Is(err, os.ErrInvalid) {
		t.Fatal("disabled subscribed", err)
	}
	select {
	case <-done:
		t.Fatal("retained subscription owner was destroyed")
	default:
	}
	again := runtimeLogPublish(t, f, option.LogOptions{Level: "info"})
	if err := again.Retire(context.Background()); err != nil {
		t.Fatal(err)
	}
	logger.Info("second-enabled")
	if entry := <-sub; !strings.Contains(entry.Message, "second-enabled") {
		t.Fatal(entry)
	}
	if !strings.Contains(output.text(), "retained-before-start") {
		t.Fatal("tag/reference stranded")
	}
}

type runtimeBlockingLogWriter struct {
	entered, release chan struct{}
	once             sync.Once
	unblockOnce      sync.Once
	next             io.Writer
}

func (w *runtimeBlockingLogWriter) unblock() { w.unblockOnce.Do(func() { close(w.release) }) }
func (w *runtimeBlockingLogWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	if w.next != nil {
		return w.next.Write(p)
	}
	return len(p), nil
}

func TestRuntimeLogPublishDoesNotWaitForOldEmissionButRetirementDoes(t *testing.T) {
	w := &runtimeBlockingLogWriter{entered: make(chan struct{}), release: make(chan struct{})}
	value, err := New(Options{Context: context.Background(), DefaultWriter: w})
	if err != nil {
		t.Fatal(err)
	}
	f := value.(*runtimeFactory)
	defer f.Close()
	defer w.unblock()
	if err := f.Start(); err != nil {
		t.Fatal(err)
	}
	emitted := make(chan struct{})
	go func() { defer close(emitted); f.Logger().Info("old-graph-reference") }()
	<-w.entered
	change := runtimeLogPublish(t, f, option.LogOptions{Disabled: true})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := change.Retire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("drain fabricated", err)
	}
	select {
	case <-change.before.done:
		t.Fatal("old emission not retained")
	default:
	}
	w.unblock()
	<-emitted
	if err := change.Retire(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeLogBoundFileClosesOnlyAfterItsEmissionDrain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "singbox.log")
	value, err := New(Options{Context: context.Background(), Options: option.LogOptions{Output: path}})
	if err != nil {
		t.Fatal(err)
	}
	f := value.(*runtimeFactory)
	defer f.Close()
	if err := f.Start(); err != nil {
		t.Fatal(err)
	}
	file := f.current.sink.file
	blocked := &runtimeBlockingLogWriter{entered: make(chan struct{}), release: make(chan struct{}), next: file}
	defer blocked.unblock()
	f.current.sink.writer = blocked
	emitted := make(chan struct{})
	go func() { defer close(emitted); f.NewLogger("old").Info("old-file") }()
	<-blocked.entered
	change := runtimeLogPublish(t, f, option.LogOptions{Disabled: true})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = change.Retire(ctx)
	if _, err := file.Stat(); err != nil {
		t.Fatal("file closed while old emitter holds it", err)
	}
	blocked.unblock()
	<-emitted
	if err := change.Retire(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("old file not closed", err)
	}
	again := runtimeLogPublish(t, f, option.LogOptions{Output: path})
	if err := again.Retire(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.NewLogger("new").Info("new-file")
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(data, []byte("old-file")) || !bytes.Contains(data, []byte("new-file")) {
		t.Fatalf("%s %v", data, err)
	}
}

func TestRuntimeLogPreparationAbortAndOutputFailureKeepCurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "singbox.log")
	value, err := New(Options{Context: context.Background(), Options: option.LogOptions{Output: path}})
	if err != nil {
		t.Fatal(err)
	}
	f := value.(*runtimeFactory)
	defer f.Close()
	if err := f.Start(); err != nil {
		t.Fatal(err)
	}
	original := f.current
	change, err := PrepareRuntimeOptions(f, option.LogOptions{Disabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if f.current != original {
		t.Fatal("prepare published disabled state")
	}
	fence, err := change.PreparePublication()
	if err != nil {
		t.Fatal(err)
	}
	fence.Finish() // A failed graph CAS: do not call Publish.
	if err := change.Abort(); err != nil {
		t.Fatal(err)
	}
	if f.current != original {
		t.Fatal("abort changed active logger")
	}
	disabled := runtimeLogPublish(t, f, option.LogOptions{Disabled: true})
	if err := disabled.Retire(context.Background()); err != nil {
		t.Fatal(err)
	}
	preparedEnable, err := PrepareRuntimeOptions(f, option.LogOptions{Output: path})
	if err != nil {
		t.Fatal(err)
	}
	candidateFile := preparedEnable.next.sink.file
	if _, err := candidateFile.Stat(); err != nil {
		t.Fatal(err)
	}
	if err := preparedEnable.Abort(); err != nil {
		t.Fatal(err)
	}
	if _, err := candidateFile.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("aborted candidate file still open", err)
	}
	if !f.current.options.Disabled {
		t.Fatal("candidate enable escaped prepare")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	before := f.current
	if _, err := PrepareRuntimeOptions(f, option.LogOptions{Output: path}); err == nil {
		t.Fatal("missing bound file was created during hot preparation")
	}
	if f.current != before || !f.current.options.Disabled {
		t.Fatal("output failure advanced active logger")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed prepare left a new file", err)
	}
}

func TestRuntimeLogEligibilityRejectsPathsFormatsAndLegacyFactories(t *testing.T) {
	value, err := New(Options{Context: context.Background(), Options: option.LogOptions{Disabled: true}, DefaultWriter: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	defer value.Close()
	for _, next := range []option.LogOptions{
		{Output: filepath.Join(t.TempDir(), "arbitrary")}, {Timestamp: true}, {DisableColor: true}, {Level: "invented"},
	} {
		if RuntimeOptionsEligible(value, next) {
			t.Fatalf("unsupported admitted: %+v", next)
		}
	}
	if !RuntimeOptionsEligible(value, option.LogOptions{Level: "debug"}) {
		t.Fatal("initial disabled enable unsupported")
	}
	if RuntimeOptionsEligible(NewNOPFactory(), option.LogOptions{}) {
		t.Fatal("explicit legacy NOP claims a switchable owner")
	}
	if _, err := PrepareRuntimeOptions(NewNOPFactory(), option.LogOptions{}); err == nil {
		t.Fatal("legacy logger silently replaced")
	}
}

func TestRuntimeLogUnobservableSubscriptionIsAnErrorAndCloseJoinsEmitter(t *testing.T) {
	w := &runtimeBlockingLogWriter{entered: make(chan struct{}), release: make(chan struct{})}
	value, err := New(Options{Context: context.Background(), DefaultWriter: w})
	if err != nil {
		t.Fatal(err)
	}
	f := value.(*runtimeFactory)
	if err := f.Start(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.Subscribe(); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	emit := make(chan struct{})
	go func() { defer close(emit); f.Logger().Info("in-flight") }()
	<-w.entered
	closed := make(chan error, 1)
	go func() { closed <- f.Close() }()
	select {
	case err := <-closed:
		t.Fatal("Close did not join owned emission", err)
	default:
	}
	w.unblock()
	<-emit
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal("sticky close", err)
	}
}

func runtimeLogEntry(t *testing.T, subscription observable.Subscription[Entry]) Entry {
	t.Helper()
	select {
	case entry := <-subscription:
		return entry
	case <-time.After(5 * time.Second):
		t.Fatal("missing actual observer entry")
		return Entry{}
	}
}

var _ observable.Observable[Entry] = (*runtimeFactory)(nil)

func TestRuntimeLogFailedColdOutputDoesNotStartObserver(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "log")
	value, err := New(Options{Context: context.Background(), Options: option.LogOptions{Output: path}, Observable: true})
	if err != nil {
		t.Fatal(err)
	}
	f := value.(*runtimeFactory)
	if err := f.Start(); err == nil {
		t.Fatal("invalid cold output accepted")
	}
	if f.observer != nil || f.started {
		t.Fatal("failed cold start retained a running observer")
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeLogFenceExcludesCloseAndRejectsAbortedOwner(t *testing.T) {
	value, err := New(Options{Context: context.Background(), DefaultWriter: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	f := value.(*runtimeFactory)
	if err := f.Start(); err != nil {
		t.Fatal(err)
	}
	change, err := PrepareRuntimeOptions(f, option.LogOptions{Disabled: true})
	if err != nil {
		t.Fatal(err)
	}
	fence, err := change.PreparePublication()
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- f.Close() }()
	select {
	case err := <-closed:
		t.Fatal("Close passed publication fence", err)
	default:
	}
	fence.Finish()
	if err := change.Abort(); err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if _, err := change.PreparePublication(); err == nil {
		t.Fatal("aborted/closed owner fenced again")
	}
}

func TestRuntimeLogColdDisabledRetainsHostFileAnchorWithoutOpeningIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host-owned.log")
	if err := os.WriteFile(path, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := New(Options{Context: context.Background(), Options: option.LogOptions{Disabled: true, Output: path}})
	if err != nil {
		t.Fatal(err)
	}
	f := value.(*runtimeFactory)
	defer f.Close()
	retained := f.NewLogger("created-while-disabled")
	if err := f.Start(); err != nil {
		t.Fatal(err)
	}
	retained.Info("must-not-be-written")
	if data, err := os.ReadFile(path); err != nil || string(data) != "original\n" {
		t.Fatalf("disabled startup touched file: %q %v", data, err)
	}
	for index := 0; index < 2; index++ {
		enabled := runtimeLogPublish(t, f, option.LogOptions{Output: path})
		if err := enabled.Retire(context.Background()); err != nil {
			t.Fatal(err)
		}
		retained.Info("same-component-after-enable")
		disabled := runtimeLogPublish(t, f, option.LogOptions{Disabled: true, Output: path})
		if err := disabled.Retire(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || bytes.Count(data, []byte("same-component-after-enable")) != 2 || bytes.Contains(data, []byte("must-not-be-written")) {
		t.Fatalf("retained file logger %q %v", data, err)
	}
}

func TestRuntimeLogColdDisabledMissingNamedPathIsInertAndNotImplicitlyCreated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.log")
	value, err := New(Options{Context: context.Background(), Options: option.LogOptions{Disabled: true, Output: path}})
	if err != nil {
		t.Fatal(err)
	}
	f := value.(*runtimeFactory)
	defer f.Close()
	if err := f.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("disabled startup created output", err)
	}
	if _, err := PrepareRuntimeOptions(f, option.LogOptions{Output: path}); err == nil {
		t.Fatal("missing named output acquired implicit creation authority")
	}
	if !f.current.options.Disabled || f.pending != nil {
		t.Fatal("failed output preparation changed running logger")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("failed preparation created output", err)
	}
}
