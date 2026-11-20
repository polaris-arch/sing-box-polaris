package openvpn

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

type materialResourceDirectoryManager struct{ filemanager.Manager }

func (m materialResourceDirectoryManager) ConfigurationDirectoryPath(path string) string {
	return m.BasePath(path)
}

func TestMaterialSourcePreservesEmptyAndUsesWindowsResourceBase(t *testing.T) {
	directory := t.TempDir()
	ctx := filemanager.WithDefault(context.Background(), directory, "", 0, 0)
	if material, err := materialSource(ctx, "tls.client_certificate", nil, "client.pem"); err != nil || material.Path != "client.pem" {
		t.Fatalf("ordinary file manager changed material: %+v, %v", material, err)
	}
	ctx = service.ContextWith[filemanager.Manager](ctx, materialResourceDirectoryManager{service.FromContext[filemanager.Manager](ctx)})
	for _, path := range []string{"", "client.pem"} {
		material, err := materialSource(ctx, "tls.client_certificate", nil, path)
		if err != nil {
			t.Fatal(err)
		}
		expected := path
		if runtime.GOOS == "windows" && path != "" {
			expected = filepath.Join(directory, path)
		}
		if material.Path != expected {
			t.Fatalf("material path = %q; want %q", material.Path, expected)
		}
	}
	if _, err := materialSource(ctx, "tls.client_certificate", []string{"inline"}, "client.pem"); err == nil {
		t.Fatal("inline material and a path must still conflict")
	}
}

func fixtureRuntimeClient() *runtimeClientState {
	ctx, cancel := context.WithCancel(context.Background())
	return &runtimeClientState{ctx: ctx, cancel: cancel, scope: adapter.NewScope(ctx, log.NewNOPFactory().Logger()), callbacks: outbound.NewRuntimeIOFence(nil), carriers: outbound.NewRuntimeIOFenceSet(), closeDone: make(chan struct{})}
}

func TestRuntimeClientPublicationRequiresCompletedStage(t *testing.T) {
	r := fixtureRuntimeClient()
	defer r.close()
	e := &ClientEndpoint{runtime: r}
	if _, err := e.RuntimePreparePublication(); err == nil {
		t.Fatal("unprepared client admitted")
	}
	r.stageDone = make(chan struct{})
	r.staged = true
	close(r.stageDone)
	publish, err := e.RuntimePreparePublication()
	if err != nil {
		t.Fatal(err)
	}
	if r.gate.Load() || r.ingress.Load() {
		t.Fatal("prepare published")
	}
	publish()
	if !r.gate.Load() || !r.ingress.Load() {
		t.Fatal("publication missing")
	}
	e.RuntimeStop()
	if r.ingress.Load() || !r.gate.Load() {
		t.Fatal("retirement stopped retained flows")
	}
}

func TestRuntimeClientJoinsCallbacksBeforeDeviceCleanup(t *testing.T) {
	r := fixtureRuntimeClient()
	leave, err := r.callbacks.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	nativeClosed := make(chan struct{})
	r.nativeClose = func() error { close(nativeClosed); return nil }
	deviceClosed := make(chan struct{})
	r.scope.Add(func() error { close(deviceClosed); return nil })
	done := make(chan struct{})
	go func() { defer close(done); _ = r.close() }()
	select {
	case <-nativeClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("native stop not requested")
	}
	select {
	case <-deviceClosed:
		t.Fatal("device destroyed while callback admitted")
	default:
	}
	leave()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("callback completion not joined")
	}
	select {
	case <-deviceClosed:
	default:
		t.Fatal("device cleanup missing")
	}
}

func TestRuntimeClientLateNativeConstructorCompensates(t *testing.T) {
	r := fixtureRuntimeClient()
	if err := r.close(); err != nil {
		t.Fatal(err)
	}
	calls := 0
	failure := errors.New("native close failed")
	err := r.installNative(func() error { calls++; return failure })
	if calls != 1 || !tls.IsRuntimeCleanupIncomplete(err) {
		t.Fatal("late constructor lost cleanup uncertainty")
	}
}

func TestRuntimeClientNativeCloseErrorIsSticky(t *testing.T) {
	r := fixtureRuntimeClient()
	calls := 0
	r.nativeClose = func() error { calls++; return errors.New("native close failed") }
	first := r.close()
	second := r.close()
	if !tls.IsRuntimeCleanupIncomplete(first) || second != first || calls != 1 {
		t.Fatal("native cleanup result changed")
	}
}
