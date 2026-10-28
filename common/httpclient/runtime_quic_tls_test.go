//go:build with_quic

package httpclient

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
)

func TestRuntimeQUICTLSProviderCallbackIsIndependentOfRunContext(t *testing.T) {
	entered, finish := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	original := &tls.Config{Time: func() time.Time { calls.Add(1); close(entered); <-finish; return time.Unix(123, 0) }}
	fence := outbound.NewRuntimeIOFence(nil)
	guarded := guardRuntimeQUICTLS(original, fence)
	returned := make(chan struct{})
	go func() { defer close(returned); _ = guarded.Time() }()
	<-entered
	if err := fence.Close(); err != nil && !errors.Is(err, outbound.ErrRuntimeClosePending) {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- fence.Wait() }()
	select {
	case <-closed:
		t.Fatal("provider callback tail was not joined")
	default:
	}
	close(finish)
	<-returned
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	_ = guarded.Time()
	if calls.Load() != 1 {
		t.Fatal("late provider callback reached retired owner")
	}
	if guarded.VerifyConnection != nil || guarded.GetConfigForClient != nil || guarded.ClientSessionCache != nil {
		t.Fatal("nil capabilities changed ChromeParrot validation")
	}
	if original.Time == nil {
		t.Fatal("caller config mutated")
	}
}

// This exercises the entropy-reader wrapper's lifecycle, not a TLS handshake.
// Production guard wiring is reviewed separately; avoid deprecated TLS fields
// in this regression fixture.
func TestRuntimeQUICTLSReaderJoinsBlockedReadAndRejectsLateRead(t *testing.T) {
	entered, finish, cleanupDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var finishOnce sync.Once
	var calls atomic.Int32
	readErr := errors.New("entropy provider read failed")
	fence := outbound.NewRuntimeIOFence(func() error {
		close(cleanupDone)
		return nil
	})
	t.Cleanup(func() {
		finishOnce.Do(func() { close(finish) })
		_ = fence.Close()
	})
	guarded := runtimeQUICReader{
		reader: runtimeQUICTestReaderFunc(func(p []byte) (int, error) {
			if calls.Add(1) == 1 {
				close(entered)
			}
			<-finish
			return copy(p, "rng"), readErr
		}),
		fence: fence,
	}
	type readResult struct {
		n   int
		err error
	}
	buffer := []byte("-----")
	readDone := make(chan readResult, 1)
	go func() {
		n, err := guarded.Read(buffer)
		readDone <- readResult{n: n, err: err}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("entropy provider was not entered")
	}
	if err := fence.Close(); err != nil && !errors.Is(err, outbound.ErrRuntimeClosePending) {
		t.Fatal(err)
	}
	select {
	case <-cleanupDone:
	case <-time.After(3 * time.Second):
		t.Fatal("entropy provider fence did not initiate cleanup")
	}
	retired := make(chan error, 1)
	go func() { retired <- fence.Wait() }()
	select {
	case err := <-retired:
		t.Fatalf("retirement completed during a blocked entropy read: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	finishOnce.Do(func() { close(finish) })
	select {
	case result := <-readDone:
		if result.n != 3 || result.err != readErr || !bytes.Equal(buffer, []byte("rng--")) {
			t.Fatalf("entropy reader changed count, error, or bytes: n=%d err=%v bytes=%q", result.n, result.err, buffer)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("entropy read did not return after provider release")
	}
	select {
	case err := <-retired:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("retirement did not join the released entropy read")
	}
	late := []byte("late")
	if n, err := guarded.Read(late); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("retired entropy reader accepted a late read: n=%d err=%v", n, err)
	}
	if calls.Load() != 1 || !bytes.Equal(late, []byte("late")) {
		t.Fatal("late entropy read invoked the provider or changed the destination")
	}
}

type runtimeQUICTestReaderFunc func([]byte) (int, error)

func (f runtimeQUICTestReaderFunc) Read(p []byte) (int, error) { return f(p) }
