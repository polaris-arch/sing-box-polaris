package dialer

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

func runtimeSlowOpenFixture(dial func(context.Context, string, string, []byte) (net.Conn, error)) *slowOpenConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &slowOpenConn{ctx: ctx, cancel: cancel, network: "tcp", destination: M.Socksaddr{Fqdn: "example.org", Port: 443}, create: make(chan struct{}), done: make(chan struct{}), creationDone: make(chan struct{}), dial: dial}
}

func TestSlowOpenCloseJoinsPendingCreationAndRawClose(t *testing.T) {
	ctx := runtimeRacerContext(t)
	dialEntered, dialRelease := make(chan struct{}), make(chan struct{})
	closeEntered, closeRelease := make(chan struct{}), make(chan struct{})
	var dOnce, cOnce sync.Once
	releaseDial := func() { dOnce.Do(func() { close(dialRelease) }) }
	releaseClose := func() { cOnce.Do(func() { close(closeRelease) }) }
	t.Cleanup(releaseClose)
	t.Cleanup(releaseDial)
	raw := &runtimeRacerConn{closeFn: func() error { close(closeEntered); <-closeRelease; return nil }}
	c := runtimeSlowOpenFixture(func(context.Context, string, string, []byte) (net.Conn, error) {
		close(dialEntered)
		<-dialRelease
		return raw, nil
	})
	writeDone := make(chan error, 1)
	go func() { _, err := c.Write([]byte("first")); writeDone <- err }()
	runtimeRacerWait(t, ctx, dialEntered)
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	runtimeRacerWait(t, ctx, c.done)
	releaseDial()
	runtimeRacerWait(t, ctx, closeEntered)
	select {
	case err := <-closed:
		t.Fatalf("close reported before raw cleanup: %v", err)
	default:
	}
	releaseClose()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("closed pending creation returned success")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if c.conn.Load() != nil {
		t.Fatal("late creation installed a connection after Close")
	}
}

func TestSlowOpenLateCleanupFailureIsSticky(t *testing.T) {
	ctx := runtimeRacerContext(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	c := runtimeSlowOpenFixture(func(context.Context, string, string, []byte) (net.Conn, error) {
		close(entered)
		<-release
		return &runtimeRacerConn{closeFn: func() error { return context.Canceled }}, nil
	})
	writeDone := make(chan struct{})
	go func() { defer close(writeDone); _, _ = c.Write([]byte("first")) }()
	runtimeRacerWait(t, ctx, entered)
	result := make(chan error, 1)
	go func() { result <- c.Close() }()
	runtimeRacerWait(t, ctx, c.done)
	unblock()
	select {
	case err := <-result:
		if err == nil || errors.Is(err, context.Canceled) {
			t.Fatalf("late cleanup uncertainty was lost/filterable: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	runtimeRacerWait(t, ctx, writeDone)
	if err := c.Close(); err == nil {
		t.Fatal("second Close erased failed cleanup")
	}
}

func TestSlowOpenCreationPanicPublishesUnknownCompletion(t *testing.T) {
	c := runtimeSlowOpenFixture(func(context.Context, string, string, []byte) (net.Conn, error) { panic("native creation") })
	if _, err := c.Write([]byte("first")); err == nil {
		t.Fatal("panic lost")
	}
	if err := c.Close(); err == nil {
		t.Fatal("creation uncertainty became successful cleanup")
	}
	select {
	case <-c.create:
	default:
		t.Fatal("panic left reader readiness unpublished")
	}
}

type runtimeTFODependencyFailure struct{}

func (runtimeTFODependencyFailure) Error() string                  { return "dependency loser cleanup failed" }
func (runtimeTFODependencyFailure) RuntimeCleanupIncomplete() bool { return true }

func TestSlowOpenFailedDialOwnsReturnedConnection(t *testing.T) {
	ctx := runtimeRacerContext(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	raw := &runtimeRacerConn{closeFn: func() error { close(entered); <-release; return context.Canceled }}
	c := runtimeSlowOpenFixture(func(context.Context, string, string, []byte) (net.Conn, error) { return raw, context.Canceled })
	written := make(chan error, 1)
	go func() { _, err := c.Write([]byte("first")); written <- err }()
	runtimeRacerWait(t, ctx, entered)
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	runtimeRacerWait(t, ctx, c.done)
	select {
	case err := <-closed:
		t.Fatalf("failed dial socket cleanup not joined: %v", err)
	default:
	}
	unblock()
	select {
	case err := <-closed:
		if err == nil || errors.Is(err, context.Canceled) {
			t.Fatalf("cleanup failure lost: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case err := <-written:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("operational cancellation lost: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if c.conn.Load() != nil {
		t.Fatal("failed socket installed")
	}
}

func TestSlowOpenDependencyCleanupFailureIsSticky(t *testing.T) {
	c := runtimeSlowOpenFixture(func(context.Context, string, string, []byte) (net.Conn, error) {
		return nil, errors.Join(context.Canceled, runtimeTFODependencyFailure{})
	})
	if _, err := c.Write([]byte("first")); err == nil {
		t.Fatal("failed dial succeeded")
	}
	for i := 0; i < 2; i++ {
		if err := c.Close(); err == nil || errors.Is(err, context.Canceled) {
			t.Fatalf("dependency cleanup lost or filterable: %v", err)
		}
	}
}

func TestSlowOpenOrdinaryFailedDialHasNoCleanupUncertainty(t *testing.T) {
	c := runtimeSlowOpenFixture(func(context.Context, string, string, []byte) (net.Conn, error) { return nil, context.Canceled })
	if _, err := c.Write([]byte("first")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("ordinary dial failure became cleanup failure: %v", err)
	}
}
