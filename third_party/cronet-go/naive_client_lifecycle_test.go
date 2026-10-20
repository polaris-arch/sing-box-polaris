package cronet

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

func lifecycleTestClient(state clientState) *NaiveClient {
	c := &NaiveClient{ctx: context.Background(), started: make(chan struct{}), closed: make(chan struct{}), connections: make(map[*BidirectionalConn]struct{})}
	c.state.Store(uint32(state))
	if state == clientStateRunning {
		close(c.started)
	}
	return c
}

func awaitLifecycle(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("lifecycle did not finish")
	}
}

func TestNaiveAdmissionSealsBeforeJoin(t *testing.T) {
	c := lifecycleTestClient(clientStateRunning)
	if !c.beginOperation() || !c.beginCallback() {
		t.Fatal("running admission rejected")
	}
	// The close authority seals both gates before starting any join.
	c.lifecycle.Lock()
	c.state.Store(uint32(clientStateClosing))
	c.lifecycle.Unlock()
	if c.beginOperation() || c.beginCallback() {
		t.Fatal("admission reopened after seal")
	}
	finished := make(chan struct{})
	go func() { _ = c.doClose(); close(finished) }()
	// An already admitted callback may still register its worker after seal.
	c.proxyWaitGroup.Add(1)
	c.pending.Done()
	c.callbacks.Done()
	select {
	case <-finished:
		t.Fatal("close returned before admitted worker exited")
	default:
	}
	c.proxyWaitGroup.Done()
	awaitLifecycle(t, finished)
}

func TestNaiveTerminalRegistrationAndReleaseOnce(t *testing.T) {
	for _, alreadyDone := range []bool{false, true} {
		c := lifecycleTestClient(clientStateRunning)
		if !c.beginOperation() {
			t.Fatal("admission rejected")
		}
		conn := &BidirectionalConn{done: make(chan struct{})}
		if alreadyDone {
			close(conn.done)
		}
		c.trackConnection(conn)
		if !alreadyDone {
			if len(c.connections) != 1 {
				t.Fatal("stream escaped ownership")
			}
			// Simulate the terminal signal after native deletion was queued.
			conn.onTerminate()
			conn.onTerminate()
		}
		if len(c.connections) != 0 {
			t.Fatal("terminal stream retained")
		}
		c.pending.Done()
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNaiveRepeatedCloseWaitsForOriginalCompletion(t *testing.T) {
	c := lifecycleTestClient(clientStateRunning)
	if !c.beginOperation() {
		t.Fatal("admission rejected")
	}
	c.lifecycle.Lock()
	c.state.Store(uint32(clientStateClosing))
	c.lifecycle.Unlock()
	var wait sync.WaitGroup
	wait.Add(8)
	for range 8 {
		go func() {
			defer wait.Done()
			if err := c.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	finished := make(chan struct{})
	go func() { _ = c.doClose(); close(finished) }()
	select {
	case <-c.closed:
		t.Fatal("close completed while creation admitted")
	default:
	}
	c.pending.Done()
	awaitLifecycle(t, finished)
	wait.Wait()
}

func TestNaiveShutdownFailureNeverDestroys(t *testing.T) {
	for _, success := range []bool{false, true} {
		called := false
		err := shutdownNaiveEngine(func() Result {
			if success {
				return ResultSuccess
			}
			return Result(-1)
		}, func() { called = true })
		if called != success || (err == nil) != success {
			t.Fatalf("success=%v destroy=%v error=%v", success, called, err)
		}
	}
}

func TestNaiveClosedResultIsSticky(t *testing.T) {
	c := lifecycleTestClient(clientStateCreated)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	c = lifecycleTestClient(clientStateClosing)
	want := errors.New("native completion uncertain")
	c.closeError = want
	c.state.Store(uint32(clientStateClosed))
	close(c.closed)
	if err := c.Close(); err != want {
		t.Fatalf("sticky error = %v", err)
	}
}

func TestNaiveDialCreationBarrierAndTerminalOwnership(t *testing.T) {
	c := lifecycleTestClient(clientStateRunning)
	c.streamEngines = []StreamEngine{{}}
	entered, proceed, dialDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	conn := &BidirectionalConn{done: make(chan struct{}), close: make(chan struct{}), cancelled: true}
	go func() {
		_, err := c.dialEarly(context.Background(), M.Socksaddr{},
			func(StreamEngine, context.Context, logger.ContextLogger, bool, bool) *BidirectionalConn {
				close(entered)
				<-proceed
				return conn
			},
			func(conn *BidirectionalConn, _, _ string, _ map[string]string, _ int, _ bool) error {
				if conn.onTerminate == nil {
					t.Error("Start preceded terminal ownership")
				}
				return nil
			})
		if err != nil {
			t.Error(err)
		}
		close(dialDone)
	}()
	awaitLifecycle(t, entered)
	c.lifecycle.Lock()
	c.state.Store(uint32(clientStateClosing))
	c.lifecycle.Unlock()
	closed := make(chan struct{})
	go func() { _ = c.doClose(); close(closed) }()
	if c.beginOperation() {
		t.Fatal("late creation admitted")
	}
	select {
	case <-closed:
		t.Fatal("close overtook admitted creation")
	default:
	}
	close(proceed)
	awaitLifecycle(t, dialDone)
	awaitLifecycle(t, conn.close) // Close requested cancellation; no native callback yet.
	select {
	case <-closed:
		t.Fatal("cancellation request was treated as terminal completion")
	default:
	}
	conn.onTerminate()
	awaitLifecycle(t, closed)
}

func TestNaiveDialStartFailureAndInlineTerminal(t *testing.T) {
	for _, fail := range []bool{false, true} {
		c := lifecycleTestClient(clientStateRunning)
		c.streamEngines = []StreamEngine{{}}
		conn := &BidirectionalConn{done: make(chan struct{})}
		want := errors.New("start failed")
		_, err := c.dialEarly(context.Background(), M.Socksaddr{},
			func(StreamEngine, context.Context, logger.ContextLogger, bool, bool) *BidirectionalConn { return conn },
			func(conn *BidirectionalConn, _, _ string, _ map[string]string, _ int, _ bool) error {
				if conn.onTerminate == nil {
					t.Fatal("Start preceded terminal ownership")
				}
				close(conn.done)
				conn.onTerminate()
				if fail {
					return want
				}
				return nil
			})
		if fail && err != want || !fail && err != nil {
			t.Fatalf("start error = %v", err)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNaiveControlOperationJoinsBeforeDestruction(t *testing.T) {
	c := lifecycleTestClient(clientStateRunning)
	c.engines = []Engine{{}}
	entered, release, controlDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		c.closeAllConnections(func(Engine) { close(entered); <-release })
		close(controlDone)
	}()
	awaitLifecycle(t, entered)
	c.lifecycle.Lock()
	c.state.Store(uint32(clientStateClosing))
	c.lifecycle.Unlock()
	c.closeAllConnections(func(Engine) { t.Error("control passed sealed gate") })
	joined := make(chan struct{})
	go func() { c.pending.Wait(); close(joined) }()
	select {
	case <-joined:
		t.Fatal("control use was not retained")
	default:
	}
	close(release)
	awaitLifecycle(t, controlDone)
	awaitLifecycle(t, joined)
}
