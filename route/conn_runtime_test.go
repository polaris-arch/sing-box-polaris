package route

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
)

type managerTestCloser struct{ closes atomic.Int32 }

func (c *managerTestCloser) Close() error { c.closes.Add(1); return nil }
func managerAwait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("manager tail barrier timed out")
	}
}

func TestConnectionManagerTerminalCloseJoinsActualOwnedTail(t *testing.T) {
	m := NewConnectionManager(log.NewNOPFactory().Logger())
	entered, release, closed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	if err := m.runtimeTask(context.Background(), func(context.Context) { close(entered); <-release }); err != nil {
		t.Fatal(err)
	}
	managerAwait(t, entered)
	// Seal explicitly at the same guard used by shutdown before observing that
	// the worker blocks terminal completion; no scheduler sleep is required.
	m.access.Lock()
	m.closed = true
	m.access.Unlock()
	go func() { _ = m.closeRuntimeTasks(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("manager returned with live logger/bookkeeping tail")
	default:
	}
	if _, err := m.reserveTask(); err == nil {
		t.Fatal("terminal manager admitted work")
	}
	unblock()
	managerAwait(t, closed)
}

func TestConnectionManagerSpliceRollbackSealsLateCallback(t *testing.T) {
	m := NewConnectionManager(log.NewNOPFactory().Logger())
	local, remote := &managerTestCloser{}, &managerTestCloser{}
	var callbacks atomic.Int32
	callback, abort, err := m.spliceClose(context.Background(), local, remote, func(error) { callbacks.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	abort()
	callback(errors.New("late callback after failed install"))
	if callbacks.Load() != 0 || local.closes.Load() != 0 || remote.closes.Load() != 0 {
		t.Fatal("aborted splice callback accessed retired state")
	}
	if err := m.closeRuntimeTasks(); err != nil {
		t.Fatal(err)
	}
}

func TestConnectionManagerReusableCloseAllDoesNotSealAdmission(t *testing.T) {
	m := NewConnectionManager(log.NewNOPFactory().Logger())
	m.CloseAll()
	done, err := m.reserveTask()
	if err != nil {
		t.Fatal(err)
	}
	done()
	if err := m.closeRuntimeTasks(); err != nil {
		t.Fatal(err)
	}
}
