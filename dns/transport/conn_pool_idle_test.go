package transport

import (
	"context"
	"errors"
	"testing"
)

func TestConnPoolIdleControlPreservesSharedUsers(t *testing.T) {
	closed := make(map[int]int)
	pool := NewConnPool(ConnPoolOptions[int]{Mode: ConnPoolSingle, IsAlive: func(int) bool { return true }, Close: func(conn int, _ error) { closed[conn]++ }})
	defer pool.Close()
	dial := func(context.Context) (int, error) { return 1, nil }
	first, _, err := pool.Acquire(context.Background(), dial)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := pool.Acquire(context.Background(), dial)
	if err != nil {
		t.Fatal(err)
	}
	pool.CloseIdle()
	pool.SetKeepIdleConnections(false)
	if closed[1] != 0 {
		t.Fatal("idle effect closed an active shared session")
	}
	pool.Release(first, true)
	if closed[1] != 0 {
		t.Fatal("first response interrupted another query")
	}
	pool.Release(second, true)
	if closed[1] != 1 {
		t.Fatal("final response did not drain the now-idle session")
	}
	pool.SetKeepIdleConnections(true)
	third, _, err := pool.Acquire(context.Background(), dial)
	if err != nil {
		t.Fatal(err)
	}
	pool.Release(third, true)
	if closed[1] != 1 {
		t.Fatal("re-enabled retention was not honored")
	}
	pool.CloseIdle()
	if closed[1] != 2 {
		t.Fatal("explicit idle trim did not close the retained session")
	}
}

func TestConnPoolIdleControlPreservesSharedWaiter(t *testing.T) {
	closed := 0
	pool := NewConnPool(ConnPoolOptions[int]{Mode: ConnPoolSingle, IsAlive: func(int) bool { return true }, Close: func(int, error) { closed++ }})
	defer pool.Close()
	conn, _, err := pool.Acquire(context.Background(), func(context.Context) (int, error) { return 1, nil })
	if err != nil {
		t.Fatal(err)
	}
	// A waiter that has not collected its dial result is still a user of the
	// connection's context. It must survive the current query's final release.
	pool.access.Lock()
	state := pool.state
	state.sharedWaiters++
	pool.access.Unlock()
	pool.SetKeepIdleConnections(false)
	pool.Release(conn, true)
	if closed != 0 {
		t.Fatal("idle effect cancelled an admitted waiter")
	}
	collected, _, _, retry, err := pool.collectShared(state, &connPoolConnect[int]{}, false)
	if err != nil || retry || collected != conn {
		t.Fatal("waiter lost its shared session", err)
	}
	pool.Release(collected, true)
	if closed != 1 {
		t.Fatal("session leaked after final waiter completed")
	}
}

func TestConnPoolIdleControlPreservesOrderedUsers(t *testing.T) {
	closed := make(map[int]int)
	pool := NewConnPool(ConnPoolOptions[int]{Mode: ConnPoolOrdered, IsAlive: func(int) bool { return true }, Close: func(conn int, _ error) { closed[conn]++ }})
	defer pool.Close()
	first, _, err := pool.Acquire(context.Background(), func(context.Context) (int, error) { return 1, nil })
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := pool.Acquire(context.Background(), func(context.Context) (int, error) { return 2, nil })
	if err != nil {
		t.Fatal(err)
	}
	pool.Release(first, true)
	pool.CloseIdle()
	if closed[1] != 1 || closed[2] != 0 {
		t.Fatal("ordered trim did not distinguish active and idle connections")
	}
	pool.SetKeepIdleConnections(false)
	if closed[2] != 0 {
		t.Fatal("retention policy closed an active ordered connection")
	}
	pool.Release(second, true)
	if closed[2] != 1 {
		t.Fatal("ordered connection remained idle after its final release")
	}
}

func TestConnPoolFailedWaiterReleasesIdleSession(t *testing.T) {
	closed := 0
	pool := NewConnPool(ConnPoolOptions[int]{Mode: ConnPoolSingle, IsAlive: func(int) bool { return true }, Close: func(int, error) { closed++ }})
	defer pool.Close()
	conn, _, err := pool.Acquire(context.Background(), func(context.Context) (int, error) { return 1, nil })
	if err != nil {
		t.Fatal(err)
	}
	// A waiter from an earlier failed dial can still be waking after a newer
	// dial installs a session. Releasing that last old waiter must drain it.
	pool.access.Lock()
	state := pool.state
	state.sharedWaiters++
	pool.access.Unlock()
	pool.SetKeepIdleConnections(false)
	pool.Release(conn, true)
	failure := errors.New("earlier dial failed")
	_, _, _, _, err = pool.collectShared(state, &connPoolConnect[int]{err: failure}, true)
	if !errors.Is(err, failure) || closed != 1 {
		t.Fatal("failed waiter stranded an idle session", err)
	}
}
