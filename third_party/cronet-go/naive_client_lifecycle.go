package cronet

import (
	"fmt"
	"sync"
)

// Positive WaitGroup admissions and the transition to Closing share lifecycle.
// Close waits outside the mutex. An admitted native callback may add a proxy
// worker until it returns; therefore callbacks must join before proxy workers.
func (c *NaiveClient) beginOperation() bool {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	if clientState(c.state.Load()) != clientStateRunning {
		return false
	}
	c.pending.Add(1)
	return true
}

func (c *NaiveClient) beginCallback() bool {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	state := clientState(c.state.Load())
	if state != clientStateStarting && state != clientStateRunning {
		return false
	}
	c.callbacks.Add(1)
	return true
}

// Called with one pending operation held. Close cannot begin its active-stream
// join until that pending operation has installed this terminal callback.
func (c *NaiveClient) trackConnection(conn *BidirectionalConn) {
	c.lifecycle.Lock()
	c.activeConnections.Add(1)
	c.connections[conn] = struct{}{}
	c.lifecycle.Unlock()
	var once sync.Once
	conn.setOnTerminate(func() {
		once.Do(func() {
			c.lifecycle.Lock()
			delete(c.connections, conn)
			c.lifecycle.Unlock()
			// terminate has queued native stream deletion. Native Shutdown's
			// later thread join, not this signal, proves final destruction.
			c.activeConnections.Done()
		})
	})
}

// The native Shutdown join is the completion barrier for previously queued
// stream destruction. Failure retains the engine; callers preserve the error.
func shutdownNaiveEngine(shutdown func() Result, destroy func()) error {
	if result := shutdown(); result != ResultSuccess {
		return fmt.Errorf("failed to shut down engine: %d", result)
	}
	destroy()
	return nil
}
