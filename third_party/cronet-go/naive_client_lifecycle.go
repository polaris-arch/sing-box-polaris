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
	c.nativeOperations++
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
	c.nativeOperations++
	c.callbacks.Add(1)
	return true
}

func (c *NaiveClient) idleLocked() bool {
	return clientState(c.state.Load()) == clientStateRunning && c.nativeOperations == 0 && len(c.connections) == 0
}

// TrySealIdle prevents new operations and callbacks on an idle client. The
// owner must then call Close to join its actual native and physical workers.
func (c *NaiveClient) TrySealIdle() bool {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	if !c.idleLocked() {
		return false
	}
	c.state.Store(uint32(clientStateSealed))
	return true
}

func (c *NaiveClient) finishOperation(pending *sync.WaitGroup) {
	defer pending.Done()
	c.lifecycle.Lock()
	c.nativeOperations--
	idle := c.onIdle != nil && c.idleLocked()
	c.lifecycle.Unlock()
	if idle {
		c.onIdle()
	}
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
			defer c.activeConnections.Done()
			c.lifecycle.Lock()
			delete(c.connections, conn)
			idle := c.onIdle != nil && c.idleLocked()
			c.lifecycle.Unlock()
			// terminate has queued native stream deletion. Native Shutdown's
			// later thread join, not this signal, proves final destruction.
			if idle {
				c.onIdle()
			}
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
