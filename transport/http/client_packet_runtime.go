package http

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

)

// runtimePacketConn supplies the existing resumable packet-read deadline
// semantics with an actual producer completion barrier. The external packet
// session owns its lease; its read worker has no immortal resource self-lease.
// The generic sing deadline wrapper cannot expose that completion barrier.
type runtimePacketConn struct {
	upstream net.PacketConn
	client *Client
	release func()
	access sync.Mutex
	closed bool
	deadline time.Time
	deadlineChanged chan struct{}
	shutdown chan struct{}
	workerDone chan struct{}
	results chan *runtimePacketResult
	readAccess sync.Mutex
	pending *runtimePacketResult
	operations sync.WaitGroup
	closeOnce sync.Once
	closeErr error
}

type runtimePacketResult struct {
	data []byte
	address net.Addr
	err error
}

func (c *Client) newRuntimePacketConn(ctx context.Context, upstream net.PacketConn) (net.PacketConn, error) {
	release, err := c.reserveSession(ctx)
	if err != nil { c.recordCloseError(closeHTTPResource(upstream.Close)); return nil, err }
	conn := &runtimePacketConn{
		upstream: upstream, client: c, release: release,
		deadlineChanged: make(chan struct{}), shutdown: make(chan struct{}),
		workerDone: make(chan struct{}), results: make(chan *runtimePacketResult, 1),
	}
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		closeErr:=closeHTTPResource(upstream.Close);c.recordCloseError(closeErr)
		if closeErr==nil||httpAlreadyClosed(closeErr){release()}
		return nil, net.ErrClosed
	}
	c.packets[conn] = struct{}{}
	c.access.Unlock()
	// The session reservation and completion channel exist before publication.
	go conn.readLoop()
	return conn, nil
}

func (c *runtimePacketConn) readLoop() {
	defer close(c.workerDone)
	defer close(c.results)
	defer func() {
		if value := recover(); value != nil {
			c.client.recordCloseError(fmt.Errorf("HTTP packet read worker panic: %v", value))
		}
	}()
	for {
		data := make([]byte, 65535)
		n, address, err := c.upstream.ReadFrom(data)
		result := &runtimePacketResult{data: data[:n], address: address, err: err}
		select {
		case c.results <- result:
		case <-c.shutdown: return
		}
		if err != nil { return }
	}
}

func (c *runtimePacketConn) enter() bool {
	c.access.Lock()
	defer c.access.Unlock()
	if c.closed { return false }
	c.operations.Add(1)
	return true
}

func (c *runtimePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if !c.enter() { return 0, nil, net.ErrClosed }
	defer c.operations.Done()
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	for c.pending == nil {
		// Match the prior wrapper: already-buffered data wins over a deadline.
		select {
		case result, ok := <-c.results:
			if !ok { return 0, nil, net.ErrClosed }
			c.pending = result
			continue
		default:
		}
		c.access.Lock()
		deadline, changed, closed := c.deadline, c.deadlineChanged, c.closed
		c.access.Unlock()
		if closed { return 0, nil, net.ErrClosed }
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 { return 0, nil, os.ErrDeadlineExceeded }
			timer = time.NewTimer(remaining)
			timeout = timer.C
		}
		var err error
		select {
		case result, ok := <-c.results:
			if ok { c.pending = result } else { err = net.ErrClosed }
		case <-changed:
		case <-timeout: err = os.ErrDeadlineExceeded
		case <-c.shutdown: err = net.ErrClosed
		}
		if timer != nil { timer.Stop() }
		if err != nil { return 0, nil, err }
	}
	result := c.pending
	n := copy(p, result.data)
	result.data = result.data[n:]
	if len(result.data) > 0 { return n, result.address, nil }
	c.pending = nil
	return n, result.address, result.err
}

func (c *runtimePacketConn) WriteTo(p []byte, address net.Addr) (int, error) {
	if !c.enter() { return 0, net.ErrClosed }
	defer c.operations.Done()
	return c.upstream.WriteTo(p, address)
}

func (c *runtimePacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.access.Lock()
		c.closed = true
		close(c.shutdown)
		c.access.Unlock()
		c.closeErr = closeHTTPResource(c.upstream.Close)
		c.client.recordCloseError(c.closeErr)
		<-c.workerDone
		c.operations.Wait()
		c.client.access.Lock()
		delete(c.client.packets, c)
		c.client.access.Unlock()
		if c.closeErr==nil||httpAlreadyClosed(c.closeErr){c.release()}
	})
	return c.closeErr
}

func (c *runtimePacketConn) LocalAddr() net.Addr {
	if !c.enter() { return nil }
	defer c.operations.Done()
	return c.upstream.LocalAddr()
}

func (c *runtimePacketConn) SetReadDeadline(deadline time.Time) error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.closed { return net.ErrClosed }
	c.deadline = deadline
	close(c.deadlineChanged)
	c.deadlineChanged = make(chan struct{})
	return nil
}

func (c *runtimePacketConn) SetWriteDeadline(deadline time.Time) error {
	if !c.enter() { return net.ErrClosed }
	defer c.operations.Done()
	return c.upstream.SetWriteDeadline(deadline)
}

func (c *runtimePacketConn) SetDeadline(deadline time.Time) error {
	if err := c.SetReadDeadline(deadline); err != nil { return err }
	return c.SetWriteDeadline(deadline)
}

func (*runtimePacketConn) NeedAdditionalReadDeadline() bool { return false }
