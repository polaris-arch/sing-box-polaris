package http

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	M "github.com/sagernet/sing/common/metadata"
)

// ErrRuntimeWorkerCompletionUnknown is deliberately not a cancellation/closed
// error. Scope must not filter it: resourceOwner retains outgoing dependencies
// on this result instead of reporting a hidden worker as completed.
var ErrRuntimeWorkerCompletionUnknown = errors.New("HTTP runtime worker completion is unknown")

type clientLifecycle struct {
	access         sync.Mutex
	source         adapter.RuntimeResourceSource
	tlsWorkers     bool
	closed         bool
	operations     map[*clientOperation]context.CancelFunc
	operationGroup sync.WaitGroup
	connections    map[*clientOwnedConn]struct{}
	packets        map[*runtimePacketConn]struct{}
	closeOnce      sync.Once
	closeErr       error
	uncertain      error
	hiddenWorkers  error
}

type clientOperation struct{ reserved byte }

// Keep unread handshake bytes in a Go-owned reader. Closing the socket never
// releases a pooled buffer concurrently with a returned connection's Read.
type clientBufferedConn struct {
	net.Conn
	reader     *bufio.Reader
	readAccess sync.Mutex
}

func (c *clientBufferedConn) Read(p []byte) (int, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	return c.reader.Read(p)
}

func newClientLifecycle(source adapter.RuntimeResourceSource, tlsWorkers bool) clientLifecycle {
	return clientLifecycle{
		source:      source,
		tlsWorkers:  tlsWorkers,
		operations:  make(map[*clientOperation]context.CancelFunc),
		connections: make(map[*clientOwnedConn]struct{}),
		packets:     make(map[*runtimePacketConn]struct{}),
	}
}

func (c *Client) isClosed() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return c.closed
}

func (c *Client) beginOperation(ctx context.Context) (context.Context, func(), error) {
	ctx, release, err := adapter.AcquireRuntimeOperation(ctx, c.source)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	operation := new(clientOperation)
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		cancel()
		release()
		return nil, nil, net.ErrClosed
	}
	c.operations[operation] = cancel
	c.operationGroup.Add(1)
	c.access.Unlock()
	return ctx, func() {
		cancel()
		c.access.Lock()
		delete(c.operations, operation)
		c.access.Unlock()
		release()
		c.operationGroup.Done()
	}, nil
}

func (c *Client) markWorkerUncertain(reason string) {
	c.access.Lock()
	if c.hiddenWorkers == nil {
		c.hiddenWorkers = errors.New(reason)
	}
	c.access.Unlock()
}

// A native Close panic is uncertainty, never successful resource completion.
// Catch each close separately so independent sockets can still be stopped.
func closeHTTPResource(cleanup func() error) (err error) {
	defer func() {
		if value := recover(); value != nil {
			err = fmt.Errorf("HTTP resource close panic: %v", value)
		}
	}()
	return cleanup()
}

// Start all independent closes before waiting for any foreign close result.
// This is a terminal local task group, not another lifetime owner.
func closeHTTPResources(cleanups ...func() error) error {
	errs := make([]error, len(cleanups))
	var workers sync.WaitGroup
	for index, cleanup := range cleanups {
		index, cleanup := index, cleanup
		workers.Add(1)
		go func() { defer workers.Done(); errs[index] = closeHTTPResource(cleanup) }()
	}
	workers.Wait()
	return errors.Join(errs...)
}

func (c *Client) recordCloseError(err error) {
	if err == nil || httpAlreadyClosed(err) {
		return
	}
	c.access.Lock()
	c.uncertain = errors.Join(c.uncertain, err)
	c.access.Unlock()
}

// A repeated net.Conn.Close may wrap net.ErrClosed in net.OpError. Ignore
// only an entirely closed error tree, never a joined cancellation/failure.
func httpAlreadyClosed(err error) bool {
	if err == net.ErrClosed || err == os.ErrClosed {
		return true
	}
	switch wrapped := err.(type) {
	case interface{ Unwrap() []error }:
		children := wrapped.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if child != nil && !httpAlreadyClosed(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return httpAlreadyClosed(wrapped.Unwrap())
	default:
		return false
	}
}

// closeOnCancel joins a started callback. stop()==false proves only that the
// callback was scheduled; its actual Close may still be using dependencies.
func joinedAfterFunc(ctx context.Context, callback func()) func() bool {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		callback()
	})
	var once sync.Once
	var stopped bool
	return func() bool {
		once.Do(func() {
			stopped = stop()
			if !stopped {
				<-done
			}
		})
		return stopped
	}
}

func (c *Client) closeOnCancel(ctx context.Context, conn net.Conn) func() bool {
	return joinedAfterFunc(ctx, func() { c.recordCloseError(closeHTTPResource(conn.Close)) })
}

func (c *Client) ownConnection(ctx context.Context, conn net.Conn) (net.Conn, error) {
	release, err := c.reserveSession(ctx)
	if err != nil {
		c.recordCloseError(closeHTTPResource(conn.Close))
		return nil, err
	}
	owned := &clientOwnedConn{Conn: conn, client: c, release: release, drained: make(chan struct{})}
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		closeErr := closeHTTPResource(conn.Close)
		c.recordCloseError(closeErr)
		if closeErr == nil || httpAlreadyClosed(closeErr) {
			release()
		}
		return nil, net.ErrClosed
	}
	c.connections[owned] = struct{}{}
	c.access.Unlock()
	return owned, nil
}

func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.access.Lock()
		c.closed = true
		cancellations := make([]context.CancelFunc, 0, len(c.operations))
		for _, cancel := range c.operations {
			cancellations = append(cancellations, cancel)
		}
		connections := make([]*clientOwnedConn, 0, len(c.connections))
		for connection := range c.connections {
			connections = append(connections, connection)
		}
		packets := make([]*runtimePacketConn, 0, len(c.packets))
		for packet := range c.packets {
			packets = append(packets, packet)
		}
		c.access.Unlock()
		// Never cancel, close, invoke a callback, or join under a pool/graph lock.
		for _, cancel := range cancellations {
			cancel()
		}
		cleanups := []func() error{c.closeHTTP2}
		for _, packet := range packets {
			cleanups = append(cleanups, packet.Close)
		}
		for _, connection := range connections {
			cleanups = append(cleanups, connection.Close)
		}
		c.recordCloseError(closeHTTPResources(cleanups...))
		// beginOperation cannot add after closed is set. A creator which returns
		// late must close its result; it cannot publish into the sealed client.
		c.operationGroup.Wait()
		if c.http3 != nil {
			if terminal, ok := c.http3.(interface{ RuntimeCloseAndWait() error }); ok {
				c.recordCloseError(closeHTTPResource(terminal.RuntimeCloseAndWait))
			} else {
				c.markWorkerUncertain("custom HTTP/3 client has no actual completion contract")
				c.recordCloseError(closeHTTPResource(c.http3.Close))
			}
		}
		c.access.Lock()
		if c.source != nil {
			c.uncertain = errors.Join(c.uncertain, c.hiddenWorkers)
		}
		if c.uncertain != nil {
			// Do not unwrap a native cancellation error: Scope filters those.
			c.closeErr = fmt.Errorf("%w: %v", ErrRuntimeWorkerCompletionUnknown, c.uncertain)
		}
		c.access.Unlock()
	})
	return c.closeErr
}

// RuntimeCloseAndWait uses the same terminal ownership path as Close. For the
// local HTTP implementations it joins dependency-facing callbacks, physical
// carriers and returned-session I/O. Foreign implementations without the typed
// terminal contract retain sticky uncertainty.
func (c *Client) RuntimeCloseAndWait() error {
	if err := c.Close(); err != nil {
		return err
	}
	c.access.Lock()
	defer c.access.Unlock()
	// A shared terminal owner may use a standalone-constructed client. It
	// still must not mistake a legacy successful Close for a native join.
	if c.hiddenWorkers != nil {
		return fmt.Errorf("%w: %v", ErrRuntimeWorkerCompletionUnknown, c.hiddenWorkers)
	}
	return nil
}

// clientOwnedConn is below capsule/deadline wrappers, so their asynchronous
// reads cannot outlive the receiver's lease. Close joins actual in-flight I/O,
// not request cancellation. No Upstream escape hatch bypasses this boundary.
type clientOwnedConn struct {
	net.Conn
	client    *Client
	release   func()
	access    sync.Mutex
	closing   bool
	active    uint64
	drained   chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func (c *clientOwnedConn) enter() error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.closing {
		return net.ErrClosed
	}
	c.active++
	return nil
}

func (c *clientOwnedConn) leave() {
	c.access.Lock()
	c.active--
	if c.closing && c.active == 0 {
		close(c.drained)
	}
	c.access.Unlock()
}

func (c *clientOwnedConn) Read(p []byte) (int, error) {
	if err := c.enter(); err != nil {
		return 0, err
	}
	defer c.leave()
	return c.Conn.Read(p)
}

func (c *clientOwnedConn) Write(p []byte) (int, error) {
	if err := c.enter(); err != nil {
		return 0, err
	}
	defer c.leave()
	return c.Conn.Write(p)
}

func (c *clientOwnedConn) Close() error {
	c.closeOnce.Do(func() {
		c.access.Lock()
		c.closing = true
		if c.active == 0 {
			close(c.drained)
		}
		c.access.Unlock()
		c.closeErr = closeHTTPResource(c.Conn.Close)
		c.client.recordCloseError(c.closeErr)
		<-c.drained
		c.client.access.Lock()
		delete(c.client.connections, c)
		c.client.access.Unlock()
		if c.closeErr == nil || httpAlreadyClosed(c.closeErr) {
			c.release()
		}
	})
	return c.closeErr
}

func (c *clientOwnedConn) CloseRead() error {
	if err := c.enter(); err != nil {
		return err
	}
	defer c.leave()
	if half, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return half.CloseRead()
	}
	return os.ErrInvalid
}

func (c *clientOwnedConn) CloseWrite() error {
	if err := c.enter(); err != nil {
		return err
	}
	defer c.leave()
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return os.ErrInvalid
}

func (c *clientOwnedConn) SetDeadline(t time.Time) error {
	if err := c.enter(); err != nil {
		return err
	}
	defer c.leave()
	return c.Conn.SetDeadline(t)
}

func (c *clientOwnedConn) SetReadDeadline(t time.Time) error {
	if err := c.enter(); err != nil {
		return err
	}
	defer c.leave()
	return c.Conn.SetReadDeadline(t)
}

func (c *clientOwnedConn) SetWriteDeadline(t time.Time) error {
	if err := c.enter(); err != nil {
		return err
	}
	defer c.leave()
	return c.Conn.SetWriteDeadline(t)
}

type datagramNetConn struct{ DatagramStream }

func (*datagramNetConn) LocalAddr() net.Addr              { return M.Socksaddr{} }
func (*datagramNetConn) RemoteAddr() net.Addr             { return M.Socksaddr{} }
func (*datagramNetConn) SetDeadline(time.Time) error      { return os.ErrInvalid }
func (*datagramNetConn) SetReadDeadline(time.Time) error  { return os.ErrInvalid }
func (*datagramNetConn) SetWriteDeadline(time.Time) error { return os.ErrInvalid }

type clientOwnedDatagramStream struct {
	*clientOwnedConn
	stream DatagramStream
}

func (c *Client) ownDatagramStream(ctx context.Context, stream DatagramStream) (DatagramStream, error) {
	owned, err := c.ownConnection(ctx, &datagramNetConn{stream})
	if err != nil {
		return nil, err
	}
	return &clientOwnedDatagramStream{clientOwnedConn: owned.(*clientOwnedConn), stream: stream}, nil
}

func (s *clientOwnedDatagramStream) SendDatagram(payload []byte) error {
	if err := s.enter(); err != nil {
		return err
	}
	defer s.leave()
	return s.stream.SendDatagram(payload)
}

func (s *clientOwnedDatagramStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if err := s.enter(); err != nil {
		return nil, err
	}
	defer s.leave()
	return s.stream.ReceiveDatagram(ctx)
}

func (c *clientOwnedConn) LocalAddr() net.Addr {
	if c.enter() != nil {
		return M.Socksaddr{}
	}
	defer c.leave()
	return c.Conn.LocalAddr()
}

func (c *clientOwnedConn) RemoteAddr() net.Addr {
	if c.enter() != nil {
		return M.Socksaddr{}
	}
	defer c.leave()
	return c.Conn.RemoteAddr()
}

func (c *Client) reserveSession(ctx context.Context) (func(), error) {
	owned, err := outbound.ValidateRuntimeOwnedSession(ctx, c.source)
	if err != nil {
		return nil, err
	}
	if owned {
		return func() {}, nil
	}
	_, release, err := adapter.AcquireRuntimeOperation(ctx, c.source)
	return release, err
}

func (c *Client) ownedDialContext(ctx context.Context) (context.Context, error) {
	if c.source == nil {
		return ctx, nil
	}
	return outbound.ContextForRuntimeOwnedSession(ctx, c.source)
}
