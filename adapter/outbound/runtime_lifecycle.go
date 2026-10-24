package outbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/logger"
)

var ErrRuntimeClosePending = errors.New("runtime connection close is still in progress")

// RegisterRuntimeCleanup preserves standalone construction, but registers an
// acquired resource immediately when its existing construction owner is present.
// The caller holds the owner's construction reservation until this returns.
func RegisterRuntimeCleanup(ctx context.Context, cleanup func() error) (bool, error) {
	if !adapter.HasConstructionScope(ctx) {
		return false, nil
	}
	var started atomic.Bool
	err := adapter.DeferConstructionCleanup(ctx, func() error {
		started.Store(true)
		return cleanup()
	})
	if err != nil {
		return true, err
	}
	if err = ctx.Err(); err != nil {
		return true, err
	}
	if err = adapter.ConstructionScopeErr(ctx); err != nil {
		return true, err
	}
	if started.Load() {
		return true, os.ErrClosed
	}
	return true, nil
}

// RuntimeCloseWaiter is implemented by the actual component owning its worker
// slots. Close alone is not evidence that those workers or native callbacks left.
// It must seal scheduling, interrupt owned carriers, then join actual completion.
type RuntimeCloseWaiter interface{ RuntimeCloseAndWait() error }

// CloseRuntimeResource keeps an unknown component's exact dependency closure
// charged. The diagnostic intentionally does not wrap canceled/closed errors:
// Scope filters those, which would incorrectly certify resource completion.
func CloseRuntimeResource(ctx context.Context, name string, closer interface{ Close() error }) error {
	if _, bound := adapter.RuntimeResourceSourceFromContext(ctx); !bound {
		return closer.Close()
	}
	if waiter, ok := closer.(RuntimeCloseWaiter); ok {
		if err := waiter.RuntimeCloseAndWait(); err != nil {
			return fmt.Errorf("%s runtime cleanup incomplete: %v", name, err)
		}
		return nil
	}
	err := closer.Close()
	return fmt.Errorf("%s runtime worker completion is unproven after close (%v)", name, err)
}

func runtimeBound(ctx context.Context, source adapter.RuntimeResourceSource) bool {
	_, graph := adapter.RuntimeLeaseFromContext(ctx)
	return source != nil || graph
}

// DialRuntimeConn admits the actual receiving resource BEFORE a dial/handshake.
// A successful returned carrier consumes this reservation. Internal pool
// transports must not use this for idle owned sessions: those are joined by
// their component's sole close worker, without external self-leases.
func DialRuntimeConn(ctx context.Context, source adapter.RuntimeResourceSource, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	if !runtimeBound(ctx, source) {
		return dial(ctx)
	}
	internal, err := ValidateRuntimeOwnedSession(ctx, source)
	if err != nil {
		return nil, err
	}
	owned, release, err := adapter.AcquireRuntimeOperation(ctx, source)
	if err != nil {
		return nil, err
	}
	// Deliberately no unconditional defer: a panic provides no evidence that
	// asynchronous work started by the call has ended.
	conn, err := dial(owned)
	if err != nil {
		if conn != nil {
			closeErr := closeRuntimeCarrier(func() error { return closeRuntimeOwnedCarrier(conn) })
			if closeErr != nil {
				return nil, errors.Join(err, closeErr)
			}
		}
		if !runtimeCleanupIncomplete(err) {
			release()
		}
		return nil, err
	}
	if conn == nil {
		release()
		return nil, errors.New("runtime dial returned no connection")
	}
	if internal {
		release()
		return conn, nil
	}
	return WrapRuntimeConn(owned, release, conn), nil
}

func ListenRuntimePacket(ctx context.Context, source adapter.RuntimeResourceSource, listen func(context.Context) (net.PacketConn, error)) (net.PacketConn, error) {
	if !runtimeBound(ctx, source) {
		return listen(ctx)
	}
	internal, err := ValidateRuntimeOwnedSession(ctx, source)
	if err != nil {
		return nil, err
	}
	owned, release, err := adapter.AcquireRuntimeOperation(ctx, source)
	if err != nil {
		return nil, err
	}
	conn, err := listen(owned)
	if err != nil {
		if conn != nil {
			closeErr := closeRuntimeCarrier(func() error { return closeRuntimeOwnedCarrier(conn) })
			if closeErr != nil {
				return nil, errors.Join(err, closeErr)
			}
		}
		if !runtimeCleanupIncomplete(err) {
			release()
		}
		return nil, err
	}
	if conn == nil {
		release()
		return nil, errors.New("runtime listen returned no packet connection")
	}
	if internal {
		release()
		return conn, nil
	}
	return WrapRuntimePacketConn(owned, release, conn), nil
}

// WrapRuntimeConn consumes the caller's already-owned operation and release.
// It never publishes the underlying connection through Upstream or SyscallConn:
// bypassing these methods would also bypass continuation ownership.
func WrapRuntimeConn(ctx context.Context, release func(), conn net.Conn) net.Conn {
	state := &runtimeCarrier{ctx: ctx, release: release, closeSignal: make(chan struct{})}
	wrapped := &runtimeConn{conn: conn, state: state, local: conn.LocalAddr(), remote: conn.RemoteAddr()}
	if packet, ok := conn.(net.PacketConn); ok {
		return &runtimeConnPacket{runtimeConn: wrapped, packet: packet}
	}
	return wrapped
}

func WrapRuntimePacketConn(ctx context.Context, release func(), conn net.PacketConn) net.PacketConn {
	return &runtimePacketConn{conn: conn, local: conn.LocalAddr(), state: &runtimeCarrier{ctx: ctx, release: release, closeSignal: make(chan struct{})}}
}

// This is admission state, not another resource reference counter. Every call
// retains the existing runtimegraph leases under its own owner mutex via Fork.
// No lock is held while performing network I/O, user callbacks, Close or joins.
type runtimeCarrier struct {
	mu           sync.Mutex
	ctx          context.Context
	release      func()
	closing      bool
	closeDone    bool
	closeErr     error
	closeSignal  chan struct{}
	sealedSignal chan struct{}
	owned        bool
	ownedClose   func() error // immutable, installed before publication
	methods      sync.WaitGroup
}

func (s *runtimeCarrier) begin() (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return nil, net.ErrClosed
	}
	if s.owned {
		s.methods.Add(1)
		return s.methods.Done, nil
	}
	_, release, err := adapter.AcquireRuntimeOperation(s.ctx, nil)
	return release, err
}

type runtimeCleanupError struct{ message string }

func (e *runtimeCleanupError) Error() string                { return e.message }
func (*runtimeCleanupError) RuntimeCleanupIncomplete() bool { return true }

func runtimeCleanupIncomplete(err error) bool {
	var marker interface{ RuntimeCleanupIncomplete() bool }
	return errors.As(err, &marker) && marker.RuntimeCleanupIncomplete()
}

func closeRuntimeCarrier(closeFn func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = &runtimeCleanupError{"runtime carrier close panicked; completion unknown"}
		}
	}()
	if err = closeFn(); err != nil {
		return &runtimeCleanupError{fmt.Sprintf("runtime carrier close failed; completion unknown: %v", err)}
	}
	return nil
}

func (s *runtimeCarrier) close(closeFn func() error) error {
	s.mu.Lock()
	if s.closing {
		err := s.closeErr
		if !s.closeDone {
			err = ErrRuntimeClosePending
		}
		s.mu.Unlock()
		return err
	}
	s.closing = true
	if s.sealedSignal != nil {
		close(s.sealedSignal)
	}
	s.mu.Unlock()
	if s.owned {
		// Public Close only requests the single fixed cleanup. Its caller may
		// itself hold an admitted method; joining here would deadlock that tail.
		go s.finishClose(s.ownedClose)
		return ErrRuntimeClosePending
	}
	return s.finishClose(closeFn)
}

func (s *runtimeCarrier) finishClose(closeFn func() error) error {
	err := closeRuntimeCarrier(closeFn)
	s.mu.Lock()
	s.closeErr, s.closeDone = err, true
	close(s.closeSignal)
	release := s.release
	if err == nil {
		s.release = nil
	}
	s.mu.Unlock()
	if err == nil && release != nil {
		release()
	}
	return err
}

type runtimeConn struct {
	conn          net.Conn
	state         *runtimeCarrier
	local, remote net.Addr
}

func (c *runtimeConn) Read(p []byte) (int, error) {
	release, err := c.state.begin()
	if err != nil {
		return 0, err
	}
	n, err := c.conn.Read(p)
	release()
	return n, err
}

func (c *runtimeConn) Write(p []byte) (int, error) {
	release, err := c.state.begin()
	if err != nil {
		return 0, err
	}
	n, err := c.conn.Write(p)
	release()
	return n, err
}

func (c *runtimeConn) Close() error {
	return c.state.close(func() error { return closeRuntimeOwnedCarrier(c.conn) })
}

func (c *runtimeConn) LocalAddr() net.Addr {
	release, err := c.state.begin()
	if err != nil {
		return c.local
	}
	value := c.conn.LocalAddr()
	release()
	return value
}

func (c *runtimeConn) RemoteAddr() net.Addr {
	release, err := c.state.begin()
	if err != nil {
		return c.remote
	}
	value := c.conn.RemoteAddr()
	release()
	return value
}

func (c *runtimeConn) SetDeadline(t time.Time) error {
	release, err := c.state.begin()
	if err != nil {
		return err
	}
	err = c.conn.SetDeadline(t)
	release()
	return err
}

func (c *runtimeConn) SetReadDeadline(t time.Time) error {
	release, err := c.state.begin()
	if err != nil {
		return err
	}
	err = c.conn.SetReadDeadline(t)
	release()
	return err
}

func (c *runtimeConn) SetWriteDeadline(t time.Time) error {
	release, err := c.state.begin()
	if err != nil {
		return err
	}
	err = c.conn.SetWriteDeadline(t)
	release()
	return err
}

func (c *runtimeConn) CloseRead() error {
	release, err := c.state.begin()
	if err != nil {
		return err
	}
	if closer, ok := c.conn.(interface{ CloseRead() error }); ok {
		err = closer.CloseRead()
	} else {
		err = os.ErrInvalid
	}
	release()
	return err
}

func (c *runtimeConn) CloseWrite() error {
	release, err := c.state.begin()
	if err != nil {
		return err
	}
	if closer, ok := c.conn.(interface{ CloseWrite() error }); ok {
		err = closer.CloseWrite()
	} else {
		err = os.ErrInvalid
	}
	release()
	return err
}

type runtimeConnPacket struct {
	*runtimeConn
	packet net.PacketConn
}

func (c *runtimeConnPacket) ReadFrom(p []byte) (int, net.Addr, error) {
	release, err := c.state.begin()
	if err != nil {
		return 0, nil, err
	}
	n, addr, err := c.packet.ReadFrom(p)
	release()
	return n, addr, err
}

func (c *runtimeConnPacket) WriteTo(p []byte, addr net.Addr) (int, error) {
	release, err := c.state.begin()
	if err != nil {
		return 0, err
	}
	n, err := c.packet.WriteTo(p, addr)
	release()
	return n, err
}

type runtimePacketConn struct {
	conn  net.PacketConn
	state *runtimeCarrier
	local net.Addr
}

func (c *runtimePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	release, err := c.state.begin()
	if err != nil {
		return 0, nil, err
	}
	n, addr, err := c.conn.ReadFrom(p)
	release()
	return n, addr, err
}

func (c *runtimePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	release, err := c.state.begin()
	if err != nil {
		return 0, err
	}
	n, err := c.conn.WriteTo(p, addr)
	release()
	return n, err
}

func (c *runtimePacketConn) Close() error {
	return c.state.close(func() error { return closeRuntimeOwnedCarrier(c.conn) })
}

func (c *runtimePacketConn) LocalAddr() net.Addr {
	release, err := c.state.begin()
	if err != nil {
		return c.local
	}
	value := c.conn.LocalAddr()
	release()
	return value
}

func (c *runtimePacketConn) SetDeadline(t time.Time) error {
	release, err := c.state.begin()
	if err != nil {
		return err
	}
	err = c.conn.SetDeadline(t)
	release()
	return err
}

func (c *runtimePacketConn) SetReadDeadline(t time.Time) error {
	release, err := c.state.begin()
	if err != nil {
		return err
	}
	err = c.conn.SetReadDeadline(t)
	release()
	return err
}

func (c *runtimePacketConn) SetWriteDeadline(t time.Time) error {
	release, err := c.state.begin()
	if err != nil {
		return err
	}
	err = c.conn.SetWriteDeadline(t)
	release()
	return err
}

// OnceRuntimeCleanup preserves the first outcome, including panic uncertainty,
// when constructor rollback and the resource-owned scope both request cleanup.
// It is cleanup idempotence only; ownership remains with the existing Scope.
func OnceRuntimeCleanup(cleanup func() error) func() error {
	var once sync.Once
	var result error
	return func() error {
		once.Do(func() {
			defer func() {
				if recover() != nil {
					result = errors.New("runtime resource cleanup panicked; completion unknown")
				}
			}()
			result = cleanup()
		})
		return result
	}
}

// An owned-session marker is a borrowed, exact-resource capability. Only a
// synchronous call made while the enclosing pool owns a creation slot may use
// it. That slot must survive fence registration/publication or late-result
// cleanup. It must never be copied into an escaping worker without retaining
// its existing runtime operation and reserving the enclosing pool's slot first.
type (
	runtimeOwnedSessionKey struct{}
	runtimeOwnedSession    struct{ owner adapter.RuntimeResourceID }
)

func ContextForRuntimeOwnedSession(ctx context.Context, owner adapter.RuntimeResourceSource) (context.Context, error) {
	if owner == nil {
		return nil, errors.New("owned session has no constructor-bound owner")
	}
	lease, ok := adapter.RuntimeResourceLeaseFromContext(ctx, owner.ID())
	if !ok {
		return nil, errors.New("owned session requires its admitted owner continuation")
	}
	proof, err := lease.Fork()
	if err != nil {
		return nil, err
	}
	proof.Release()
	return context.WithValue(ctx, runtimeOwnedSessionKey{}, runtimeOwnedSession{owner: owner.ID()}), nil
}

func ValidateRuntimeOwnedSession(ctx context.Context, receiver adapter.RuntimeResourceSource) (bool, error) {
	marker, marked := ctx.Value(runtimeOwnedSessionKey{}).(runtimeOwnedSession)
	if !marked {
		return false, nil
	}
	if receiver == nil {
		return false, errors.New("owned session receiver is not resource-bound")
	}
	lease, ok := adapter.RuntimeResourceLeaseFromContext(ctx, marker.owner)
	if !ok {
		return false, errors.New("owned session lost its owner continuation")
	}
	proof, err := lease.Fork()
	if err != nil {
		return false, err
	}
	defer proof.Release()
	if receiver.ID() == marker.owner {
		return true, nil
	}
	closure, ok := proof.(adapter.RuntimeResourceContinuation)
	if !ok {
		return false, errors.New("owned session has no captured dependency closure")
	}
	dependency, err := closure.RetainResource(receiver.ID())
	if err != nil {
		return false, err
	}
	if dependency == nil {
		return false, errors.New("owned session receiver is outside its captured dependency closure")
	}
	dependency.Release()
	return true, nil
}

// RuntimeIOFence counts owned method invocations, not graph/resource leases.
// Once sealed, detached protocol workers can only observe cached addresses or
// closed errors; they cannot access the underlying retired dependency again.
// Acquire also guards protocol-specific methods (e.g. TLS ConnectionState).
// The caller must retain this fence in its existing pool owner before exposing
// its connection, and join it before releasing that owner's dependency edges.
type RuntimeIOFence struct {
	state   *runtimeCarrier
	closeFn func() error
}

func (f *RuntimeIOFence) Acquire() (func(), error) { return f.state.begin() }
func (f *RuntimeIOFence) Close() error             { return f.state.close(f.closeFn) }
func (f *RuntimeIOFence) RuntimeCloseAndWait() error {
	_ = f.Close()
	return f.Wait()
}

// Wait does not initiate close. It joins the actual close result and every
// previously admitted method; an idle owned observer cannot prevent Close.
func (f *RuntimeIOFence) Wait() error {
	<-f.state.closeSignal
	f.state.methods.Wait()
	f.state.mu.Lock()
	err := f.state.closeErr
	f.state.mu.Unlock()
	return err
}

// Only these exact private carriers carry this completion contract. A nested
// external carrier can also already be closing; treating its pending request
// as a final error would permanently poison the outer carrier's result.
func runtimeCarrierState(conn io.Closer) *runtimeCarrier {
	switch c := conn.(type) {
	case *runtimeConn:
		return c.state
	case *runtimeConnPacket:
		return c.state
	case *runtimePacketConn:
		return c.state
	default:
		return nil
	}
}

func closeRuntimeOwnedCarrier(conn interface{ Close() error }) error {
	wait, known := RuntimeConnectionCloseWaiter(conn)
	if known {
		return wait()
	}
	return conn.Close()
}

// RuntimeConnectionCloseWaiter captures only the exact private carrier's fixed
// close barrier, never its raw transport. A final flow controller may retain it
// BEFORE adding known wrappers with their own cleanup (e.g. TLS spoof or UDP
// canceler). It must still close the outer wrapper and preserve any other error.
// Call from an independent final-close worker, not a callback holding Acquire.
func RuntimeConnectionCloseWaiter(conn io.Closer) (func() error, bool) {
	state := runtimeCarrierState(conn)
	if state == nil {
		return nil, false
	}
	return func() error {
		_ = conn.Close()
		<-state.closeSignal
		state.methods.Wait()
		state.mu.Lock()
		err := state.closeErr
		state.mu.Unlock()
		return err
	}, true
}

// The listener captures this completion at the actual private-carrier creation
// boundary, before protocol wrappers obscure it. It conveys no I/O access or
// admission authority. Only final Box flow shutdown consumes the waiter.
type runtimeInboundCloseContextKey struct{}
type runtimeInboundCloseTarget struct {
	state *runtimeCarrier
	wait  func() error
}

func ContextWithRuntimeInboundClose(ctx context.Context, conn io.Closer) context.Context {
	wait, known := RuntimeConnectionCloseWaiter(conn)
	if !known {
		return ctx
	}
	state := runtimeCarrierState(conn)
	previous, _ := ctx.Value(runtimeInboundCloseContextKey{}).([]runtimeInboundCloseTarget)
	for _, target := range previous {
		if target.state == state {
			return ctx
		}
	}
	// Immutable captured construction chain; never overwrite a listener's
	// accepted carrier with a later protocol-private carrier.
	targets := append([]runtimeInboundCloseTarget(nil), previous...)
	targets = append(targets, runtimeInboundCloseTarget{state, wait})
	return context.WithValue(ctx, runtimeInboundCloseContextKey{}, targets)
}

func RuntimeInboundCloseFromContext(ctx context.Context) (func() error, bool) {
	targets, ok := ctx.Value(runtimeInboundCloseContextKey{}).([]runtimeInboundCloseTarget)
	if !ok || len(targets) == 0 {
		return nil, false
	}
	return func() error {
		// One request per captured private construction object; all children
		// join before this counted final-close worker can complete. No raw I/O
		// or resource admission is granted by this control-only context value.
		results := make(chan error, len(targets))
		for _, target := range targets {
			go func(wait func() error) { results <- waitRuntimeCloseRecovering(wait) }(target.wait)
		}
		var result error
		for range targets {
			result = errors.Join(result, <-results)
		}
		return result
	}, true
}

func waitRuntimeCloseRecovering(wait func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("runtime private connection close wait panicked; completion unknown")
		}
	}()
	return wait()
}

func WrapRuntimeOwnedConn(conn net.Conn) (net.Conn, *RuntimeIOFence) {
	state := &runtimeCarrier{owned: true, closeSignal: make(chan struct{}), ownedClose: func() error { return closeRuntimeOwnedCarrier(conn) }}
	wrapped := &runtimeConn{conn: conn, state: state, local: conn.LocalAddr(), remote: conn.RemoteAddr()}
	fence := &RuntimeIOFence{state: state, closeFn: conn.Close}
	if packet, ok := conn.(net.PacketConn); ok {
		return &runtimeConnPacket{runtimeConn: wrapped, packet: packet}, fence
	}
	return wrapped, fence
}

func WrapRuntimeOwnedPacketConn(conn net.PacketConn) (net.PacketConn, *RuntimeIOFence) {
	state := &runtimeCarrier{owned: true, closeSignal: make(chan struct{}), ownedClose: func() error { return closeRuntimeOwnedCarrier(conn) }}
	wrapped := &runtimePacketConn{conn: conn, state: state, local: conn.LocalAddr()}
	return wrapped, &RuntimeIOFence{state: state, closeFn: conn.Close}
}

// NewRuntimeIOFence shares the same admission/terminal boundary for non-network
// resources such as request bodies and callbacks. closeFn runs once outside the
// guard. RuntimeCloseAndWait must not be called by a callback holding Acquire;
// that callback may request Close and let the external owner join it afterward.
func NewRuntimeIOFence(closeFn func() error) *RuntimeIOFence {
	if closeFn == nil {
		closeFn = func() error { return nil }
	}
	return &RuntimeIOFence{state: &runtimeCarrier{owned: true, closeSignal: make(chan struct{}), ownedClose: closeFn}, closeFn: closeFn}
}

// RuntimeIOFenceSet is mechanical owned-work accounting. It has no runtime
// source, graph lease or authorization capability. A concrete pool supplies its
// own cancellation and exact-ID authorization, and calls Stop before its
// terminal close, then Wait before releasing its dependency edges.
type RuntimeIOFenceSet struct {
	mu      sync.Mutex
	sealed  bool
	pending sync.WaitGroup
	fences  map[*RuntimeIOFence]struct{}
	err     error
}

type RuntimeIOCreation struct {
	set      *RuntimeIOFenceSet
	finished bool
}

func NewRuntimeIOFenceSet() *RuntimeIOFenceSet {
	return &RuntimeIOFenceSet{fences: make(map[*RuntimeIOFence]struct{})}
}

func (s *RuntimeIOFenceSet) Begin() (*RuntimeIOCreation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sealed {
		return nil, net.ErrClosed
	}
	s.pending.Add(1)
	return &RuntimeIOCreation{set: s}, nil
}

// Done must be deferred immediately after Begin, before invoking foreign code.
// A panic resolves the accounting slot but leaves non-filterable uncertainty
// attached to the owner; it never certifies completion or swallows the panic.
func (c *RuntimeIOCreation) Done() {
	failure := recover()
	c.set.mu.Lock()
	if failure != nil {
		c.set.err = errors.Join(c.set.err, errors.New("owned creation panicked; completion unknown"))
	}
	finished := c.finished
	c.finished = true
	c.set.mu.Unlock()
	if !finished {
		c.set.pending.Done()
	}
	if failure != nil {
		panic(failure)
	}
}

func (s *RuntimeIOFenceSet) Record(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	s.err = errors.Join(s.err, fmt.Errorf("owned boundary completion unknown: %v", err))
	s.mu.Unlock()
}

// Register transfers the carrier before the creation reservation is released.
// A late result is closed and joined outside the set mutex. Its error remains
// charged to this exact concrete owner even if a caller ignores the result.
func (c *RuntimeIOCreation) Register(fence *RuntimeIOFence) error {
	s := c.set
	s.mu.Lock()
	if s.sealed || c.finished {
		s.mu.Unlock()
		err := fence.RuntimeCloseAndWait()
		s.Record(err)
		if err != nil {
			return err
		}
		return net.ErrClosed
	}
	s.fences[fence] = struct{}{}
	s.pending.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.pending.Done()
		err := fence.Wait()
		s.mu.Lock()
		if err == nil {
			delete(s.fences, fence)
		} else {
			s.err = errors.Join(s.err, fmt.Errorf("owned carrier completion unknown: %v", err))
		}
		s.mu.Unlock()
	}()
	return nil
}

// Stop seals registration and starts each sole close independently. A blocked
// native close cannot prevent another carrier from receiving its stop signal.
// Wait still waits for every actual close and admitted method; it has no timeout
// which could falsely release dependencies from a non-returning close.
func (s *RuntimeIOFenceSet) Stop() {
	s.mu.Lock()
	if s.sealed {
		s.mu.Unlock()
		return
	}
	s.sealed = true
	fences := make([]*RuntimeIOFence, 0, len(s.fences))
	for fence := range s.fences {
		fences = append(fences, fence)
	}
	s.mu.Unlock()
	for _, fence := range fences {
		go func(f *RuntimeIOFence) { _ = f.Close() }(fence)
	}
}

func (s *RuntimeIOFenceSet) Wait() error {
	s.pending.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *RuntimeIOFenceSet) RuntimeCloseAndWait() error { s.Stop(); return s.Wait() }

// CloseRuntimeCreation rolls back a partly built carrier while keeping the
// exact admitted dependency closure on any uncertain close result. It is used
// when a protocol handshake failed before it could return a typed carrier.
func CloseRuntimeCreation(ctx context.Context, source adapter.RuntimeResourceSource, closeFn func() error) error {
	if !runtimeBound(ctx, source) {
		return closeFn()
	}
	_, release, err := adapter.AcquireRuntimeOperation(ctx, source)
	if err != nil {
		return &runtimeCleanupError{fmt.Sprintf("failed carrier cleanup could not retain its owner: %v", err)}
	}
	err = closeRuntimeCarrier(closeFn)
	if err == nil {
		release()
	}
	return err
}

// RuntimeSyscallConn preserves the descriptor callback contract without an
// Upstream escape. The returned object admits each Control/Read/Write against
// every enclosing runtime carrier before invoking the original RawConn.
func RuntimeSyscallConn(conn any) (syscall.RawConn, error) {
	if guarded, ok := conn.(interface {
		runtimeSyscallConn() (syscall.RawConn, error)
	}); ok {
		return guarded.runtimeSyscallConn()
	}
	if native, ok := conn.(syscall.Conn); ok {
		return native.SyscallConn()
	}
	return nil, os.ErrInvalid
}

// Only an admitted outer carrier calls this traversal. Legacy protocol
// wrappers may expose Upstream internally; the raw connection is never returned
// and every descriptor callback remains enclosed by the outer carrier fence.
// Find another private carrier first so traversing a protocol wrapper cannot
// skip an inner runtime boundary.
func runtimeCapturedSyscallConn(conn any) (syscall.RawConn, error) {
	if guarded, ok := common.Cast[interface {
		runtimeSyscallConn() (syscall.RawConn, error)
	}](conn); ok {
		return guarded.runtimeSyscallConn()
	}
	if native, ok := common.Cast[syscall.Conn](conn); ok {
		return native.SyscallConn()
	}
	return nil, os.ErrInvalid
}

func (c *runtimeConn) runtimeSyscallConn() (syscall.RawConn, error) {
	release, err := c.state.begin()
	if err != nil {
		return nil, err
	}
	raw, err := runtimeCapturedSyscallConn(c.conn)
	release()
	if err != nil {
		return nil, err
	}
	return &runtimeRawConn{raw: raw, state: c.state}, nil
}

type runtimeRawConn struct {
	raw   syscall.RawConn
	state *runtimeCarrier
}

func (c *runtimeRawConn) Control(callback func(uintptr)) error {
	release, err := c.state.begin()
	if err != nil {
		return err
	}
	err = c.raw.Control(callback)
	release()
	return err
}

func (c *runtimeRawConn) Read(callback func(uintptr) bool) error {
	release, err := c.state.begin()
	if err != nil {
		return err
	}
	err = c.raw.Read(callback)
	release()
	return err
}

func (c *runtimeRawConn) Write(callback func(uintptr) bool) error {
	release, err := c.state.begin()
	if err != nil {
		return err
	}
	err = c.raw.Write(callback)
	release()
	return err
}

// RuntimeTCPControlConn is the narrow TCP contract needed by TLS fragmentation.
// It exposes neither *net.TCPConn nor a replacable reader/writer bypass.
type (
	RuntimeTCPControlConn interface {
		net.Conn
		syscall.Conn
		SetNoDelay(bool) error
	}
	runtimeTCPControl struct{ net.Conn }
)

func (c *runtimeTCPControl) SyscallConn() (syscall.RawConn, error) { return RuntimeSyscallConn(c.Conn) }

func (c *runtimeTCPControl) SetNoDelay(value bool) error { return runtimeSetNoDelay(c.Conn, value) }

func RuntimeTCPControl(conn net.Conn) (RuntimeTCPControlConn, error) {
	if !runtimeHasNoDelay(conn) {
		return nil, os.ErrInvalid
	}
	if _, err := RuntimeSyscallConn(conn); err != nil {
		return nil, err
	}
	return &runtimeTCPControl{Conn: conn}, nil
}

func runtimeHasNoDelay(conn net.Conn) bool {
	if guarded, ok := conn.(interface{ runtimeHasNoDelay() bool }); ok {
		return guarded.runtimeHasNoDelay()
	}
	_, ok := conn.(interface{ SetNoDelay(bool) error })
	return ok
}

func (c *runtimeConn) runtimeHasNoDelay() bool {
	release, err := c.state.begin()
	if err != nil {
		return false
	}
	defer release()
	if guarded, ok := common.Cast[interface{ runtimeHasNoDelay() bool }](c.conn); ok {
		return guarded.runtimeHasNoDelay()
	}
	_, ok := common.Cast[interface{ SetNoDelay(bool) error }](c.conn)
	return ok
}

func runtimeSetNoDelay(conn net.Conn, value bool) error {
	if guarded, ok := conn.(interface{ runtimeSetNoDelay(bool) error }); ok {
		return guarded.runtimeSetNoDelay(value)
	}
	if control, ok := conn.(interface{ SetNoDelay(bool) error }); ok {
		return control.SetNoDelay(value)
	}
	return os.ErrInvalid
}

func (c *runtimeConn) runtimeSetNoDelay(value bool) error {
	release, err := c.state.begin()
	if err != nil {
		return err
	}
	// Legacy wrapper traversal is allowed only while this carrier is admitted.
	// Find an inner private fence first instead of skipping its closing boundary.
	if guarded, ok := common.Cast[interface{ runtimeSetNoDelay(bool) error }](c.conn); ok {
		err = guarded.runtimeSetNoDelay(value)
	} else if control, ok := common.Cast[interface{ SetNoDelay(bool) error }](c.conn); ok {
		err = control.SetNoDelay(value)
	} else {
		err = os.ErrInvalid
	}
	release()
	return err
}

func (c *runtimePacketConn) runtimeSyscallConn() (syscall.RawConn, error) {
	release, err := c.state.begin()
	if err != nil {
		return nil, err
	}
	raw, err := runtimeCapturedSyscallConn(c.conn)
	release()
	if err != nil {
		return nil, err
	}
	return &runtimeRawConn{raw: raw, state: c.state}, nil
}

// RuntimeIOActivityFuncs preserves explicit accounting when a transport uses
// guarded descriptor callbacks instead of Read/Write. Copied accounting hooks
// cannot reach their original provider after the enclosing carrier is sealed.
func RuntimeIOActivityFuncs(conn any) (func(int), func(int)) {
	if guarded, ok := conn.(interface{ runtimeIOActivityFuncs() (func(int), func(int)) }); ok {
		return guarded.runtimeIOActivityFuncs()
	}
	if accounting, ok := conn.(interface{ IOActivityFuncs() (func(int), func(int)) }); ok {
		return accounting.IOActivityFuncs()
	}
	return nil, nil
}

func guardedRuntimeActivity(state *runtimeCarrier, callback func(int)) func(int) {
	if callback == nil {
		return nil
	}
	return func(size int) {
		release, err := state.begin()
		if err != nil {
			return
		}
		callback(size)
		release()
	}
}

func (c *runtimeConn) runtimeIOActivityFuncs() (func(int), func(int)) {
	release, err := c.state.begin()
	if err != nil {
		return nil, nil
	}
	read, write := RuntimeIOActivityFuncs(c.conn)
	release()
	return guardedRuntimeActivity(c.state, read), guardedRuntimeActivity(c.state, write)
}

func (c *runtimePacketConn) runtimeIOActivityFuncs() (func(int), func(int)) {
	release, err := c.state.begin()
	if err != nil {
		return nil, nil
	}
	read, write := RuntimeIOActivityFuncs(c.conn)
	release()
	return guardedRuntimeActivity(c.state, read), guardedRuntimeActivity(c.state, write)
}

// RegisterRuntimeOwnedFence binds internal physical creation to this exact
// constructor-owned boundary. The returned admission never retains a graph or
// increments the owner's external resource references. Register the owner's
// aggregate cancellation/stop cleanup AFTER this registration, so reverse-order
// scope cleanup cancels work before waiting for this fence. The aggregate must
// also join this fence before its captured dependencies can be released.
func RegisterRuntimeOwnedFence(ctx context.Context, fence *RuntimeIOFence) (func(context.Context) (context.Context, func(), error), error) {
	source, bound := adapter.RuntimeResourceSourceFromContext(ctx)
	if !bound {
		return func(ctx context.Context) (context.Context, func(), error) {
			return adapter.ContextWithRuntimeOwnership(ctx, context.Background()), func() {}, nil
		}, nil
	}
	captured, ok := source.(adapter.RuntimeCapturedResourceSource)
	if !ok {
		return nil, errors.New("runtime source does not expose captured dependency ownership")
	}
	if !adapter.HasConstructionScope(ctx) {
		return nil, errors.New("owned runtime fence requires its constructor scope")
	}
	if fence == nil {
		return nil, errors.New("owned runtime fence is nil")
	}
	if _, err := RegisterRuntimeCleanup(ctx, fence.RuntimeCloseAndWait); err != nil {
		return nil, err
	}
	return func(ctx context.Context) (context.Context, func(), error) {
		release, err := fence.Acquire()
		if err != nil {
			return nil, nil, err
		}
		lease := &runtimeOwnedLease{source: captured, fence: fence, release: release}
		ctx = adapter.ContextWithRuntimeOwnership(ctx, context.Background())
		return adapter.ContextWithRuntimeResourceLease(ctx, lease), lease.Release, nil
	}, nil
}

// This capability is backed by an actually registered owner-method fence, not
// a resource reference. Its only authority is its constructor's immutable DAG.
type runtimeOwnedLease struct {
	mu       sync.Mutex
	source   adapter.RuntimeCapturedResourceSource
	fence    *RuntimeIOFence
	release  func()
	released bool
}

func (l *runtimeOwnedLease) ID() adapter.RuntimeResourceID { return l.source.ID() }
func (l *runtimeOwnedLease) Retiring() <-chan struct{} {
	state := l.fence.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.sealedSignal == nil {
		state.sealedSignal = make(chan struct{})
		if state.closing {
			close(state.sealedSignal)
		}
	}
	return state.sealedSignal
}

func (l *runtimeOwnedLease) Fork() (adapter.RuntimeResourceLease, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return nil, net.ErrClosed
	}
	release, err := l.fence.Acquire()
	if err != nil {
		return nil, err
	}
	return &runtimeOwnedLease{source: l.source, fence: l.fence, release: release}, nil
}

func (l *runtimeOwnedLease) Release() {
	l.mu.Lock()
	if l.released {
		l.mu.Unlock()
		return
	}
	l.released = true
	release := l.release
	l.mu.Unlock()
	release()
}

func (l *runtimeOwnedLease) RetainResource(id adapter.RuntimeResourceID) (adapter.RuntimeResourceLease, error) {
	if id == l.ID() {
		return l.Fork()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return nil, net.ErrClosed
	}
	return l.source.RetainCapturedResource(id)
}

// WrapRuntimeLogger isolates callbacks from library-owned idle workers. All
// methods, including context and exceptional levels, use the same owner fence.
func WrapRuntimeLogger(base logger.ContextLogger, fence *RuntimeIOFence) logger.ContextLogger {
	return &runtimeLogger{ContextLogger: base, fence: fence}
}

type runtimeLogger struct {
	logger.ContextLogger
	fence *RuntimeIOFence
}

func (l *runtimeLogger) Trace(args ...any) {
	release, err := l.fence.Acquire()
	if err != nil {
		return
	}
	l.ContextLogger.Trace(args...)
	release()
}

func (l *runtimeLogger) TraceContext(ctx context.Context, args ...any) {
	release, err := l.fence.Acquire()
	if err != nil {
		return
	}
	l.ContextLogger.TraceContext(ctx, args...)
	release()
}

func (l *runtimeLogger) Debug(args ...any) {
	release, err := l.fence.Acquire()
	if err != nil {
		return
	}
	l.ContextLogger.Debug(args...)
	release()
}

func (l *runtimeLogger) DebugContext(ctx context.Context, args ...any) {
	release, err := l.fence.Acquire()
	if err != nil {
		return
	}
	l.ContextLogger.DebugContext(ctx, args...)
	release()
}

func (l *runtimeLogger) Info(args ...any) {
	release, err := l.fence.Acquire()
	if err != nil {
		return
	}
	l.ContextLogger.Info(args...)
	release()
}

func (l *runtimeLogger) InfoContext(ctx context.Context, args ...any) {
	release, err := l.fence.Acquire()
	if err != nil {
		return
	}
	l.ContextLogger.InfoContext(ctx, args...)
	release()
}

func (l *runtimeLogger) Warn(args ...any) {
	release, err := l.fence.Acquire()
	if err != nil {
		return
	}
	l.ContextLogger.Warn(args...)
	release()
}

func (l *runtimeLogger) WarnContext(ctx context.Context, args ...any) {
	release, err := l.fence.Acquire()
	if err != nil {
		return
	}
	l.ContextLogger.WarnContext(ctx, args...)
	release()
}

func (l *runtimeLogger) Error(args ...any) {
	release, err := l.fence.Acquire()
	if err != nil {
		return
	}
	l.ContextLogger.Error(args...)
	release()
}

func (l *runtimeLogger) ErrorContext(ctx context.Context, args ...any) {
	release, err := l.fence.Acquire()
	if err != nil {
		return
	}
	l.ContextLogger.ErrorContext(ctx, args...)
	release()
}

func (l *runtimeLogger) Fatal(args ...any) {
	release, err := l.fence.Acquire()
	if err != nil {
		return
	}
	l.ContextLogger.Fatal(args...)
	release()
}

func (l *runtimeLogger) FatalContext(ctx context.Context, args ...any) {
	release, err := l.fence.Acquire()
	if err != nil {
		return
	}
	l.ContextLogger.FatalContext(ctx, args...)
	release()
}

func (l *runtimeLogger) Panic(args ...any) {
	release, err := l.fence.Acquire()
	if err != nil {
		return
	}
	l.ContextLogger.Panic(args...)
	release()
}

func (l *runtimeLogger) PanicContext(ctx context.Context, args ...any) {
	release, err := l.fence.Acquire()
	if err != nil {
		return
	}
	l.ContextLogger.PanicContext(ctx, args...)
	release()
}

// RuntimeConnContext exposes only a private carrier's already-owned lineage to
// protocol server adapters. It does not retain it: the adapter must keep conn
// alive and fork an operation before accessing graph resources.
func RuntimeConnContext(conn net.Conn) (context.Context, bool) {
	switch value := conn.(type) {
	case *runtimeConn:
		return value.state.ctx, true
	case *runtimeConnPacket:
		return value.state.ctx, true
	default:
		return nil, false
	}
}
