package hysteria2

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-quic/hysteria2/realm"
	"sync"
	"sync/atomic"
)

// clientRuntime owns every client worker, including discarded Realm offers
// and connection generations replaced by network or idle closure. It is not a
// graph lease: the embedding adapter owns its immutable dependency closure.
type clientRuntime struct {
	mu          sync.Mutex
	closed      atomic.Bool
	workers     sync.WaitGroup
	connections map[*clientQUICConnection]struct{}
	cancel      context.CancelFunc
	closeOnce   sync.Once
	closeErr    error
}

func (c *Client) initRuntime() {
	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	c.ctx, c.runtime.cancel = context.WithCancel(ctx)
	c.runtime.connections = make(map[*clientQUICConnection]struct{})
}
func (r *clientRuntime) run(task func()) bool {
	r.mu.Lock()
	if r.closed.Load() {
		r.mu.Unlock()
		return false
	}
	r.workers.Add(1)
	r.mu.Unlock()
	go func() { defer r.workers.Done(); task() }()
	return true
}
func (r *clientRuntime) register(conn *clientQUICConnection) {
	r.mu.Lock()
	conn.runtimeOwner = r
	r.connections[conn] = struct{}{}
	closed := r.closed.Load()
	r.mu.Unlock()
	if closed {
		conn.closeWithError(net.ErrClosed)
	}
}
func (c *Client) runConnectionTask(conn *clientQUICConnection, task func()) bool {
	if c.runtime.run(task) {
		return true
	}
	conn.closeWithError(net.ErrClosed)
	return false
}

// RuntimeCloseAndWait is terminal. CloseWithError remains a reusable network
// reset and must never be substituted for this terminal worker join.
func (c *Client) RuntimeCloseAndWait() error {
	c.runtime.closeOnce.Do(func() {
		c.runtime.mu.Lock()
		c.runtime.closed.Store(true)
		connections := make([]*clientQUICConnection, 0, len(c.runtime.connections))
		for conn := range c.runtime.connections {
			connections = append(connections, conn)
		}
		c.runtime.mu.Unlock()
		c.runtime.cancel()
		closers := []func() error{func() error { return c.CloseWithError(net.ErrClosed) }}
		for _, conn := range connections {
			closers = append(closers, func() error { conn.closeWithError(net.ErrClosed); conn.closeTransport(); return conn.transportErr })
		}
		_ = joinClientClosers(closers...)
		c.runtime.workers.Wait()
		// Late offers registered their transport before leaving the counted worker.
		c.runtime.mu.Lock()
		connections = connections[:0]
		for conn := range c.runtime.connections {
			connections = append(connections, conn)
		}
		c.runtime.mu.Unlock()
		for _, conn := range connections {
			conn.closeTransport()
		}
	})
	c.runtime.mu.Lock()
	defer c.runtime.mu.Unlock()
	return c.runtime.closeErr
}

// Closing a replaced session also cancels an in-flight port hop, without
// canceling the reusable client or any newer physical session.
type clientCancelableConn struct {
	net.Conn
	cancel context.CancelFunc
}

func (c *clientCancelableConn) Close() error  { c.cancel(); return c.Conn.Close() }
func (c *clientCancelableConn) Upstream() any { return c.Conn }

func (c *clientCancelableConn) IOActivityFuncs() (func(int), func(int)) {
	if accounting, ok := c.Conn.(interface{ IOActivityFuncs() (func(int), func(int)) }); ok {
		return accounting.IOActivityFuncs()
	}
	return nil, nil
}

func (r *clientRuntime) retire(conn *clientQUICConnection, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.connections, conn)
	r.closeErr = errors.Join(r.closeErr, err)
}

// Hooks replace native operations only at their actual call boundary. The
// lifecycle, cancellation, late-result disposal and joins remain production code.
type realmClientHooks struct {
	discover     func(context.Context, net.PacketConn, []netip.AddrPort) ([]netip.AddrPort, error)
	punch        func(context.Context, net.PacketConn, []netip.AddrPort, realm.PunchMetadata) (realm.PunchResult, error)
	newMapper    func(context.Context, uint16, realm.PortMappingOptions) (realmPortMapper, error)
	authenticate func(context.Context, net.PacketConn, net.Addr) (*clientQUICConnection, error)
}

type realmPortMapper interface {
	ExternalAddr() netip.AddrPort
	KeepAliveContext(context.Context) error
	Close() error
}

// Cleanup failures keep the enclosing runtime closure charged. A normal
// canceled lookup or losing punch is not itself an incomplete cleanup.
type realmCleanupError struct{ err error }

func (e *realmCleanupError) Error() string                { return e.err.Error() }
func (e *realmCleanupError) Unwrap() error                { return e.err }
func (*realmCleanupError) RuntimeCleanupIncomplete() bool { return true }
func (r *clientRuntime) recordClose(err error) error {
	if err == nil {
		return nil
	}
	var incomplete *realmCleanupError
	if !errors.As(err, &incomplete) {
		err = &realmCleanupError{err}
	}
	r.mu.Lock()
	r.closeErr = errors.Join(r.closeErr, err)
	r.mu.Unlock()
	return err
}

// Closing a family is idempotent even when cancellation, a late loser, reset
// and terminal cleanup race. Every native close error is retained by its client.
type realmOwnedPacketConn struct {
	net.PacketConn
	runtime *clientRuntime
	once    sync.Once
	err     error
}

func (c *realmOwnedPacketConn) Close() error {
	c.once.Do(func() { c.err = c.runtime.recordClose(c.PacketConn.Close()) })
	return c.err
}

func closeRealmFamilies(families []*realmFamilyConn) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	for _, family := range families {
		wg.Go(func() {
			err := family.conn.Close()
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return errors.Join(errs...)
}

// The callback must leave before its parent operation reports completion.
// Closing interrupts a native packet read; cancellation alone does not.
func realmCancelPacket(ctx context.Context, conn net.PacketConn) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(done); _ = conn.Close() })
	return func() {
		if !stop() {
			<-done
		}
	}
}

// One demand-created session owns every family and its mapper. It transfers
// intact to the authenticated carrier; no active registry lookup can rebind it.
type clientRealmSession struct {
	client       *Client
	families     []*realmFamilyConn
	mapper       realmPortMapper
	mapperCancel context.CancelFunc
	mapperDone   chan struct{}
	mapperErr    error
	once         sync.Once
	err          error
}

func (s *clientRealmSession) startMapper(mapper realmPortMapper) error {
	s.mapper = mapper
	ctx, cancel := context.WithCancel(s.client.ctx)
	s.mapperCancel = cancel
	s.mapperDone = make(chan struct{})
	if !s.client.runtime.run(func() {
		defer close(s.mapperDone)
		s.mapperErr = s.client.runtime.recordClose(mapper.KeepAliveContext(ctx))
	}) {
		cancel()
		s.mapperErr = s.client.runtime.recordClose(mapper.Close())
		close(s.mapperDone)
		return errors.Join(net.ErrClosed, s.mapperErr)
	}
	return nil
}
func (s *clientRealmSession) stopMapper() error {
	if s.mapperCancel != nil {
		s.mapperCancel()
		<-s.mapperDone
		return s.mapperErr
	}
	return nil
}
func (s *clientRealmSession) Close() error {
	s.once.Do(func() {
		if s.mapperCancel != nil {
			s.mapperCancel()
		}
		familyErr := closeRealmFamilies(s.families)
		s.err = errors.Join(familyErr, s.stopMapper())
	})
	return s.err
}

type realmSessionPacketConn struct {
	net.PacketConn
	session *clientRealmSession
}

func (c *realmSessionPacketConn) Close() error { return c.session.Close() }

func (c *Client) realmDiscover(ctx context.Context, conn net.PacketConn, servers []netip.AddrPort) ([]netip.AddrPort, error) {
	join := realmCancelPacket(ctx, conn)
	defer join()
	if c.realmHooks != nil && c.realmHooks.discover != nil {
		return c.realmHooks.discover(ctx, conn, servers)
	}
	return realm.Discover(ctx, conn, servers)
}
func (c *Client) realmPunch(ctx context.Context, conn net.PacketConn, peers []netip.AddrPort, metadata realm.PunchMetadata) (realm.PunchResult, error) {
	join := realmCancelPacket(ctx, conn)
	defer join()
	if c.realmHooks != nil && c.realmHooks.punch != nil {
		return c.realmHooks.punch(ctx, conn, peers, metadata)
	}
	return realm.Punch(ctx, conn, peers, metadata)
}

// Preserve close results on every partial handshake, including an HTTP body
// returned together with an error. The operation's caller joins all these tails.
func (c *Client) closeFailedAuthentication(raw io.Closer, transport http.RoundTripper, conn *quic.Conn, body io.ReadCloser, cause error) error {
	closers := []func() error{raw.Close}
	if body != nil {
		closers = append(closers, body.Close)
	}
	if closer, ok := transport.(io.Closer); ok {
		closers = append(closers, closer.Close)
	}
	if conn != nil {
		closers = append(closers, func() error { return conn.CloseWithError(0, "") })
	}
	return errors.Join(cause, c.runtime.recordClose(joinClientClosers(closers...)))
}

// ControlClient consumes JSON synchronously, but a body may ignore request
// cancellation. Own its close and every admitted read, including late bodies.
type realmOwnedHTTPTransport struct {
	transport http.RoundTripper
	runtime   *clientRuntime
}

func (t *realmOwnedHTTPTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.transport.RoundTrip(request)
	if response == nil {
		return nil, err
	}
	if response.Body != nil {
		response.Body = newRealmHTTPBody(request.Context(), response.Body, t.runtime)
	}
	if err != nil || request.Context().Err() != nil {
		if response.Body != nil {
			err = errors.Join(err, response.Body.Close())
		}
		return nil, errors.Join(err, request.Context().Err())
	}
	return response, nil
}

type realmHTTPBody struct {
	body       io.ReadCloser
	runtime    *clientRuntime
	mu         sync.Mutex
	closed     bool
	reads      sync.WaitGroup
	once       sync.Once
	err        error
	stop       func() bool
	stopOnce   sync.Once
	cancelDone chan struct{}
}

func newRealmHTTPBody(ctx context.Context, body io.ReadCloser, runtime *clientRuntime) *realmHTTPBody {
	b := &realmHTTPBody{body: body, runtime: runtime, cancelDone: make(chan struct{})}
	b.stop = context.AfterFunc(ctx, func() { defer close(b.cancelDone); b.closeAndWait() })
	return b
}
func (b *realmHTTPBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return 0, net.ErrClosed
	}
	b.reads.Add(1)
	b.mu.Unlock()
	defer b.reads.Done()
	return b.body.Read(p)
}
func (b *realmHTTPBody) closeAndWait() {
	b.once.Do(func() {
		b.mu.Lock()
		b.closed = true
		b.mu.Unlock()
		err := b.body.Close()
		b.reads.Wait()
		b.err = b.runtime.recordClose(err)
	})
}
func (b *realmHTTPBody) Close() error {
	b.stopOnce.Do(func() {
		if !b.stop() {
			<-b.cancelDone
		}
	})
	b.closeAndWait()
	return b.err
}

// Independent interrupts must all start before joining a foreign close. Every
// task is joined by its caller; none can become an uncounted cleanup tail.
func joinClientClosers(closers ...func() error) error {
	var wg sync.WaitGroup
	errs := make([]error, len(closers))
	for i, closeFn := range closers {
		wg.Go(func() { errs[i] = closeFn() })
	}
	wg.Wait()
	return errors.Join(errs...)
}

func linkRealmOfferCancellation(ctx context.Context, cancel context.CancelFunc) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(done); cancel() })
	var once sync.Once
	return func() {
		once.Do(func() {
			if !stop() {
				<-done
			}
		})
	}
}
