package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	E "github.com/sagernet/sing/common/exceptions"

	mDNS "github.com/miekg/dns"
)

const (
	reuseStateUnknown int32 = iota
	reuseStateProbing
	reuseStateSupported
	reuseStateUnsupported
)

const (
	reuseProbeTimeout       = 5 * time.Second
	reuseProbeRetryInterval = time.Minute
	reuseDemoteFailureLimit = 3

	reuseProbeQueryIdA uint16 = 1
	reuseProbeQueryIdB uint16 = 2
)

type queryMultiplexerOptions struct {
	context        context.Context
	dial           func(ctx context.Context) (net.Conn, error)
	write          func(conn net.Conn, message *mDNS.Msg, queryId uint16) error
	readNext       func(conn net.Conn) (*mDNS.Msg, error)
	retryReadError bool
	probeReuse     bool
}

type queryMultiplexer struct {
	options    queryMultiplexerOptions
	connection *ConnPool[*multiplexConn]

	queryAccess   sync.Mutex
	queryId       uint16
	queries       map[uint16]*pendingQuery
	workers       sync.WaitGroup
	workSealed    bool // guarded by queryAccess
	workerCtx     context.Context
	workerCancel  context.CancelFunc
	stopOnce      sync.Once
	closeDone     chan struct{}
	closeErr      error
	cleanupAccess sync.Mutex
	cleanupErr    error

	reuseState     atomic.Int32
	demoteFailures atomic.Int32
	keepIdle       atomic.Bool

	probeAccess   sync.Mutex
	probeEpoch    uint32
	lastProbeTime time.Time
	probeStopped  bool
	probeCtx      context.Context
	probeCancel   context.CancelFunc
}

type multiplexConn struct {
	net.Conn
	readEpoch atomic.Uint64
}

type queryMultiplexerReadError struct {
	cause error
}

func (e *queryMultiplexerReadError) Error() string {
	return e.cause.Error()
}

func (e *queryMultiplexerReadError) Unwrap() error {
	return e.cause
}

type pendingQuery struct {
	conn        *multiplexConn
	message     *mDNS.Msg
	readEpoch   uint64
	callback    func(response *mDNS.Msg, err error)
	stopContext func() bool
	stopConn    func() bool
	retryCtx    context.Context
}

func newQueryMultiplexer(options queryMultiplexerOptions) *queryMultiplexer {
	parent := options.context
	if parent == nil {
		parent = context.Background()
	}
	workerCtx, workerCancel := context.WithCancel(parent)
	probeCtx, probeCancel := context.WithCancel(workerCtx)
	multiplexer := &queryMultiplexer{
		workerCtx: workerCtx, workerCancel: workerCancel,
		probeCtx: probeCtx, probeCancel: probeCancel,
		closeDone: make(chan struct{}),
		options:   options,
		queries:   make(map[uint16]*pendingQuery),
		connection: NewConnPool(ConnPoolOptions[*multiplexConn]{
			Mode: ConnPoolSingle,
			IsAlive: func(conn *multiplexConn) bool {
				return conn != nil
			},
			Close: func(conn *multiplexConn, cause error) {
				conn.Close()
			},
		}),
	}
	dial := multiplexer.options.dial
	multiplexer.options.dial = func(ctx context.Context) (net.Conn, error) {
		conn, err := dial(ctx)
		if conn != nil {
			conn = multiplexer.trackClose(conn)
		}
		if runtimeDNSCleanupIncomplete(err) {
			multiplexer.recordCleanup(err)
		}
		return conn, err
	}
	multiplexer.keepIdle.Store(true)
	return multiplexer
}

func (m *queryMultiplexer) SetKeepIdleConnections(keep bool) {
	m.keepIdle.Store(keep)
	m.closeIdleConnection()
}

func (m *queryMultiplexer) CloseIdleConnections() {
	m.connection.CloseIdle()
}

func (m *queryMultiplexer) closeIdleConnection() {
	if !m.keepIdle.Load() {
		m.connection.CloseIdle()
	}
}

func (m *queryMultiplexer) Close() error {
	m.Stop()
	<-m.closeDone
	return m.closeErr
}

// Stop is a nonjoining request, safe from an owned callback. Actual cleanup
// runs separately and joins socket/dial/callback/worker completion exactly once.
func (m *queryMultiplexer) Stop() {
	m.stopOnce.Do(func() {
		m.queryAccess.Lock()
		m.workSealed = true
		m.queryAccess.Unlock()
		m.StopProbes()
		m.workerCancel()
		go func() {
			// Stop moved cleanup off the caller stack, so preserve the owner
			// boundary's panic-to-sticky-error behavior on this worker too.
			// A failed close is uncertainty, never successful worker drain.
			defer func() {
				if value := recover(); value != nil {
					m.closeErr = fmt.Errorf("DNS multiplexer close panic: %v", value)
				}
				close(m.closeDone)
			}()
			m.closeErr = m.connection.Close()
			m.workers.Wait()
			m.cleanupAccess.Lock()
			m.closeErr = errors.Join(m.closeErr, m.cleanupErr)
			m.cleanupAccess.Unlock()
		}()
	})
}

func (m *queryMultiplexer) StopProbes() {
	m.probeAccess.Lock()
	m.probeStopped = true
	m.probeAccess.Unlock()
	m.probeCancel()
}

func (m *queryMultiplexer) reserveWorker() bool {
	m.queryAccess.Lock()
	defer m.queryAccess.Unlock()
	if m.workSealed {
		return false
	}
	m.workers.Add(1)
	return true
}

func (m *queryMultiplexer) goWorker(work func()) bool {
	if !m.reserveWorker() {
		return false
	}
	go func() { defer m.workers.Done(); work() }()
	return true
}

// Callbacks reserve before AfterFunc registration. A false stop result is not
// completion: only the actual callback discharges that already-owned slot.
func (m *queryMultiplexer) afterFuncLocked(ctx context.Context, callback func()) (func() bool, bool) {
	if m.workSealed {
		return nil, false
	}
	m.workers.Add(1)
	stop := context.AfterFunc(ctx, func() { defer m.workers.Done(); callback() })
	var once sync.Once
	var stopped bool
	return func() bool {
		once.Do(func() {
			stopped = stop()
			if stopped {
				m.workers.Done()
			}
		})
		return stopped
	}, true
}

func (m *queryMultiplexer) afterFunc(ctx context.Context, callback func()) (func() bool, bool) {
	m.queryAccess.Lock()
	defer m.queryAccess.Unlock()
	return m.afterFuncLocked(ctx, callback)
}

func (m *queryMultiplexer) linkWorkerContext(ctx context.Context) (context.Context, func(), bool) {
	bound, cancel := context.WithCancel(ctx)
	stop, ok := m.afterFunc(m.workerCtx, cancel)
	if !ok {
		cancel()
		return nil, nil, false
	}
	if m.workerCtx.Err() != nil {
		cancel()
	}
	return bound, func() { stop(); cancel() }, true
}

func (m *queryMultiplexer) Reset() {
	if m.options.probeReuse {
		m.probeAccess.Lock()
		m.probeEpoch++
		m.reuseState.Store(reuseStateUnknown)
		m.lastProbeTime = time.Time{}
		m.probeAccess.Unlock()
		m.demoteFailures.Store(0)
	}
	m.connection.Reset()
}

func (m *queryMultiplexer) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	done := make(chan struct{})
	var (
		response *mDNS.Msg
		err      error
	)
	m.ExchangeAsync(ctx, message, func(callbackResponse *mDNS.Msg, callbackErr error) {
		response = callbackResponse
		err = callbackErr
		close(done)
	})
	<-done
	return response, err
}

func (m *queryMultiplexer) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	if !m.reserveWorker() {
		callback(nil, net.ErrClosed)
		return
	}
	defer m.workers.Done() // invocation stack, even for a synchronous callback
	ctx, releaseContext, ok := m.linkWorkerContext(ctx)
	if !ok {
		callback(nil, net.ErrClosed)
		return
	}
	if !m.reserveWorker() {
		releaseContext()
		callback(nil, net.ErrClosed)
		return
	}
	var called atomic.Bool
	finish := func(response *mDNS.Msg, err error) {
		if !called.CompareAndSwap(false, true) {
			return
		}
		defer m.workers.Done()
		defer releaseContext()
		callback(response, err)
	}
	m.dispatch(ctx, message, finish, true)
}

func (m *queryMultiplexer) dispatch(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error), retryReadError bool) {
	if !m.reserveWorker() {
		callback(nil, net.ErrClosed)
		return
	}
	defer m.workers.Done()
	if m.options.probeReuse && m.reuseState.Load() != reuseStateSupported {
		m.maybeStartProbe(ctx, message)
		if !m.goWorker(func() { m.exchangeSingle(ctx, message, callback) }) {
			callback(nil, net.ErrClosed)
		}
		return
	}
	m.exchangeAsync(ctx, message, callback, retryReadError)
}

func (m *queryMultiplexer) exchangeSingle(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	conn, err := m.options.dial(ctx)
	if err != nil {
		callback(nil, err)
		return
	}
	defer conn.Close()
	stop, admitted := m.afterFunc(ctx, func() { conn.Close() })
	if !admitted {
		callback(nil, net.ErrClosed)
		return
	}
	defer stop()
	err = m.options.write(conn, message, message.Id)
	if err != nil {
		ctxErr := ctx.Err()
		if ctxErr != nil {
			callback(nil, ctxErr)
			return
		}
		callback(nil, E.Cause(err, "write request"))
		return
	}
	for {
		var response *mDNS.Msg
		response, err = m.options.readNext(conn)
		if err != nil {
			ctxErr := ctx.Err()
			if ctxErr != nil {
				callback(nil, ctxErr)
				return
			}
			callback(nil, E.Cause(err, "read response"))
			return
		}
		if response == nil {
			continue
		}
		response.Id = message.Id
		callback(response, nil)
		return
	}
}

func (m *queryMultiplexer) maybeStartProbe(ctx context.Context, message *mDNS.Msg) {
	if len(message.Question) == 0 {
		return
	}
	m.probeAccess.Lock()
	if m.probeStopped || m.reuseState.Load() == reuseStateProbing {
		m.probeAccess.Unlock()
		return
	}
	if !m.lastProbeTime.IsZero() && time.Since(m.lastProbeTime) < reuseProbeRetryInterval {
		m.probeAccess.Unlock()
		return
	}
	// Reserve under the producer gate before publication. StopProbes cannot
	// acknowledge retirement while an unreserved probe is still being queued.
	if !m.reserveWorker() {
		m.probeAccess.Unlock()
		return
	}
	m.reuseState.Store(reuseStateProbing)
	m.lastProbeTime = time.Now()
	epoch := m.probeEpoch
	questionName := message.Question[0].Name
	m.probeAccess.Unlock()
	go func() { defer m.workers.Done(); m.runReuseProbe(m.probeCtx, questionName, epoch) }()
}

func (m *queryMultiplexer) runReuseProbe(ctx context.Context, questionName string, epoch uint32) {
	supported, dialFailed := m.executeReuseProbe(ctx, questionName)
	m.probeAccess.Lock()
	defer m.probeAccess.Unlock()
	if m.probeEpoch != epoch {
		return
	}
	switch {
	case supported:
		m.reuseState.Store(reuseStateSupported)
		m.demoteFailures.Store(0)
	case dialFailed:
		m.reuseState.Store(reuseStateUnknown)
	default:
		m.reuseState.Store(reuseStateUnsupported)
	}
}

func (m *queryMultiplexer) executeReuseProbe(ctx context.Context, questionName string) (supported bool, dialFailed bool) {
	probeCtx, cancel := context.WithTimeout(ctx, reuseProbeTimeout)
	defer cancel()
	conn, err := m.options.dial(probeCtx)
	if err != nil {
		return false, true
	}
	defer conn.Close()
	stop, admitted := m.afterFunc(probeCtx, func() { conn.Close() })
	if !admitted {
		return false, false
	}
	defer stop()
	queryA := new(mDNS.Msg)
	queryA.SetQuestion(questionName, mDNS.TypeA)
	queryAAAA := new(mDNS.Msg)
	queryAAAA.SetQuestion(questionName, mDNS.TypeAAAA)
	err = m.options.write(conn, queryA, reuseProbeQueryIdA)
	if err == nil {
		err = m.options.write(conn, queryAAAA, reuseProbeQueryIdB)
	}
	if err != nil {
		return false, false
	}
	var seenA, seenAAAA bool
	for !seenA || !seenAAAA {
		var response *mDNS.Msg
		response, err = m.options.readNext(conn)
		if err != nil {
			return false, false
		}
		if response == nil {
			continue
		}
		switch response.Id {
		case reuseProbeQueryIdA:
			seenA = true
		case reuseProbeQueryIdB:
			seenAAAA = true
		}
	}
	return true, false
}

func (m *queryMultiplexer) recordConnDeath(conn *multiplexConn) {
	if !m.options.probeReuse || m.reuseState.Load() != reuseStateSupported {
		return
	}
	if conn.readEpoch.Load() == 0 {
		return
	}
	m.queryAccess.Lock()
	var pendingOnConn int
	for _, pending := range m.queries {
		if pending.conn == conn {
			pendingOnConn++
		}
	}
	m.queryAccess.Unlock()
	if pendingOnConn == 0 {
		m.demoteFailures.Store(0)
		return
	}
	if m.demoteFailures.Add(1) < reuseDemoteFailureLimit {
		return
	}
	m.probeAccess.Lock()
	if m.reuseState.Load() == reuseStateSupported {
		m.reuseState.Store(reuseStateUnsupported)
		m.lastProbeTime = time.Now()
	}
	m.probeAccess.Unlock()
	m.demoteFailures.Store(0)
}

func (m *queryMultiplexer) exchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error), retryReadError bool) {
	for firstAttempt := true; ; firstAttempt = false {
		conn, connCtx, created, err := m.connection.AcquireShared(ctx, m.dialConn)
		if err != nil {
			callback(nil, err)
			return
		}
		if created {
			if !m.goWorker(func() { m.recvLoop(conn) }) {
				m.connection.Invalidate(conn, net.ErrClosed)
				callback(nil, net.ErrClosed)
				return
			}
		}
		queryId, err := m.register(ctx, connCtx, conn, message, callback, retryReadError && m.options.retryReadError && !created)
		if err != nil {
			m.connection.Release(conn, true)
			m.closeIdleConnection()
			callback(nil, err)
			return
		}
		writeErr := m.options.write(conn, message, queryId)
		if writeErr == nil {
			return
		}
		pending := m.take(queryId)
		m.connection.Invalidate(conn, writeErr)
		if pending == nil {
			return
		}
		if !created && firstAttempt {
			continue
		}
		callback(nil, E.Cause(writeErr, "write request"))
		return
	}
}

func (m *queryMultiplexer) dialConn(ctx context.Context) (*multiplexConn, error) {
	conn, err := m.options.dial(ctx)
	if err != nil {
		return nil, err
	}
	return &multiplexConn{Conn: conn}, nil
}

func (m *queryMultiplexer) register(ctx context.Context, connCtx context.Context, conn *multiplexConn, message *mDNS.Msg, callback func(response *mDNS.Msg, err error), retryReadError bool) (uint16, error) {
	m.queryAccess.Lock()
	defer m.queryAccess.Unlock()
	if m.workSealed {
		return 0, net.ErrClosed
	}
	start := m.queryId
	for {
		m.queryId++
		if _, exists := m.queries[m.queryId]; !exists {
			break
		}
		if m.queryId == start {
			return 0, E.New("no available query ID")
		}
	}
	queryId := m.queryId
	pending := &pendingQuery{
		conn:      conn,
		message:   message,
		readEpoch: conn.readEpoch.Load(),
		callback:  callback,
	}
	if retryReadError {
		pending.retryCtx = ctx
	}
	m.queries[queryId] = pending
	pending.stopContext, _ = m.afterFuncLocked(ctx, func() {
		m.completeContextDone(queryId, ctx)
	})
	pending.stopConn, _ = m.afterFuncLocked(connCtx, func() {
		m.completeConnDone(queryId, connCtx)
	})
	return queryId, nil
}

func (m *queryMultiplexer) completeConnDone(queryId uint16, connCtx context.Context) {
	pending := m.take(queryId)
	if pending == nil {
		return
	}
	connErr := context.Cause(connCtx)
	_, readFailed := connErr.(*queryMultiplexerReadError)
	if pending.retryCtx != nil && readFailed {
		m.dispatch(pending.retryCtx, pending.message, pending.callback, false)
		return
	}
	pending.callback(nil, connErr)
}

func (m *queryMultiplexer) take(queryId uint16) *pendingQuery {
	m.queryAccess.Lock()
	pending, loaded := m.queries[queryId]
	if !loaded {
		m.queryAccess.Unlock()
		return nil
	}
	delete(m.queries, queryId)
	m.queryAccess.Unlock()
	pending.stopContext()
	pending.stopConn()
	return pending
}

func (m *queryMultiplexer) complete(queryId uint16, response *mDNS.Msg, err error, releaseConn bool) {
	pending := m.take(queryId)
	if pending == nil {
		return
	}
	if releaseConn {
		m.connection.Release(pending.conn, true)
	}
	if response != nil {
		response.Id = pending.message.Id
	}
	pending.callback(response, err)
	m.closeIdleConnection()
}

func (m *queryMultiplexer) completeContextDone(queryId uint16, ctx context.Context) {
	pending := m.take(queryId)
	if pending == nil {
		return
	}
	err := ctx.Err()
	if errors.Is(err, context.DeadlineExceeded) && pending.conn.readEpoch.Load() == pending.readEpoch {
		m.connection.Invalidate(pending.conn, err)
	} else {
		m.connection.Release(pending.conn, true)
	}
	pending.callback(nil, err)
	m.closeIdleConnection()
}

func (m *queryMultiplexer) recvLoop(conn *multiplexConn) {
	for {
		message, err := m.options.readNext(conn)
		if err != nil {
			m.recordConnDeath(conn)
			m.connection.Invalidate(conn, &queryMultiplexerReadError{cause: err})
			return
		}
		conn.readEpoch.Add(1)
		if message == nil {
			continue
		}
		m.complete(message.Id, message, nil, true)
	}
}
