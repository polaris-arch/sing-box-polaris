package httpclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"

	"github.com/sagernet/sing-box/adapter/outbound"
	boxTLS "github.com/sagernet/sing-box/common/tls"
)

// RuntimeTransportBoundary owns the edges from a transport's private workers
// into caller bodies, traces, dialers, pools and physical connections. It keeps
// no graph/self lease. Its enclosing transport owns pending construction and
// calls Close after sealing external admission. Private HTTP worker tails may
// outlive Close only after every dependency-facing method is sealed and joined.
type RuntimeTransportBoundary struct {
	mu          sync.Mutex
	closed      bool
	stopOnce    sync.Once
	fence       *outbound.RuntimeIOFence
	connections *outbound.RuntimeIOFenceSet
	dials       map[*runtimeDialBoundary]context.CancelFunc
	resources   []outbound.RuntimeCloseWaiter
	requests    map[*runtimeRequestBoundary]struct{}
	closeInner  func() error
	closeErr    error
}

func NewRuntimeTransportBoundary(closeInner func() error) *RuntimeTransportBoundary {
	b := &RuntimeTransportBoundary{connections: outbound.NewRuntimeIOFenceSet(), dials: make(map[*runtimeDialBoundary]context.CancelFunc), requests: make(map[*runtimeRequestBoundary]struct{}), closeInner: closeInner}
	b.fence = outbound.NewRuntimeIOFence(b.closeDependencies)
	return b
}

func (b *RuntimeTransportBoundary) closeDependencies() error {
	b.mu.Lock()
	b.closed = true
	cancels := make([]context.CancelFunc, 0, len(b.dials))
	for _, cancel := range b.dials {
		cancels = append(cancels, cancel)
	}
	requests := make([]*runtimeRequestBoundary, 0, len(b.requests))
	for r := range b.requests {
		requests = append(requests, r)
	}
	resources := append([]outbound.RuntimeCloseWaiter(nil), b.resources...)
	b.mu.Unlock()
	// Cancel physical creation as well: HTTP may deliberately detach its dial
	// context from the originating request before entering our callback.
	for _, cancel := range cancels {
		cancel()
	}
	b.connections.Stop()
	// Cancel requests before waiting for their callbacks or socket reads.
	for _, r := range requests {
		r.cancel()
	}
	var errs []error
	var results sync.Mutex
	var workers sync.WaitGroup
	join := func(cleanup func() error) {
		workers.Go(func() {
			var err error
			defer func() {
				if value := recover(); value != nil {
					err = fmt.Errorf("HTTP cleanup panic: %v", value)
				}
				if err != nil {
					results.Lock()
					errs = append(errs, err)
					results.Unlock()
				}
			}()
			err = cleanup()
		})
	}
	// Initiate every independent close before waiting for any foreign Close.
	// A blocked native/socket cleanup must not prevent another from receiving
	// its cancellation. This local group is part of the actual terminal call.
	join(b.connections.Wait)
	for _, resource := range resources {
		join(resource.RuntimeCloseAndWait)
	}
	if b.closeInner != nil {
		join(b.closeInner)
	}
	for _, r := range requests {
		join(r.Close)
	}
	workers.Wait()
	b.mu.Lock()
	errs = append(errs, b.closeErr)
	b.mu.Unlock()
	return errors.Join(errs...)
}

func (b *RuntimeTransportBoundary) Close() error {
	err := b.fence.RuntimeCloseAndWait()
	b.mu.Lock()
	defer b.mu.Unlock()
	return errors.Join(err, b.closeErr)
}
func (b *RuntimeTransportBoundary) RuntimeCloseAndWait() error { return b.Close() }

func (b *RuntimeTransportBoundary) record(err error) {
	if err == nil {
		return
	}
	b.mu.Lock()
	b.closeErr = errors.Join(b.closeErr, fmt.Errorf("HTTP boundary cleanup incomplete: %v", err))
	b.mu.Unlock()
}

// GuardConnection is called while the enclosing dial/construction invocation
// is admitted. It preserves TLS state but exposes no raw fast-path escape.
func (b *RuntimeTransportBoundary) GuardConnection(conn net.Conn) (net.Conn, error) {
	guarded, fence := outbound.WrapRuntimeOwnedConn(conn)
	creation, err := b.connections.Begin()
	if err != nil {
		closeErr := fence.RuntimeCloseAndWait()
		b.record(closeErr)
		return nil, errors.Join(err, closeErr)
	}
	defer creation.Done()
	if err = creation.Register(fence); err != nil {
		return nil, err
	}
	if tlsConn, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return &runtimeStateConn{Conn: guarded, state: tlsConn.ConnectionState()}, nil
	}
	return guarded, nil
}

type runtimeStateConn struct {
	net.Conn
	state tls.ConnectionState
}

func (c *runtimeStateConn) ConnectionState() tls.ConnectionState { return c.state }

// The non-zero size gives concurrent dial reservations distinct pointer identities.
type runtimeDialBoundary struct{ _ byte }

// BeginDial reserves and makes cancellation visible before calling any external
// dial/handshake. A late result must transfer to GuardConnection/RegisterResource
// before release. There is no background idle self-lease.
func (b *RuntimeTransportBoundary) BeginDial(ctx context.Context) (context.Context, func(), error) {
	leave, err := b.fence.Acquire()
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	slot := new(runtimeDialBoundary)
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		cancel()
		leave()
		return nil, nil, net.ErrClosed
	}
	b.dials[slot] = cancel
	b.mu.Unlock()
	return ctx, func() {
		failure := recover()
		cancel()
		b.mu.Lock()
		delete(b.dials, slot)
		b.mu.Unlock()
		if failure != nil {
			b.record(fmt.Errorf("HTTP physical creation panic: %v", failure))
		}
		leave()
		if failure != nil {
			panic(failure)
		}
	}, nil
}

func (b *RuntimeTransportBoundary) Dial(ctx context.Context, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	ctx, release, err := b.BeginDial(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	conn, err := dial(ctx)
	if err != nil {
		if boxTLS.IsRuntimeCleanupIncomplete(err) {
			b.record(err)
		}
		return nil, err
	}
	return b.GuardConnection(conn)
}

func (b *RuntimeTransportBoundary) RoundTrip(request *http.Request, roundTrip func(*http.Request) (*http.Response, error)) (*http.Response, error) {
	release, err := b.fence.Acquire()
	if err != nil {
		return nil, err
	}
	defer release()
	r := newRuntimeRequestBoundary(request)
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		_ = r.Close()
		return nil, net.ErrClosed
	}
	b.requests[r] = struct{}{}
	b.mu.Unlock()
	response, err := roundTrip(r.request)
	if err != nil || response == nil || response.Body == nil {
		b.record(r.Close())
		b.mu.Lock()
		delete(b.requests, r)
		b.mu.Unlock()
		return response, err
	}
	body := &runtimeResponseBody{ReadCloser: response.Body, request: r, boundary: b}
	if writer, ok := response.Body.(io.Writer); ok {
		response.Body = &runtimeResponseReadWriteBody{runtimeResponseBody: body, writer: writer}
	} else {
		response.Body = body
	}
	return response, nil
}

type runtimeRequestBoundary struct {
	mu          sync.Mutex
	closed      bool
	retryBodies []*runtimeBody
	request     *http.Request
	cancel      context.CancelFunc
	callbacks   *outbound.RuntimeIOFence
	body        *runtimeBody
	once        sync.Once
	err         error
}

type runtimeBody struct {
	io.ReadCloser
	fence *outbound.RuntimeIOFence
}

func newRuntimeBody(body io.ReadCloser) *runtimeBody {
	return &runtimeBody{ReadCloser: body, fence: outbound.NewRuntimeIOFence(body.Close)}
}

func (b *runtimeBody) Read(p []byte) (int, error) {
	release, err := b.fence.Acquire()
	if err != nil {
		return 0, err
	}
	defer release()
	return b.ReadCloser.Read(p)
}
func (b *runtimeBody) Close() error { return b.fence.RuntimeCloseAndWait() }

// Without a trace-key override, httptrace.WithClientTrace composes with the
// original callbacks and would silently reintroduce an unfenced invocation.
type runtimeTraceContext struct{ context.Context }

func (c runtimeTraceContext) Value(key any) any {
	value := c.Context.Value(key)
	if _, ok := value.(*httptrace.ClientTrace); ok {
		return nil
	}
	return value
}

func newRuntimeRequestBoundary(request *http.Request) *runtimeRequestBoundary {
	ctx, cancel := context.WithCancel(runtimeTraceContext{request.Context()})
	r := &runtimeRequestBoundary{cancel: cancel}
	r.callbacks = outbound.NewRuntimeIOFence(func() error { return nil })
	r.request = request.Clone(ctx)
	if request.Body != nil {
		r.body = newRuntimeBody(request.Body)
		r.request.Body = r.body
	}
	if request.GetBody != nil {
		get := request.GetBody
		r.request.GetBody = func() (io.ReadCloser, error) {
			release, err := r.callbacks.Acquire()
			if err != nil {
				return nil, err
			}
			defer release()
			body, err := get()
			if err != nil {
				return nil, err
			}
			// Retry bodies are transport-owned and closed by the transport. They
			// require their own boundary and are collected by the parent request.
			return r.trackRetryBody(body), nil
		}
	}
	if trace := httptrace.ContextClientTrace(request.Context()); trace != nil {
		r.request = r.request.WithContext(httptrace.WithClientTrace(ctx, r.guardTrace(trace)))
	}
	return r
}

// Every retry body is sealed and joined, even if an abandoned retry never
// reaches the dependency's ordinary Body.Close call.
func (r *runtimeRequestBoundary) trackRetryBody(body io.ReadCloser) io.ReadCloser {
	guarded := newRuntimeBody(body)
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		err := guarded.Close()
		r.mu.Lock()
		r.err = errors.Join(r.err, err)
		r.mu.Unlock()
		return guarded
	}
	r.retryBodies = append(r.retryBodies, guarded)
	r.mu.Unlock()
	return guarded
}

func (r *runtimeRequestBoundary) Close() error {
	r.once.Do(func() {
		r.mu.Lock()
		r.closed = true
		bodies := append([]*runtimeBody(nil), r.retryBodies...)
		r.mu.Unlock()
		r.cancel()
		var err error
		if r.body != nil {
			err = r.body.Close()
		}
		for _, body := range bodies {
			err = errors.Join(err, body.Close())
		}
		err = errors.Join(err, r.callbacks.RuntimeCloseAndWait())
		r.mu.Lock()
		r.err = errors.Join(r.err, err)
		r.mu.Unlock()
	})
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

type runtimeResponseReadWriteBody struct {
	*runtimeResponseBody
	writer io.Writer
}

func (b *runtimeResponseReadWriteBody) Write(p []byte) (int, error) { return b.writer.Write(p) }

type runtimeResponseBody struct {
	io.ReadCloser
	request  *runtimeRequestBoundary
	boundary *RuntimeTransportBoundary
	once     sync.Once
	err      error
}

func (b *runtimeResponseBody) Close() error {
	b.once.Do(func() {
		b.err = errors.Join(b.ReadCloser.Close(), b.request.Close())
		b.boundary.record(b.err)
		b.boundary.mu.Lock()
		delete(b.boundary.requests, b.request)
		b.boundary.mu.Unlock()
	})
	return b.err
}

func (b *RuntimeTransportBoundary) BindHTTP1(t *http.Transport) {
	if dial := t.DialContext; dial != nil {
		t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return b.Dial(ctx, func(ctx context.Context) (net.Conn, error) { return dial(ctx, network, addr) })
		}
	}
	if dial := t.DialTLSContext; dial != nil {
		t.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return b.Dial(ctx, func(ctx context.Context) (net.Conn, error) { return dial(ctx, network, addr) })
		}
	}
}

// RegisterResource transfers a completed creation to the enclosing pool before
// its creation slot can release. A late result is cleaned and joined in place.
func (b *RuntimeTransportBoundary) RegisterResource(resource outbound.RuntimeCloseWaiter) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		err := resource.RuntimeCloseAndWait()
		b.record(err)
		return errors.Join(net.ErrClosed, err)
	}
	b.resources = append(b.resources, resource)
	b.mu.Unlock()
	return nil
}
func (b *RuntimeTransportBoundary) Acquire() (func(), error) { return b.fence.Acquire() }

// RecordClose retains a concrete late-result cleanup error on this owner.
func (b *RuntimeTransportBoundary) RecordClose(err error) { b.record(err) }

// RegisterRuntimeOwner is used only by concrete background session engines
// (for example grpc reconnect), not to borrow an arbitrary request's identity.
// The existing boundary is the registered owner fence; no idle lease is held.
func (b *RuntimeTransportBoundary) RegisterRuntimeOwner(ctx context.Context) (func(context.Context) (context.Context, func(), error), error) {
	return outbound.RegisterRuntimeOwnedFence(ctx, b.fence)
}

func (b *RuntimeTransportBoundary) StopRuntimeOperations() {
	b.stopOnce.Do(func() { go func() { _ = b.fence.Close() }() })
}
