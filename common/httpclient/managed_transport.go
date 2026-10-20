package httpclient

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

type innerTransport interface {
	http.RoundTripper
	CloseIdleConnections()
	Close() error
}

var _ adapter.HTTPTransport = (*ManagedTransport)(nil)

type ManagedTransport struct {
	epoch           atomic.Pointer[transportEpoch]
	rebuildAccess   sync.Mutex
	factory         func() (innerTransport, error)
	cheapRebuild    bool
	creating        chan struct{}
	closed          bool
	epochs          map[*transportEpoch]struct{}
	fence           *outbound.RuntimeIOFence
	ownedCallbacks  *outbound.RuntimeIOFence
	stopOnce        sync.Once
	source          adapter.RuntimeResourceSource
	closeErr        error
	dialer          N.Dialer
	headers         http.Header
	host            string
	tag             string
	detour          string
	defaultOutbound bool
}

type transportEpoch struct {
	transport innerTransport
	active    atomic.Int64
	marked    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

func (e *transportEpoch) tryClose() error {
	e.closeOnce.Do(func() {
		defer func() {
			if value := recover(); value != nil {
				e.closeErr = E.New("HTTP epoch cleanup panic: ", value)
			}
		}()
		e.closeErr = e.transport.Close()
	})
	return e.closeErr
}

func (t *ManagedTransport) initializeRuntime(ctx context.Context) error {
	t.source, _ = adapter.RuntimeResourceSourceFromContext(ctx)
	t.epochs = make(map[*transportEpoch]struct{})
	if epoch := t.epoch.Load(); epoch != nil {
		t.epochs[epoch] = struct{}{}
	}
	t.fence = outbound.NewRuntimeIOFence(t.closeOwned)
	if adapter.HasConstructionScope(ctx) {
		if err := adapter.DeferConstructionCleanup(ctx, t.RuntimeCloseAndWait); err != nil {
			return err
		}
		if err := adapter.ConstructionScopeErr(ctx); err != nil {
			return errors.Join(err, t.RuntimeCloseAndWait())
		}
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(err, t.RuntimeCloseAndWait())
	}
	t.rebuildAccess.Lock()
	closed := t.closed
	t.rebuildAccess.Unlock()
	if closed {
		return net.ErrClosed
	}
	return nil
}

func (t *ManagedTransport) recordClose(err error) {
	if err == nil {
		return
	}
	t.rebuildAccess.Lock()
	t.closeErr = errors.Join(t.closeErr, err)
	t.rebuildAccess.Unlock()
}

func (t *ManagedTransport) getEpoch() (*transportEpoch, error) {
	for {
		t.rebuildAccess.Lock()
		if t.closed {
			t.rebuildAccess.Unlock()
			return nil, net.ErrClosed
		}
		if epoch := t.epoch.Load(); epoch != nil {
			t.rebuildAccess.Unlock()
			return epoch, nil
		}
		if pending := t.creating; pending != nil {
			t.rebuildAccess.Unlock()
			<-pending
			continue
		}
		pending := make(chan struct{})
		t.creating = pending
		t.rebuildAccess.Unlock()
		inner, err := t.constructEpoch(pending)
		t.rebuildAccess.Lock()
		closed := t.closed
		var epoch *transportEpoch
		if err == nil && !closed {
			epoch = &transportEpoch{transport: inner}
			t.epoch.Store(epoch)
			t.epochs[epoch] = struct{}{}
		}
		t.creating = nil
		close(pending)
		t.rebuildAccess.Unlock()
		if err != nil {
			return nil, err
		}
		if closed {
			closeErr := inner.Close()
			t.recordClose(closeErr)
			return nil, errors.Join(net.ErrClosed, closeErr)
		}
		return epoch, nil
	}
}

// A failed factory must not strand waiters or turn a panic into successful
// retirement. Keep an opaque terminal error even when its caller recovers.
func (t *ManagedTransport) constructEpoch(pending chan struct{}) (inner innerTransport, err error) {
	defer func() {
		if value := recover(); value != nil {
			t.rebuildAccess.Lock()
			t.closeErr = errors.Join(t.closeErr, E.New("HTTP factory panic: ", value))
			t.creating = nil
			close(pending)
			t.rebuildAccess.Unlock()
			panic(value)
		}
	}()
	return t.factory()
}

func (t *ManagedTransport) acquireEpoch() (*transportEpoch, error) {
	for {
		epoch, err := t.getEpoch()
		if err != nil {
			return nil, err
		}
		epoch.active.Add(1)
		if epoch == t.epoch.Load() {
			return epoch, nil
		}
		t.releaseEpoch(epoch)
	}
}

func (t *ManagedTransport) releaseEpoch(epoch *transportEpoch) {
	if epoch.active.Add(-1) == 0 && epoch.marked.Load() {
		t.recordClose(epoch.tryClose())
	}
}

func (t *ManagedTransport) retireEpoch(epoch *transportEpoch) {
	if epoch == nil {
		return
	}
	epoch.marked.Store(true)
	if epoch.active.Load() == 0 {
		t.recordClose(epoch.tryClose())
	}
}

func (t *ManagedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	ctx, releaseRuntime, err := adapter.AcquireRuntimeOperation(request.Context(), t.source)
	if err != nil {
		return nil, err
	}
	leave, err := t.fence.Acquire()
	if err != nil {
		releaseRuntime()
		return nil, err
	}
	defer leave()
	// All physical transport connections belong to this incarnation's pool.
	// The request/body reservation remains external until the body is closed.
	if t.source != nil {
		ctx, err = outbound.ContextForRuntimeOwnedSession(ctx, t.source)
		if err != nil {
			releaseRuntime()
			return nil, err
		}
	}
	epoch, err := t.acquireEpoch()
	if err != nil {
		releaseRuntime()
		return nil, E.Cause(err, "rebuild http transport")
	}
	release := func() { t.releaseEpoch(epoch); releaseRuntime() }
	if t.tag != "" {
		if tag, ok := transportTagFromContext(ctx); ok && tag == t.tag {
			release()
			return nil, E.New("HTTP request loopback in transport[", t.tag, "]")
		}
		ctx = contextWithTransportTag(ctx, t.tag)
	}
	request = request.Clone(ctx)
	applyHeaders(request, t.headers, t.host)
	response, err := epoch.transport.RoundTrip(request)
	if err != nil || response == nil || response.Body == nil {
		release()
		return response, err
	}
	body := &managedResponseBody{body: newRuntimeBody(response.Body), release: release}
	if writer, ok := response.Body.(io.Writer); ok {
		response.Body = &managedResponseReadWriteBody{managedResponseBody: body, writer: writer}
	} else {
		response.Body = body
	}
	return response, nil
}

type managedResponseReadWriteBody struct {
	*managedResponseBody
	writer io.Writer
}

func (b *managedResponseReadWriteBody) Write(p []byte) (int, error) {
	leave, err := b.body.fence.Acquire()
	if err != nil {
		return 0, err
	}
	defer leave()
	return b.writer.Write(p)
}

type managedResponseBody struct {
	body    *runtimeBody
	release func()
	once    sync.Once
	err     error
}

func (b *managedResponseBody) Read(p []byte) (int, error) { return b.body.Read(p) }
func (b *managedResponseBody) Close() error {
	b.once.Do(func() {
		b.err = b.body.Close()
		if b.err == nil {
			b.release()
		}
	})
	return b.err
}

var _ io.ReadCloser = (*managedResponseBody)(nil)

func (t *ManagedTransport) CloseIdleConnections() {
	leave, err := t.fence.Acquire()
	if err != nil {
		return
	}
	defer leave()
	old := t.epoch.Swap(nil)
	if old == nil {
		return
	}
	t.retireEpoch(old)
}

func (t *ManagedTransport) Reset() {
	leave, err := t.fence.Acquire()
	if err != nil {
		return
	}
	defer leave()
	old := t.epoch.Swap(nil)
	t.retireEpoch(old)
	// Lazy rebuilding avoids allocation under the epoch guard and preserves
	// the captured registry and immutable factory options for this incarnation.
}

func (t *ManagedTransport) closeOwned() error {
	t.rebuildAccess.Lock()
	t.closed = true
	t.epoch.Store(nil)
	epochs := make([]*transportEpoch, 0, len(t.epochs))
	for e := range t.epochs {
		epochs = append(epochs, e)
	}
	t.rebuildAccess.Unlock()
	var closes sync.WaitGroup
	for _, epoch := range epochs {
		closes.Go(func() { t.recordClose(epoch.tryClose()) })
	}
	closes.Wait()
	if t.ownedCallbacks != nil {
		t.recordClose(t.ownedCallbacks.RuntimeCloseAndWait())
	}
	return nil
}

func (t *ManagedTransport) RuntimeCloseAndWait() error {
	err := t.fence.RuntimeCloseAndWait()
	t.rebuildAccess.Lock()
	defer t.rebuildAccess.Unlock()
	if t.closeErr != nil {
		return E.New("HTTP transport cleanup incomplete: ", errors.Join(err, t.closeErr))
	}
	return err
}

var _ adapter.HTTPTransport = (*sharedRef)(nil)

type (
	sharedRef struct {
		managed *ManagedTransport
		shared  *sharedState
		idle    atomic.Bool
	}
	sharedState struct{ activeRefs atomic.Int32 }
)

func newSharedRef(managed *ManagedTransport, shared *sharedState) *sharedRef {
	shared.activeRefs.Add(1)
	return &sharedRef{managed: managed, shared: shared}
}

func (r *sharedRef) RoundTrip(request *http.Request) (*http.Response, error) {
	if r.idle.CompareAndSwap(true, false) {
		r.shared.activeRefs.Add(1)
	}
	return r.managed.RoundTrip(request)
}

func (r *sharedRef) CloseIdleConnections() {
	if r.idle.CompareAndSwap(false, true) && r.shared.activeRefs.Add(-1) == 0 {
		r.managed.CloseIdleConnections()
	}
}
func (r *sharedRef) Reset() { r.managed.Reset() }

func (t *ManagedTransport) StopRuntimeOperations() {
	t.stopOnce.Do(func() { go func() { _ = t.fence.Close() }() })
}
