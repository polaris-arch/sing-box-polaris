package certificate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing/common/logger"
)

type runtimeStore struct {
	ctx           context.Context
	cancel        context.CancelFunc
	source        adapter.RuntimeResourceSource
	fence         *outbound.RuntimeIOFence
	callbacks     *outbound.RuntimeIOFence
	beginCallback func(context.Context) (context.Context, func(), error)
	changes       chan struct{}
	reload        sync.Mutex
	mu            sync.Mutex
	stopped       bool
	startDone     chan struct{}
	startErr      error
	startReturned bool
}

func (s *Store) initializeRuntime(ctx context.Context) error {
	source, ok := adapter.RuntimeResourceSourceFromContext(ctx)
	if !ok || !adapter.HasConstructionScope(ctx) {
		return errors.New("certificate store requires its constructor resource and scope")
	}
	if source.ID() == (adapter.RuntimeResourceID{}) {
		return errors.New("certificate store has no runtime resource identity")
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &runtimeStore{ctx: ctx, cancel: cancel, source: source, changes: make(chan struct{}, 1)}
	s.runtime = r
	r.callbacks = outbound.NewRuntimeIOFence(nil)
	begin, err := outbound.RegisterRuntimeOwnedFence(ctx, r.callbacks)
	if err != nil {
		cancel()
		return err
	}
	r.beginCallback = begin
	r.fence = outbound.NewRuntimeIOFence(func() error {
		r.stop()
		r.mu.Lock()
		started := r.startDone
		r.mu.Unlock()
		if started != nil {
			<-started
		}
		var closeErr error
		if s.watcher != nil {
			closeErr = s.watcher.Close()
		}
		// fswatch's accept loop/timer tails need not be joined once every callback
		// and logger entry into this store's graph authority is sealed and drained.
		closeErr = errors.Join(closeErr, r.callbacks.RuntimeCloseAndWait())
		r.mu.Lock()
		incomplete := r.startDone != nil && !r.startReturned
		startErr := r.startErr
		r.mu.Unlock()
		var marker interface{ RuntimeCleanupIncomplete() bool }
		if errors.As(startErr, &marker) && marker.RuntimeCleanupIncomplete() {
			closeErr = errors.Join(closeErr, startErr)
		}
		if incomplete {
			closeErr = errors.Join(closeErr, errors.New("certificate watcher start completion unknown"))
		}
		s.access.Lock()
		snapshot := s.latest
		s.latest = nil
		s.currentPool = nil
		s.anchorPEM = nil
		s.access.Unlock()
		if snapshot != nil {
			snapshot.Release()
		}
		if closeErr != nil {
			return &storeCleanupError{cause: closeErr}
		}
		return nil
	})
	_, err = outbound.RegisterRuntimeOwnedFence(ctx, r.fence)
	if err != nil {
		cancel()
		return err
	}
	return nil
}
func (r *runtimeStore) stop() { r.mu.Lock(); r.stopped = true; r.mu.Unlock(); r.cancel() }
func (s *Store) RuntimeResourceID() adapter.RuntimeResourceID {
	if s.runtime == nil {
		return adapter.RuntimeResourceID{}
	}
	return s.runtime.source.ID()
}

func (s *Store) RuntimeValidate() error {
	if s.runtime == nil {
		return errors.New("certificate store lacks its staged resource adapter")
	}
	s.access.RLock()
	valid := s.latest != nil
	s.access.RUnlock()
	if !valid {
		return errors.New("certificate store has no complete root snapshot")
	}
	return nil
}

func (s *Store) PrepareRuntime(stage adapter.StartStage, _ *adapter.Scope) error {
	if err := s.RuntimeValidate(); err != nil {
		return err
	}
	r := s.runtime
	leave, err := r.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return net.ErrClosed
	}
	if stage != adapter.StartStateStart {
		r.mu.Unlock()
		return r.ctx.Err()
	}
	if r.startDone != nil {
		done := r.startDone
		r.mu.Unlock()
		<-done
		r.mu.Lock()
		err := r.startErr
		r.mu.Unlock()
		return err
	}
	r.startDone = make(chan struct{})
	done := r.startDone
	r.startErr = errors.New("certificate watcher start did not complete")
	r.mu.Unlock()
	defer close(done)
	if s.watcher != nil {
		err = s.watcher.Start()
	}
	if err == nil {
		err = r.ctx.Err()
	}
	r.mu.Lock()
	r.startErr, r.startReturned = err, true
	r.mu.Unlock()
	return err
}

// RuntimeStop seals callback admission promptly at retirement. Old graph
// consumers hold independent immutable snapshots and native anchor references.
// The sole registered close joins real Start/callback/native cleanup outside
// the transaction publication guard; it never claims an unreturned call ended.
func (s *Store) RuntimeStop() {
	if s.runtime != nil {
		s.runtime.stop()
		_ = s.runtime.fence.Close()
	}
}

func (s *Store) RuntimeCloseAndWait() error {
	if s.runtime == nil {
		return errors.New("legacy certificate store is scope-owned")
	}
	return s.runtime.fence.RuntimeCloseAndWait()
}

func (s *Store) RuntimeRevision() uint64 {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.revision
}

// RuntimeChanges is bounded and coalesced. It announces a new private candidate,
// never permission to mutate active consumers. The Box owner snapshots latest,
// fingerprints Digest, and runs its normal internal graph transaction. Failed
// publication keeps the old graph snapshot. The channel is not closed; the
// subscribing owner cancels its own select loop when this source is retired.
func (s *Store) RuntimeChanges() <-chan struct{} {
	if s.runtime == nil {
		return nil
	}
	return s.runtime.changes
}

func (s *Store) reloadRuntime() error {
	r := s.runtime
	ctx, release, err := r.beginCallback(r.ctx)
	if err != nil {
		return err
	}
	defer release()
	r.reload.Lock()
	defer r.reload.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	pool, pemBytes, err := s.loadWithContext(ctx)
	if err != nil {
		return err
	}
	s.access.RLock()
	unchanged := s.currentPool != nil && s.currentPool.Equal(pool) && bytes.Equal(s.anchorPEM, pemBytes)
	revision := s.revision + 1
	s.access.RUnlock()
	if unchanged {
		return nil
	}
	if revision == 0 {
		return errors.New("certificate snapshot revision exhausted")
	}
	// Native parsing may fail. Neither pool nor anchor generation is published
	// until both are complete, so a failed native allocation cannot mix roots.
	snapshot, err := newRootSnapshot(r.source.ID(), revision, s.storeType, pool, pemBytes)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		snapshot.Release()
		return err
	}
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		snapshot.Release()
		return net.ErrClosed
	}
	s.access.Lock()
	old := s.latest
	s.latest = snapshot
	s.revision = revision
	s.currentPool = pool
	s.anchorPEM = append([]byte(nil), pemBytes...)
	s.access.Unlock()
	r.mu.Unlock()
	if old != nil {
		old.Release()
	}
	// No owner callback occurs under store locks; a one-slot signal bounds burst
	// delivery even if the Box transaction is busy or currently failing.
	select {
	case r.changes <- struct{}{}:
	default:
	}
	return nil
}

type storeCleanupError struct{ cause error }

func (e *storeCleanupError) Error() string {
	return fmt.Sprintf("certificate store cleanup incomplete: %v", e.cause)
}
func (*storeCleanupError) RuntimeCleanupIncomplete() bool { return true }

type runtimeStoreLogger struct {
	logger.Logger
	fence *outbound.RuntimeIOFence
}

func (l *runtimeStoreLogger) Trace(args ...any) {
	leave, err := l.fence.Acquire()
	if err != nil {
		return
	}
	defer leave()
	l.Logger.Trace(args...)
}

func (l *runtimeStoreLogger) Debug(args ...any) {
	leave, err := l.fence.Acquire()
	if err != nil {
		return
	}
	defer leave()
	l.Logger.Debug(args...)
}

func (l *runtimeStoreLogger) Info(args ...any) {
	leave, err := l.fence.Acquire()
	if err != nil {
		return
	}
	defer leave()
	l.Logger.Info(args...)
}

func (l *runtimeStoreLogger) Warn(args ...any) {
	leave, err := l.fence.Acquire()
	if err != nil {
		return
	}
	defer leave()
	l.Logger.Warn(args...)
}

func (l *runtimeStoreLogger) Error(args ...any) {
	leave, err := l.fence.Acquire()
	if err != nil {
		return
	}
	defer leave()
	l.Logger.Error(args...)
}

func (l *runtimeStoreLogger) Fatal(args ...any) {
	leave, err := l.fence.Acquire()
	if err != nil {
		return
	}
	defer leave()
	l.Logger.Fatal(args...)
}

func (l *runtimeStoreLogger) Panic(args ...any) {
	leave, err := l.fence.Acquire()
	if err != nil {
		return
	}
	defer leave()
	l.Logger.Panic(args...)
}
