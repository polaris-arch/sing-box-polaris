package urltest

import (
	"context"
	"errors"

	"github.com/sagernet/sing-box/adapter"
)

var ErrStaleHistory = errors.New("URL test network epoch is not current and ready")

// HistoryEpoch is an opaque, storage-bound identity. Cancellation requests that
// admitted probes stop; it never certifies their actual completion.
type HistoryEpoch struct {
	ctx    context.Context
	cancel context.CancelFunc
	ready  bool // protected by the owning HistoryStorage.access
}

func newHistoryEpoch(ready bool) *HistoryEpoch {
	ctx, cancel := context.WithCancel(context.Background())
	return &HistoryEpoch{ctx: ctx, cancel: cancel, ready: ready}
}

func (s *HistoryStorage) Epoch() *HistoryEpoch {
	if s == nil {
		return nil
	}
	s.access.RLock()
	defer s.access.RUnlock()
	if s.closed {
		return nil
	}
	return s.epoch
}

func (s *HistoryStorage) currentLocked(epoch *HistoryEpoch) bool {
	return !s.closed && epoch != nil && s.epoch == epoch && epoch.ready
}

func (s *HistoryStorage) IsCurrent(epoch *HistoryEpoch) bool {
	if s == nil {
		return false
	}
	s.access.RLock()
	defer s.access.RUnlock()
	return s.currentLocked(epoch)
}

// AdvanceNetworkEpoch is called once by the interface transition owner. Work
// cannot be admitted until that owner has prepared and marked this epoch ready.
func (s *HistoryStorage) AdvanceNetworkEpoch() *HistoryEpoch {
	if s == nil {
		return nil
	}
	s.access.Lock()
	if s.closed || s.authority != s {
		s.access.Unlock()
		return nil
	}
	previous := s.epoch
	s.epoch = newHistoryEpoch(false)
	next := s.epoch
	for view := range s.views {
		view.epoch = next
		clear(view.delayHistory)
		view.notifyLocalLocked()
	}
	s.access.Unlock()
	previous.cancel()
	return next
}

func (s *HistoryStorage) MarkReady(epoch *HistoryEpoch) bool {
	if s == nil {
		return false
	}
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed || s.authority != s || epoch == nil || s.epoch != epoch {
		return false
	}
	epoch.ready = true
	return true
}

// ProbeContext requires readiness at admission, rather than allowing work
// started during preparation to become valid merely because readiness changes.
func (s *HistoryStorage) ProbeContext(ctx context.Context, epoch *HistoryEpoch) (context.Context, context.CancelFunc, error) {
	s.access.RLock()
	if !s.currentLocked(epoch) {
		s.access.RUnlock()
		return nil, nil, ErrStaleHistory
	}
	probeCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(epoch.ctx, cancel)
	s.access.RUnlock()
	return probeCtx, func() { stop(); cancel() }, nil
}

func (s *HistoryStorage) Snapshot(epoch *HistoryEpoch) (map[string]*adapter.URLTestHistory, bool) {
	if result, valid, bound := s.projectedSnapshot(epoch); bound {
		return result, valid
	}
	s.access.RLock()
	defer s.access.RUnlock()
	if !s.currentLocked(epoch) {
		return nil, false
	}
	result := make(map[string]*adapter.URLTestHistory, len(s.delayHistory))
	for tag, history := range s.delayHistory {
		if history != nil {
			copy := *history
			result[tag] = &copy
		}
	}
	return result, true
}

func (s *HistoryStorage) StoreIfCurrent(epoch *HistoryEpoch, tag string, history *adapter.URLTestHistory) bool {
	s.access.Lock()
	defer s.access.Unlock()
	if !s.currentLocked(epoch) || !s.writableLocked() || history == nil {
		return false
	}
	copy := *history
	s.delayHistory[tag] = &copy
	s.notifyUpdated()
	return true
}

func (s *HistoryStorage) DeleteIfCurrent(epoch *HistoryEpoch, tag string) bool {
	s.access.Lock()
	defer s.access.Unlock()
	if !s.currentLocked(epoch) || !s.writableLocked() {
		return false
	}
	delete(s.delayHistory, tag)
	s.notifyUpdated()
	return true
}

// PublishIfCurrent only admits a short in-memory publication. publish must not
// re-enter history, acquire a group lock, call external code, or wait. Group
// callers already hold their own admission lock before entering this method.
func (s *HistoryStorage) PublishIfCurrent(epoch *HistoryEpoch, publish func()) bool {
	s.access.RLock()
	defer s.access.RUnlock()
	if !s.currentLocked(epoch) {
		return false
	}
	publish()
	return true
}
