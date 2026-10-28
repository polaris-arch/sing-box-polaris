package urltest

import (
	"github.com/sagernet/sing-box/adapter"
)

// RuntimeHistoryView is implemented by the immutable admitted graph. Histories
// and their consumer lists belong to actual resource incarnations, not tags in
// a mutable global catalog. Each returned list is detached from the view.
type RuntimeHistoryView interface {
	RuntimeURLTestHistory(string) (*HistoryStorage, adapter.RuntimeResourceID, bool)
	RuntimeURLTestConsumers(string) []*HistoryStorage
}

// BindRuntimeAdmission makes Store publication the sole authority for visible
// history. No coordinator callback is registered. Reads acquire Store outside
// the history mutex and retain that graph until all result values are copied.
func (s *HistoryStorage) BindRuntimeAdmission(admission adapter.RuntimeAdmission) {
	if s == nil {
		return
	}
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed || s.authority != s {
		return
	}
	s.runtimeAdmission = admission
	clear(s.delayHistory)
}

// SetRuntimeActiveHistories controls notifications only, never visible values.
// Call immediately after successful Store publication. The reconciliation event
// causes consumers to reread the currently admitted immutable graph. A stale
// event in the publication interval carries no history payload and authorizes
// only that current reread, never old-incarnation values.
func (s *HistoryStorage) SetRuntimeActiveHistories(histories []*HistoryStorage) {
	if s == nil {
		return
	}
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed || s.authority != s {
		return
	}
	active := make(map[*HistoryStorage]struct{}, len(histories))
	for _, history := range histories {
		if history != nil && history != s && history.authority == s && !history.closed {
			active[history] = struct{}{}
		}
	}
	s.runtimeActive = active
	s.notifyLocalLocked()
}

func (s *HistoryStorage) runtimeReader() (adapter.RuntimeLease, RuntimeHistoryView, bool) {
	s.access.RLock()
	admission := s.runtimeAdmission
	bound := s.authority == s && admission != nil
	closed := s.closed
	s.access.RUnlock()
	if !bound {
		return nil, nil, false
	}
	if closed {
		return nil, nil, true
	}
	lease, err := admission.Acquire()
	if err != nil {
		return nil, nil, true
	}
	view, ok := lease.View().(RuntimeHistoryView)
	if !ok {
		lease.Release()
		return nil, nil, true
	}
	return lease, view, true
}

func (s *HistoryStorage) projectedHistoryLocked(tag string, histories []*HistoryStorage) *adapter.URLTestHistory {
	var latest *adapter.URLTestHistory
	for _, history := range histories {
		if history == nil || history.authority != s.authority || history.closed || !history.currentLocked(s.epoch) {
			continue
		}
		value := history.delayHistory[tag]
		if value != nil && (latest == nil || value.Time.After(latest.Time)) {
			latest = value
		}
	}
	if latest == nil {
		return nil
	}
	copy := *latest
	return &copy
}

func (s *HistoryStorage) projectedLoad(tag string) (*adapter.URLTestHistory, bool) {
	lease, view, bound := s.runtimeReader()
	if !bound || lease == nil {
		return nil, bound
	}
	defer lease.Release()
	consumers := view.RuntimeURLTestConsumers(tag)
	s.access.RLock()
	defer s.access.RUnlock()
	if s.closed {
		return nil, true
	}
	return s.projectedHistoryLocked(tag, consumers), true
}

func (s *HistoryStorage) projectedSnapshot(epoch *HistoryEpoch) (map[string]*adapter.URLTestHistory, bool, bool) {
	lease, view, bound := s.runtimeReader()
	if !bound || lease == nil {
		return nil, false, bound
	}
	defer lease.Release()
	consumers := make(map[string][]*HistoryStorage)
	for _, outbound := range lease.View().OutboundManager().Outbounds() {
		consumers[outbound.Tag()] = view.RuntimeURLTestConsumers(outbound.Tag())
	}
	s.access.RLock()
	defer s.access.RUnlock()
	if !s.currentLocked(epoch) {
		return nil, false, true
	}
	result := make(map[string]*adapter.URLTestHistory)
	for tag, histories := range consumers {
		if value := s.projectedHistoryLocked(tag, histories); value != nil {
			result[tag] = value
		}
	}
	return result, true, true
}

func (s *HistoryStorage) writableLocked() bool {
	return !s.closed && (s.authority != s || s.runtimeAdmission == nil)
}
