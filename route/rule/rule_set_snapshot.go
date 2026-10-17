package rule

import (
 "sync"
 "sync/atomic"

 "github.com/sagernet/sing-box/adapter"
 E "github.com/sagernet/sing/common/exceptions"
 "github.com/sagernet/sing/common/x/list"
)

// Rules and all data derived from them are immutable after publication. Readers
// retain one generation, including the merge decision and its fallback match.
// This is a per-rule-set transaction, not an atomic replacement of the router.
type ruleSetSnapshot struct {
 rules []adapter.HeadlessRule
 metadata adapter.RuleSetMetadata
 digest string
 revision uint64
}
var emptyRuleSetSnapshot = &ruleSetSnapshot{}

type ruleSetPublication struct {
 access sync.RWMutex
 reloadAccess sync.Mutex
 snapshot atomic.Pointer[ruleSetSnapshot]
 closed bool
 watcherState string
 lastError string
 callbacks list.List[adapter.RuleSetUpdateCallback]
}
func (s *ruleSetPublication) loadSnapshot() *ruleSetSnapshot {
 if p := s.snapshot.Load(); p != nil { return p }
 return emptyRuleSetSnapshot
}
func (s *ruleSetPublication) publish(rules []adapter.HeadlessRule, metadata adapter.RuleSetMetadata, digest string) ([]adapter.RuleSetUpdateCallback, error) {
 s.access.Lock()
 defer s.access.Unlock()
 if s.closed { return nil, E.New("rule-set is closed") }
 old := s.loadSnapshot()
 s.snapshot.Store(&ruleSetSnapshot{rules: rules, metadata: metadata, digest: digest, revision: old.revision + 1})
 s.lastError = ""
 return s.callbacks.Array(), nil
}
func (s *ruleSetPublication) recordError(err error) {
 if err == nil { return }
 s.access.Lock()
 defer s.access.Unlock()
 if !s.closed { s.lastError = err.Error() }
}
func (s *ruleSetPublication) closePublication() {
 s.access.Lock()
 defer s.access.Unlock()
 s.closed = true
 s.watcherState = "closed"
 old := s.loadSnapshot()
 // Never mutate a retired rule or slice: in-flight matches own that snapshot.
 s.snapshot.Store(&ruleSetSnapshot{metadata: old.metadata, revision: old.revision})
}
func (s *ruleSetPublication) cleanupPublication() {
 s.access.Lock()
 defer s.access.Unlock()
 old := s.loadSnapshot()
 s.snapshot.Store(&ruleSetSnapshot{metadata: old.metadata, revision: old.revision})
}
func (s *ruleSetPublication) RuleSetStatus() adapter.RuleSetLoadStatus {
 s.access.RLock()
 defer s.access.RUnlock()
 p := s.loadSnapshot()
 return adapter.RuleSetLoadStatus{ActiveDigest:p.digest, Revision:p.revision, WatcherState:s.watcherState, LastError:s.lastError, Closed:s.closed}
}

type ruleSetSnapshotProvider interface { loadSnapshot() *ruleSetSnapshot }
