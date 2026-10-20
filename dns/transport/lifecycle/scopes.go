package lifecycle

import (
	"context"
	"errors"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

// Scopes bounds live and retiring socket cohorts inside a resolver. Replacing a
// discovered server list explicitly reconnects only that list's sockets. Close
// runs off callback/update stacks and joins the underlying transports' actual
// worker cleanup. Failed cleanup remains charged and is returned by Close.
// This is cleanup bookkeeping, not another runtime resource reference system.
type Scopes struct {
	access sync.Mutex
	sealed bool
	entries map[*adapter.Scope]bool
	workers sync.WaitGroup
	errors []error
	changed chan struct{}
}

// One active cohort and one candidate/retiring cohort. A further replacement
// waits for actual retirement rather than growing an arbitrary backlog.
var ErrSocketCohortBusy = errors.New("previous DNS socket cohort is still retiring")

func (s *Scopes) New(ctx context.Context, logger log.ContextLogger) (*adapter.Scope, error) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.sealed { return nil, ErrStopped }
	if len(s.entries) >= 2 { return nil, ErrSocketCohortBusy }
	if s.entries == nil { s.entries = make(map[*adapter.Scope]bool) }
	scope := adapter.NewScope(ctx, logger)
	s.entries[scope] = false
	return scope, nil
}

func (s *Scopes) Retire(scope *adapter.Scope) {
	if scope == nil { return }
	s.access.Lock()
	closing, exists := s.entries[scope]
	if !exists || closing { s.access.Unlock(); return }
	s.entries[scope] = true
	s.workers.Add(1)
	s.access.Unlock()
	go func() {
		defer s.workers.Done()
		err := CleanupResult("DNS socket cohort", func() error { return Uncertain("DNS socket cohort", scope.Close()) })
		s.access.Lock()
		if err == nil { delete(s.entries, scope); s.signalLocked() } else { s.errors = append(s.errors, err) }
		s.access.Unlock()
	}()
}

func (s *Scopes) Stop() {
	s.access.Lock()
	s.sealed = true
	s.signalLocked()
	entries := make([]*adapter.Scope, 0, len(s.entries))
	for scope := range s.entries { entries = append(entries, scope) }
	s.access.Unlock()
	for _, scope := range entries { s.Retire(scope) }
}

func (s *Scopes) Close() error {
	s.Stop()
	// Stop scheduled every remaining entry before waiting; sealed admission
	// prevents a future zero-to-one Add racing this wait.
	s.workers.Wait()
	s.access.Lock(); defer s.access.Unlock()
	return errors.Join(s.errors...)
}

func (s *Scopes) signalLocked() {
	if s.changed != nil { close(s.changed) }
	s.changed = make(chan struct{})
}

// WaitReady waits for actual successful cleanup, not a cancellation request.
// An uncertain cohort remains charged until component shutdown reports it.
func (s *Scopes) WaitReady(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil { return err }
		s.access.Lock()
		if s.sealed { s.access.Unlock(); return ErrStopped }
		if len(s.entries) < 2 { s.access.Unlock(); return nil }
		if s.changed == nil { s.changed = make(chan struct{}) }
		changed := s.changed
		s.access.Unlock()
		select { case <-ctx.Done(): return ctx.Err(); case <-changed: }
	}
}
