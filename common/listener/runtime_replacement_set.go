package listener

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// ListenerSetImpact includes only physical restrictions, not protocol/schema
// exclusions. In particular port swaps and TCP/UDP splits are staged as a group.
type ListenerSetImpact struct {
	LocalReconnect             bool
	UDPAssociationsInterrupted bool
	Reasons                    []string
}

type listenerOldState struct {
	paused     bool
	released   bool
	pauseError error
}

type ListenerSetTransaction struct {
	mu          sync.Mutex
	previous    []*Listener
	next        []*Listener
	reuse       map[*Listener]*Listener
	releaseOld  map[*Listener]bool
	oldState    map[*Listener]*listenerOldState
	transferred map[*Listener]bool
	impact      ListenerSetImpact
	busy        bool
	staged      bool
	finished    bool
	restoration *Restoration
}

// ReserveListenerSet takes only changed/removed old listeners and new candidate
// listeners. Unchanged retained listeners stay outside the set; Box must still
// include their endpoint occupancy when validating the full candidate inventory.
// Every pointer may occur once. There is one reservation for the whole set.
func planListenerSet(previous, next []*Listener) (*ListenerSetTransaction, error) {
	t := &ListenerSetTransaction{previous: append([]*Listener(nil), previous...), next: append([]*Listener(nil), next...), reuse: make(map[*Listener]*Listener), releaseOld: make(map[*Listener]bool), oldState: make(map[*Listener]*listenerOldState), transferred: make(map[*Listener]bool)}
	seen := make(map[*Listener]bool)
	for _, l := range append(append([]*Listener(nil), previous...), next...) {
		if l == nil || l.runtime == nil || seen[l] {
			return nil, errors.New("listener set requires distinct runtime instances")
		}
		seen[l] = true
	}
	for i, candidate := range next {
		for _, other := range next[:i] {
			if listenersMayConflict(candidate, other) {
				return nil, errors.New("candidate listeners have overlapping exclusive endpoints")
			}
		}
	}
	used := make(map[*Listener]bool)
	for _, candidate := range next {
		for _, old := range previous {
			if !used[old] && onlyTCP(old) && onlyTCP(candidate) && listenersMayConflict(old, candidate) && sameSocketOptions(old, candidate) && canPauseTCP(old) {
				t.reuse[candidate] = old
				used[old] = true
				break
			}
		}
	}
	for _, old := range previous {
		t.oldState[old] = &listenerOldState{}
		// A retired, untransferred listening socket must not remain an
		// invisible address reservation after it leaves the active inventory.
		// Established TCP sessions are independent; UDP write-back associations
		// on an exclusively released socket are disclosed as interrupted.
		if !used[old] || (hasRuntimeTCP(old) && !canPauseTCP(old)) {
			t.releaseOld[old] = true
		}
		for _, candidate := range next {
			if listenersMayConflict(old, candidate) && t.reuse[candidate] != old {
				t.releaseOld[old] = true
			}
		}
		if t.releaseOld[old] {
			t.impact.LocalReconnect = true
			if hasRuntimeUDP(old) {
				t.impact.UDPAssociationsInterrupted = true
			}
			t.impact.Reasons = append(t.impact.Reasons, "old listener must release its exclusive or non-interruptible socket before candidate bind")
		}
	}
	return t, nil
}

func PlanListenerSet(previous, next []*Listener) (ListenerSetImpact, error) {
	t, err := planListenerSet(previous, next)
	if err != nil {
		return ListenerSetImpact{}, err
	}
	return t.Impact(), nil
}

func ReserveListenerSet(previous, next []*Listener, allowLocalReconnect bool) (*ListenerSetTransaction, error) {
	t, err := planListenerSet(previous, next)
	if err != nil {
		return nil, err
	}
	if t.impact.LocalReconnect && !allowLocalReconnect {
		return nil, errors.New("listener set requires explicit local-reconnect impact acceptance")
	}
	all := append(append([]*Listener(nil), previous...), next...)
	replacementReservations.Lock()
	defer replacementReservations.Unlock()
	for _, l := range all {
		l.runtime.mu.Lock()
		held := l.runtime.replacement != nil || l.runtime.setReplacement != nil
		l.runtime.mu.Unlock()
		if held {
			return nil, errors.New("listener is already reserved")
		}
	}
	for _, l := range previous {
		l.runtime.mu.Lock()
		phase := l.runtime.phase
		l.runtime.mu.Unlock()
		if phase != "active" {
			return nil, errors.New("previous listener is not active")
		}
	}
	for _, l := range next {
		l.runtime.mu.Lock()
		phase := l.runtime.phase
		l.runtime.mu.Unlock()
		if phase != "inert" && phase != "prepared" {
			return nil, errors.New("candidate listener is not inert or privately prepared")
		}
	}
	for _, l := range all {
		l.runtime.mu.Lock()
		l.runtime.setReplacement = t
		l.runtime.mu.Unlock()
	}
	return t, nil
}

func (t *ListenerSetTransaction) Impact() ListenerSetImpact {
	result := t.impact
	result.Reasons = append([]string(nil), result.Reasons...)
	return result
}

func (t *ListenerSetTransaction) begin() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.busy || t.finished {
		return ErrRuntimeTransition
	}
	t.busy = true
	return nil
}
func (t *ListenerSetTransaction) end() { t.mu.Lock(); t.busy = false; t.mu.Unlock() }
func (t *ListenerSetTransaction) releaseReservations() {
	replacementReservations.Lock()
	defer replacementReservations.Unlock()
	for _, l := range append(append([]*Listener(nil), t.previous...), t.next...) {
		l.runtime.mu.Lock()
		l.runtime.setReplacement = nil
		l.runtime.mu.Unlock()
	}
}

func (t *ListenerSetTransaction) Stage(ctx context.Context) error {
	if err := t.begin(); err != nil {
		return err
	}
	defer t.end()
	if t.staged {
		return nil
	}
	for _, candidate := range t.next {
		if err := candidate.ValidateRuntime(); err != nil {
			return err
		}
	}
	for _, old := range t.previous {
		if err := ctx.Err(); err != nil {
			return err
		}
		state := t.oldState[old]
		var err error
		if t.releaseOld[old] {
			err = old.PauseIngressForRebind()
		} else {
			err = old.PauseIngress()
		}
		if err != nil {
			state.pauseError = err
			return err
		}
		state.paused = true
	}
	// All old readers are joined before releasing any conflicting descriptor.
	for _, old := range t.previous {
		if t.releaseOld[old] {
			t.oldState[old].released = true
			if err := old.releaseRuntimeSockets(); err != nil {
				return err
			}
		}
	}
	for _, candidate := range t.next {
		if err := ctx.Err(); err != nil {
			return err
		}
		if old := t.reuse[candidate]; old != nil {
			if err := transferTCPAcceptor(old, candidate); err != nil {
				return err
			}
			t.transferred[candidate] = true
		} else if err := candidate.Prepare(); err != nil {
			return err
		}
	}
	for _, candidate := range t.next {
		if err := candidate.ArmIngress(); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	t.staged = true
	return nil
}

func (t *ListenerSetTransaction) Commit() error {
	if err := t.begin(); err != nil {
		return err
	}
	defer t.end()
	if !t.staged {
		return errors.New("listener set not staged")
	}
	t.finished = true
	var err error
	for _, candidate := range t.next {
		err = errors.Join(err, candidate.Activate())
	}
	t.releaseReservations()
	return err
}

// Compensate first removes every candidate bind, then restores old binds. This
// order is essential for port swaps and split/merged TCP+UDP inventories. It
// returns each physical interruption even if address restoration succeeds.
func (t *ListenerSetTransaction) Compensate() Restoration { return t.CompensateBeforeActivate(nil) }

// The callback runs after actual old sockets are restored and armed, while
// public admission remains closed. It may perform fallible control restoration;
// failure preserves closed admission and is never reported as rollback success.
// No transaction/listener/publication mutex is held while invoking it.
func (t *ListenerSetTransaction) CompensateBeforeActivate(beforeActivate func() error) Restoration {
	t.mu.Lock()
	previous := t.restoration
	t.mu.Unlock()
	if previous != nil {
		return *previous
	}
	if err := t.begin(); err != nil {
		return Restoration{Error: err}
	}
	defer t.end()
	result := Restoration{}
	var err error
	for _, candidate := range t.next {
		if t.transferred[candidate] {
			pauseErr := candidate.PauseIngress()
			if pauseErr == nil {
				pauseErr = transferTCPAcceptor(candidate, t.reuse[candidate])
			}
			if pauseErr != nil {
				err = errors.Join(err, pauseErr)
			}
		}
	}
	for _, candidate := range t.next {
		err = errors.Join(err, candidate.RuntimeCloseAndWait())
	}
	// Even with a candidate cleanup failure, attempt independent old restores;
	// any bind conflict or uncertain close remains visible in the aggregate.
	for _, old := range t.previous {
		state := t.oldState[old]
		status := old.RuntimeStatus()
		old.runtime.mu.Lock()
		physicallyClosed := old.runtime.tcpReleased || old.runtime.udpReleased
		old.runtime.mu.Unlock()
		if state.released || physicallyClosed {
			result.LocalReconnect = true
			if t.impact.UDPAssociationsInterrupted {
				result.UDPAssociationsInterrupted = true
			}
		}
		if state.pauseError != nil {
			err = errors.Join(err, fmt.Errorf("previous ingress pause incomplete: %v", state.pauseError))
			continue
		}
		if !state.paused {
			continue
		}
		var restoreErr error
		if status.Phase == "released" {
			restoreErr = old.restoreRuntimeSockets()
		}
		if restoreErr == nil {
			restoreErr = old.ArmIngress()
		}
		err = errors.Join(err, restoreErr)
	}
	if err == nil && beforeActivate != nil {
		err = beforeActivate()
	}
	if err == nil {
		for _, old := range t.previous {
			if t.oldState[old].paused {
				err = errors.Join(err, old.Activate())
			}
		}
	}
	result.Restored = err == nil
	if err != nil {
		result.Error = fmt.Errorf("listener set compensation incomplete: %v", err)
	}
	t.mu.Lock()
	t.finished = true
	t.restoration = &result
	t.mu.Unlock()
	t.releaseReservations()
	return result
}
