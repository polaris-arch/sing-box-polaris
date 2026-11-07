package listener

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

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
type runtimeTCPMove struct {
	member      *runtimeTCPMember
	from, to    *Listener
	transferred bool
}
type ListenerSetTransaction struct {
	mu                     sync.Mutex
	previous, next         []*Listener
	moves                  []*runtimeTCPMove
	releaseOld             map[*Listener]bool
	holdOld                map[*Listener]bool
	oldState               map[*Listener]*listenerOldState
	impact                 ListenerSetImpact
	busy, staged, finished bool
	restoration            *Restoration
	retirement             *ListenerRetirement
}

// PhysicalHandoffError is a structural refusal, not an attempted bind failure.
// It requires an actual conflicting exclusive member which cannot transfer.
type PhysicalHandoffError struct{}

func (*PhysicalHandoffError) Error() string {
	return "exclusive IPv6 endpoint cannot transfer without destroying rollback custody; restart required"
}

func planListenerSet(previous, next []*Listener) (*ListenerSetTransaction, error) {
	return planListenerSetMode(previous, next, false)
}

// The standalone replacement historically holds nonconflicting pure TCP old
// ingress through commit. Keep that zero-reconnect contract in the same engine;
// Box and ordinary ListenerSet removal still release ordinary old binds in Stage.
func planListenerSetMode(previous, next []*Listener, standalone bool) (*ListenerSetTransaction, error) {
	t := &ListenerSetTransaction{previous: append([]*Listener(nil), previous...), next: append([]*Listener(nil), next...), releaseOld: make(map[*Listener]bool), holdOld: make(map[*Listener]bool), oldState: make(map[*Listener]*listenerOldState)}
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
	used := make(map[*runtimeTCPMember]bool)
	for _, candidate := range next {
		for _, spec := range candidate.runtimeTCPExpected() {
			// A privately prepared candidate already owns its actual binding.
			if candidate.hasRuntimeTCPMember(spec) {
				continue
			}
			found := false
			for _, old := range previous {
				for _, member := range old.runtimeTCPMembers() {
					if !used[member] && runtimeTCPInterruptible(member) && sameRuntimeTCPOptions(old, candidate, member.spec, spec) {
						t.moves = append(t.moves, &runtimeTCPMove{member: member, from: old, to: candidate})
						used[member] = true
						found = true
						break
					}
				}
				if found {
					break
				}
			}
		}
	}
	for _, old := range previous {
		t.oldState[old] = &listenerOldState{}
		for _, member := range old.runtimeTCPMembers() {
			if used[member] {
				continue
			}
			if member.spec.narrowExclusive {
				if !runtimeTCPInterruptible(member) {
					return nil, &PhysicalHandoffError{}
				}
				for _, candidate := range next {
					for _, spec := range candidate.runtimeTCPExpected() {
						if runtimeTCPConflict(member.spec, spec) {
							return nil, &PhysicalHandoffError{}
						}
					}
				}
				t.holdOld[old] = true
			} else if standalone && onlyTCP(old) && runtimeTCPInterruptible(member) && !runtimeTCPConflictsCandidates(member.spec, next) {
				t.holdOld[old] = true
			} else {
				t.releaseOld[old] = true
			}
		}
		if hasRuntimeUDP(old) {
			t.releaseOld[old] = true
		}
		if t.releaseOld[old] {
			t.impact.LocalReconnect = true
			if hasRuntimeUDP(old) {
				t.impact.UDPAssociationsInterrupted = true
			}
			t.impact.Reasons = append(t.impact.Reasons, "old ordinary or non-interruptible socket requires local handoff; exclusive IPv6 ingress is retained until publication")
		}
	}
	t.retirement = newListenerRetirement(previous, t.holdOld)
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
	return reserveListenerSetMode(previous, next, allowLocalReconnect, false)
}

func reserveListenerSetMode(previous, next []*Listener, allowLocalReconnect, standalone bool) (*ListenerSetTransaction, error) {
	t, err := planListenerSetMode(previous, next, standalone)
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
		held := l.runtime.setReplacement != nil
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
		if l.runtime.setReplacement == t {
			l.runtime.setReplacement = nil
		}
		l.runtime.mu.Unlock()
	}
}

func (t *ListenerSetTransaction) isTransferredSpec(candidate *Listener, spec runtimeTCPBindSpec) bool {
	for _, move := range t.moves {
		if move.to == candidate && runtimeTCPSameEndpoint(move.member.spec, spec) {
			return true
		}
	}
	return false
}

func (t *ListenerSetTransaction) conflictsWithOld(spec runtimeTCPBindSpec) bool {
	for _, old := range t.previous {
		for _, member := range old.runtimeTCPMembers() {
			if runtimeTCPConflict(member.spec, spec) {
				return true
			}
		}
	}
	return false
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
	// Acquire all independent real TCP sockets before any old pause or release.
	// In particular new tcp6 rejects occupancy while old IPv4 remains active.
	for _, candidate := range t.next {
		if candidate.runtime.prepareSockets != nil {
			continue
		}
		for index := 0; index < len(candidate.runtimeTCPExpected()); index++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			spec := candidate.runtimeTCPExpected()[index]
			if candidate.hasRuntimeTCPMember(spec) || t.isTransferredSpec(candidate, spec) || t.conflictsWithOld(spec) {
				continue
			}
			if err := candidate.prepareRuntimeTCPMember(spec); err != nil {
				return err
			}
		}
	}
	for _, old := range t.previous {
		if err := ctx.Err(); err != nil {
			return err
		}
		state := t.oldState[old]
		before := old.runtimeTCPMembers()
		var err error
		if t.releaseOld[old] {
			err = old.PauseIngressForRebind()
		} else {
			err = old.PauseIngress()
		}
		// PauseForRebind can itself close an ordinary acceptor. Record that
		// physical effect even if a later pause, cancellation or move fails.
		for _, member := range before {
			select {
			case <-member.close.done:
				state.released = true
			default:
			}
		}
		old.runtime.mu.Lock()
		state.released = state.released || old.runtime.udpReleased
		old.runtime.mu.Unlock()
		if err != nil {
			state.pauseError = err
			return err
		}
		state.paused = true
	}
	// Every old ingress worker is joined before any descriptor custody moves.
	for _, move := range t.moves {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := moveRuntimeTCPMember(move.from, move.to, move.member); err != nil {
			return err
		}
		move.transferred = true
	}
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
		if err := candidate.prepareRuntimeForSet(); err != nil {
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

// Standalone users also own H: do not leak a held old listener when they use
// Commit instead of Box's prepared graph publication. Native retirement occurs
// only after the transaction operation has released its mutex/reservations.
func (t *ListenerSetTransaction) Commit() error {
	// PreparePublication owns begin/end and validates every candidate gate
	// before any opens. Failure leaves the staged set available to Compensate.
	publication, err := t.PreparePublication()
	if err != nil {
		return err
	}
	publication.Publish()
	publication.Finish()
	return t.retirement.RetirePrevious()
}

func (t *ListenerSetTransaction) Compensate() Restoration { return t.CompensateBeforeActivate(nil) }
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
	// Return exact transferred members before candidate-owned socket cleanup.
	pausedCandidates := make(map[*Listener]bool)
	for _, move := range t.moves {
		if !move.transferred {
			continue
		}
		candidate := move.to
		if !pausedCandidates[candidate] {
			candidate.runtime.mu.Lock()
			phase := candidate.runtime.phase
			candidate.runtime.mu.Unlock()
			var pauseErr error
			if phase == "active" || phase == "armed" {
				pauseErr = candidate.PauseIngress()
			} else if phase == "inert" || phase == "prepared" || phase == "failed" {
				// prepareRuntimeForSet never starts workers on these phases.
				candidate.runtime.mu.Lock()
				candidate.runtime.phase = "paused"
				candidate.runtime.mu.Unlock()
			} else if phase != "paused" {
				pauseErr = ErrRuntimeTransition
			}
			if pauseErr != nil {
				err = errors.Join(err, pauseErr)
				continue
			}
			pausedCandidates[candidate] = true
		}
		moveErr := moveRuntimeTCPMember(candidate, move.from, move.member)
		if moveErr == nil {
			move.transferred = false
		}
		err = errors.Join(err, moveErr)
	}
	for _, candidate := range t.next {
		err = errors.Join(err, candidate.RuntimeCloseAndWait())
	}
	for _, old := range t.previous {
		state := t.oldState[old]
		if state.released {
			result.LocalReconnect = true
			result.UDPAssociationsInterrupted = t.impact.UDPAssociationsInterrupted
		}
		if state.pauseError != nil {
			err = errors.Join(err, fmt.Errorf("previous ingress pause incomplete: %v", state.pauseError))
			continue
		}
		if !state.paused {
			continue
		}
		var restoreErr error
		if state.released {
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

func runtimeTCPConflictsCandidates(spec runtimeTCPBindSpec, next []*Listener) bool {
	for _, candidate := range next {
		for _, wanted := range candidate.runtimeTCPExpected() {
			if runtimeTCPConflict(spec, wanted) {
				return true
			}
		}
	}
	return false
}
