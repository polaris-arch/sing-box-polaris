package listener

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
)

type ReplacementMode string
const (
	ReplacementIndependent ReplacementMode = "independent-bind"
	ReplacementReuseTCP ReplacementMode = "reuse-tcp-acceptor"
	ReplacementExclusive ReplacementMode = "exclusive-rebind"
)

type ReplacementImpact struct {
	Mode ReplacementMode
	LocalReconnect bool
	UDPAssociationsInterrupted bool
	Reason string
}

type Restoration struct {
	Restored bool
	LocalReconnect bool
	UDPAssociationsInterrupted bool
	Error error
}

// Replacement is an exclusive reservation on two concrete listener instances.
// It never invokes a whole Box restart. Same-address rebind can fail twice: a
// candidate bind may fail, and restoring the previous bind may also fail. The
// latter is reported as degraded restoration, never successful rollback.
type Replacement struct {
	mu sync.Mutex
	previous *Listener
	next *Listener
	impact ReplacementImpact
	busy bool
	staged bool
	finished bool
	oldPauseAttempted bool
	oldPauseError error
	restoration *Restoration
	oldPaused bool
	oldReleased bool
	transferred bool
}
var replacementReservations sync.Mutex

func PlanReplacement(previous, next *Listener) (ReplacementImpact, error) {
	if next == nil || next.runtime == nil { return ReplacementImpact{}, errors.New("candidate listener requires runtime binding") }
	if previous == nil { return ReplacementImpact{Mode: ReplacementIndependent}, nil }
	if previous == next || previous.runtime == nil { return ReplacementImpact{}, errors.New("replacement requires distinct runtime listener instances") }
	if !listenersMayConflict(previous, next) { return ReplacementImpact{Mode: ReplacementIndependent}, nil }
	if onlyTCP(previous) && onlyTCP(next) && sameSocketOptions(previous, next) && canPauseTCP(previous) {
		return ReplacementImpact{Mode: ReplacementReuseTCP, Reason: "transfer paused TCP acceptor; established connections retain their original receiver"}, nil
	}
	udp := common.Contains(previous.network, N.NetworkUDP) || common.Contains(next.network, N.NetworkUDP)
	return ReplacementImpact{Mode: ReplacementExclusive, LocalReconnect: true, UDPAssociationsInterrupted: udp, Reason: "exclusive same-address socket must close before rebinding; restoration can require client reconnect"}, nil
}

func ReserveReplacement(previous, next *Listener, allowLocalReconnect bool) (*Replacement, error) {
	impact, err := PlanReplacement(previous, next)
	if err != nil { return nil, err }
	if impact.LocalReconnect && !allowLocalReconnect { return nil, errors.New("replacement requires explicit local-reconnect impact acceptance") }
	r := &Replacement{previous: previous, next: next, impact: impact}
	replacementReservations.Lock(); defer replacementReservations.Unlock()
	if previous != nil {
		previous.runtime.mu.Lock(); held := previous.runtime.replacement != nil || previous.runtime.setReplacement != nil; previous.runtime.mu.Unlock()
		if held { return nil, errors.New("previous listener already reserved") }
	}
	next.runtime.mu.Lock(); held := next.runtime.replacement != nil || next.runtime.setReplacement != nil; next.runtime.mu.Unlock()
	if held { return nil, errors.New("candidate listener already reserved") }
	if previous != nil { previous.runtime.mu.Lock(); previous.runtime.replacement = r; previous.runtime.mu.Unlock() }
	next.runtime.mu.Lock(); next.runtime.replacement = r; next.runtime.mu.Unlock()
	return r, nil
}
func (r *Replacement) Impact() ReplacementImpact { return r.impact }
func (r *Replacement) begin() error { r.mu.Lock(); defer r.mu.Unlock(); if r.busy || r.finished { return ErrRuntimeTransition }; r.busy = true; return nil }
func (r *Replacement) end() { r.mu.Lock(); r.busy = false; r.mu.Unlock() }
func (r *Replacement) releaseReservation() {
	replacementReservations.Lock(); defer replacementReservations.Unlock()
	if r.previous != nil { r.previous.runtime.mu.Lock(); r.previous.runtime.replacement = nil; r.previous.runtime.mu.Unlock() }
	r.next.runtime.mu.Lock(); r.next.runtime.replacement = nil; r.next.runtime.mu.Unlock()
}

// Stage completes every fallible socket operation before publication. On error,
// the reservation remains owned and Compensate must be called. A request cancel
// does not discard the record of physical effects which have already occurred.
func (r *Replacement) Stage(ctx context.Context) error {
	if err := r.begin(); err != nil { return err }; defer r.end()
	if r.staged { return nil }
	if err := ctx.Err(); err != nil { return err }
	if err := r.next.ValidateRuntime(); err != nil { return err }
	if r.impact.Mode == ReplacementIndependent {
		if err := r.next.Prepare(); err != nil { return err }
		if err := r.next.ArmIngress(); err != nil { return err }
	}
	if r.previous != nil {
		r.oldPauseAttempted = true
		var err error
		if r.impact.Mode == ReplacementExclusive { err = r.previous.PauseIngressForRebind() } else { err = r.previous.PauseIngress() }
		if err != nil {
			r.oldPauseError = err
			r.previous.runtime.mu.Lock()
			r.oldReleased = r.previous.runtime.tcpReleased || r.previous.runtime.udpReleased
			r.previous.runtime.mu.Unlock()
			return err
		}
		r.oldPaused = true
	}
	if err := ctx.Err(); err != nil { return err }
	switch r.impact.Mode {
	case ReplacementReuseTCP:
		if err := transferTCPAcceptor(r.previous, r.next); err != nil { return err }
		r.transferred = true
		if err := r.next.ArmIngress(); err != nil { return err }
	case ReplacementExclusive:
		r.oldReleased = true // a failed close is a real, possibly partial effect
		if err := r.previous.releaseRuntimeSockets(); err != nil { return err }
		if err := r.next.Prepare(); err != nil { return err }
		if err := r.next.ArmIngress(); err != nil { return err }
	}
	if err := ctx.Err(); err != nil { return err }
	r.staged = true
	return nil
}

// Commit is called after Box has published the candidate graph. Publication is
// the point of no return: a subsequent unexpected activation invariant failure
// is reported, not disguised by publishing the previous graph again.
func (r *Replacement) Commit() error {
	if err := r.begin(); err != nil { return err }; defer r.end()
	if !r.staged { return errors.New("replacement not staged") }
	r.finished = true
	err := r.next.Activate()
	r.releaseReservation()
	return err
}

func (r *Replacement) Compensate() Restoration {
	r.mu.Lock(); previous := r.restoration; r.mu.Unlock()
	if previous != nil { return *previous }
	if err := r.begin(); err != nil { return Restoration{Error: err} }; defer r.end()
	result := Restoration{LocalReconnect: r.oldReleased, UDPAssociationsInterrupted: r.oldReleased && r.impact.UDPAssociationsInterrupted}
	var err error
	if r.oldPauseAttempted && !r.oldPaused {
		r.previous.runtime.mu.Lock(); phase := r.previous.runtime.phase; r.previous.runtime.mu.Unlock()
		if phase != "active" && phase != "armed" { err = fmt.Errorf("previous ingress pause did not complete: %v", r.oldPauseError) }
	}
	if r.transferred {
		if err = r.next.PauseIngress(); err == nil { err = transferTCPAcceptor(r.next, r.previous) }
	}
	// Closing next cannot close a successfully transferred-back acceptor.
	err = errors.Join(err, r.next.RuntimeCloseAndWait())
	if r.previous != nil && r.oldPaused && err == nil {
		if r.oldReleased { err = r.previous.restoreRuntimeSockets() }
		if err == nil { err = r.previous.ArmIngress() }
		if err == nil { err = r.previous.Activate() }
	}
	result.Restored = err == nil
	if err != nil { result.Error = fmt.Errorf("listener compensation incomplete: %v", err) }
	r.mu.Lock(); r.finished = true; r.restoration = &result; r.mu.Unlock()
	r.releaseReservation()
	return result
}

func canPauseTCP(l *Listener) bool { l.runtime.mu.Lock(); defer l.runtime.mu.Unlock(); _, ok := l.tcpListener.(interface { SetDeadline(time.Time) error }); return ok }
func hasRuntimeTCP(l *Listener) bool { l.runtime.mu.Lock(); defer l.runtime.mu.Unlock(); return l.tcpListener != nil }
func hasRuntimeUDP(l *Listener) bool { l.runtime.mu.Lock(); defer l.runtime.mu.Unlock(); return l.udpConn != nil }
func onlyTCP(l *Listener) bool { return len(l.network) == 1 && l.network[0] == N.NetworkTCP }
func listenersMayConflict(a, b *Listener) bool {
	if a.listenOptions.ListenPort == 0 || a.listenOptions.ListenPort != b.listenOptions.ListenPort || a.listenOptions.NetNs != b.listenOptions.NetNs { return false }
	overlap := false; for _, network := range a.network { if slices.Contains(b.network, network) { overlap = true } }
	if !overlap { return false }
	defaultAddr := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	left, right := a.listenOptions.Listen.Build(defaultAddr), b.listenOptions.Listen.Build(defaultAddr)
	return left.IsUnspecified() || right.IsUnspecified() || left.Unmap() == right.Unmap()
}
func sameSocketOptions(a, b *Listener) bool {
	left, right := freezeListenOptions(a.listenOptions), freezeListenOptions(b.listenOptions)
	// Per-flow settings do not change the bound descriptor. Handler objects are
	// never reused here; transferTCPAcceptor changes only the acceptor's owner.
	left.Detour, right.Detour = "", ""
	left.UDPTimeout, right.UDPTimeout = 0, 0
	return reflect.DeepEqual(left, right) && a.tproxy == b.tproxy && !a.setSystemProxy && !b.setSystemProxy
}

func transferTCPAcceptor(from, to *Listener) error {
	// The replacement reservation and joined ingress make these object updates
	// private; neither mutex is held while calling foreign code.
	from.runtime.mu.Lock()
	if from.runtime.phase != "paused" && from.runtime.phase != "prepared" { from.runtime.mu.Unlock(); return ErrRuntimeTransition }
	conn := from.tcpListener
	if conn == nil || !from.runtime.ownsTCP { from.runtime.mu.Unlock(); return errors.New("TCP acceptor is not owned by transfer source") }
	from.runtime.mu.Unlock()
	to.runtime.mu.Lock()
	if to.runtime.phase != "inert" && to.runtime.phase != "released" { to.runtime.mu.Unlock(); return ErrRuntimeTransition }
	to.tcpListener = conn; to.runtime.ownsTCP = true; to.runtime.phase = "prepared"
	to.runtime.mu.Unlock()
	from.runtime.mu.Lock(); from.tcpListener = nil; from.runtime.ownsTCP = false; from.runtime.phase = "released"; from.runtime.mu.Unlock()
	return nil
}

func (l *Listener) releaseRuntimeSockets() error {
	r := l.runtime
	r.mu.Lock()
	if r.phase != "paused" && r.phase != "prepared" { r.mu.Unlock(); return ErrRuntimeTransition }
	r.phase = "releasing"
	if r.outputStarted { close(l.packetOutboundClosed) }
	r.outputStarted = false
	r.mu.Unlock()
	var err error
	if l.tcpListener != nil && !r.tcpReleased { err = l.tcpListener.Close() }
	if l.udpConn != nil && !r.udpReleased { err = errors.Join(err, l.udpConn.Close()) }
	r.output.Wait(); l.releasePacketOutbound()
	r.mu.Lock()
	if err == nil {
		l.tcpListener, l.udpConn = nil, nil
		r.ownsTCP, r.ownsUDP = false, false
		r.tcpReleased, r.udpReleased = false, false
		r.phase = "released"
		l.runtimeOutputStarted.Store(false)
	} else { r.phase = "release-failed" }
	r.mu.Unlock()
	if err != nil { return fmt.Errorf("exclusive socket release completion unknown: %v", err) }
	return nil
}
func (l *Listener) restoreRuntimeSockets() error {
	r := l.runtime
	r.mu.Lock()
	if r.phase != "released" { r.mu.Unlock(); return errors.New("old socket release did not complete; automatic restoration is unsafe") }
	r.phase = "inert"
	r.mu.Unlock()
	return l.Prepare()
}
