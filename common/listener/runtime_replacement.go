package listener

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	N "github.com/sagernet/sing/common/network"
)

type ReplacementMode string

const (
	ReplacementIndependent ReplacementMode = "independent-bind"
	ReplacementReuseTCP    ReplacementMode = "reuse-tcp-acceptor"
	ReplacementExclusive   ReplacementMode = "exclusive-rebind"
)

type ReplacementImpact struct {
	Mode                       ReplacementMode
	LocalReconnect             bool
	UDPAssociationsInterrupted bool
	Reason                     string
}
type Restoration struct {
	Restored                   bool
	LocalReconnect             bool
	UDPAssociationsInterrupted bool
	Error                      error
}

// Single replacements share the whole-set custody and compensation machinery.
// There is no second singleton path capable of closing a held IPv6 member.
type Replacement struct {
	transaction *ListenerSetTransaction
	impact      ReplacementImpact
}

var replacementReservations sync.Mutex

func PlanReplacement(previous, next *Listener) (ReplacementImpact, error) {
	if next == nil || next.runtime == nil {
		return ReplacementImpact{}, errors.New("candidate listener requires runtime binding")
	}
	var old []*Listener
	if previous != nil {
		old = []*Listener{previous}
	}
	t, err := planListenerSetMode(old, []*Listener{next}, true)
	if err != nil {
		return ReplacementImpact{}, err
	}
	if previous == nil {
		return ReplacementImpact{Mode: ReplacementIndependent}, nil
	}
	impact := ReplacementImpact{Mode: ReplacementIndependent, LocalReconnect: t.impact.LocalReconnect, UDPAssociationsInterrupted: t.impact.UDPAssociationsInterrupted}
	if listenersMayConflict(previous, next) {
		impact.Mode = ReplacementExclusive
		impact.Reason = "exclusive same-address socket must close before rebinding; restoration can require client reconnect"
		if len(t.moves) > 0 && !t.releaseOld[previous] && !t.holdOld[previous] {
			impact.Mode = ReplacementReuseTCP
			impact.Reason = "transfer paused TCP acceptors; established connections retain their original receiver"
		}
	}
	return impact, nil
}

func ReserveReplacement(previous, next *Listener, allowLocalReconnect bool) (*Replacement, error) {
	impact, err := PlanReplacement(previous, next)
	if err != nil {
		return nil, err
	}
	var old []*Listener
	if previous != nil {
		old = []*Listener{previous}
	}
	t, err := reserveListenerSetMode(old, []*Listener{next}, allowLocalReconnect, true)
	if err != nil {
		return nil, err
	}
	return &Replacement{transaction: t, impact: impact}, nil
}
func (r *Replacement) Impact() ReplacementImpact       { return r.impact }
func (r *Replacement) Stage(ctx context.Context) error { return r.transaction.Stage(ctx) }
func (r *Replacement) Commit() error                   { return r.transaction.Commit() }
func (r *Replacement) Compensate() Restoration         { return r.transaction.Compensate() }

func hasRuntimeUDP(l *Listener) bool {
	l.runtime.mu.Lock()
	defer l.runtime.mu.Unlock()
	return l.udpConn != nil
}
func onlyTCP(l *Listener) bool { return len(l.network) == 1 && l.network[0] == N.NetworkTCP }
func listenersMayConflict(a, b *Listener) bool {
	if a.listenOptions.ListenPort == 0 || a.listenOptions.ListenPort != b.listenOptions.ListenPort || a.listenOptions.NetNs != b.listenOptions.NetNs {
		return false
	}
	overlap := false
	for _, network := range a.network {
		if slices.Contains(b.network, network) {
			overlap = true
		}
	}
	if !overlap {
		return false
	}
	defaultAddr := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	left, right := a.listenOptions.Listen.Build(defaultAddr), b.listenOptions.Listen.Build(defaultAddr)
	return left.IsUnspecified() || right.IsUnspecified() || left.Unmap() == right.Unmap()
}

// releaseRuntimeSockets releases only the legacy handoff members. An old
// narrow-exclusive IPv6 socket remains physically owned through K and H.
func (l *Listener) releaseRuntimeSockets() error {
	r := l.runtime
	r.mu.Lock()
	if r.phase != "paused" && r.phase != "prepared" {
		r.mu.Unlock()
		return ErrRuntimeTransition
	}
	r.phase = "releasing"
	if r.outputStarted {
		close(l.packetOutboundClosed)
	}
	r.outputStarted = false
	r.mu.Unlock()
	err := l.closeRuntimeTCPMembers(false)
	if l.udpConn != nil && !r.udpReleased {
		err = errors.Join(err, runtimeSocketCall(l.udpConn.Close))
	}
	r.output.Wait()
	l.releasePacketOutbound()
	r.mu.Lock()
	if err == nil {
		l.udpConn = nil
		r.ownsUDP = false
		r.udpReleased = false
		if r.tcp.count == 0 {
			r.phase = "released"
		} else {
			r.phase = "paused"
		}
		l.runtimeOutputStarted.Store(false)
	} else {
		r.phase = "release-failed"
		r.socketCloseErr = errors.Join(r.socketCloseErr, err)
	}
	r.mu.Unlock()
	if err != nil {
		return fmt.Errorf("exclusive socket release completion unknown: %v", err)
	}
	return nil
}

func (l *Listener) restoreRuntimeSockets() error {
	r := l.runtime
	r.mu.Lock()
	if r.phase != "released" && r.phase != "paused" {
		r.mu.Unlock()
		return errors.New("old socket release did not complete; automatic restoration is unsafe")
	}
	r.phase = "inert"
	r.mu.Unlock()
	return l.prepareRuntimeForSet()
}
