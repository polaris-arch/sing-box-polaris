package listener

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
)

var (
	ErrRuntimeTransition   = errors.New("listener lifecycle transition is in progress")
	ErrRuntimeRawTransport = errors.New("raw listener transport needs its staged runtime lifecycle adapter")
	ErrRuntimeSystemEffect = errors.New("system proxy requires a staged platform-effect transaction")
	ErrPauseRequiresRebind = errors.New("listener cannot interrupt Accept without closing; plan a local rebind")
)

type (
	runtimeBindingKey struct{}
	RuntimeBinding    struct{ Admission adapter.RuntimeAdmission }
)

// ContextWithRuntimeBinding opts a constructor into inert listener creation.
// The exact resource source is taken from that constructor's own context.
func ContextWithRuntimeBinding(ctx context.Context, binding RuntimeBinding) context.Context {
	return context.WithValue(ctx, runtimeBindingKey{}, binding)
}

type runtimeListener struct {
	mu             sync.Mutex
	phase          string
	gateway        *AdmissionGateway
	stopped        atomic.Bool
	runStop        chan struct{}
	ingress        sync.WaitGroup
	output         sync.WaitGroup
	outputStarted  bool
	closeDone      chan struct{}
	closeErr       error
	socketCloseErr error
	ingressErr     error
	setReplacement *ListenerSetTransaction
	// Test fixtures can replace binding without touching a real socket.
	prepareSockets          func() error
	constructionErr         error
	tcp                     runtimeTCPSet
	ownsUDP                 bool
	udpReleased             bool
	udpLocal                atomic.Pointer[net.UDPAddr]
	packetTransportDeclared bool
	control                 RuntimePacketControl
	controlOpen             bool
	controlEnding           bool
	controlCalls            sync.WaitGroup
	directWrites            sync.WaitGroup
	controlError            error
}

func freezeListenOptions(options option.ListenOptions) option.ListenOptions {
	if options.Listen != nil {
		value := *options.Listen
		options.Listen = &value
	}
	if options.UDPFragment != nil {
		value := *options.UDPFragment
		options.UDPFragment = &value
	}
	return options
}

func (l *Listener) initializeRuntime() {
	if l.ctx == nil {
		l.ctx = context.Background()
	}
	binding, exists := l.ctx.Value(runtimeBindingKey{}).(RuntimeBinding)
	if !exists && !adapter.IsRuntimePreparation(l.ctx) {
		return
	}
	source, found := adapter.RuntimeResourceSourceFromContext(l.ctx)
	l.runtime = &runtimeListener{phase: "inert", gateway: NewAdmissionGateway(binding.Admission, source), closeDone: make(chan struct{})}
	if binding.Admission == nil || !found {
		l.runtime.constructionErr = errors.New("runtime listener has no admission/resource binding")
		return
	}
	if !adapter.HasConstructionScope(l.ctx) {
		l.runtime.constructionErr = errors.New("runtime listener requires construction cleanup registration")
		return
	}
	l.runtime.constructionErr = adapter.DeferConstructionCleanup(l.ctx, l.RuntimeCloseAndWait)
	if l.runtime.constructionErr == nil {
		l.runtime.constructionErr = adapter.ConstructionScopeErr(l.ctx)
	}
}

func (l *Listener) RuntimeEnabled() bool { return l.runtime != nil }

// ValidateRuntime checks the concrete handler contract without opening sockets.
func (l *Listener) ValidateRuntime() error {
	r := l.runtime
	if r == nil {
		return errors.New("listener has no runtime binding")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.constructionErr != nil {
		return r.constructionErr
	}
	if l.setSystemProxy {
		return ErrRuntimeSystemEffect
	}
	if common.Contains(l.network, N.NetworkTCP) {
		if err := l.validateRuntimeTCPPolicy(); err != nil {
			return err
		}
	}
	if common.Contains(l.network, N.NetworkTCP) && l.connHandler == nil {
		return errors.New("TCP listener has no connection handler")
	}
	if common.Contains(l.network, N.NetworkUDP) && !(r.packetTransportDeclared && l.packetHandler == nil && l.oobPacketHandler == nil) {
		if l.oobPacketHandler != nil {
			if _, ok := l.oobPacketHandler.(RuntimeOOBPacketHandler); !ok {
				return errors.New("OOB packet handler has no runtime session ownership adapter")
			}
		} else if _, ok := l.packetHandler.(RuntimePacketHandler); !ok {
			return errors.New("packet handler has no runtime session ownership adapter")
		}
	}
	return nil
}

// Prepare opens sockets privately. No accept/read loop, graph callback or OS
// proxy mutation happens here. A candidate's ordinary Start calls only Prepare.
func (l *Listener) Prepare() error {
	if err := l.ValidateRuntime(); err != nil {
		return err
	}
	r := l.runtime
	if r == nil {
		return errors.New("listener has no runtime binding")
	}
	r.mu.Lock()
	if r.constructionErr != nil {
		err := r.constructionErr
		r.mu.Unlock()
		return err
	}
	if r.phase == "prepared" || r.phase == "paused" {
		r.mu.Unlock()
		return nil
	}
	if r.phase != "inert" {
		r.mu.Unlock()
		return ErrRuntimeTransition
	}
	if l.setSystemProxy {
		r.mu.Unlock()
		return ErrRuntimeSystemEffect
	}
	if common.Contains(l.network, N.NetworkUDP) {
		if l.oobPacketHandler != nil {
			if _, ok := l.oobPacketHandler.(RuntimeOOBPacketHandler); !ok {
				r.mu.Unlock()
				return errors.New("OOB packet handler has no runtime session ownership adapter")
			}
		} else if _, ok := l.packetHandler.(RuntimePacketHandler); !ok {
			r.mu.Unlock()
			return errors.New("packet handler has no runtime session ownership adapter")
		}
	}
	r.phase = "preparing"
	r.mu.Unlock()
	err := runtimePrepareCall(func() error {
		var err error
		if r.prepareSockets != nil {
			err = r.prepareSockets()
		} else {
			if common.Contains(l.network, N.NetworkTCP) {
				err = l.prepareRuntimeTCP()
			}
			if err == nil && common.Contains(l.network, N.NetworkUDP) {
				_, err = l.listenUDPWithConfig(net.ListenConfig{})
			}
		}
		return err
	})
	r.mu.Lock()
	if err == nil {
		r.phase = "prepared"
	} else {
		r.phase = "failed"
	}
	r.mu.Unlock()
	if err != nil {
		return errors.Join(err, l.RuntimeCloseAndWait())
	}
	return nil
}

// ArmIngress is fallible and must run before graph publication. Workers wait at
// the closed admission gate, so a prepared/armed candidate remains invisible.
func (l *Listener) ArmIngress() error {
	r := l.runtime
	if r == nil {
		return errors.New("listener has no runtime binding")
	}
	r.mu.Lock()
	if r.phase != "prepared" && r.phase != "paused" {
		r.mu.Unlock()
		return ErrRuntimeTransition
	}
	r.phase = "arming"
	r.mu.Unlock()
	var err error
	members := l.runtimeTCPMembers()
	if err = l.validateRuntimeTCPComplete(); err == nil {
		for _, member := range members {
			if deadline, ok := member.socket.(interface{ SetDeadline(time.Time) error }); ok {
				err = errors.Join(err, runtimeSocketCall(func() error { return deadline.SetDeadline(time.Time{}) }))
			}
		}
	}
	if err == nil && l.udpConn != nil {
		err = runtimeSocketCall(func() error { return l.udpConn.SetReadDeadline(time.Time{}) })
	}
	r.mu.Lock()
	if err != nil {
		r.phase = "paused"
		r.mu.Unlock()
		return err
	}
	r.stopped.Store(false)
	r.runStop = make(chan struct{})
	if l.udpConn != nil && !r.outputStarted {
		l.packetOutbound = make(chan *N.PacketBuffer, 64)
		l.packetOutboundClosed = make(chan struct{})
		r.outputStarted = true
		if !l.disablePacketOutput {
			r.output.Add(1)
		}
	}
	r.ingress.Add(len(members))
	if l.udpConn != nil {
		r.ingress.Add(1)
	}
	startOutput := l.udpConn != nil && !l.disablePacketOutput && !l.runtimeOutputStarted.Swap(true)
	r.phase = "armed"
	r.mu.Unlock()
	for _, member := range members {
		socket := member.socket
		go func() { defer r.ingress.Done(); l.loopTCPInFor(socket) }()
	}
	if l.udpConn != nil {
		go func() { defer r.ingress.Done(); l.loopUDPIn() }()
	}
	if startOutput {
		go func() { defer r.output.Done(); l.loopUDPOut() }()
	}
	return nil
}

// Activate opens only the pre-armed gate. Box must publish the exact graph which
// includes this listener's resource before opening it. No socket operation runs.
func (l *Listener) Activate() error {
	r := l.runtime
	if r == nil {
		return errors.New("listener has no runtime binding")
	}
	r.mu.Lock()
	if r.phase != "armed" {
		r.mu.Unlock()
		return ErrRuntimeTransition
	}
	err := r.gateway.Resume()
	if err == nil {
		r.phase = "active"
	}
	r.mu.Unlock()
	return err
}

// PauseIngress joins accept/read loops and packet callbacks while preserving
// established TCP connections and the UDP write-back socket/output worker.
func (l *Listener) PauseIngress() error { return l.pauseIngress(false) }

// PauseIngressForRebind may close a non-interruptible acceptor. It is only for
// a replacement whose explicit local-reconnect impact has been accepted.
func (l *Listener) PauseIngressForRebind() error { return l.pauseIngress(true) }

func (l *Listener) pauseIngress(allowClose bool) error {
	r := l.runtime
	if r == nil {
		return errors.New("listener has no runtime binding")
	}
	r.mu.Lock()
	if r.phase == "paused" || r.phase == "prepared" || r.phase == "inert" {
		r.mu.Unlock()
		return nil
	}
	if r.phase != "active" && r.phase != "armed" {
		r.mu.Unlock()
		return ErrRuntimeTransition
	}
	members := append([]*runtimeTCPMember(nil), r.tcp.members[:r.tcp.count]...)
	for _, member := range members {
		if !runtimeTCPInterruptible(member) && (!allowClose || member.spec.narrowExclusive) {
			r.mu.Unlock()
			return ErrPauseRequiresRebind
		}
	}
	r.phase = "pausing"
	r.stopped.Store(true)
	close(r.runStop)
	r.mu.Unlock()
	r.gateway.PauseAndWait()
	var err error
	for _, member := range members {
		var memberErr error
		canClose := allowClose && !member.spec.narrowExclusive
		if deadline, ok := member.socket.(interface{ SetDeadline(time.Time) error }); ok {
			memberErr = runtimeSocketCall(func() error { return deadline.SetDeadline(time.Now()) })
			if memberErr != nil && canClose {
				memberErr = member.closeAndWait()
				if memberErr == nil {
					l.removeRuntimeTCPMember(member)
				}
			}
		} else if canClose {
			memberErr = member.closeAndWait()
			if memberErr == nil {
				l.removeRuntimeTCPMember(member)
			}
		}
		err = errors.Join(err, memberErr)
	}
	if l.udpConn != nil {
		udpErr := runtimeSocketCall(func() error { return l.udpConn.SetReadDeadline(time.Now()) })
		if udpErr != nil && allowClose {
			udpErr = runtimeSocketCall(l.udpConn.Close)
			if udpErr != nil {
				r.mu.Lock()
				r.socketCloseErr = errors.Join(r.socketCloseErr, udpErr)
				r.mu.Unlock()
			}
			if udpErr == nil {
				r.mu.Lock()
				r.udpReleased = true
				r.mu.Unlock()
			}
		}
		err = errors.Join(err, udpErr)
	}
	if err != nil {
		r.mu.Lock()
		r.phase = "pause-failed"
		r.mu.Unlock()
		return fmt.Errorf("listener ingress interruption incomplete: %v", err)
	}
	r.ingress.Wait()
	r.mu.Lock()
	r.phase = "paused"
	r.mu.Unlock()
	return nil
}

func (l *Listener) runtimeWaitIngress() bool {
	if l.runtime == nil {
		return true
	}
	return l.runtime.gateway.WaitOpen(l.runtime.runStop)
}

func (l *Listener) runtimeIngressStopped() bool { return l.runtime != nil && l.runtime.stopped.Load() }

// RuntimeCloseAndWait is the concrete close barrier; Scope.Close is not one.
// It never closes accepted TCP carriers, whose separate leases keep protocol
// resources alive until their actual use ends. Errors remain non-filterable.
func (l *Listener) RuntimeCloseAndWait() (result error) {
	r := l.runtime
	if r == nil {
		return l.Close()
	}
	r.mu.Lock()
	if r.phase == "closing" || r.phase == "closed" {
		done := r.closeDone
		r.mu.Unlock()
		<-done
		r.mu.Lock()
		err := r.closeErr
		r.mu.Unlock()
		return err
	}
	if r.phase == "preparing" || r.phase == "arming" || r.phase == "pausing" || r.phase == "releasing" {
		r.mu.Unlock()
		return ErrRuntimeTransition
	}
	joinedBefore := r.phase == "paused" || r.phase == "prepared" || r.phase == "released" || r.phase == "inert" || r.phase == "failed"
	r.phase = "closing"
	r.controlOpen = false
	if !r.stopped.Swap(true) && r.runStop != nil {
		close(r.runStop)
	}
	l.shutdown.Store(true)
	ownedUDP := r.ownsUDP && !r.udpReleased
	if r.outputStarted {
		close(l.packetOutboundClosed)
		r.outputStarted = false
	}
	debt := r.socketCloseErr
	r.mu.Unlock()
	// Publish one sticky failure even when a foreign close panics. A later Scope
	// close must observe this same failed barrier rather than repeat native I/O.
	defer func() {
		if recover() != nil {
			result = errors.Join(result, errors.New("runtime listener close panicked; completion unknown"))
		}
		r.mu.Lock()
		result = errors.Join(result, r.controlError)
		if result != nil {
			result = fmt.Errorf("runtime listener close completion failed: %v", result)
		}
		r.closeErr = result
		r.phase = "closed"
		close(r.closeDone)
		r.mu.Unlock()
	}()
	r.gateway.SealAndWait()
	canJoin := true
	result = debt
	for _, member := range l.runtimeTCPMembers() {
		interrupted := joinedBefore
		if deadline, ok := member.socket.(interface{ SetDeadline(time.Time) error }); ok {
			interrupted = runtimeSocketCall(func() error { return deadline.SetDeadline(time.Now()) }) == nil || interrupted
		}
		closeErr := member.closeAndWait()
		result = errors.Join(result, closeErr)
		if closeErr == nil {
			l.removeRuntimeTCPMember(member)
		} else if !interrupted {
			canJoin = false
		}
	}
	if ownedUDP && l.udpConn != nil {
		interrupted := joinedBefore || runtimeSocketCall(func() error { return l.udpConn.SetReadDeadline(time.Now()) }) == nil
		closeErr := runtimeSocketCall(l.udpConn.Close)
		result = errors.Join(result, closeErr)
		if closeErr != nil && !interrupted {
			canJoin = false
		}
	}
	// Even after a Close error, a successful deadline interrupts Accept and the
	// raw-Accept/admission gap must be joined before closeDone is published.
	if canJoin {
		r.ingress.Wait()
	} else {
		result = errors.Join(result, errors.New("runtime listener ingress join remains unconfirmed"))
	}
	r.controlCalls.Wait()
	r.directWrites.Wait()
	r.output.Wait()
	l.releasePacketOutbound()
	return result
}

type RuntimeListenerStatus struct {
	Phase        string
	IngressError error
	CloseError   error
}

func (l *Listener) RuntimeStatus() RuntimeListenerStatus {
	if l.runtime == nil {
		return RuntimeListenerStatus{Phase: "legacy"}
	}
	r := l.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	return RuntimeListenerStatus{Phase: r.phase, IngressError: r.ingressErr, CloseError: r.closeErr}
}

func (l *Listener) recordRuntimeIngressError(err error) {
	r := l.runtime
	r.mu.Lock()
	r.ingressErr = errors.Join(r.ingressErr, err)
	r.mu.Unlock()
}
