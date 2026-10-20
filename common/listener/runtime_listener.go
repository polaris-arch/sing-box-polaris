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
	ErrRuntimeTransition = errors.New("listener lifecycle transition is in progress")
	ErrRuntimeRawTransport = errors.New("raw listener transport needs its staged runtime lifecycle adapter")
	ErrRuntimeSystemEffect = errors.New("system proxy requires a staged platform-effect transaction")
	ErrPauseRequiresRebind = errors.New("listener cannot interrupt Accept without closing; plan a local rebind")
)

type runtimeBindingKey struct{}
type RuntimeBinding struct { Admission adapter.RuntimeAdmission }

// ContextWithRuntimeBinding opts a constructor into inert listener creation.
// The exact resource source is taken from that constructor's own context.
func ContextWithRuntimeBinding(ctx context.Context, binding RuntimeBinding) context.Context {
	return context.WithValue(ctx, runtimeBindingKey{}, binding)
}

type runtimeListener struct {
	mu sync.Mutex
	phase string
	gateway *AdmissionGateway
	stopped atomic.Bool
	runStop chan struct{}
	ingress sync.WaitGroup
	output sync.WaitGroup
	outputStarted bool
	closeDone chan struct{}
	closeErr error
	ingressErr error
	replacement *Replacement
	setReplacement *ListenerSetTransaction
	// Test fixtures can replace binding without touching a real socket.
	prepareSockets func() error
	constructionErr error
	ownsTCP bool
	ownsUDP bool
	tcpReleased bool
	udpReleased bool
 udpLocal atomic.Pointer[net.UDPAddr]
 packetTransportDeclared bool
 control RuntimePacketControl
 controlOpen bool
 controlEnding bool
 controlCalls sync.WaitGroup
 directWrites sync.WaitGroup
 controlError error
}

func freezeListenOptions(options option.ListenOptions) option.ListenOptions {
	if options.Listen != nil { value := *options.Listen; options.Listen = &value }
	if options.UDPFragment != nil { value := *options.UDPFragment; options.UDPFragment = &value }
	return options
}

func (l *Listener) initializeRuntime() {
	if l.ctx == nil { l.ctx = context.Background() }
	binding, exists := l.ctx.Value(runtimeBindingKey{}).(RuntimeBinding)
	if !exists && !adapter.IsRuntimePreparation(l.ctx) { return }
	source, found := adapter.RuntimeResourceSourceFromContext(l.ctx)
	l.runtime = &runtimeListener{phase: "inert", gateway: NewAdmissionGateway(binding.Admission, source), closeDone: make(chan struct{})}
	if binding.Admission == nil || !found { l.runtime.constructionErr = errors.New("runtime listener has no admission/resource binding"); return }
	if !adapter.HasConstructionScope(l.ctx) { l.runtime.constructionErr = errors.New("runtime listener requires construction cleanup registration"); return }
	l.runtime.constructionErr = adapter.DeferConstructionCleanup(l.ctx, l.RuntimeCloseAndWait)
	if l.runtime.constructionErr == nil { l.runtime.constructionErr = adapter.ConstructionScopeErr(l.ctx) }
}

func (l *Listener) RuntimeEnabled() bool { return l.runtime != nil }


// ValidateRuntime checks the concrete handler contract without opening sockets.
func (l *Listener) ValidateRuntime() error {
	r := l.runtime
	if r == nil { return errors.New("listener has no runtime binding") }
	r.mu.Lock(); defer r.mu.Unlock()
	if r.constructionErr != nil { return r.constructionErr }
	if l.setSystemProxy { return ErrRuntimeSystemEffect }
	if common.Contains(l.network, N.NetworkTCP) && l.connHandler == nil { return errors.New("TCP listener has no connection handler") }
	if common.Contains(l.network, N.NetworkUDP) && !(r.packetTransportDeclared&&l.packetHandler==nil&&l.oobPacketHandler==nil) {
		if l.oobPacketHandler != nil {
			if _, ok := l.oobPacketHandler.(RuntimeOOBPacketHandler); !ok { return errors.New("OOB packet handler has no runtime session ownership adapter") }
		} else if _, ok := l.packetHandler.(RuntimePacketHandler); !ok { return errors.New("packet handler has no runtime session ownership adapter") }
	}
	return nil
}

// Prepare opens sockets privately. No accept/read loop, graph callback or OS
// proxy mutation happens here. A candidate's ordinary Start calls only Prepare.
func (l *Listener) Prepare() error {
	if err := l.ValidateRuntime(); err != nil { return err }
	r := l.runtime
	if r == nil { return errors.New("listener has no runtime binding") }
	r.mu.Lock()
	if r.constructionErr != nil { err := r.constructionErr; r.mu.Unlock(); return err }
	if r.phase == "prepared" || r.phase == "paused" { r.mu.Unlock(); return nil }
	if r.phase != "inert" { r.mu.Unlock(); return ErrRuntimeTransition }
	if l.setSystemProxy { r.mu.Unlock(); return ErrRuntimeSystemEffect }
	if common.Contains(l.network, N.NetworkUDP) {
		if l.oobPacketHandler != nil {
			if _, ok := l.oobPacketHandler.(RuntimeOOBPacketHandler); !ok { r.mu.Unlock(); return errors.New("OOB packet handler has no runtime session ownership adapter") }
		} else if _, ok := l.packetHandler.(RuntimePacketHandler); !ok { r.mu.Unlock(); return errors.New("packet handler has no runtime session ownership adapter") }
	}
	r.phase = "preparing"
	r.mu.Unlock()
	var err error
	if r.prepareSockets != nil { err = r.prepareSockets() } else {
		if common.Contains(l.network, N.NetworkTCP) { _, err = l.listenTCP() }
		if err == nil && common.Contains(l.network, N.NetworkUDP) { _, err = l.listenUDPWithConfig(net.ListenConfig{}) }
	}
	r.mu.Lock()
	if err == nil { r.phase = "prepared" } else { r.phase = "failed" }
	r.mu.Unlock()
	if err != nil { return errors.Join(err, l.RuntimeCloseAndWait()) }
	return nil
}

// ArmIngress is fallible and must run before graph publication. Workers wait at
// the closed admission gate, so a prepared/armed candidate remains invisible.
func (l *Listener) ArmIngress() error {
	r := l.runtime
	if r == nil { return errors.New("listener has no runtime binding") }
	r.mu.Lock()
	if r.phase != "prepared" && r.phase != "paused" { r.mu.Unlock(); return ErrRuntimeTransition }
	r.phase = "arming"
	r.mu.Unlock()
	var err error
	if l.tcpListener != nil {
		if deadline, ok := l.tcpListener.(interface { SetDeadline(time.Time) error }); ok { err = deadline.SetDeadline(time.Time{}) }
	}
	if err == nil && l.udpConn != nil { err = l.udpConn.SetReadDeadline(time.Time{}) }
	r.mu.Lock()
	if err != nil { r.phase = "paused"; r.mu.Unlock(); return err }
	r.stopped.Store(false)
	r.runStop = make(chan struct{})
	if l.udpConn != nil && !r.outputStarted {
		l.packetOutbound = make(chan *N.PacketBuffer, 64)
		l.packetOutboundClosed = make(chan struct{})
		r.outputStarted = true
		if !l.disablePacketOutput { r.output.Add(1) }
	}
	if l.tcpListener != nil { r.ingress.Add(1) }
	if l.udpConn != nil { r.ingress.Add(1) }
	startOutput := l.udpConn != nil && !l.disablePacketOutput && !l.runtimeOutputStarted.Swap(true)
	r.phase = "armed"
	r.mu.Unlock()
	if l.tcpListener != nil { go func() { defer r.ingress.Done(); l.loopTCPIn() }() }
	if l.udpConn != nil { go func() { defer r.ingress.Done(); l.loopUDPIn() }() }
	if startOutput { go func() { defer r.output.Done(); l.loopUDPOut() }() }
	return nil
}

// Activate opens only the pre-armed gate. Box must publish the exact graph which
// includes this listener's resource before opening it. No socket operation runs.
func (l *Listener) Activate() error {
	r := l.runtime
	if r == nil { return errors.New("listener has no runtime binding") }
	r.mu.Lock()
	if r.phase != "armed" { r.mu.Unlock(); return ErrRuntimeTransition }
	err := r.gateway.Resume()
	if err == nil { r.phase = "active" }
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
	if r == nil { return errors.New("listener has no runtime binding") }
	r.mu.Lock()
	if r.phase == "paused" || r.phase == "prepared" || r.phase == "inert" { r.mu.Unlock(); return nil }
	if r.phase != "active" && r.phase != "armed" { r.mu.Unlock(); return ErrRuntimeTransition }
	var tcpDeadline interface { SetDeadline(time.Time) error }
	if l.tcpListener != nil {
		var ok bool
		tcpDeadline, ok = l.tcpListener.(interface { SetDeadline(time.Time) error })
		if !ok && !allowClose { r.mu.Unlock(); return ErrPauseRequiresRebind }
	}
	r.phase = "pausing"
	r.stopped.Store(true)
	close(r.runStop)
	r.mu.Unlock()
	r.gateway.PauseAndWait()
	var err error
	if tcpDeadline != nil { err = tcpDeadline.SetDeadline(time.Now()) } else if l.tcpListener != nil {
		err = l.tcpListener.Close()
		if err == nil { r.mu.Lock(); r.tcpReleased = true; r.mu.Unlock() }
	}
	if err != nil && allowClose && l.tcpListener != nil && tcpDeadline != nil {
		err = l.tcpListener.Close()
		if err == nil { r.mu.Lock(); r.tcpReleased = true; r.mu.Unlock() }
	}
	if l.udpConn != nil {
		udpErr := l.udpConn.SetReadDeadline(time.Now())
		if udpErr != nil && allowClose { udpErr = l.udpConn.Close(); if udpErr == nil { r.mu.Lock(); r.udpReleased = true; r.mu.Unlock() } }
		err = errors.Join(err, udpErr)
	}
	if err != nil {
		r.mu.Lock(); r.phase = "pause-failed"; r.mu.Unlock()
		return fmt.Errorf("listener ingress interruption incomplete: %v", err)
	}
	r.ingress.Wait()
	r.mu.Lock(); r.phase = "paused"; r.mu.Unlock()
	return nil
}

func (l *Listener) runtimeWaitIngress() bool {
	if l.runtime == nil { return true }
	return l.runtime.gateway.WaitOpen(l.runtime.runStop)
}
func (l *Listener) runtimeIngressStopped() bool { return l.runtime != nil && l.runtime.stopped.Load() }

// RuntimeCloseAndWait is the concrete close barrier; Scope.Close is not one.
// It never closes accepted TCP carriers, whose separate leases keep protocol
// resources alive until their actual use ends. Errors remain non-filterable.
func (l *Listener) RuntimeCloseAndWait() error {
	r := l.runtime
	if r == nil { return l.Close() }
	r.mu.Lock()
	if r.phase == "closing" || r.phase == "closed" { done := r.closeDone; r.mu.Unlock(); <-done; r.mu.Lock(); err := r.closeErr; r.mu.Unlock(); return err }
	if r.phase == "preparing" || r.phase == "arming" || r.phase == "pausing" || r.phase == "releasing" { r.mu.Unlock(); return ErrRuntimeTransition }
	r.phase = "closing"
 r.controlOpen=false
	if !r.stopped.Swap(true) && r.runStop != nil { close(r.runStop) }
	l.shutdown.Store(true)
	ownedTCP, ownedUDP := r.ownsTCP && !r.tcpReleased, r.ownsUDP && !r.udpReleased
	if r.outputStarted { close(l.packetOutboundClosed) }
	r.mu.Unlock()
	r.gateway.SealAndWait()
	var err error
	if ownedTCP && l.tcpListener != nil { err = l.tcpListener.Close() }
	if ownedUDP && l.udpConn != nil { err = errors.Join(err, l.udpConn.Close()) }
	r.ingress.Wait()
 r.controlCalls.Wait()
 r.directWrites.Wait()
	r.output.Wait()
	l.releasePacketOutbound()
	if err != nil { err = fmt.Errorf("runtime listener close completion failed: %v", err) }
	r.mu.Lock();err=errors.Join(err,r.controlError); r.closeErr = err; r.phase = "closed"; close(r.closeDone); r.mu.Unlock()
	return err
}


type RuntimeListenerStatus struct { Phase string; IngressError error; CloseError error }
func (l *Listener) RuntimeStatus() RuntimeListenerStatus {
	if l.runtime == nil { return RuntimeListenerStatus{Phase: "legacy"} }
	r := l.runtime; r.mu.Lock(); defer r.mu.Unlock()
	return RuntimeListenerStatus{Phase: r.phase, IngressError: r.ingressErr, CloseError: r.closeErr}
}
func (l *Listener) recordRuntimeIngressError(err error) {
	r := l.runtime; r.mu.Lock(); r.ingressErr = errors.Join(r.ingressErr, err); r.mu.Unlock()
}
