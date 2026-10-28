/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 *
 * This is based heavily on timers.c from the kernel implementation.
 */

package device

import (
	"sync"
	"time"
	_ "unsafe"
)

//go:linkname fastrandn runtime.fastrandn
func fastrandn(n uint32) uint32

// A Timer manages time-based aspects of the WireGuard protocol.
// Timer roughly copies the interface of the Linux kernel's struct timer_list.
type Timer struct {
 modifyingLock sync.RWMutex
 runningLock sync.Mutex
 stopLock sync.Mutex
 pending sync.WaitGroup
 stopping bool
 current *timerRun
 runs map[*timerRun]struct{}
 peer *Peer
 expiration func(*Peer)
}

type timerRun struct {
 timer *time.Timer
 cancel chan struct{}
 cancelled bool // guarded by Timer.modifyingLock
}

func (peer *Peer) NewTimer(expirationFunction func(*Peer)) *Timer {
 return &Timer{peer:peer,expiration:expirationFunction,runs:make(map[*timerRun]struct{})}
}

// Each scheduling has a distinct original callback reservation. A successful
// Stop proves that scheduling cannot run; otherwise only its actual return
// releases the reservation, including a callback queued behind runningLock.
func (timer *Timer) finishLocked(run *timerRun) {
 delete(timer.runs,run)
 timer.pending.Done()
 timer.peer.device.runtimeWorkers.workers.Done()
}
func (timer *Timer) cancelLocked(run *timerRun) bool {
 if run==nil || run.cancelled { return false }
 run.cancelled=true
 close(run.cancel)
 if timer.current==run { timer.current=nil }
 if run.timer.Stop() { timer.finishLocked(run); return true }
 return false
}
func (timer *Timer) run(run *timerRun) {
 defer func(){timer.modifyingLock.Lock();timer.finishLocked(run);timer.modifyingLock.Unlock()}()
 timer.runningLock.Lock()
 defer timer.runningLock.Unlock()
 timer.modifyingLock.Lock()
 if run.cancelled { timer.modifyingLock.Unlock();return }
 if timer.current==run { timer.current=nil }
 timer.modifyingLock.Unlock()
 // A paused Box must not prevent original callback retirement. Cancellation
 // belongs to this timer scheduling and the exact Device, not a global resume.
 if manager:=timer.peer.device.pauseManager;manager!=nil {
  ticker:=time.NewTicker(50*time.Millisecond)
  defer ticker.Stop()
  for manager.IsPaused(){select{
  case <-run.cancel:return
  case <-timer.peer.device.runtimeWorkers.stop:return
  case <-ticker.C:
  }}
 }
 select{case <-run.cancel:return;case <-timer.peer.device.runtimeWorkers.stop:return;default:}
 timer.expiration(timer.peer)
}
func (timer *Timer) Mod(d time.Duration) { timer.Reset(d) }
func (timer *Timer) Reset(d time.Duration) bool {
 timer.modifyingLock.Lock()
 defer timer.modifyingLock.Unlock()
 if timer.stopping || !timer.peer.isRunning.Load() { return false }
 active:=timer.cancelLocked(timer.current)
 if !timer.peer.device.beginRuntimeTask(){return active}
 run:=&timerRun{cancel:make(chan struct{})}
 timer.current=run
 timer.runs[run]=struct{}{}
 timer.pending.Add(1)
 run.timer=time.AfterFunc(d,func(){timer.run(run)})
 return active
}
func (timer *Timer) Stop() bool {
 timer.modifyingLock.Lock()
 defer timer.modifyingLock.Unlock()
 return timer.cancelLocked(timer.current)
}
func (timer *Timer) Del() { timer.Stop() }
func (timer *Timer) DelSync() {
 timer.stopLock.Lock()
 defer timer.stopLock.Unlock()
 timer.modifyingLock.Lock()
 timer.stopping=true
 for run:=range timer.runs {timer.cancelLocked(run)}
 timer.modifyingLock.Unlock()
 timer.pending.Wait()
 timer.modifyingLock.Lock()
 timer.stopping=false
 timer.modifyingLock.Unlock()
}
func (timer *Timer) IsPending() bool {
 timer.modifyingLock.RLock()
 defer timer.modifyingLock.RUnlock()
 return timer.current!=nil
}

func (peer *Peer) timersActive() bool {
	return peer.isRunning.Load() && peer.device != nil && peer.device.isUp()
}

func expiredRetransmitHandshake(peer *Peer) {
	if peer.timers.handshakeAttempts.Load() > MaxTimerHandshakes {
		peer.device.log.Verbosef("%s - Handshake did not complete after %d attempts, giving up", peer, MaxTimerHandshakes+2)

		if peer.timersActive() {
			peer.timers.sendKeepalive.Del()
		}

		/* We drop all packets without a keypair and don't try again,
		 * if we try unsuccessfully for too long to make a handshake.
		 */
		peer.FlushStagedPackets()

		/* We set a timer for destroying any residue that might be left
		 * of a partial exchange.
		 */
		if peer.timersActive() && !peer.timers.zeroKeyMaterial.IsPending() {
			peer.timers.zeroKeyMaterial.Mod(RejectAfterTime * 3)
		}
		peer.noteSessionHandshakeStopped()
	} else {
		peer.timers.handshakeAttempts.Add(1)
		peer.device.log.Verbosef("%s - Handshake did not complete after %d seconds, retrying (try %d)", peer, int(RekeyTimeout.Seconds()), peer.timers.handshakeAttempts.Load()+1)

		/* We clear the endpoint address src address, in case this is the cause of trouble. */
		peer.markEndpointSrcForClearing()

		peer.SendHandshakeInitiation(true)
	}
}

func expiredSendKeepalive(peer *Peer) {
	peer.SendKeepalive()
	if peer.timers.needAnotherKeepalive.Load() {
		peer.timers.needAnotherKeepalive.Store(false)
		if peer.timersActive() {
			peer.timers.sendKeepalive.Mod(KeepaliveTimeout)
		}
	}
}

func expiredNewHandshake(peer *Peer) {
	peer.device.log.Verbosef("%s - Retrying handshake because we stopped hearing back after %d seconds", peer, int((KeepaliveTimeout + RekeyTimeout).Seconds()))
	/* We clear the endpoint address src address, in case this is the cause of trouble. */
	peer.markEndpointSrcForClearing()
	peer.SendHandshakeInitiation(false)
}

func expiredZeroKeyMaterial(peer *Peer) {
	peer.device.log.Verbosef("%s - Removing all keys, since we haven't received a new one in %d seconds", peer, int((RejectAfterTime * 3).Seconds()))
	peer.ZeroAndFlushAll()
	if peer.deleteOnIdle {
		peer.device.log.Verbosef("%s - Removing idle lazy peer", peer)
		// Remove the peer from the device in a new goroutine as we're currently
		// holding timer locks which RemovePeer also needs. This is TOCTOU, but
		// acceptable since the worst case is we remove the peer and the lazy
		// peerfunc created it again after. We might lose some packets.
		peer.device.scheduleRuntimeTask(func(){peer.device.RemovePeer(peer.handshake.remoteStatic)})
	}
}

func expiredSession(peer *Peer) {
	peer.sessionState.Lock()
	defer peer.sessionState.Unlock()
	if peer.sessionState.sessionExpires.IsZero() || time.Now().Before(peer.sessionState.sessionExpires) {
		return
	}
	peer.device.log.Verbosef("%s - Session expired after %d seconds", peer, int(RejectAfterTime.Seconds()))
	peer.noteSessionStateLocked(PeerSessionExpired)
}

func expiredPersistentKeepalive(peer *Peer) {
	if peer.persistentKeepaliveInterval.Load() > 0 {
		peer.SendKeepalive()
	}
}

/* Should be called after an authenticated data packet is sent. */
func (peer *Peer) timersDataSent() {
	if peer.timersActive() && !peer.timers.newHandshake.IsPending() {
		peer.timers.newHandshake.Mod(KeepaliveTimeout + RekeyTimeout + time.Millisecond*time.Duration(fastrandn(RekeyTimeoutJitterMaxMs)))
	}
}

/* Should be called after an authenticated data packet is received. */
func (peer *Peer) timersDataReceived() {
	if peer.timersActive() {
		if !peer.timers.sendKeepalive.IsPending() {
			peer.timers.sendKeepalive.Mod(KeepaliveTimeout)
		} else {
			peer.timers.needAnotherKeepalive.Store(true)
		}
	}
}

/* Should be called after any type of authenticated packet is sent -- keepalive, data, or handshake. */
func (peer *Peer) timersAnyAuthenticatedPacketSent() {
	if peer.timersActive() {
		peer.timers.sendKeepalive.Del()
	}
}

/* Should be called after any type of authenticated packet is received -- keepalive, data, or handshake. */
func (peer *Peer) timersAnyAuthenticatedPacketReceived() {
	if peer.timersActive() {
		peer.timers.newHandshake.Del()
	}
}

/* Should be called after a handshake initiation message is sent. */
func (peer *Peer) timersHandshakeInitiated() {
	if peer.timersActive() {
		peer.timers.retransmitHandshake.Mod(RekeyTimeout + time.Millisecond*time.Duration(fastrandn(RekeyTimeoutJitterMaxMs)))
	}
	peer.noteSessionHandshakeStarted()
}

/* Should be called after a handshake response message is received and processed or when getting key confirmation via the first data message. */
func (peer *Peer) timersHandshakeComplete() {
	if peer.timersActive() {
		peer.timers.retransmitHandshake.Del()
	}
	peer.timers.handshakeAttempts.Store(0)
	peer.timers.sentLastMinuteHandshake.Store(false)
	peer.lastHandshakeNano.Store(time.Now().UnixNano())
}

/* Should be called after an ephemeral key is created, which is before sending a handshake response or after receiving a handshake response. */
func (peer *Peer) timersSessionDerived() {
	if peer.timersActive() {
		peer.sessionState.Lock()
		peer.sessionState.sessionExpires = time.Now().Add(RejectAfterTime)
		peer.noteSessionStateLocked(PeerSessionEstablished)
		peer.sessionState.Unlock()
		peer.timers.sessionExpired.Mod(RejectAfterTime)
		peer.timers.zeroKeyMaterial.Mod(RejectAfterTime * 3)
	} else {
		peer.noteSessionState(PeerSessionEstablished)
	}
}

/* Should be called before a packet with authentication -- keepalive, data, or handshake -- is sent, or after one is received. */
func (peer *Peer) timersAnyAuthenticatedPacketTraversal() {
	keepalive := peer.persistentKeepaliveInterval.Load()
	if keepalive > 0 && peer.timersActive() {
		peer.timers.persistentKeepalive.Mod(time.Duration(keepalive) * time.Second)
	}
}

func (peer *Peer) timersInit() {
	peer.timers.retransmitHandshake = peer.NewTimer(expiredRetransmitHandshake)
	peer.timers.sendKeepalive = peer.NewTimer(expiredSendKeepalive)
	peer.timers.newHandshake = peer.NewTimer(expiredNewHandshake)
	peer.timers.sessionExpired = peer.NewTimer(expiredSession)
	peer.timers.zeroKeyMaterial = peer.NewTimer(expiredZeroKeyMaterial)
	peer.timers.persistentKeepalive = peer.NewTimer(expiredPersistentKeepalive)
}

func (peer *Peer) timersStart() {
	peer.timers.handshakeAttempts.Store(0)
	peer.timers.sentLastMinuteHandshake.Store(false)
	peer.timers.needAnotherKeepalive.Store(false)
}

func (peer *Peer) timersStop() {
	peer.timers.retransmitHandshake.DelSync()
	peer.timers.sendKeepalive.DelSync()
	peer.timers.newHandshake.DelSync()
	peer.timers.sessionExpired.DelSync()
	peer.timers.zeroKeyMaterial.DelSync()
	peer.timers.persistentKeepalive.DelSync()
}
