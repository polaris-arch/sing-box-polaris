package device

import (
 "testing"
 "github.com/sagernet/wireguard-go/conn"
 "time"
)

func runtimeTestTimer(t *testing.T,expire func(*Peer))(*Device,*Timer){
 t.Helper()
 device:=new(Device)
 peer:=&Peer{device:device}
 peer.isRunning.Store(true)
 return device,peer.NewTimer(expire)
}
func runtimeAwait(t *testing.T,done <-chan struct{}){
 t.Helper();select{case <-done:case <-time.After(time.Second):t.Fatal("original operation did not complete")}
}
func TestRuntimeTimerDelSyncJoinsOriginalCallback(t *testing.T){
 entered,release:=make(chan struct{}),make(chan struct{})
 _,timer:=runtimeTestTimer(t,func(*Peer){close(entered);<-release})
 timer.Mod(0);runtimeAwait(t,entered)
 done:=make(chan struct{});go func(){timer.DelSync();close(done)}()
 select{case <-done:t.Fatal("active callback was declared complete");case <-time.After(10*time.Millisecond):}
 close(release);runtimeAwait(t,done)
 if timer.IsPending(){t.Fatal("timer remains pending")}
}
func TestRuntimeTimerDelSyncJoinsQueuedAfterFunc(t *testing.T){
 entered,release:=make(chan struct{}),make(chan struct{})
 device,timer:=runtimeTestTimer(t,func(*Peer){t.Error("cancelled expiration ran")})
 // The native scheduler has entered its original callback but has not entered
 // timer.run yet. Stop(false) must retain this precise callback reservation.
 timer.modifyingLock.Lock()
 if !device.beginRuntimeTask(){t.Fatal("device reservation failed")}
 run:=&timerRun{cancel:make(chan struct{})}
 timer.current=run;timer.runs[run]=struct{}{};timer.pending.Add(1)
 run.timer=time.AfterFunc(0,func(){close(entered);<-release;timer.run(run)})
 timer.modifyingLock.Unlock()
 runtimeAwait(t,entered)
 done:=make(chan struct{});go func(){timer.DelSync();close(done)}()
 select{case <-done:t.Fatal("queued callback was declared complete");case <-time.After(10*time.Millisecond):}
 close(release);runtimeAwait(t,done)
}
func TestRuntimeTimerCancelledScheduleReleasesOnce(t *testing.T){
 device,timer:=runtimeTestTimer(t,func(*Peer){t.Error("cancelled expiration ran")})
 timer.Mod(time.Hour)
 if !timer.Stop(){t.Fatal("pending original timer was not stopped")}
 timer.DelSync();timer.DelSync()
 done:=make(chan struct{});go func(){device.runtimeWorkers.workers.Wait();close(done)}()
 runtimeAwait(t,done)
}
func TestRuntimeTimerCannotRearmStoppedPeer(t *testing.T){
 _,timer:=runtimeTestTimer(t,func(*Peer){t.Error("stopped peer expiration ran")})
 timer.peer.isRunning.Store(false);timer.Mod(time.Hour)
 if timer.IsPending(){t.Fatal("stopped peer rearmed timer after retirement")}
 timer.DelSync()
}
func TestRuntimeWorkerAdmissionClosesBeforeWait(t *testing.T){
 device:=new(Device)
 if !device.beginRuntimeTask(){t.Fatal("initial task denied")}
 device.runtimeWorkers.Lock();device.runtimeWorkers.closed=true;close(device.runtimeWorkers.stop);device.runtimeWorkers.Unlock()
 if device.beginRuntimeTask(){t.Fatal("late original task admitted behind wait")}
 done:=make(chan struct{});go func(){device.runtimeWorkers.workers.Wait();close(done)}()
 select{case <-done:t.Fatal("original worker still reserved");default:}
 device.runtimeWorkers.workers.Done();runtimeAwait(t,done)
}

func TestRuntimeFinalJoinHoldsNoStateOrNetLocks(t *testing.T) {
 device := new(Device)
 device.closed = make(chan struct{})
 device.queue.encryption = newOutboundQueue()
 device.queue.decryption = newInboundQueue()
 device.queue.handshake = newHandshakeQueue()
 device.queue.encryption.wg.Done()
 device.queue.decryption.wg.Done()
 device.queue.handshake.wg.Done()
 entered, release := make(chan struct{}), make(chan struct{})
 device.startNativeWorker(func() {
  close(entered)
  <-release
  device.state.Lock(); device.state.Unlock()
  device.net.Lock(); device.net.Unlock()
 })
 runtimeAwait(t, entered)
 done := make(chan struct{})
 go func() { device.waitNativeCompletion(); close(done) }()
 select { case <-done: t.Fatal("original native invocation still active"); default: }
 close(release)
 runtimeAwait(t, done)
 runtimeAwait(t, device.closed)
}
func TestRuntimePoolCloseUnblocksOriginalWaiter(t *testing.T) {
 pool := NewWaitPool(1, func() any { return new(int) })
 first := pool.Get()
 done := make(chan struct{})
 go func() { second := pool.Get(); pool.Put(second); close(done) }()
 pool.Close()
 runtimeAwait(t, done)
 pool.Put(first)
 pool.Close()
}

func TestRuntimeConstructorAdmissionPreventsEarlyCompletion(t *testing.T) {
 device := new(Device)
 // Model NewDevice's reservation before the first launch. An early TUN error
 // may start shutdown before the constructor publishes the event reader.
 device.nativeWorkers.Add(1)
 done := make(chan struct{})
 go func() { device.nativeWorkers.Wait(); close(done) }()
 entered, release := make(chan struct{}), make(chan struct{})
 device.startNativeWorker(func() { close(entered); <-release })
 runtimeAwait(t, entered)
 device.nativeWorkers.Done() // constructor has published its final worker
 select { case <-done: t.Fatal("constructor admitted worker behind completion"); default: }
 close(release)
 runtimeAwait(t, done)
}

type runtimeSourceEndpoint struct {
 conn.Endpoint
 clears int
}
func (endpoint *runtimeSourceEndpoint) ClearSrc() { endpoint.clears++ }
func TestRuntimeSourceGenerationInvalidatesBeforeSend(t *testing.T) {
 device := new(Device)
 peer := &Peer{device: device}
 endpoint := new(runtimeSourceEndpoint)
 peer.endpoint.val = endpoint
 device.net.Lock()
 first := new(endpointSourceGeneration)
 device.net.sourceGeneration = first
 device.net.Unlock()
 check := func() {
  device.net.RLock()
  peer.endpoint.Lock()
  peer.clearEndpointSourceLocked()
  peer.endpoint.Unlock()
  device.net.RUnlock()
 }
 check()
 if endpoint.clears != 1 { t.Fatal("new peer missed bind generation") }
 check()
 if endpoint.clears != 1 { t.Fatal("unchanged generation cleared again") }
 device.net.Lock()
 device.net.sourceGeneration = new(endpointSourceGeneration)
 if device.net.sourceGeneration == first { t.Fatal("live generation identity reused") }
 device.net.Unlock()
 check()
 if endpoint.clears != 2 { t.Fatal("stale source survived bind generation") }
 peer.endpoint.Lock(); peer.endpoint.clearSrcOnTx = true; peer.endpoint.Unlock()
 check()
 if endpoint.clears != 3 { t.Fatal("explicit route invalidation lost") }
}
func TestRuntimeMarkChangeDoesNotAcquirePeersLock(t *testing.T) {
 device := new(Device)
 device.peers.Lock()
 defer device.peers.Unlock()
 done := make(chan struct{})
 go func() { _ = device.BindSetMark(17); close(done) }()
 runtimeAwait(t, done)
 if device.runtimeRouteMark.Load() != 17 { t.Fatal("route mark not published") }
}
