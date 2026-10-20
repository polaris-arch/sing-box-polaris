package wireguard

import (
 "errors"
 "sync"

 "github.com/sagernet/sing-box/adapter/outbound"
 "github.com/sagernet/sing-box/common/tls"
 "github.com/sagernet/wireguard-go/conn"
)

// A physical device's own callbacks, not a baseline graph lease. Device.Close
// already joins its receive/peer/device workers. This fence covers the actual
// graph-facing power and pause callback entries and retains bind Close errors
// which wireguard-go's void Device.Close cannot return to its owner.
type endpointRuntime struct{
 callbacks *outbound.RuntimeIOFence
 wake chan struct{}
 stopSignal chan struct{}
 pauseDone chan struct{}
 stopOnce sync.Once
 mu sync.Mutex
 err error
}
func(e *Endpoint)initializeRuntime()error{
 r:=&endpointRuntime{callbacks:outbound.NewRuntimeIOFence(nil),wake:make(chan struct{},1),stopSignal:make(chan struct{})}
 e.runtime=r
 _,err:=outbound.RegisterRuntimeOwnedFence(e.options.Context,r.callbacks);return err
}
func(e *Endpoint)runtimeActivity(callback func(int))func(int){
 if e.runtime==nil{return callback}
 return func(size int){leave,err:=e.runtime.callbacks.Acquire();if err!=nil{return};defer leave();callback(size)}
}
func(r *endpointRuntime)notifyPause(){
 leave,err:=r.callbacks.Acquire();if err!=nil{return};defer leave()
 // pause.Manager invokes callbacks while holding its own lock. Do not call
 // device, network, logger, or another pause method from that callback.
 select{case r.wake<-struct{}{}:default:}
}
func(r *endpointRuntime)startPause(e *Endpoint){
 r.pauseDone=make(chan struct{})
 go func(){defer close(r.pauseDone);for{select{case <-r.stopSignal:return;case <-r.wake:
  paused:=e.pause.IsNetworkPaused()
  e.stateAccess.Lock();native:=e.device.Load()
  if native!=nil{e.networkPaused=paused;if paused{native.Down()}else if !e.suspended.Load(){native.Up()}}
  e.stateAccess.Unlock()
 }}}()
}
func(r *endpointRuntime)stop(){r.stopOnce.Do(func(){close(r.stopSignal);_ = r.callbacks.Close()})}
func(r *endpointRuntime)record(err error){if err==nil{return};r.mu.Lock();r.err=errors.Join(r.err,tls.NewRuntimeCleanupError(err));r.mu.Unlock()}
func(r *endpointRuntime)wait()error{
 if r.pauseDone!=nil{<-r.pauseDone};fenceErr:=r.callbacks.Wait()
 r.mu.Lock();defer r.mu.Unlock();return errors.Join(r.err,fenceErr)
}
type runtimeStandardBind struct{*conn.StdNetBind;owner *endpointRuntime}
func(b *runtimeStandardBind)Close()error{err:=b.StdNetBind.Close();b.owner.record(err);return err}

// Device.Close has a void result, so retain the original bind close error.
type runtimeClientBind struct{*ClientBind;owner *endpointRuntime}
func(b *runtimeClientBind)Close()error{err:=b.ClientBind.Close();b.owner.record(err);return err}

// Preserve native Linux sticky-route monitoring through this exact capability.
func(b *runtimeStandardBind)RuntimeStandardBind()*conn.StdNetBind{return b.StdNetBind}
