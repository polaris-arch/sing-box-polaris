package tls

import (
 "errors"
 "net"
 "sync"

 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/adapter/outbound"
)

// Server preparation may start a private file watcher. The existing owned fence
// seals late callbacks; this one start-result slot orders cleanup after a partial
// Start has really unwound. It does not invent completion for provider workers.
type runtimeServerLifecycle struct {
 mu sync.Mutex
 closing bool
 started chan struct{}
 startErr error
 startReturned bool
 fence *outbound.RuntimeIOFence
}
func(c *STDServerConfig)initializeRuntimeServer()error{
 if !adapter.IsRuntimePreparation(c.ctx){return nil}
 state:=&runtimeServerLifecycle{}
 state.fence=outbound.NewRuntimeIOFence(func()error{
  state.mu.Lock();state.closing=true;started:=state.started;state.mu.Unlock()
  if started!=nil{<-started}
  err:=c.closeUnfenced()
  state.mu.Lock();uncertain:=state.started!=nil&&!state.startReturned;startErr:=state.startErr;state.mu.Unlock()
  if IsRuntimeCleanupIncomplete(startErr){return NewRuntimeCleanupError(errors.Join(err,startErr))}
  if uncertain{return NewRuntimeCleanupError(errors.Join(err,errors.New("TLS server Start unwound without a completion result")))}

  return err
 })
 c.runtime=state
 if err:=adapter.DeferConstructionCleanup(c.ctx,state.fence.RuntimeCloseAndWait);err!=nil{return err}
 return adapter.ConstructionScopeErr(c.ctx)
}
func(s *runtimeServerLifecycle)start(start func()error)error{
 leave,err:=s.fence.Acquire();if err!=nil{return err};defer leave()
 s.mu.Lock()
 if s.closing{s.mu.Unlock();return net.ErrClosed}
 if s.started!=nil {done:=s.started;s.mu.Unlock();<-done;s.mu.Lock();err:=s.startErr;s.mu.Unlock();return err}
 s.started=make(chan struct{});done:=s.started;s.startErr=errors.New("TLS server Start did not complete");s.mu.Unlock()
 defer close(done)
 err=start()
 s.mu.Lock();s.startErr=err;s.startReturned=true;s.mu.Unlock()
 return err
}
func(c *STDServerConfig)RuntimeCloseAndWait()error{return c.Close()}
func(c *STDServerConfig)RuntimeValidate()error{
 if c.runtime==nil{return errors.New("TLS server lacks staged lifecycle")}
 for _,provider:=range []any{c.certificateProvider,c.acmeService}{
  if provider==nil{continue}
  runtime,ok:=provider.(interface{RuntimeValidate()error});if !ok{return errors.New("certificate provider lacks staged validation")}
  if err:=runtime.RuntimeValidate();err!=nil{return err}
 }
 return nil
}

func ValidateRuntimeServer(config ServerConfig)error{
 if config==nil{return nil}
 switch value:=config.(type){
 case interface{RuntimeValidate()error}:return value.RuntimeValidate()
 case *KTlSServerConfig:return ValidateRuntimeServer(value.ServerConfig)
 default:return errors.New("TLS server type requires its staged resource adapter")
 }
}
