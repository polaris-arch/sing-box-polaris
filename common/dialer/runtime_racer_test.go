package dialer

import (
 "context"
 "errors"
 "net"
 "net/netip"
 "sync"
 "testing"
 "time"

 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/internal/runtimegraph"
 M "github.com/sagernet/sing/common/metadata"
)

func runtimeRacerContext(t *testing.T) context.Context {
 t.Helper()
 ctx,cancel := context.WithTimeout(context.Background(),5*time.Second)
 t.Cleanup(cancel)
 return ctx
}
func runtimeRacerWait(t *testing.T, ctx context.Context, done <-chan struct{}) {
 t.Helper()
 select { case <-done: case <-ctx.Done(): t.Fatal("racer barrier: ",ctx.Err()) }
}
func runtimeRacerOwner(t *testing.T) *runtimegraph.ResourceOwner {
 t.Helper()
 owner,err := runtimegraph.NewResourceOwner(context.Background(),adapter.RuntimeResourceID{Incarnation:"racer",Sequence:1},nil,func()error{return nil})
 if err != nil { t.Fatal(err) }; return owner
}

func TestRuntimeRacerRetainsReceiverThroughActualTail(t *testing.T) {
 ctx := runtimeRacerContext(t)
 owner := runtimeRacerOwner(t)
 entered,release := make(chan struct{}),make(chan struct{})
 var once sync.Once
 unblock := func(){once.Do(func(){close(release)})}
 t.Cleanup(unblock)
 failures := make(chan error,1)
 if err := startRuntimeRacer(ctx,owner,func(context.Context)error{close(entered);<-release;return nil},func(err error){failures<-err}); err != nil {t.Fatal(err)}
 runtimeRacerWait(t,ctx,entered)
 owner.Seal()
 select {case <-owner.Closed():t.Fatal("live racer released its receiver");default:}
 unblock()
 if err:=owner.WaitClosed(ctx);err!=nil{t.Fatal(err)}
 select {case err:=<-failures:t.Fatal(err);default:}
}

func TestRuntimeRacerRejectsSealedAdmissionBeforeDispatch(t *testing.T) {
 owner:=runtimeRacerOwner(t);owner.Seal()
 called:=false
 if err:=startRuntimeRacer(context.Background(),owner,func(context.Context)error{called=true;return nil},func(error){});err==nil{t.Fatal("sealed admission accepted")}
 if called{t.Fatal("rejected worker dispatched")}
}

func TestRuntimeRacerUnknownCompletionRetainsOwner(t *testing.T) {
 for _,panics:=range []bool{false,true}{t.Run(map[bool]string{false:"close_error",true:"panic"}[panics],func(t *testing.T){
  ctx:=runtimeRacerContext(t);owner:=runtimeRacerOwner(t);reported:=make(chan error,1)
  if err:=startRuntimeRacer(ctx,owner,func(context.Context)error{if panics{panic("unknown native tail")};return errors.New("close failed")},func(err error){reported<-err});err!=nil{t.Fatal(err)}
  select{case err:=<-reported:if err==nil{t.Fatal("missing uncertainty")};case <-ctx.Done():t.Fatal(ctx.Err())}
  owner.Seal()
  select{case <-owner.Closed():t.Fatal("uncertain racer falsely released receiver");default:}
 })}
}

type runtimeRacerConn struct{net.Conn;closeFn func()error}
func(c *runtimeRacerConn)Close()error{if c.closeFn!=nil{return c.closeFn()};return nil}
type runtimeRacerDialer struct{dial func(context.Context,M.Socksaddr)(net.Conn,error)}
func(d runtimeRacerDialer)DialContext(ctx context.Context,_ string,address M.Socksaddr)(net.Conn,error){return d.dial(ctx,address)}
func(d runtimeRacerDialer)ListenPacket(context.Context,M.Socksaddr)(net.PacketConn,error){return nil,errors.New("unused packet operation")}

func TestRuntimeAddressRaceRetainsLosingConnectionClose(t *testing.T){
 ctx:=runtimeRacerContext(t);owner:=runtimeRacerOwner(t)
 parent,err:=owner.Acquire();if err!=nil{t.Fatal(err)}
 t.Cleanup(parent.Release)
 ctx=adapter.ContextWithRuntimeResourceLease(ctx,parent)
 primaryEntered,primaryRelease:=make(chan struct{}),make(chan struct{})
 closeEntered,closeRelease:=make(chan struct{}),make(chan struct{})
 var primaryOnce,closeOnce sync.Once
 openPrimary:=func(){primaryOnce.Do(func(){close(primaryRelease)})}
 openClose:=func(){closeOnce.Do(func(){close(closeRelease)})}
 t.Cleanup(openClose);t.Cleanup(openPrimary)
 winner:=&runtimeRacerConn{}
 loser:=&runtimeRacerConn{closeFn:func()error{close(closeEntered);<-closeRelease;return nil}}
 dialer:=runtimeRacerDialer{dial:func(ctx context.Context,address M.Socksaddr)(net.Conn,error){
  if address.Addr.Is4(){close(primaryEntered);<-primaryRelease;return loser,nil}
  select{case <-primaryEntered:return winner,nil;case <-ctx.Done():return nil,ctx.Err()}
 }}
 conn,err:=DialParallelNetwork(ctx,runtimeSerialInterfaceDialer{dialer},"tcp",M.Socksaddr{Fqdn:"example.org",Port:443},[]netip.Addr{netip.MustParseAddr("192.0.2.1"),netip.MustParseAddr("2001:db8::1")},false,nil,nil,nil,time.Nanosecond)
 if err!=nil||conn!=winner{t.Fatalf("winning result: %v %v",conn,err)}
 parent.Release();owner.Seal();openPrimary()
 runtimeRacerWait(t,ctx,closeEntered)
 select{case <-owner.Closed():t.Fatal("losing Close tail freed receiver");default:}
 openClose()
 if err:=owner.WaitClosed(ctx);err!=nil{t.Fatal(err)}
}
