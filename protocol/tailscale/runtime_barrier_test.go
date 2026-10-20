//go:build with_tailscale

package tailscale

import (
 "context"
 "errors"
 "net"
 "sync/atomic"
 "testing"

 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/adapter/outbound"
 "github.com/sagernet/tailscale/net/netmon"
 "github.com/sagernet/tailscale/types/nettype"
 "github.com/sagernet/tailscale/wgengine/router"
 "github.com/sagernet/tailscale/wgengine/wgcfg"
 tsDNS "github.com/sagernet/tailscale/net/dns"
)

func TestRuntimeDNSRetirementWaitsOriginalCallback(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background());defer cancel()
 scope:=adapter.NewScope(ctx,nil);closed:=make(chan struct{});scope.Add(func()error{close(closed);return nil})
 snapshot:=&runtimeDNSSnapshot{ctx:ctx,cancel:cancel,scope:scope,fence:outbound.NewRuntimeIOFence(nil),carriers:outbound.NewRuntimeIOFenceSet(),done:make(chan struct{})}
 leave,err:=snapshot.fence.Acquire();if err!=nil{t.Fatal(err)}
 state:=&runtimeDNSState{retiring:make(map[*runtimeDNSSnapshot]struct{})}
 state.retire(snapshot)
 select{case <-closed:t.Fatal("resolver closed before original callback returned");default:}
 if _,err:=snapshot.fence.Acquire();!errors.Is(err,net.ErrClosed){t.Fatalf("new admission after retirement: %v",err)}
 leave();<-snapshot.done
 if snapshot.err!=nil{t.Fatal(snapshot.err)}
 select{case <-closed:default:t.Fatal("resolver scope did not close")}
 state.mu.Lock();remaining:=len(state.retiring);state.mu.Unlock();if remaining!=0{t.Fatal("completed snapshot retained")}
}
func TestRuntimeReconfigConsumersUnregisterIndependently(t *testing.T){
 logical:=&Endpoint{runtime:&runtimeEndpointState{}}
 physical:=&runtimeEndpointPhysical{attachments:map[*runtimeEndpointBinding]struct{}{&runtimeEndpointBinding{logical:logical}:{}}}
 first,second:=outbound.NewRuntimeIOFence(nil),outbound.NewRuntimeIOFence(nil)
 var callsA,callsB atomic.Int32
 removeA,err:=logical.registerRuntimeReconfig(first,func(*Endpoint,*wgcfg.Config,*router.Config,*tsDNS.Config){callsA.Add(1)});if err!=nil{t.Fatal(err)}
 removeB,err:=logical.registerRuntimeReconfig(second,func(*Endpoint,*wgcfg.Config,*router.Config,*tsDNS.Config){callsB.Add(1)});if err!=nil{t.Fatal(err)};defer removeB()
 physical.reconfigured(nil,nil,nil,nil);removeA();physical.reconfigured(nil,nil,nil,nil)
 if callsA.Load()!=1||callsB.Load()!=2{t.Fatalf("cross-consumer unregister: %d %d",callsA.Load(),callsB.Load())}
 if err:=first.Wait();err!=nil{t.Fatal(err)}
}
func TestRuntimePacketListenerWaitsFactoryReturn(t *testing.T){
 callbacks:=outbound.NewRuntimeIOFence(nil);ctx,cancel:=context.WithCancel(context.Background());defer cancel()
 physical:=&runtimeEndpointPhysical{ctx:ctx,callbacks:callbacks,carriers:outbound.NewRuntimeIOFenceSet()}
 binding:=newRuntimeBindingFixture(t,1);binding.physical=physical;physical.bootstrap=binding
 defer binding.closeAndWait()
 entered,release,returned:=make(chan struct{}),make(chan struct{}),make(chan struct{})
 next:=netmon.PacketListenerFunc(func(context.Context,string,string)(nettype.PacketConn,error){close(entered);<-release;return nil,net.ErrClosed})
 go func(){defer close(returned);_,_ = physical.packetListener(ctx,"udp4",":0",next)}()
 <-entered;physical.carriers.Stop();waiting:=make(chan struct{});go func(){defer close(waiting);_ = physical.carriers.Wait()}()
 select{case <-waiting:t.Fatal("factory completion fabricated before return");default:}
 close(release);<-returned;<-waiting
}
