package netmon

import (
 "errors"
 "net"
 "net/netip"
 "sync"
 "testing"
)
func runtimeTestInterfaces(name,address string)func()([]Interface,error){return func()([]Interface,error){return []Interface{{Interface:&net.Interface{Name:name,Index:1,Flags:net.FlagUp},AltAddrs:[]net.Addr{&net.IPNet{IP:net.ParseIP(address),Mask:net.CIDRMask(24,32)}}}},nil}}
func TestRuntimeInterfaceHooksAreMonitorLocal(t *testing.T){
 first:=&Monitor{hooks:Hooks{Interfaces:runtimeTestInterfaces("first","192.0.2.1")}}
 second:=&Monitor{hooks:Hooks{Interfaces:runtimeTestInterfaces("second","198.51.100.1")}}
 var workers sync.WaitGroup
 for _,monitor:=range []*Monitor{first,second}{workers.Add(1);go func(m *Monitor){defer workers.Done();for range 20{state,err:=m.interfaceStateUncached();if err!=nil{t.Error(err);return};if len(state.Interface)!=1{t.Errorf("cross-monitor inventory: %v",state.Interface);return}}}(monitor)}
 workers.Wait()
 for _,test:=range []struct{monitor *Monitor;name,address string}{{first,"first","192.0.2.1"},{second,"second","198.51.100.1"}}{
  state,err:=test.monitor.interfaceStateUncached();if err!=nil{t.Fatal(err)};if _,ok:=state.Interface[test.name];!ok{t.Fatalf("wrong namespace: %v",state.Interface)}
  addresses,_,err:=test.monitor.LocalAddresses();if err!=nil{t.Fatal(err)};if len(addresses)!=1||addresses[0]!=netip.MustParseAddr(test.address){t.Fatalf("wrong endpoints: %v",addresses)}
 }
}
func TestRuntimeInterfaceHookErrorsDoNotFallback(t *testing.T){
 expected:=errors.New("owner sealed")
 monitor:=&Monitor{hooks:Hooks{Interfaces:func()([]Interface,error){return nil,expected}}}
 if _,err:=monitor.interfaceStateUncached();!errors.Is(err,expected){t.Fatalf("state fallback: %v",err)}
 if _,_,err:=monitor.LocalAddresses();!errors.Is(err,expected){t.Fatalf("endpoint fallback: %v",err)}
 if _,err:=monitor.HasCGNATInterface();!errors.Is(err,expected){t.Fatalf("CGNAT fallback: %v",err)}
}
func TestRuntimeCGNATUsesOnlyOwnerInterfaces(t *testing.T){
 first:=&Monitor{hooks:Hooks{Interfaces:runtimeTestInterfaces("wan-a","100.64.1.1")}}
 second:=&Monitor{hooks:Hooks{Interfaces:runtimeTestInterfaces("wan-b","192.0.2.1")}}
 yes,err:=first.HasCGNATInterface();if err!=nil||!yes{t.Fatalf("first: %v %v",yes,err)}
 no,err:=second.HasCGNATInterface();if err!=nil||no{t.Fatalf("second: %v %v",no,err)}
}
