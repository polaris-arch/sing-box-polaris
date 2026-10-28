package ratelimiter

import (
 "net/netip"
 "sync/atomic"
 "testing"
 "time"
)

func TestRuntimeCloseJoinsOriginalCollector(t *testing.T){
 entered,release:=make(chan struct{}),make(chan struct{})
 var calls atomic.Int32
 rate:=new(Ratelimiter)
 rate.timeNow=func()time.Time{if calls.Add(1)==2{close(entered);<-release};return time.Now()}
 rate.Init();rate.Allow(netip.MustParseAddr("192.0.2.1"))
 select{case <-entered:case <-time.After(3*time.Second):t.Fatal("collector did not enter original cleanup")}
 done:=make(chan struct{});go func(){rate.Close();close(done)}()
 select{case <-done:t.Fatal("collector was declared complete inside cleanup");case <-time.After(10*time.Millisecond):}
 close(release)
 select{case <-done:case <-time.After(time.Second):t.Fatal("collector close failed to join")}
 rate.Close()
 if rate.Allow(netip.MustParseAddr("192.0.2.2")){t.Fatal("closed collector accepted new entry")}
 rate.Init();rate.Close()
}
