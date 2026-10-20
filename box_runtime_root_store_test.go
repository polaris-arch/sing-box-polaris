package box

import (
 "context"
 "testing"
 "time"

 C "github.com/sagernet/sing-box/constant"
 "github.com/sagernet/sing-box/option"
)

func TestRuntimeRootSnapshotFingerprintRebuildsConsumersOnly(t *testing.T){
 configs:=map[string]runtimeNodeOptions{
  "inbound:tun":{inbound:&option.Inbound{Type:C.TypeTun}},
  "inbound:http":{inbound:&option.Inbound{Type:C.TypeHTTP}},
  "outbound:tls":{outbound:&option.Outbound{Type:C.TypeHTTP}},
 }
 nodes:=[]runtimeDependencyNode{{name:"http-manager",fingerprint:"http"},{name:"inbound:tun",fingerprint:"tun"},{name:"inbound:http",fingerprint:"in"},{name:"outbound:tls",fingerprint:"out"},{name:"rule-set:test",fingerprint:"set"}}
 first:=append([]runtimeDependencyNode(nil),nodes...)
 second:=append([]runtimeDependencyNode(nil),nodes...)
 runtimeBindRootFingerprints(first,configs,[32]byte{1})
 runtimeBindRootFingerprints(second,configs,[32]byte{2})
 for i:=range nodes{
  capture:=i==0||i==2||i==3
  if (first[i].fingerprint!=second[i].fingerprint)!=capture{t.Fatalf("unexpected root dependency for %s",nodes[i].name)}
 }
}

func TestRuntimeRootWatcherWithoutFileWatcherSignalsAndJoins(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background());defer cancel()
 roots:=make(chan struct{},1)
 p:=&runtimeSourceProducer{ctx:ctx,cancel:cancel,rootChanges:roots,eventsDone:make(chan struct{}),changed:make(chan struct{},1)}
 go p.events()
 defer func(){cancel();<-p.eventsDone}()
 roots<-struct{}{}
 select{case <-p.changed:case <-time.After(5*time.Second):t.Fatal("root notification was not forwarded")}
 // Cancellation joins the actual event select tail even with nil fsnotify
 // channels. No root update directly calls graph mutation or a TLS consumer.
 cancel();<-p.eventsDone
}
