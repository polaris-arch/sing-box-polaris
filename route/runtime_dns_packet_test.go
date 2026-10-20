package route

import (
	"context"
	"testing"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	mDNS "github.com/miekg/dns"
)

type packetQueryView struct {
	adapter.RuntimeView
	identity adapter.RuntimeRevision
	dns adapter.DNSRouter
}
func (v *packetQueryView) Identity() adapter.RuntimeRevision { return v.identity }
func (v *packetQueryView) DNSRouter() adapter.DNSRouter { return v.dns }
type packetQueryDNS struct { adapter.DNSRouter; calls chan func(*mDNS.Msg,error) }
func (d *packetQueryDNS) ExchangeAsync(_ context.Context, _ *mDNS.Msg, _ adapter.DNSQueryOptions, cb func(*mDNS.Msg,error)) { d.calls <- cb }
type packetQueryWriter struct { N.PacketWriter; entered chan struct{}; release chan struct{} }
func (w *packetQueryWriter) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	defer buffer.Release()
	close(w.entered); <-w.release; return nil
}
func packetQueryWait(t *testing.T, ch <-chan struct{}) {
	t.Helper(); select { case <-ch: case <-time.After(5*time.Second): t.Fatal("packet query completion watchdog") }
}
func packetQueryPending(t *testing.T, ch <-chan struct{}) {
	t.Helper(); select { case <-ch: t.Fatal("query resource retired before response write completed"); default: }
}

func TestRuntimeDNSPacketUsesCurrentPolicyAndRetainsOldWriterThroughWrite(t *testing.T) {
	store, err := runtimegraph.NewStore("packet-test"); if err != nil { t.Fatal(err) }
	defer store.Seal()
	oldDNS := &packetQueryDNS{calls:make(chan func(*mDNS.Msg,error),1)}
	newDNS := &packetQueryDNS{calls:make(chan func(*mDNS.Msg,error),1)}
	oldID := adapter.RuntimeRevision{Incarnation:"packet-test",Revision:1}
	oldGraph, err := runtimegraph.NewGraph(&packetQueryView{identity:oldID,dns:oldDNS}, nil); if err != nil { t.Fatal(err) }
	if _, err := store.Publish(adapter.RuntimeRevision{Incarnation:"packet-test"}, oldGraph); err != nil { t.Fatal(err) }
	oldLease, err := store.Acquire(); if err != nil { t.Fatal(err) }; defer oldLease.Release()
	newGraph, err := runtimegraph.NewGraph(&packetQueryView{identity:adapter.RuntimeRevision{Incarnation:"packet-test",Revision:2},dns:newDNS}, nil); if err != nil { t.Fatal(err) }
	if _, err := store.Publish(oldID,newGraph); err != nil { t.Fatal(err) }
	ctx := adapter.ContextWithRuntimeLease(context.Background(),oldLease)
	ctx = adapter.ContextWithRuntimeDNSIngress(ctx,NewRuntimeDNSRouter(store))
	leaf := &Router{dns:oldDNS,logger:log.NewNOPFactory().Logger()}
	message := new(mDNS.Msg); message.SetQuestion("example.org.",mDNS.TypeA)
	payload, err := message.Pack(); if err != nil { t.Fatal(err) }
	writer := &packetQueryWriter{entered:make(chan struct{}),release:make(chan struct{})}
	unblock := sync.OnceFunc(func(){ close(writer.release) })
	done := make(chan struct{})
	started := false
	t.Cleanup(func(){ unblock(); if started { packetQueryWait(t,done) } })
	leaf.HijackDNSPacket(ctx,payload,writer,adapter.InboundContext{})
	var callback func(*mDNS.Msg,error)
	select { case callback = <-newDNS.calls: default: t.Fatal("query did not admit current DNS") }
	select { case <-oldDNS.calls: t.Fatal("query used carrier's old DNS policy"); default: }
	oldLease.Release(); store.Seal()
	packetQueryPending(t,oldGraph.Drained()); packetQueryPending(t,newGraph.Drained())
	started = true
	go func(){ defer close(done); response:=new(mDNS.Msg); response.SetReply(message); callback(response,nil) }()
	packetQueryWait(t,writer.entered)
	packetQueryPending(t,oldGraph.Drained()); packetQueryPending(t,newGraph.Drained())
	unblock(); packetQueryWait(t,done)
	packetQueryWait(t,oldGraph.Drained()); packetQueryWait(t,newGraph.Drained())
}
