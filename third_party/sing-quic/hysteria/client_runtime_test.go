package hysteria

import (
 "context"
 "crypto/tls"
 "crypto/x509"
 "net/http/httptest"
 "sync/atomic"
 "testing"
 "time"

 "github.com/sagernet/quic-go"
)

func TestClientStreamCloseAfterPeerReset(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	fixture := httptest.NewTLSServer(nil)
	fixture.Close()
	protocols := []string{"hysteria-test"}
	fixture.TLS.NextProtos = protocols
	listener, err := quic.ListenAddr("127.0.0.1:0", fixture.TLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	certs := x509.NewCertPool()
	certs.AddCert(fixture.Certificate())
	client, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{ServerName: "127.0.0.1", RootCAs: certs, NextProtos: protocols}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(0, "")
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.CloseWithError(0, "")
	stream, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	peer, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Any peer STOP_SENDING code completes this stream's send side.
	peer.CancelRead(42)
	select {
	case <-stream.Context().Done():
	case <-ctx.Done():
		t.Fatal("peer reset did not reach the client")
	}
	owner := &clientQUICConnection{streams: 1, closeIdle: new(atomic.Bool)}
	if err := (&clientConn{Stream: stream, parent: owner}).Close(); err != nil {
		t.Fatalf("Close after this stream's peer reset returned %v", err)
	}
	if owner.streams != 0 {
		t.Fatalf("client owns %d streams after close", owner.streams)
	}
}

func TestClientRuntimeJoinsActualWorkerAndRejectsNewWork(t *testing.T){
 c:=&Client{ctx:context.Background()};c.initRuntime()
 entered,release,closed:=make(chan struct{}),make(chan struct{}),make(chan struct{})
 if !c.runtime.run(func(){close(entered);<-release}){t.Fatal("initial admission rejected")}
 <-entered
 go func(){_ = c.RuntimeCloseAndWait();close(closed)}()
 select{case <-c.ctx.Done():case <-time.After(5*time.Second):t.Fatal("close did not cancel client lifetime")}
 select{case <-closed:t.Fatal("close certified an unfinished worker");default:}
 if c.runtime.run(func(){t.Error("sealed worker was dispatched")}){t.Fatal("sealed admission accepted")}
 close(release)
 select{case <-closed:case <-time.After(5*time.Second):t.Fatal("actual worker completion was not joined")}
 if _,err:=c.offer(context.Background());err==nil{t.Fatal("terminal client reused")}
 if err:=c.RuntimeCloseAndWait();err!=nil{t.Fatal(err)}
}
func TestClientRuntimeCancelsPendingOfferBeforeJoin(t *testing.T){
 c:=&Client{ctx:context.Background()};c.initRuntime()
 ctx,cancel:=context.WithCancelCause(c.ctx)
 c.pending=&clientOffer{done:make(chan struct{}),cancel:cancel}
 left:=make(chan struct{})
 if !c.runtime.run(func(){<-ctx.Done();close(left)}){t.Fatal("admission")}
 if err:=c.RuntimeCloseAndWait();err!=nil{t.Fatal(err)}
 select{case <-left:default:t.Fatal("pending offer was not joined")}
 if !c.pending.discarded{t.Fatal("late pending offer may publish")}
}
