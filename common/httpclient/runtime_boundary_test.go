package httpclient

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

// These deterministic barrier fixtures are source-authored only. Every blocked
// stage is released by a channel owned by the test; no network or timing oracle
// is needed to distinguish close initiation from actual method completion.
type runtimeBarrierConn struct {
	readEntered chan struct{}
	readReturn chan struct{}
	closeEntered chan struct{}
	closeReturn chan struct{}
	readOnce sync.Once
	closeOnce sync.Once
	closes atomic.Int32
}
func newRuntimeBarrierConn()*runtimeBarrierConn{return &runtimeBarrierConn{readEntered:make(chan struct{}),readReturn:make(chan struct{}),closeEntered:make(chan struct{}),closeReturn:make(chan struct{})}}
func(c *runtimeBarrierConn)Read([]byte)(int,error){c.readOnce.Do(func(){close(c.readEntered)});<-c.readReturn;return 0,io.EOF}
func(c *runtimeBarrierConn)Write(p []byte)(int,error){return len(p),nil}
func(c *runtimeBarrierConn)Close()error{c.closes.Add(1);c.closeOnce.Do(func(){close(c.closeEntered)});<-c.closeReturn;return nil}
func(*runtimeBarrierConn)LocalAddr()net.Addr{return &net.TCPAddr{}}
func(*runtimeBarrierConn)RemoteAddr()net.Addr{return &net.TCPAddr{}}
func(*runtimeBarrierConn)SetDeadline(time.Time)error{return nil}
func(*runtimeBarrierConn)SetReadDeadline(time.Time)error{return nil}
func(*runtimeBarrierConn)SetWriteDeadline(time.Time)error{return nil}

func TestRuntimeBoundaryJoinsAdmittedSocketTail(t *testing.T){
	b:=NewRuntimeTransportBoundary(nil)
	raw:=newRuntimeBarrierConn();close(raw.closeReturn)
	conn,err:=b.GuardConnection(raw);if err!=nil{t.Fatal(err)}
	readDone:=make(chan struct{});go func(){defer close(readDone);_,_=conn.Read(make([]byte,1))}();<-raw.readEntered
	closed:=make(chan error,1);go func(){closed<-b.Close()}();<-raw.closeEntered
	select{case <-closed:t.Fatal("close reported completion before admitted read returned");default:}
	close(raw.readReturn);<-readDone;if err=<-closed;err!=nil{t.Fatal(err)}
	if _,err=conn.Read(nil);!errors.Is(err,net.ErrClosed){t.Fatalf("post-close read: %v",err)}
	if raw.closes.Load()!=1{t.Fatalf("raw closes: %d",raw.closes.Load())}
}

func TestRuntimeBoundaryJoinsLateDialCleanup(t *testing.T){
	sealed:=make(chan struct{});b:=NewRuntimeTransportBoundary(func()error{close(sealed);return nil})
	entered,finish:=make(chan struct{}),make(chan struct{});raw:=newRuntimeBarrierConn()
	dialDone:=make(chan error,1);go func(){_,err:=b.Dial(context.Background(),func(context.Context)(net.Conn,error){close(entered);<-finish;return raw,nil});dialDone<-err}();<-entered
	closed:=make(chan error,1);go func(){closed<-b.Close()}();<-sealed;close(finish);<-raw.closeEntered
	select{case <-closed:t.Fatal("close escaped a blocked late-result close");default:}
	close(raw.closeReturn);if err:=<-dialDone;!errors.Is(err,net.ErrClosed){t.Fatalf("late dial: %v",err)}
	if err:=<-closed;err!=nil{t.Fatal(err)}
}

func TestRuntimeRequestJoinsTraceAndRejectsLateTrace(t *testing.T){
	entered,finish:=make(chan struct{}),make(chan struct{});var calls atomic.Int32
	request,_:=http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(),&httptrace.ClientTrace{WroteRequest:func(httptrace.WroteRequestInfo){calls.Add(1);close(entered);<-finish}}),http.MethodGet,"https://example.invalid",nil)
	b:=NewRuntimeTransportBoundary(nil);returned:=make(chan struct{});var trace *httptrace.ClientTrace
	go func(){defer close(returned);_,_=b.RoundTrip(request,func(r *http.Request)(*http.Response,error){trace=httptrace.ContextClientTrace(r.Context());go trace.WroteRequest(httptrace.WroteRequestInfo{});<-entered;return nil,io.EOF})}()
	<-entered;select{case <-returned:t.Fatal("request returned through active caller callback");default:};close(finish);<-returned
	trace.WroteRequest(httptrace.WroteRequestInfo{});if calls.Load()!=1{t.Fatal("sealed trace called original callback")}
	if err:=b.Close();err!=nil{t.Fatal(err)}
}

type runtimeTestInner struct{closed atomic.Int32}
func(t *runtimeTestInner)RoundTrip(r *http.Request)(*http.Response,error){return &http.Response{StatusCode:200,Body:io.NopCloser(strings.NewReader("ok")),Request:r},nil}
func(*runtimeTestInner)CloseIdleConnections(){}
func(t *runtimeTestInner)Close()error{t.closed.Add(1);return nil}

func TestRuntimeManagerFreezeAndTerminalDefault(t *testing.T){
	inner:=new(runtimeTestInner)
	m:=NewManager(context.Background(),nil,nil,"")
	if err:=m.PrepareRuntime(func()(*ManagedTransport,error){managed:=&ManagedTransport{factory:func()(innerTransport,error){return inner,nil}};managed.epoch.Store(&transportEpoch{transport:inner});if err:=managed.initializeRuntime(context.Background());err!=nil{return nil,err};return managed,nil});err!=nil{t.Fatal(err)}
	if err:=m.FreezeRuntime();err!=nil{t.Fatal(err)}
	if err:=m.RuntimeCloseAndWait();err!=nil{t.Fatal(err)}
	request,_:=http.NewRequest(http.MethodGet,"https://example.invalid",nil)
	if _,err:=m.DefaultTransport().RoundTrip(request);!errors.Is(err,net.ErrClosed){t.Fatalf("terminal default: %v",err)}
	if _,err:=m.ResolveTransport(context.Background(),nil,option.HTTPClientOptions{});!errors.Is(err,net.ErrClosed){t.Fatalf("terminal resolve: %v",err)}
	if inner.closed.Load()!=1{t.Fatalf("actual inner closes: %d",inner.closed.Load())}
}

func TestRuntimeBoundaryCancelsDetachedPhysicalDial(t *testing.T){
	b:=NewRuntimeTransportBoundary(nil);entered,returned:=make(chan struct{}),make(chan struct{})
	go func(){defer close(returned);_,_=b.Dial(context.Background(),func(ctx context.Context)(net.Conn,error){close(entered);<-ctx.Done();return nil,ctx.Err()})}();<-entered
	if err:=b.Close();err!=nil{t.Fatal(err)};<-returned
}

func TestRuntimeBoundaryRetainsCleanupPanic(t *testing.T){
	b:=NewRuntimeTransportBoundary(func()error{panic("native teardown")})
	if err:=b.Close();err==nil{t.Fatal("cleanup panic was certified complete")}
	if err:=b.Close();err==nil{t.Fatal("cleanup uncertainty was not sticky")}
}
