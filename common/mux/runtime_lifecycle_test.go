package mux

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	M "github.com/sagernet/sing/common/metadata"
)

type muxTestSource struct { mu sync.Mutex; refs int }
type muxTestLease struct { source *muxTestSource; released bool }
func (*muxTestSource) ID() adapter.RuntimeResourceID { return adapter.RuntimeResourceID{Incarnation: "mux-test", Sequence: 1} }
func (s *muxTestSource) Acquire() (adapter.RuntimeResourceLease, error) { s.mu.Lock(); defer s.mu.Unlock(); s.refs++; return &muxTestLease{source:s},nil }
func (l *muxTestLease) ID() adapter.RuntimeResourceID { return l.source.ID() }
func (*muxTestLease) Retiring() <-chan struct{} { return nil }
func (l *muxTestLease) Fork() (adapter.RuntimeResourceLease,error) { l.source.mu.Lock(); defer l.source.mu.Unlock(); if l.released { return nil,net.ErrClosed }; l.source.refs++;return &muxTestLease{source:l.source},nil }
func (l *muxTestLease) Release() { l.source.mu.Lock();defer l.source.mu.Unlock();if !l.released { l.released=true;l.source.refs-- } }

type muxTestDialer struct { entered chan context.Context; proceed chan struct{}; conn *muxTestConn }
func (d *muxTestDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn,error) { d.entered<-ctx; <-d.proceed;return d.conn,nil }
func (*muxTestDialer) ListenPacket(context.Context,M.Socksaddr)(net.PacketConn,error) { return nil,net.ErrClosed }
type muxTestConn struct { closes atomic.Int32; closeErr error }
func (*muxTestConn) Read([]byte)(int,error){return 0,net.ErrClosed}
func (*muxTestConn) Write(p []byte)(int,error){return len(p),nil}
func (c *muxTestConn) Close()error{c.closes.Add(1);return c.closeErr}
func (*muxTestConn) LocalAddr()net.Addr{return &net.TCPAddr{}}
func (*muxTestConn) RemoteAddr()net.Addr{return &net.TCPAddr{}}
func (*muxTestConn) SetDeadline(time.Time)error{return nil}
func (*muxTestConn) SetReadDeadline(time.Time)error{return nil}
func (*muxTestConn) SetWriteDeadline(time.Time)error{return nil}

func TestOwnedMultiplexLatePhysicalResultCannotPublish(t *testing.T) {
	for _, closeErr := range []error{nil, context.Canceled} {
		source := &muxTestSource{}
		lease, _ := source.Acquire()
		ctx := adapter.ContextWithRuntimeResourceLease(context.Background(), lease)
		stop, cancel := context.WithCancel(context.Background())
		owner := &Client{source:source,stop:stop,cancel:cancel,fences:outbound.NewRuntimeIOFenceSet()}
		raw := &muxTestConn{closeErr:closeErr}
		underlying := &muxTestDialer{entered:make(chan context.Context),proceed:make(chan struct{}),conn:raw}
		dialer := &clientDialer{Dialer:underlying,owner:owner}
		result := make(chan error,1)
		go func(){ conn,err:=dialer.DialContext(ctx,"tcp",M.Socksaddr{});if conn!=nil { result<-errors.New("late carrier published");return };result<-err }()
		physicalContext := <-underlying.entered
		owner.fences.Stop();cancel()
		<-physicalContext.Done()
		close(underlying.proceed)
		if err:=<-result;err==nil { t.Fatal("sealed pool published a physical carrier") }
		err:=owner.fences.Wait()
		if closeErr==nil && err!=nil { t.Fatal(err) }
		if closeErr!=nil && (err==nil || errors.Is(err,context.Canceled)) { t.Fatal("uncertain close became filterable completion") }
		if raw.closes.Load()!=1 { t.Fatal("late raw close did not have one actual owner") }
		lease.Release()
		source.mu.Lock();refs:=source.refs;source.mu.Unlock()
		if refs!=0 { t.Fatal("idle physical carrier pinned the owner") }
	}
}
