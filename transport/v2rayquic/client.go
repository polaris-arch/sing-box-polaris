//go:build with_quic

package v2rayquic

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.V2RayMultiplexClientTransport = (*Client)(nil)

type Client struct {
	ctx        context.Context
	dialer     N.Dialer
	serverAddr M.Socksaddr
	tlsConfig  tls.Config
	quicConfig *quic.Config
	connAccess sync.Mutex
	conn       common.TypedValue[*clientConnection]
	boundary *httpclient.RuntimeTransportBoundary
	source adapter.RuntimeResourceSource
	closed bool
	creating chan struct{}
	closeIdle  atomic.Bool
}

type clientConnection struct {
	*quic.Conn
	session *httpclient.RuntimeQUICSession
	access    sync.Mutex
	streams   int
	closed    bool
	closeIdle *atomic.Bool
}

func (c *clientConnection) active() bool {
	c.access.Lock()
	closed := c.closed
	c.access.Unlock()
	return !closed && !common.Done(c.Context())
}

func (c *clientConnection) acquireStream() bool {
	c.access.Lock()
	defer c.access.Unlock()
	if c.closed {
		return false
	}
	c.streams++
	return true
}

func (c *clientConnection) releaseStream(keepSession bool) {
	c.access.Lock()
	c.streams--
	closed := c.closeIdle.Load() && !keepSession && c.streams == 0 && c.markClosedLocked()
	c.access.Unlock()
	if closed {
		c.session.RuntimeCloseAndWait()
	}
}

func (c *clientConnection) markClosedLocked() bool {
	if c.closed {
		return false
	}
	c.closed = true
	return true
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayQUICOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery: !C.IsLinux && !C.IsWindows,
	}
	if len(tlsConfig.NextProtos()) == 0 {
		tlsConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	client:=&Client{
		ctx:        ctx,
		dialer:     dialer,
		serverAddr: serverAddr,
		tlsConfig:  tlsConfig,
		quicConfig: quicConfig,
	}
	client.source,_=adapter.RuntimeResourceSourceFromContext(ctx)
	client.boundary=httpclient.NewRuntimeTransportBoundary(func()error{client.connAccess.Lock();client.closed=true;client.conn.Swap(nil);client.connAccess.Unlock();return nil})
	return client,nil
}

func(c *Client)offer(ctx context.Context)(*clientConnection,error){
	for{
		c.connAccess.Lock();if c.closed{c.connAccess.Unlock();return nil,net.ErrClosed}
		if conn:=c.conn.Load();conn!=nil&&conn.active(){c.connAccess.Unlock();return conn,nil}
		if pending:=c.creating;pending!=nil{c.connAccess.Unlock();select{case <-pending:continue;case <-ctx.Done():return nil,ctx.Err()}}
		pending:=make(chan struct{});c.creating=pending;c.connAccess.Unlock()
		conn,err:=c.offerNew(ctx)
		c.connAccess.Lock();closed:=c.closed;if err==nil&&!closed{c.conn.Store(conn)};c.creating=nil;close(pending);c.connAccess.Unlock()
		if err!=nil{return nil,err};if closed{c.boundary.RecordClose(conn.session.RuntimeCloseAndWait());return nil,net.ErrClosed};return conn,nil
	}
}
func(c *Client)offerNew(ctx context.Context)(*clientConnection,error){
	ctx,leave,err:=c.boundary.BeginDial(ctx);if err!=nil{return nil,err};defer leave()
	if c.source!=nil{var err error;ctx,err=outbound.ContextForRuntimeOwnedSession(ctx,c.source);if err!=nil{return nil,err}}
	config,err:=c.tlsConfig.STDConfig();if err!=nil{return nil,err}
	raw,err:=c.dialer.DialContext(ctx,N.NetworkUDP,c.serverAddr);if err!=nil{return nil,err}
	session,err:=httpclient.DialRuntimeQUIC(ctx,raw,config,c.quicConfig,c.boundary.RecordClose);if err!=nil{return nil,err}
	if err=c.boundary.RegisterResource(session);err!=nil{return nil,err}
	// This protocol historically used Dial, not DialEarly: do not publish a
	// stream before the authenticated handshake has actually completed.
	select{case <-session.Conn.HandshakeComplete():case <-session.Conn.Context().Done():return nil,context.Cause(session.Conn.Context());case <-ctx.Done():c.boundary.RecordClose(session.RuntimeCloseAndWait());return nil,ctx.Err()}
	return &clientConnection{Conn:session.Conn,session:session,closeIdle:&c.closeIdle},nil
}

func(c *Client)DialContext(ctx context.Context)(net.Conn,error){
	ctx,release,err:=adapter.AcquireRuntimeOperation(ctx,c.source);if err!=nil{return nil,err}
	leave,err:=c.boundary.Acquire();if err!=nil{release();return nil,err};defer leave()
	conn,err:=c.dialContextOwned(ctx);if err!=nil{release();return nil,err};return outbound.WrapRuntimeConn(ctx,release,conn),nil
}
func (c *Client) dialContextOwned(ctx context.Context) (net.Conn, error) {
	for {
		conn, err := c.offer(ctx)
		if err != nil {
			return nil, err
		}
		if !conn.acquireStream() {
			continue
		}
		stream, err := conn.OpenStream()
		if err != nil {
			conn.releaseStream(false)
			return nil, err
		}
		keepSession := adapter.KeepSessionFromContext(ctx)
		return &StreamWrapper{Conn: conn.Conn, Stream: stream, onClose: func() { conn.releaseStream(keepSession) }}, nil
	}
}

func (c *Client) MultiplexEnabled() bool {
	return true
}

func (c *Client) SetKeepIdleConnections(keep bool) {
	c.closeIdle.Store(!keep)
	if !keep {
		c.CloseIdleConnections()
	}
}

func (c *Client) CloseIdleConnections() {
	conn := c.conn.Load()
	if conn == nil {
		return
	}
	conn.access.Lock()
	closed := conn.streams == 0 && conn.markClosedLocked()
	conn.access.Unlock()
	if closed {
		conn.session.RuntimeCloseAndWait()
	}
}

func(c *Client)Close()error{return c.boundary.RuntimeCloseAndWait()}
func(c *Client)RuntimeCloseAndWait()error{return c.Close()}

func(c *Client)StopRuntimeOperations(){c.boundary.StopRuntimeOperations()}
