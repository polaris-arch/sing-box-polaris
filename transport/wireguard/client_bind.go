package wireguard

import (
	"context"
 "errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/conn"
)

var _ conn.Bind = (*ClientBind)(nil)

type ClientBind struct {
	ctx                 context.Context
	logger              logger.Logger
	pauseManager        pause.Manager
	bindAccess sync.Mutex
 closeAccess sync.Mutex
 closeErr error
	bindCtx             context.Context
	bindDone            context.CancelFunc
	dialer              N.Dialer
	reservedAccess      sync.RWMutex
	reservedForEndpoint map[netip.AddrPort][3]uint8
	connAccess          sync.Mutex
	conn                *wireConn
	done                chan struct{}
	isConnect           bool
	connectAddr         netip.AddrPort
	reserved            [3]uint8
}

func NewClientBind(ctx context.Context, logger logger.Logger, dialer N.Dialer, isConnect bool, connectAddr netip.AddrPort, reserved [3]uint8) *ClientBind {
	return &ClientBind{
		ctx:                 ctx,
		logger:              logger,
		pauseManager:        service.FromContext[pause.Manager](ctx),
		dialer:              dialer,
		reservedForEndpoint: make(map[netip.AddrPort][3]uint8),
		done:                make(chan struct{}),
		isConnect:           isConnect,
		connectAddr:         connectAddr,
		reserved:            reserved,
	}
}

func (c *ClientBind) connect(ctx context.Context) (*wireConn, error) {
 if ctx==nil{return nil,net.ErrClosed}
 c.connAccess.Lock();defer c.connAccess.Unlock()
 if ctx.Err()!=nil{return nil,net.ErrClosed}
 if current:=c.conn;current!=nil{select{case <-current.done:c.record(current.closeErr);default:return current,nil}}
 var packet net.PacketConn
 if c.isConnect{
  raw,err:=c.dialer.DialContext(ctx,N.NetworkUDP,M.SocksaddrFromNetIP(c.connectAddr))
  if err!=nil{if raw!=nil{c.record(raw.Close())};return nil,err}
  packet=bufio.NewUnbindPacketConn(raw)
 }else{
  raw,err:=c.dialer.ListenPacket(ctx,M.Socksaddr{Addr:netip.IPv4Unspecified()})
  if err!=nil{if raw!=nil{c.record(raw.Close())};return nil,err};packet=raw
 }
 candidate:=&wireConn{PacketConn:packet,done:make(chan struct{})}
 if ctx.Err()!=nil{c.record(candidate.Close());return nil,net.ErrClosed}
 c.conn=candidate;return candidate,nil
}
func(c *ClientBind)currentContext()context.Context{c.bindAccess.Lock();defer c.bindAccess.Unlock();return c.bindCtx}
func(c *ClientBind)record(err error){if err==nil{return};c.closeAccess.Lock();c.closeErr=errors.Join(c.closeErr,err);c.closeAccess.Unlock()}
func(c *ClientBind)retry(ctx context.Context)error{
 if ctx==nil{return net.ErrClosed}
 // A root pause.Manager.WaitActive cannot be interrupted by this bind's
 // cancellation. This bounded retry preserves pause behavior while letting the
 // actual receive routine exit on Close, even if the Box remains paused.
 timer:=time.NewTimer(time.Second);defer timer.Stop()
 for{select{case <-ctx.Done():return net.ErrClosed;case <-timer.C:
  if c.pauseManager==nil||!c.pauseManager.IsPaused(){return nil};timer.Reset(time.Second)
 }}
}
func (c *ClientBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
 c.bindAccess.Lock();defer c.bindAccess.Unlock()
 if c.bindCtx!=nil&&c.bindCtx.Err()==nil{return nil,0,conn.ErrBindAlreadyOpen}
 c.done=make(chan struct{});c.bindCtx,c.bindDone=context.WithCancel(c.ctx);ctx:=c.bindCtx
 // Capture the exact epoch: a retiring receive routine must never reconnect
 // against a later Open's context, socket, or done channel.
 return []conn.ReceiveFunc{func(packets [][]byte,sizes []int,eps []conn.Endpoint)(int,error){return c.receive(ctx,packets,sizes,eps)}},0,nil
}
func (c *ClientBind) receive(ctx context.Context,packets [][]byte,sizes []int,eps []conn.Endpoint)(count int,err error){
 udpConn,err:=c.connect(ctx)
 if err!=nil{if ctx.Err()!=nil{return 0,net.ErrClosed};c.logger.Error(E.Cause(err,"connect to server"));return 0,c.retry(ctx)}
 n,addr,err:=udpConn.ReadFrom(packets[0])
 if err!=nil{c.record(udpConn.Close());if ctx.Err()!=nil{return 0,net.ErrClosed};c.logger.Error(E.Cause(err,"read packet"));return 0,nil}
 sizes[0]=n;if n>3{clear(packets[0][1:4])};eps[0]=remoteEndpoint(M.SocksaddrFromNet(addr).Unwrap().AddrPort());return 1,nil
}
func (c *ClientBind) Close()error{
 c.bindAccess.Lock()
 if c.bindDone!=nil{c.bindDone()}
 select{case <-c.done:default:close(c.done)}
 c.bindAccess.Unlock()
 // Cancellation precedes taking connAccess, so a blocked context-aware dial
 // can return. A context-ignoring late dial is retained until it really exits.
 c.connAccess.Lock();current:=c.conn;c.conn=nil
 if current!=nil{c.record(current.Close())};c.connAccess.Unlock()
 c.closeAccess.Lock();defer c.closeAccess.Unlock();return c.closeErr
}

func (c *ClientBind) SetMark(mark uint32) error {
	return nil
}

func (c *ClientBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	ctx:=c.currentContext()
 udpConn, err := c.connect(ctx)
	if err != nil {
		_ = c.retry(ctx)
		return err
	}
	destination := netip.AddrPort(ep.(remoteEndpoint))
	for _, buf := range bufs {
		if offset > 0 {
			buf = buf[offset:]
		}
		if len(buf) > 3 {
			c.reservedAccess.RLock()
			reserved, loaded := c.reservedForEndpoint[destination]
			c.reservedAccess.RUnlock()
			if !loaded {
				reserved = c.reserved
			}
			copy(buf[1:4], reserved[:])
		}
		_, err = udpConn.WriteToUDPAddrPort(buf, destination)
		if err != nil {
			c.record(udpConn.Close())
			return err
		}
	}
	return nil
}

func (c *ClientBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return remoteEndpoint(ap), nil
}

func (c *ClientBind) BatchSize() int {
	return 1
}

func (c *ClientBind) SetReservedForEndpoint(destination netip.AddrPort, reserved [3]byte) {
	c.reservedAccess.Lock()
	c.reservedForEndpoint[destination] = reserved
	c.reservedAccess.Unlock()
}

type wireConn struct {
	net.PacketConn
	conn   net.Conn
	closeOnce sync.Once
 closeErr error
	done   chan struct{}
}

func (w *wireConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	if w.conn != nil {
		return w.conn.Write(b)
	}
	return w.PacketConn.WriteTo(b, M.SocksaddrFromNetIP(addr).UDPAddr())
}

func (w *wireConn) Close()error{
 w.closeOnce.Do(func(){defer close(w.done);w.closeErr=errors.New("WireGuard socket close did not return");w.closeErr=w.PacketConn.Close()})
 <-w.done;return w.closeErr
}

var _ conn.Endpoint = (*remoteEndpoint)(nil)

type remoteEndpoint netip.AddrPort

func (e remoteEndpoint) ClearSrc() {
}

func (e remoteEndpoint) SrcToString() string {
	return ""
}

func (e remoteEndpoint) DstToString() string {
	return netip.AddrPort(e).String()
}

func (e remoteEndpoint) DstToBytes() []byte {
	b, _ := netip.AddrPort(e).MarshalBinary()
	return b
}

func (e remoteEndpoint) DstIP() netip.Addr {
	return netip.AddrPort(e).Addr()
}

func (e remoteEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}
