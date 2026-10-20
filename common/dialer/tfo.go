package dialer

import (
	"context"
 "errors"
 "fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/database64128/tfo-go/v2"
)

type slowOpenConn struct {
	dialer      *tfo.Dialer
	ctx         context.Context
	cancel      context.CancelFunc
	network     string
	destination M.Socksaddr
	conn        atomic.Pointer[net.TCPConn]
	create      chan struct{}
	done        chan struct{}
	access      sync.Mutex
	closeOnce   sync.Once
	err         error
 lifecycleAccess sync.Mutex
 creating bool
 creationDone chan struct{}
 closed bool
 lateCloseErr error
 closeErr error
 dial func(context.Context,string,string,[]byte)(net.Conn,error)
}

func DialSlowContext(dialer *tfo.Dialer, ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if dialer.DisableTFO || N.NetworkName(network) != N.NetworkTCP {
		switch N.NetworkName(network) {
		case N.NetworkTCP, N.NetworkUDP:
			return dialer.Dialer.DialContext(ctx, network, destination.String())
		default:
			return dialer.Dialer.DialContext(ctx, network, destination.AddrString())
		}
	}
	dialCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	return &slowOpenConn{
		dialer:      dialer,
		ctx:         dialCtx,
		cancel:      cancel,
		network:     network,
		destination: destination,
		create:      make(chan struct{}),
		done:        make(chan struct{}),
  creationDone: make(chan struct{}),
  dial: dialer.DialContext,
	}, nil
}

func (c *slowOpenConn) Read(b []byte) (n int, err error) {
	conn := c.conn.Load()
	if conn != nil {
		return conn.Read(b)
	}
	select {
	case <-c.create:
		if c.err != nil {
			return 0, c.err
		}
		return c.conn.Load().Read(b)
	case <-c.done:
		return 0, os.ErrClosed
	}
}

func (c *slowOpenConn) Write(b []byte) (n int, err error) {
	tcpConn := c.conn.Load()
	if tcpConn != nil {
		return tcpConn.Write(b)
	}
	c.access.Lock()
	defer c.access.Unlock()
	select {
	case <-c.create:
		if c.err != nil {
			return 0, c.err
		}
		return c.conn.Load().Write(b)
	case <-c.done:
		return 0, os.ErrClosed
	default:
	}
 c.lifecycleAccess.Lock()
 if c.closed { c.lifecycleAccess.Unlock(); return 0,os.ErrClosed }
 c.creating = true
 c.lifecycleAccess.Unlock()
 defer func(){
  if value:=recover();value!=nil{
   err=fmt.Errorf("TFO creation completion unknown after panic: %v",value)
   c.err=err
   c.lifecycleAccess.Lock();c.lateCloseErr=err;c.lifecycleAccess.Unlock()
  }
  close(c.create)
  c.lifecycleAccess.Lock()
  c.creating = false
  close(c.creationDone)
  c.lifecycleAccess.Unlock()
 }()
 conn, err := c.dial(c.ctx, c.network, c.destination.String(), b)
	if err != nil {
  // A failed dial can still transfer a partially created socket. Its actual
  // Close belongs to this writer and is included in creationDone below.
  var cleanupErr error
  if conn != nil { cleanupErr = closeSlowOpenConnection(conn) }
  var incomplete interface { RuntimeCleanupIncomplete() bool }
  if errors.As(err, &incomplete) && incomplete.RuntimeCleanupIncomplete() {
   // Keep cleanup failure separate from cancellation/operational dial errors.
   // %v deliberately prevents cancellation filtering from erasing uncertainty.
   cleanupErr = errors.Join(cleanupErr,fmt.Errorf("TFO dependency cleanup incomplete: %v",err))
  }
  c.lifecycleAccess.Lock()
  c.lateCloseErr = errors.Join(c.lateCloseErr,cleanupErr)
  c.lifecycleAccess.Unlock()
  err = errors.Join(err,cleanupErr)
		c.err = err
	} else {
  tcpConn, validTCP := conn.(*net.TCPConn)
  c.lifecycleAccess.Lock()
  closed := c.closed
  if !closed && validTCP { c.conn.Store(tcpConn) }
  c.lifecycleAccess.Unlock()
  if closed || !validTCP {
   closeErr := closeSlowOpenConnection(conn)
   c.lifecycleAccess.Lock()
   c.lateCloseErr = closeErr
   c.lifecycleAccess.Unlock()
   err = errors.Join(os.ErrClosed,closeErr)
   c.err = err
  }
	}
	n = len(b)
	return
}

func (c *slowOpenConn) Close() error {
 c.closeOnce.Do(func() {
  c.lifecycleAccess.Lock()
  c.closed = true
  close(c.done)
  conn := c.conn.Load()
  creating := c.creating
  c.lifecycleAccess.Unlock()
  c.cancel()
  if conn != nil { c.closeErr = closeSlowOpenConnection(conn) }
  // The first writer owns any connection created after close admission. Its
  // actual late-close tail must finish before terminal success can be reported.
  if creating { <-c.creationDone }
  c.lifecycleAccess.Lock()
  c.closeErr = errors.Join(c.closeErr,c.lateCloseErr)
  c.lifecycleAccess.Unlock()
 })
 return c.closeErr
}

func (c *slowOpenConn) LocalAddr() net.Addr {
	conn := c.conn.Load()
	if conn == nil {
		return M.Socksaddr{}
	}
	return conn.LocalAddr()
}

func (c *slowOpenConn) RemoteAddr() net.Addr {
	conn := c.conn.Load()
	if conn == nil {
		return M.Socksaddr{}
	}
	return conn.RemoteAddr()
}

func (c *slowOpenConn) SetDeadline(t time.Time) error {
	conn := c.conn.Load()
	if conn == nil {
		return os.ErrInvalid
	}
	return conn.SetDeadline(t)
}

func (c *slowOpenConn) SetReadDeadline(t time.Time) error {
	conn := c.conn.Load()
	if conn == nil {
		return os.ErrInvalid
	}
	return conn.SetReadDeadline(t)
}

func (c *slowOpenConn) SetWriteDeadline(t time.Time) error {
	conn := c.conn.Load()
	if conn == nil {
		return os.ErrInvalid
	}
	return conn.SetWriteDeadline(t)
}

func (c *slowOpenConn) Upstream() any {
	return common.PtrOrNil(c.conn.Load())
}

func (c *slowOpenConn) ReaderReplaceable() bool {
	return c.conn.Load() != nil
}

func (c *slowOpenConn) WriterReplaceable() bool {
	return c.conn.Load() != nil
}

func (c *slowOpenConn) NeedHandshake() bool {
	return c.conn.Load() == nil
}

func (c *slowOpenConn) WriteTo(w io.Writer) (n int64, err error) {
	conn := c.conn.Load()
	if conn == nil {
		select {
		case <-c.create:
			if c.err != nil {
				return 0, c.err
			}
		case <-c.done:
			return 0, c.err
		}
	}
	return bufio.Copy(w, c.conn.Load())
}

// A panic or failed raw close is not cancellation evidence and must remain
// visible to the receiving resource's terminal cleanup.
func closeSlowOpenConnection(conn net.Conn) (err error) {
 defer func(){if value:=recover();value!=nil{err=fmt.Errorf("TFO connection cleanup unknown after panic: %v",value)}}()
 if closeErr:=conn.Close();closeErr!=nil{return fmt.Errorf("TFO connection cleanup incomplete: %v",closeErr)}
 return nil
}
