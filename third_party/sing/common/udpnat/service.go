package udpnat

import (
	"context"
	"io"
	"net"
	"os"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/cache"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

// Deprecated: Use N.UDPConnectionHandler instead.
//
//nolint:staticcheck
type Handler interface {
	N.UDPConnectionHandler
	E.Handler
}

type Service[K comparable] struct {
	nat       *cache.LruCache[K, *conn]
	handler   Handler
	handlerEx N.UDPConnectionHandlerEx
}

// Deprecated: Use NewEx instead.
func New[K comparable](maxAge int64, handler Handler) *Service[K] {
	service := &Service[K]{
		nat: cache.New(
			cache.WithAge[K, *conn](maxAge),
			cache.WithUpdateAgeOnGet[K, *conn](),
			cache.WithEvict[K, *conn](func(key K, conn *conn) {
				conn.Close()
			}),
		),
		handler: handler,
	}
	return service
}

func NewEx[K comparable](maxAge int64, handler N.UDPConnectionHandlerEx) *Service[K] {
	service := &Service[K]{
		nat: cache.New(
			cache.WithAge[K, *conn](maxAge),
			cache.WithUpdateAgeOnGet[K, *conn](),
			cache.WithEvict[K, *conn](func(key K, conn *conn) {
				conn.Close()
			}),
		),
		handlerEx: handler,
	}
	return service
}

func (s *Service[T]) WriteIsThreadUnsafe() {
}

// Deprecated: don't use
func (s *Service[T]) NewPacketDirect(ctx context.Context, key T, conn N.PacketConn, buffer *buf.Buffer, metadata M.Metadata) {
	s.NewContextPacket(ctx, key, buffer, metadata, func(natConn N.PacketConn) (context.Context, N.PacketWriter) {
		return ctx, &DirectBackWriter{conn, natConn}
	})
}

type DirectBackWriter struct {
	Source N.PacketConn
	Nat    N.PacketConn
}

func (w *DirectBackWriter) WritePacket(buffer *buf.Buffer, addr M.Socksaddr) error {
	return w.Source.WritePacket(buffer, M.SocksaddrFromNet(w.Nat.LocalAddr()))
}

func (w *DirectBackWriter) Upstream() any {
	return w.Source
}

// Deprecated: use NewPacketEx instead.
func (s *Service[T]) NewPacket(ctx context.Context, key T, buffer *buf.Buffer, metadata M.Metadata, init func(natConn N.PacketConn) N.PacketWriter) {
	s.NewContextPacket(ctx, key, buffer, metadata, func(natConn N.PacketConn) (context.Context, N.PacketWriter) {
		return ctx, init(natConn)
	})
}

func (s *Service[T]) NewPacketEx(ctx context.Context, key T, buffer *buf.Buffer, source M.Socksaddr, destination M.Socksaddr, init func(natConn N.PacketConn) N.PacketWriter) {
	s.NewContextPacketEx(ctx, key, buffer, source, destination, func(natConn N.PacketConn) (context.Context, N.PacketWriter) {
		return ctx, init(natConn)
	})
}

// Deprecated: Use NewPacketConnectionEx instead.
func (s *Service[T]) NewContextPacket(ctx context.Context, key T, buffer *buf.Buffer, metadata M.Metadata, init func(natConn N.PacketConn) (context.Context, N.PacketWriter)) {
	s.NewContextPacketEx(ctx, key, buffer, metadata.Source, metadata.Destination, init)
}

func (s *Service[T]) NewContextPacketEx(ctx context.Context, key T, buffer *buf.Buffer, source M.Socksaddr, destination M.Socksaddr, init func(natConn N.PacketConn) (context.Context, N.PacketWriter)) {
 // Legacy packet handlers are synchronous owners: their return plus the
 // error/close/cache-removal tail ends the session. Retain BEFORE the lookup,
 // so failure never publishes an unowned cache entry or callback. Existing
 // sessions release this packet's temporary reservation without changing the
 // first packet's admitted lineage. Ex handlers retain their existing contract.
 var bind func(context.Context) context.Context
 var release func()
 if owner, ok := s.handler.(RuntimePacketContextOwner); ok {
  var err error
  bind, release, err = owner.RetainPacketContext(ctx)
  if err != nil { buffer.Release(); return }
 }
	c, loaded := s.nat.LoadOrStore(key, func() *conn {
		c := &conn{
			data:         make(chan packet, 64),
			localAddr:    source,
			remoteAddr:   destination,
			readDeadline: pipe.MakeDeadline(),
		}
		c.ctx, c.cancel = context.WithCancelCause(ctx)
		return c
	})
	if loaded && release != nil { release() }
	if !loaded {
		ctx, c.source = init(c)
		if bind != nil { ctx = bind(ctx) }
		go func() {
			if release != nil { defer release() }
			if s.handlerEx != nil {
				s.handlerEx.NewPacketConnectionEx(ctx, c, source, destination, func(err error) {
					s.nat.Delete(key)
				})
			} else {
				//nolint:staticcheck
				err := s.handler.NewPacketConnection(ctx, c, M.Metadata{
					Source:      source,
					Destination: destination,
				})
				if err != nil {
					s.handler.NewError(ctx, err)
				}
				c.Close()
				s.nat.Delete(key)
			}
		}()
	}
	if common.Done(c.ctx) {
		s.nat.Delete(key)
		if !common.Done(ctx) {
			s.NewContextPacketEx(ctx, key, buffer, source, destination, init)
		}
		return
	}
	c.data <- packet{
		data:        buffer,
		destination: destination,
	}
}

type packet struct {
	data        *buf.Buffer
	destination M.Socksaddr
}

var _ N.PacketConn = (*conn)(nil)

type conn struct {
	ctx             context.Context
	cancel          context.CancelCauseFunc
	data            chan packet
	localAddr       M.Socksaddr
	remoteAddr      M.Socksaddr
	source          N.PacketWriter
	readDeadline    pipe.Deadline
	readWaitOptions N.ReadWaitOptions
}

func (c *conn) ReadPacket(buffer *buf.Buffer) (addr M.Socksaddr, err error) {
	select {
	case p := <-c.data:
		_, err = buffer.ReadOnceFrom(p.data)
		p.data.Release()
		return p.destination, err
	case <-c.ctx.Done():
		return M.Socksaddr{}, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

func (c *conn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return c.source.WritePacket(buffer, destination)
}

func (c *conn) Close() error {
	select {
	case <-c.ctx.Done():
	default:
		c.cancel(net.ErrClosed)
	}
	if sourceCloser, sourceIsCloser := c.source.(io.Closer); sourceIsCloser {
		return sourceCloser.Close()
	}
	return nil
}

func (c *conn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *conn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *conn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *conn) Upstream() any {
	return c.source
}


// RuntimePacketContextOwner is an optional legacy-handler lifecycle boundary.
// bind copies only retained lifetime into the final protocol context; ordinary
// values such as relay authentication remain unchanged. release must be once-safe.
type RuntimePacketContextOwner interface {
 RetainPacketContext(context.Context) (func(context.Context) context.Context, func(), error)
}

// RuntimePacketContextSupported prevents an integration silently enabling UDP
// against a dependency lacking its actual prelaunch ownership boundary.
func RuntimePacketContextSupported() bool { return true }
