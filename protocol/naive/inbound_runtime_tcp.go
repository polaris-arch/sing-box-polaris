package naive

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/transport/runtimeingress"
	"github.com/sagernet/sing/common"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type runtimeNaiveTCP struct {
	inbound     *Inbound
	acceptor    *runtimeingress.StreamAcceptor
	connections *outbound.RuntimeIOFenceSet
	done        chan struct{}
	err         error
	started     bool
}

func newRuntimeNaiveTCP(n *Inbound) *runtimeNaiveTCP {
	return &runtimeNaiveTCP{inbound: n, acceptor: runtimeingress.NewStreamAcceptor(), connections: outbound.NewRuntimeIOFenceSet(), done: make(chan struct{})}
}

func (s *runtimeNaiveTCP) prepare() error {
	n := s.inbound
	if n.tlsConfig != nil {
		if len(n.tlsConfig.NextProtos()) == 0 {
			n.tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
		} else if !common.Contains(n.tlsConfig.NextProtos(), http2.NextProtoTLS) {
			n.tlsConfig.SetNextProtos(append([]string{http2.NextProtoTLS}, n.tlsConfig.NextProtos()...))
		}
	}
	n.httpServer = &http.Server{
		Handler:     h2c.NewHandler(n, &http2.Server{}),
		BaseContext: func(net.Listener) context.Context { return n.ctx },
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context { return runtimeingress.Context(ctx, conn) },
	}
	s.started = true
	go func() {
		returned := false
		defer close(s.done)
		defer func() {
			if value := recover(); value != nil || !returned {
				s.err = fmt.Errorf("Naive Serve did not complete (panic=%v)", value)
				n.runtime.record(s.err)
			}
		}()
		s.err = n.httpServer.Serve(&runtimeNaiveListener{runtimeNaiveTCP: s})
		returned = true
	}()
	context.AfterFunc(n.ctx, func() { _ = s.Close() })
	select {
	case <-s.acceptor.Ready():
		select {
		case <-s.done:
			return errors.New("Naive Serve stopped at private readiness")
		default:
			return nil
		}
	case <-s.done:
		if s.err != nil {
			return s.err
		}
		return errors.New("Naive Serve stopped before private accept readiness")
	case <-n.ctx.Done():
		return n.ctx.Err()
	}
}

func (s *runtimeNaiveTCP) Close() error {
	// HTTP's h2c upgrade removes a connection from Server's own map. Our physical
	// fence set therefore owns all accepted connections, including hijacked H2.
	_ = s.acceptor.Close()
	s.connections.Stop()
	var err error
	if s.inbound.httpServer != nil {
		err = s.inbound.httpServer.Close()
	}
	err = errors.Join(err, s.connections.Wait())
	if s.started {
		<-s.done
		if s.err != nil && !errors.Is(s.err, http.ErrServerClosed) && !errors.Is(s.err, net.ErrClosed) {
			err = errors.Join(err, s.err)
		}
	}
	return err
}

type runtimeNaiveListener struct{ *runtimeNaiveTCP }

func (l *runtimeNaiveListener) Addr() net.Addr { return l.acceptor.Addr() }
func (l *runtimeNaiveListener) Close() error   { return l.acceptor.Close() }
func (l *runtimeNaiveListener) Accept() (net.Conn, error) {
	conn, err := l.acceptor.Accept()
	if err != nil {
		return nil, err
	}
	slot, err := l.connections.Begin()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	defer slot.Done()
	ctx := runtimeingress.Context(l.inbound.ctx, conn)
	if _, ok := adapter.RuntimeLeaseFromContext(ctx); !ok {
		_ = conn.Close()
		return nil, errors.New("Naive accepted carrier lacks physical lineage")
	}
	var actual net.Conn = conn
	if l.inbound.tlsConfig != nil {
		actual = newRuntimeNaiveTLSConn(ctx, conn, l.inbound.tlsConfig, l.inbound.runtime)
	}
	guarded, fence := outbound.WrapRuntimeOwnedConn(actual)
	if err := slot.Register(fence); err != nil {
		return nil, err
	}
	return &runtimeingress.Conn{Conn: guarded, Context: ctx}, nil
}

// The legacy TLS listener starts lazy handshakes with context.Background. This
// narrowly owned lazy wrapper keeps the same lazy behavior with exact admitted
// context and joins handshake completion before its physical close completes.
type runtimeNaiveTLSConn struct {
	raw     net.Conn
	config  tls.ServerConfig
	runtime *inboundRuntime
	ctx     context.Context
	once    sync.Once
	conn    net.Conn
	err     error
	fence   *outbound.RuntimeIOFence
}

func newRuntimeNaiveTLSConn(ctx context.Context, raw net.Conn, config tls.ServerConfig, r *inboundRuntime) *runtimeNaiveTLSConn {
	c := &runtimeNaiveTLSConn{raw: raw, config: config, runtime: r, ctx: ctx}
	c.fence = outbound.NewRuntimeIOFence(func() error {
		err := raw.Close()
		c.once.Do(func() { c.err = net.ErrClosed })
		if c.conn != nil {
			err = errors.Join(err, c.conn.Close())
		}
		return err
	})
	return c
}

func (c *runtimeNaiveTLSConn) invoke(call func(net.Conn) (int, error)) (int, error) {
	owned, release, err := c.runtime.enter(c.ctx)
	if err != nil {
		return 0, err
	}
	defer release()
	leave, err := c.fence.Acquire()
	if err != nil {
		return 0, err
	}
	defer leave()
	c.once.Do(func() { c.conn, c.err = tls.ServerHandshake(owned, c.raw, c.config) })
	if c.err != nil {
		return 0, c.err
	}
	return call(c.conn)
}

func (c *runtimeNaiveTLSConn) Read(p []byte) (int, error) {
	return c.invoke(func(conn net.Conn) (int, error) { return conn.Read(p) })
}

func (c *runtimeNaiveTLSConn) Write(p []byte) (int, error) {
	return c.invoke(func(conn net.Conn) (int, error) { return conn.Write(p) })
}
func (c *runtimeNaiveTLSConn) Close() error                       { return c.fence.RuntimeCloseAndWait() }
func (c *runtimeNaiveTLSConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *runtimeNaiveTLSConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *runtimeNaiveTLSConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *runtimeNaiveTLSConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *runtimeNaiveTLSConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

type runtimeNaiveResponseConn struct {
	net.Conn
	writer http.ResponseWriter
}

func (c *runtimeNaiveResponseConn) Close() error {
	// Interrupt flow-controlled writes before the carrier waits for admitted I/O.
	err := http.NewResponseController(c.writer).SetWriteDeadline(time.Now())
	closeErr := c.Conn.Close()
	if err != nil {
		return fmt.Errorf("Naive response write interruption unproven: %v; close: %v", err, closeErr)
	}
	return closeErr
}
