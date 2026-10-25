//go:build with_utls

package tls

import (
	"errors"
	"net"
	"sync/atomic"
)

type realityVisionObservedConn struct {
	net.Conn
	reads, writes, closes atomic.Int32
}

func (c *realityVisionObservedConn) Read(p []byte) (int, error) {
	c.reads.Add(1)
	return c.Conn.Read(p)
}

func (c *realityVisionObservedConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(p)
}
func (c *realityVisionObservedConn) Close() error { c.closes.Add(1); return c.Conn.Close() }

func verifyRealityVisionRetirement(secured Conn, observed *realityVisionObservedConn) error {
	first := secured.Close()
	reads, writes := observed.reads.Load(), observed.writes.Load()
	if observed.closes.Load() != 1 {
		return errors.New("owned REALITY raw close was not exactly once")
	}
	called := false
	if err := WithRuntimeTLSInspection(secured, func(net.Conn) error { called = true; return nil }); err == nil || called {
		return errors.New("sealed REALITY inspection admitted")
	}
	if _, err := secured.Read(make([]byte, 1)); err == nil {
		return errors.New("sealed REALITY read admitted")
	}
	if _, err := secured.Write([]byte{1}); err == nil {
		return errors.New("sealed REALITY write admitted")
	}
	if _, err := secured.NetConn().Read(make([]byte, 1)); err == nil {
		return errors.New("sealed REALITY direct read admitted")
	}
	_ = secured.Close()
	if observed.reads.Load() != reads || observed.writes.Load() != writes || observed.closes.Load() != 1 {
		return errors.New("sealed REALITY called its physical carrier")
	}
	return first
}
