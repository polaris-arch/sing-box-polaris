package local

import (
	"context"
	"net"
	"testing"
)

type idleResponderConn struct { net.Conn; closes int }
func (c *idleResponderConn) Close() error { c.closes++; return nil }

func TestDarwinResponderIdleControlPreservesSharedQueries(t *testing.T) {
	resolver := new(systemResolver)
	resolver.initOnce.Do(resolver.init)
	defer resolver.close()
	conn := new(idleResponderConn)
	dial := func(context.Context) (net.Conn, error) { return conn, nil }
	first, _, err := resolver.connection.Acquire(context.Background(), dial); if err != nil { t.Fatal(err) }
	second, _, err := resolver.connection.Acquire(context.Background(), dial); if err != nil { t.Fatal(err) }
	resolver.setKeepIdleConnections(false)
	resolver.closeIdleConnections()
	if conn.closes != 0 { t.Fatal("idle observer closed active responder connection") }
	resolver.connection.Release(first, true)
	if conn.closes != 0 { t.Fatal("idle policy interrupted remaining responder query") }
	resolver.connection.Release(second, true)
	if conn.closes != 1 { t.Fatal("final responder query did not release idle connection") }
}
