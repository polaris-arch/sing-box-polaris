package local

import (
	"context"
	"errors"
	"net"
	"testing"
)

type failedHandshakeConn struct {
	net.Conn
	closes int
}

func (c *failedHandshakeConn) Write([]byte) (int, error) { return 0, errors.New("handshake failed") }
func (c *failedHandshakeConn) Close() error              { c.closes++; return errors.New("compensation failed") }
func TestResolverFailedHandshakeRetainsCloseFailure(t *testing.T) {
	resolver := new(systemResolver)
	conn := new(failedHandshakeConn)
	result, err := resolver.initializeConnection(context.Background(), conn)
	if err == nil || result != nil || conn.closes != 1 || resolver.socketErrors.result() == nil {
		t.Fatal("failed handshake compensation lost")
	}
	if resolver.close() == nil {
		t.Fatal("resolver close certified failed compensation")
	}
}
