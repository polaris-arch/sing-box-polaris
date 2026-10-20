package local

import (
	"errors"
	"net"
	"sync"
	"testing"
)

type failingResolverConn struct {
	net.Conn
	calls   int
	failure error
}

func (c *failingResolverConn) Close() error { c.calls++; return c.failure }
func TestResolverSocketCloseFailureStickyAndOnce(t *testing.T) {
	native := &failingResolverConn{failure: errors.New("close failed")}
	var retained resolverSocketErrors
	conn := &resolverOwnedConn{Conn: native, errors: &retained}
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			if conn.Close() != native.failure {
				t.Error("close error lost")
			}
		}()
	}
	group.Wait()
	if native.calls != 1 || retained.result() == nil {
		t.Fatal("physical close repeated or uncertainty lost")
	}
}
