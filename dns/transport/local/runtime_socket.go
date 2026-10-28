package local

import (
	"errors"
	"net"
	"sync"

	"github.com/sagernet/sing-box/dns/transport/lifecycle"
)

// The pool close callback has no error return. Keep actual socket destruction
// errors at its owning resolver until the existing operation/reader joins end.
type resolverSocketErrors struct {
	mu  sync.Mutex
	err error
}

func (e *resolverSocketErrors) record(err error) {
	if err == nil {
		return
	}
	e.mu.Lock()
	e.err = errors.Join(e.err, lifecycle.Uncertain("mDNSResponder socket", err))
	e.mu.Unlock()
}
func (e *resolverSocketErrors) result() error { e.mu.Lock(); defer e.mu.Unlock(); return e.err }

type resolverOwnedConn struct {
	net.Conn
	once   sync.Once
	err    error
	errors *resolverSocketErrors
}

func (c *resolverOwnedConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); c.errors.record(c.err) })
	return c.err
}
