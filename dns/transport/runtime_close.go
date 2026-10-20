package transport

import (
	"errors"
	"fmt"
	"net"
	"sync"
)

type runtimeDNSCloseError struct{ message string }

func (e *runtimeDNSCloseError) Error() string                { return e.message }
func (*runtimeDNSCloseError) RuntimeCleanupIncomplete() bool { return true }
func runtimeDNSCleanupIncomplete(err error) bool {
	var marker interface{ RuntimeCleanupIncomplete() bool }
	return errors.As(err, &marker) && marker.RuntimeCleanupIncomplete()
}

func (m *queryMultiplexer) recordCleanup(err error) {
	if err == nil {
		return
	}
	m.cleanupAccess.Lock()
	m.cleanupErr = errors.Join(m.cleanupErr, err)
	m.cleanupAccess.Unlock()
}

func (m *queryMultiplexer) trackClose(conn net.Conn) net.Conn {
	return &runtimeDNSCloseConn{Conn: conn, owner: m}
}

type runtimeDNSCloseConn struct {
	net.Conn
	owner *queryMultiplexer
	once  sync.Once
	err   error
}

func (c *runtimeDNSCloseConn) Close() error {
	c.once.Do(func() {
		defer func() {
			if value := recover(); value != nil {
				c.err = &runtimeDNSCloseError{fmt.Sprintf("DNS carrier close panic: %v", value)}
			}
			c.owner.recordCleanup(c.err)
		}()
		if err := c.Conn.Close(); err != nil {
			c.err = &runtimeDNSCloseError{fmt.Sprintf("DNS carrier cleanup incomplete: %v", err)}
		}
	})
	return c.err
}
