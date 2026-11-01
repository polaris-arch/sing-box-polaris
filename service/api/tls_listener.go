package api

import (
	"context"
	"net"
	"sync"

	aTLS "github.com/sagernet/sing/common/tls"
)

// API stop must close the physical socket without waiting for a peer's TLS
// handshake. Keep that target immutable: LazyConn replaces its embedded Conn
// after handshake, racing promoted Close/Addr/Deadline methods during stop.
type apiTLSListener struct {
	net.Listener
	config aTLS.ServerConfig
}

func (l apiTLSListener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &apiTLSConn{Conn: raw, config: l.config}, nil
}

type apiTLSConn struct {
	net.Conn // immutable physical Close, addresses and concurrent deadlines
	config   aTLS.ServerConfig
	once     sync.Once
	secured  aTLS.Conn // published only by once; every reader waits for it
	err      error
}

func (c *apiTLSConn) handshake() error {
	c.once.Do(func() {
		c.secured, c.err = aTLS.ServerHandshake(context.Background(), c.Conn, c.config)
	})
	return c.err
}

func (c *apiTLSConn) Read(p []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	return c.secured.Read(p)
}

func (c *apiTLSConn) Write(p []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	return c.secured.Write(p)
}
