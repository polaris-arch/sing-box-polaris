package tor

import (
	"context"
	"errors"
	"net"
	"net/textproto"
	"sync"

	"github.com/cretz/bine/control"
)

// The synchronous controller has no context-aware reads. Own cancellation of
// its actual socket, including during Start authentication, and join the exact
// cancellation callback before retiring the controller. No QUIT request may
// queue behind a blocked GetInfo while shutdown waits for it.
type runtimeControl struct {
	conn net.Conn
	once sync.Once
	err  error
	stop func() bool
	done chan struct{}
}

func (c *runtimeControl) close() error {
	c.once.Do(func() {
		defer func() {
			if recover() != nil {
				c.err = errors.New("tor control socket close panicked; completion unknown")
			}
		}()
		c.err = c.conn.Close()
	})
	return c.err
}

func (t *Tor) bindRuntimeControl(ctx context.Context, conn net.Conn) {
	owned := &runtimeControl{conn: conn, done: make(chan struct{})}
	owned.stop = context.AfterFunc(ctx, func() { _ = owned.close(); close(owned.done) })
	t.runtimeControl = owned
	t.Control = control.NewConn(textproto.NewConn(conn))
	t.Control.DebugWriter = t.DebugWriter
}

// InterruptControl closes and joins the owned control socket without sending a
// command. It is safe after the Start caller has returned, before joining its
// managed bootstrap task. Process Wait is a separate mandatory barrier.
func (t *Tor) InterruptControl() error {
	owned := t.runtimeControl
	if owned == nil {
		return nil
	}
	err := owned.close()
	if owned.stop() {
		close(owned.done)
	}
	<-owned.done
	return err
}
