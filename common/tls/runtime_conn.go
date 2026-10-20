package tls

import (
	"context"
	"errors"
	"net"
	"syscall"

	"github.com/sagernet/sing-box/adapter/outbound"
	E "github.com/sagernet/sing/common/exceptions"
	aTLS "github.com/sagernet/sing/common/tls"
)

// The private handshake carrier forwards only guarded descriptor callbacks
// and TCP controls. Apple duplicates an fd inside Control and owns that duplicate
// through its native terminal barrier; kTLS retains only this fenced RawConn.
type runtimeHandshakeConn struct{ net.Conn }

func (c *runtimeHandshakeConn) SyscallConn() (syscall.RawConn, error) {
	return outbound.RuntimeSyscallConn(c.Conn)
}

func (c *runtimeHandshakeConn) SetNoDelay(value bool) error {
	control, err := outbound.RuntimeTCPControl(c.Conn)
	if err != nil {
		return err
	}
	return control.SetNoDelay(value)
}

// runtimeTLSConn retains no graph or resource lease: its enclosing caller or
// pool already owns the physical session. RuntimeIOFence is the existing raw
// method barrier, not another resource owner. All TLS provider callbacks occur
// inside an admitted handshake/read/write or the synchronous cleanup call.
type runtimeTLSConn struct {
	net.Conn
	tlsConn aTLS.Conn
	raw     net.Conn
	fence   *outbound.RuntimeIOFence
	state   ConnectionState
}

func (c *runtimeTLSConn) HandshakeContext(ctx context.Context) error {
	release, err := c.fence.Acquire()
	if err != nil {
		return err
	}
	defer release()
	return c.tlsConn.HandshakeContext(ctx)
}

func (c *runtimeTLSConn) ConnectionState() ConnectionState { return c.state }
func (c *runtimeTLSConn) NetConn() net.Conn                { return c.raw }
func (c *runtimeTLSConn) Close() error                     { return c.fence.RuntimeCloseAndWait() }
func (c *runtimeTLSConn) RuntimeCloseAndWait() error       { return c.fence.RuntimeCloseAndWait() }

// clientHandshakeOwned closes and joins the raw carrier on every failed
// handshake, including a cancellation callback scheduled after the handshake
// returned. On success, all subsequent TLS methods use the same method fence.
func clientHandshakeOwned(ctx context.Context, conn net.Conn, config Config) (Conn, error) {
	if contextual, ok := config.(interface{ withRuntimeContext(context.Context) Config }); ok {
		config = contextual.withRuntimeContext(ctx)
	}
	guarded, rawFence := outbound.WrapRuntimeOwnedConn(conn)
	raw := &runtimeHandshakeConn{Conn: guarded}
	tlsConn, err := aTLS.ClientHandshake(ctx, raw, config)
	if err != nil {
		closeErr := rawFence.RuntimeCloseAndWait()
		if closeErr != nil {
			return nil, NewRuntimeCleanupError(E.New("TLS handshake cleanup incomplete: ", err, ": ", closeErr))
		}
		return nil, err
	}
	state := tlsConn.ConnectionState()
	// TLS.Close retains the provider close-notify behavior; its raw Close is
	// cached and joined before the final fence joins admitted TLS methods.
	wrapped, fence := outbound.WrapRuntimeOwnedConn(&runtimeTLSCloser{Conn: tlsConn, raw: rawFence})
	return &runtimeTLSConn{Conn: wrapped, tlsConn: tlsConn, raw: guarded, fence: fence, state: state}, nil
}

type runtimeTLSCloser struct {
	Conn
	raw *outbound.RuntimeIOFence
}

func (c *runtimeTLSCloser) Close() error {
	tlsErr := c.Conn.Close()
	rawErr := c.raw.RuntimeCloseAndWait()
	if rawErr == nil && runtimeTLSAlreadyClosed(tlsErr) {
		tlsErr = nil
	}
	return errors.Join(tlsErr, rawErr)
}

// crypto/tls reports a close-notify write on an already sealed carrier even
// though its synchronous Close has completed. Suppress only an entirely
// net.ErrClosed / pending-close observation tree after the actual raw close
// and methods joined successfully.
func runtimeTLSAlreadyClosed(err error) bool {
	if err == net.ErrClosed || err == outbound.ErrRuntimeClosePending {
		return true
	}
	switch value := err.(type) {
	case interface{ Unwrap() []error }:
		children := value.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if child != nil && !runtimeTLSAlreadyClosed(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return runtimeTLSAlreadyClosed(value.Unwrap())
	}
	return false
}

// WithRuntimeTLSInspection is a constructor-only compatibility boundary for
// Vision's concrete TLS buffer inspection. The callback must keep ordinary I/O
// on conn, not the inspected provider. Native NetConn already contains the raw
// fence. No raw getter or generic Upstream escape is exposed on the wrapper.
func WithRuntimeTLSInspection(conn net.Conn, inspect func(net.Conn) error) error {
	if runtime, ok := conn.(*runtimeTLSConn); ok {
		leave, err := runtime.fence.Acquire()
		if err != nil {
			return err
		}
		defer leave()
		return inspect(runtime.tlsConn)
	}
	return inspect(conn)
}

// Runtime cleanup uncertainty is opaque to errors.Is: construction Scope must
// not filter it as cancellation. Enclosing owners retain their exact dependency
// closure when this marker crosses an unsuccessful creation boundary.
type runtimeCleanupError struct{ cause error }

func (e *runtimeCleanupError) Error() string                { return e.cause.Error() }
func (*runtimeCleanupError) RuntimeCleanupIncomplete() bool { return true }
func NewRuntimeCleanupError(err error) error {
	if err == nil {
		return nil
	}
	return &runtimeCleanupError{cause: err}
}

func IsRuntimeCleanupIncomplete(err error) bool {
	var marker interface{ RuntimeCleanupIncomplete() bool }
	return errors.As(err, &marker) && marker.RuntimeCleanupIncomplete()
}

// Preserve the optional kTLS splice contract without exposing a descriptor
// outside either the provider-method or physical-carrier boundary.
func (c *runtimeTLSConn) SyscallConnForRead() syscall.RawConn {
	leave, err := c.fence.Acquire()
	if err != nil {
		return nil
	}
	defer leave()
	provider, ok := c.tlsConn.(interface{ SyscallConnForRead() syscall.RawConn })
	if !ok {
		return nil
	}
	raw := provider.SyscallConnForRead()
	if raw == nil {
		return nil
	}
	return &runtimeTLSRawConn{raw: raw, fence: c.fence}
}

func (c *runtimeTLSConn) SyscallConnForWrite() syscall.RawConn {
	leave, err := c.fence.Acquire()
	if err != nil {
		return nil
	}
	defer leave()
	provider, ok := c.tlsConn.(interface{ SyscallConnForWrite() syscall.RawConn })
	if !ok {
		return nil
	}
	raw := provider.SyscallConnForWrite()
	if raw == nil {
		return nil
	}
	return &runtimeTLSRawConn{raw: raw, fence: c.fence}
}

func (c *runtimeTLSConn) HandleSyscallReadError(input error) ([]byte, error) {
	leave, err := c.fence.Acquire()
	if err != nil {
		return nil, err
	}
	defer leave()
	provider, ok := c.tlsConn.(interface{ HandleSyscallReadError(error) ([]byte, error) })
	if !ok {
		return nil, input
	}
	return provider.HandleSyscallReadError(input)
}

type runtimeTLSRawConn struct {
	raw   syscall.RawConn
	fence *outbound.RuntimeIOFence
}

func (c *runtimeTLSRawConn) Control(callback func(uintptr)) error {
	leave, err := c.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	return c.raw.Control(callback)
}

func (c *runtimeTLSRawConn) Read(callback func(uintptr) bool) error {
	leave, err := c.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	return c.raw.Read(callback)
}

func (c *runtimeTLSRawConn) Write(callback func(uintptr) bool) error {
	leave, err := c.fence.Acquire()
	if err != nil {
		return err
	}
	defer leave()
	return c.raw.Write(callback)
}

// Staged ingress already owns its graph admission through the raw carrier.
// The private TLS method fence joins provider methods and the raw close tail;
// it does not create a second graph lease or expose the native socket.
func serverHandshakeOwned(ctx context.Context, conn net.Conn, config ServerConfig) (Conn, error) {
	guarded, rawFence := outbound.WrapRuntimeOwnedConn(conn)
	raw := &runtimeHandshakeConn{Conn: guarded}
	tlsConn, err := aTLS.ServerHandshake(ctx, raw, config)
	if err != nil {
		closeErr := rawFence.RuntimeCloseAndWait()
		if closeErr != nil {
			return nil, NewRuntimeCleanupError(E.New("TLS server handshake cleanup incomplete: ", err, ": ", closeErr))
		}
		return nil, err
	}
	state := tlsConn.ConnectionState()
	wrapped, fence := outbound.WrapRuntimeOwnedConn(&runtimeTLSCloser{Conn: tlsConn, raw: rawFence})
	return &runtimeTLSConn{Conn: wrapped, tlsConn: tlsConn, raw: guarded, fence: fence, state: state}, nil
}
