//go:build with_quic

package httpclient

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"syscall"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	E "github.com/sagernet/sing/common/exceptions"
)

// RuntimeQUICSession joins its socket and provider boundaries. Normal pinned
// QUIC shutdown also joins crypto/send workers; early setup errors do not, so
// the independent provider fence below is required even after Context.Done.
// Any remaining private worker can touch only sealed boundaries and immutable
// connection/config data, never retired graph resources.
type RuntimeQUICSession struct {
	Conn      *quic.Conn
	raw       *outbound.RuntimeIOFence
	callbacks *outbound.RuntimeIOFence
	done      chan struct{}
	err       error
}

func DialRuntimeQUIC(ctx context.Context, raw net.Conn, tlsConfig *tls.Config, config *quic.Config, recordIncomplete func(error)) (*RuntimeQUICSession, error) {
	guarded, fence := outbound.WrapRuntimeOwnedConn(raw)
	carrier := &runtimeQUICCarrier{Conn: guarded}
	callbacks := outbound.NewRuntimeIOFence(nil)
	guardedTLS := guardRuntimeQUICTLS(tlsConfig, callbacks)
	conn, err := quic.DialEarlyConn(ctx, carrier, guardedTLS, config)
	if err != nil {
		closeErr := errors.Join(fence.RuntimeCloseAndWait(), callbacks.RuntimeCloseAndWait())
		if closeErr != nil {
			incomplete := boxTLS.NewRuntimeCleanupError(E.New("QUIC creation cleanup incomplete: ", err, ": ", closeErr))
			if recordIncomplete != nil {
				recordIncomplete(incomplete)
			}
			return nil, incomplete
		}
		return nil, err
	}
	session := &RuntimeQUICSession{Conn: conn, raw: fence, callbacks: callbacks, done: make(chan struct{})}
	go func() {
		defer close(session.done)
		<-conn.Context().Done()
		session.err = errors.Join(fence.RuntimeCloseAndWait(), callbacks.RuntimeCloseAndWait())
	}()
	return session, nil
}

func (s *RuntimeQUICSession) Close() error {
	// Seal graph callbacks and interrupt socket I/O before joining normal
	// QUIC teardown and the actual boundary-close watcher.
	_ = s.callbacks.Close()
	rawErr := s.raw.Close()
	quicErr := s.Conn.CloseWithError(0, "")
	<-s.done
	// Close can report another closer is still in flight. The terminal Wait
	// result supersedes that observation; it does not discard real failures.
	_ = rawErr
	return errors.Join(quicErr, s.err)
}
func (s *RuntimeQUICSession) RuntimeCloseAndWait() error { return s.Close() }

// quic-go's exact pinned connected-socket path uses RawConn callbacks for all
// fd I/O, including GSO/ECN/PMTU setup. Keep those optimizations and the original
// accounting hooks while admitting every callback through the carrier fence.
type runtimeQUICCarrier struct{ net.Conn }

func (c *runtimeQUICCarrier) SyscallConn() (syscall.RawConn, error) {
	return outbound.RuntimeSyscallConn(c.Conn)
}

func (c *runtimeQUICCarrier) IOActivityFuncs() (func(int), func(int)) {
	return outbound.RuntimeIOActivityFuncs(c.Conn)
}
