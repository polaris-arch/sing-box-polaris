package v2ray

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/transport/runtimeingress"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var ErrRuntimeServerPreparing = errors.New("server transport closed or already preparing")

type runtimeServer struct {
	adapter.V2RayServerTransport
	mu        sync.Mutex
	acceptor  *runtimeAcceptor
	done      chan struct{}
	preparing chan struct{}
	result    error
	closing   bool
	closed    chan struct{}
	closeErr  error
}
type runtimeAcceptor = runtimeingress.StreamAcceptor

type runtimeTransportHandler struct {
	handler adapter.V2RayServerTransportHandler
}

func (h *runtimeTransportHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	owned, release, err := runtimeingress.Acquire(ctx, true)
	if err != nil {
		_ = conn.Close()
		if onClose != nil {
			onClose(err)
		}
		return
	}
	invocation, leave, err := adapter.AcquireRuntimeOperation(owned, nil)
	if err != nil {
		release()
		_ = conn.Close()
		if onClose != nil {
			onClose(err)
		}
		return
	}
	defer leave()
	carrier := outbound.WrapRuntimeConn(owned, release, conn)
	h.handler.NewConnectionEx(invocation, carrier, source, destination, N.OnceClose(func(err error) {
		_ = carrier.Close()
		if onClose != nil {
			onClose(err)
		}
	}))
}

func wrapRuntimeServer(ctx context.Context, transport adapter.V2RayServerTransport) (adapter.V2RayServerTransport, error) {
	if transport == nil {
		return nil, nil
	}
	result := &runtimeServer{V2RayServerTransport: transport, closed: make(chan struct{})}
	context.AfterFunc(ctx, func() { _ = result.RuntimeCloseAndWait() })
	if err := adapter.DeferConstructionCleanup(ctx, result.RuntimeCloseAndWait); err != nil {
		return nil, err
	}
	if err := adapter.ConstructionScopeErr(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

func ValidateRuntimeServer(transport adapter.V2RayServerTransport) error {
	if transport == nil {
		return nil
	}
	value, ok := transport.(*runtimeServer)
	if !ok {
		return errors.New("server transport lacks staged ownership")
	}
	networks := value.Network()
	if len(networks) != 1 {
		return errors.New("mixed raw server transport requires its staged adapter")
	}
	if networks[0] != N.NetworkTCP {
		if _, ok := value.V2RayServerTransport.(interface {
			PrepareRuntimeServer(context.Context, *listener.Listener) error
		}); !ok {
			return errors.New("packet server requires staged session adapter")
		}
	}
	return nil
}

func PrepareRuntimeServer(ctx context.Context, transport adapter.V2RayServerTransport, l *listener.Listener) error {
	if transport == nil {
		return nil
	}
	if err := ValidateRuntimeServer(transport); err != nil {
		return err
	}
	value := transport.(*runtimeServer)
	value.mu.Lock()
	if value.closing || value.preparing != nil {
		value.mu.Unlock()
		return ErrRuntimeServerPreparing
	}
	value.preparing = make(chan struct{})
	preparing := value.preparing
	value.mu.Unlock()
	defer close(preparing)
	if staged, ok := value.V2RayServerTransport.(interface {
		PrepareRuntimeServer(context.Context, *listener.Listener) error
	}); ok {
		return staged.PrepareRuntimeServer(ctx, l)
	}
	value.mu.Lock()
	if value.closing {
		value.mu.Unlock()
		return net.ErrClosed
	}
	if value.acceptor != nil {
		value.mu.Unlock()
		return errors.New("server transport already prepared")
	}
	acceptor := runtimeingress.NewStreamAcceptor()
	if err := l.BindRuntimeStreamHandler(acceptor); err != nil {
		value.mu.Unlock()
		return err
	}
	value.acceptor = acceptor
	value.done = make(chan struct{})
	done := value.done
	value.mu.Unlock()
	go func() {
		// A panic cannot certify completion. Preserve the diagnostic while ensuring
		// waiters receive an actual terminal signal instead of an orphaned channel.
		var err error
		defer func() {
			if failure := recover(); failure != nil {
				err = errors.New("server transport Serve panicked; cleanup completion is unknown")
			}
			value.mu.Lock()
			value.result = err
			value.mu.Unlock()
			close(done)
		}()
		err = value.V2RayServerTransport.Serve(acceptor)
	}()
	select {
	case <-acceptor.Ready():
		return nil
	case <-done:
		value.mu.Lock()
		err := value.result
		value.mu.Unlock()
		if err == nil {
			err = errors.New("server stopped before accept admission")
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *runtimeServer) Close() error { return s.RuntimeCloseAndWait() }
func (s *runtimeServer) RuntimeCloseAndWait() (err error) {
	s.mu.Lock()
	if s.closing {
		done := s.closed
		s.mu.Unlock()
		<-done
		s.mu.Lock()
		err = s.closeErr
		s.mu.Unlock()
		return err
	}
	s.closing = true
	preparing := s.preparing
	s.mu.Unlock()
	defer func() {
		if failure := recover(); failure != nil {
			err = fmt.Errorf("staged server close panicked; completion unknown: %v", failure)
		}
		if err != nil {
			err = fmt.Errorf("staged server cleanup incomplete: %v", err)
		}
		s.mu.Lock()
		s.closeErr = err
		close(s.closed)
		s.mu.Unlock()
	}()
	if preparing != nil {
		<-preparing
	}
	s.mu.Lock()
	acceptor, done := s.acceptor, s.done
	s.mu.Unlock()
	if acceptor != nil {
		_ = acceptor.Close()
	}
	err = s.V2RayServerTransport.Close()
	if done != nil {
		<-done
	}
	s.mu.Lock()
	serveErr := s.result
	s.mu.Unlock()
	// Closed-network and server shutdown are expected, but arbitrary Serve
	// failures and panics remain retained evidence, rather than false completion.
	if serveErr != nil && !errors.Is(serveErr, net.ErrClosed) && !errors.Is(serveErr, http.ErrServerClosed) {
		err = errors.Join(err, serveErr)
	}
	return err
}

// BindRuntimeServer records only an inert, concrete transport capability. The
// endpoint itself is prepared later and must exist before socket staging.
func BindRuntimeServer(transport adapter.V2RayServerTransport, l *listener.Listener) error {
	if transport == nil {
		return nil
	}
	if err := ValidateRuntimeServer(transport); err != nil {
		return err
	}
	networks := transport.Network()
	if len(networks) == 1 && networks[0] == N.NetworkUDP {
		return l.DeclareRuntimePacketTransport()
	}
	return nil
}
