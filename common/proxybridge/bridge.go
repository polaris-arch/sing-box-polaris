package proxybridge

import (
	std_bufio "bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/service"
)

type Bridge struct {
	ctx            context.Context
	runtimeSource  adapter.RuntimeResourceSource
	admitRuntime   func(context.Context) (context.Context, func(), error)
	fences         *outbound.RuntimeIOFenceSet
	handlers       *outbound.RuntimeIOFence
	cleanup        func() error
	listenerAccess sync.Mutex
	logger         logger.ContextLogger
	tag            string
	dialer         N.Dialer
	connection     adapter.ConnectionManager
	tcpListener    *net.TCPListener
	username       string
	password       string
	authenticator  *auth.Authenticator
}

func New(ctx context.Context, logger logger.ContextLogger, tag string, dialer N.Dialer) (*Bridge, error) {
	username := randomHex(16)
	password := randomHex(16)
	// This is internal owned work. Keep registry/cancellation/logging values,
	// but never inherit a caller's borrowed graph or resource handles.
	ctx = adapter.ContextWithRuntimeOwnership(ctx, context.Background())
	ctx, cancel := context.WithCancel(ctx)
	instance := &Bridge{
		ctx:           ctx,
		logger:        logger,
		tag:           tag,
		dialer:        dialer,
		connection:    service.FromContext[adapter.ConnectionManager](ctx),
		username:      username,
		password:      password,
		authenticator: auth.NewAuthenticator([]auth.User{{Username: username, Password: password}}),
	}
	instance.runtimeSource, _ = adapter.RuntimeResourceSourceFromContext(ctx)
	instance.fences = outbound.NewRuntimeIOFenceSet()
	instance.handlers = outbound.NewRuntimeIOFence(func() error { cancel(); return nil })
	instance.cleanup = outbound.OnceRuntimeCleanup(instance.closeAndWait)
	return instance, nil
}

// NewWithRuntimeContinuation accepts the exact owner-fence admission bound by
// the constructor. It reserves only each physical creation, never a graph,
// another user stream, or an idle resource baseline.
func NewWithRuntimeContinuation(ctx context.Context, logger logger.ContextLogger, tag string, dialer N.Dialer, admit func(context.Context) (context.Context, func(), error)) (*Bridge, error) {
	bridge, err := New(ctx, logger, tag, dialer)
	if err != nil {
		return nil, err
	}
	bridge.admitRuntime = admit
	return bridge, nil
}

func (b *Bridge) acquireRuntime(ctx context.Context) (context.Context, func(), error) {
	if b.admitRuntime != nil {
		return b.admitRuntime(ctx)
	}
	if b.runtimeSource != nil {
		return nil, nil, E.New("runtime bridge requires constructor-owned fence admission")
	}
	return adapter.AcquireRuntimeOperation(ctx, nil)
}

func (b *Bridge) Start() error {
	creation, err := b.fences.Begin()
	if err != nil {
		return err
	}
	defer creation.Done()
	tcpListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	fence := outbound.NewRuntimeIOFence(tcpListener.Close)
	if err := creation.Register(fence); err != nil {
		return err
	}
	b.listenerAccess.Lock()
	b.tcpListener = tcpListener
	b.listenerAccess.Unlock()
	release, err := b.handlers.Acquire()
	if err != nil {
		return fence.RuntimeCloseAndWait()
	}
	go func() { defer release(); b.acceptLoop(tcpListener) }()
	return nil
}

func randomHex(size int) string {
	raw := make([]byte, size)
	rand.Read(raw)
	return hex.EncodeToString(raw)
}

func (b *Bridge) Port() uint16 {
	b.listenerAccess.Lock()
	listener := b.tcpListener
	b.listenerAccess.Unlock()
	if listener == nil {
		return 0
	}
	return M.SocksaddrFromNet(listener.Addr()).Port
}

func (b *Bridge) Username() string {
	return b.username
}

func (b *Bridge) Password() string {
	return b.password
}

func (b *Bridge) Close() error               { return b.cleanup() }
func (b *Bridge) RuntimeCloseAndWait() error { return b.cleanup() }

func (b *Bridge) closeAndWait() error {
	_ = b.handlers.Close()
	b.fences.Stop()
	if err := b.handlers.Wait(); err != nil {
		b.fences.Record(err)
	}
	return b.fences.Wait()
}

func (b *Bridge) acceptLoop(listener *net.TCPListener) {
	for b.acceptOne(listener) {
	}
}

func (b *Bridge) acceptOne(listener *net.TCPListener) bool {
	creation, err := b.fences.Begin()
	if err != nil {
		return false
	}
	defer creation.Done()
	tcpConn, err := listener.AcceptTCP()
	if err != nil {
		return false
	}
	conn, fence := outbound.WrapRuntimeOwnedConn(tcpConn)
	if err := creation.Register(fence); err != nil {
		return false
	}
	release, err := b.handlers.Acquire()
	if err != nil {
		b.fences.Record(fence.RuntimeCloseAndWait())
		return false
	}
	ctx := log.ContextWithNewID(b.ctx)
	go func() {
		// A panic cannot certify completion of a callback that may already
		// have dispatched graph-reaching work.
		hErr := socks.HandleConnectionEx(ctx, conn, std_bufio.NewReader(conn), b.authenticator, b, nil, 0, M.SocksaddrFromNet(conn.RemoteAddr()), nil)
		if hErr != nil {
			_ = conn.Close()
			if E.IsClosedOrCanceled(hErr) {
				b.logger.DebugContext(ctx, E.Cause(hErr, b.tag, " connection closed"))
			} else {
				b.logger.ErrorContext(ctx, E.Cause(hErr, b.tag))
			}
		}
		release()
	}()
	return true
}

func (b *Bridge) guardOnClose(onClose N.CloseHandlerFunc) N.CloseHandlerFunc {
	if onClose == nil {
		return nil
	}
	return func(err error) {
		release, acquireErr := b.handlers.Acquire()
		if acquireErr != nil {
			return
		}
		onClose(err)
		release()
	}
}

func (b *Bridge) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	release, err := b.handlers.Acquire()
	if err != nil {
		_ = conn.Close()
		return
	}
	defer release()
	var metadata adapter.InboundContext
	metadata.Source = source
	metadata.Destination = destination
	metadata.Network = N.NetworkTCP
	b.logger.InfoContext(ctx, b.tag, " connection to ", metadata.Destination)
	b.connection.NewConnection(ctx, &ownedDialer{bridge: b}, conn, metadata, b.guardOnClose(onClose))
}

func (b *Bridge) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	release, err := b.handlers.Acquire()
	if err != nil {
		_ = conn.Close()
		return
	}
	defer release()
	var metadata adapter.InboundContext
	metadata.Source = source
	metadata.Destination = destination
	metadata.Network = N.NetworkUDP
	b.logger.InfoContext(ctx, b.tag, " packet connection to ", metadata.Destination)
	b.connection.NewPacketConnection(ctx, &ownedDialer{bridge: b}, conn, metadata, b.guardOnClose(onClose))
}
