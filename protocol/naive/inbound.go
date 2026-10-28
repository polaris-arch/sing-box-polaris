package naive

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/badhttp"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayhttp"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c" //nolint:staticcheck
)

var (
	PrepareRuntimeHTTP3ListenerFunc func(ctx context.Context, logger logger.Logger, listener *listener.Listener, handler http.Handler, tlsConfig tls.ServerConfig, options option.NaiveInboundOptions) (io.Closer, error)
	ConfigureHTTP3ListenerFunc      func(ctx context.Context, logger logger.Logger, listener *listener.Listener, handler http.Handler, tlsConfig tls.ServerConfig, options option.NaiveInboundOptions) (io.Closer, error)
	WrapError                       func(error) error
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.NaiveInboundOptions](registry, C.TypeNaive, NewInbound)
}

type Inbound struct {
	runtime     *inboundRuntime
	runtimeTCP  *runtimeNaiveTCP
	http3Server io.Closer
	inbound.Adapter
	ctx              context.Context
	router           adapter.ConnectionRouterEx
	logger           logger.ContextLogger
	options          option.NaiveInboundOptions
	listener         *listener.Listener
	network          []string
	networkIsDefault bool
	authenticator    *auth.Authenticator
	tlsConfig        tls.ServerConfig
	httpServer       *http.Server
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NaiveInboundOptions) (adapter.Inbound, error) {
	udpFragmentDefault := options.UDPFragmentDefault
	options, err := cloneInboundOptions(ctx, options)
	if err != nil {
		return nil, err
	}
	options.UDPFragmentDefault = udpFragmentDefault
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeNaive, tag),
		ctx:     ctx,
		router:  uot.NewRouter(router, logger),
		logger:  logger,
		options: options,

		networkIsDefault: options.Network == "",
		network:          options.Network.Build(),
		authenticator:    auth.NewAuthenticator(options.Users),
	}
	runtime, finishRuntimeConstruction, runtimeErr := newInboundRuntimeConstruction(ctx, inbound.closeRuntimeProtocol)
	defer finishRuntimeConstruction()
	if runtimeErr != nil {
		return nil, runtimeErr
	}
	inbound.runtime = runtime
	if runtime != nil {
		logger = runtime.wrapLogger(logger)
		inbound.logger = logger
		ctx = runtime.bindContext(ctx)
		inbound.ctx = ctx
		if inbound.networkIsDefault && PrepareRuntimeHTTP3ListenerFunc == nil {
			inbound.network = []string{N.NetworkTCP}
		}
	}
	inbound.router = uot.NewRouter(router, logger)
	inbound.listener = listener.New(listener.Options{Context: ctx, Logger: logger, Network: inbound.network, Listen: options.ListenOptions})
	if runtime != nil {
		if common.Contains(inbound.network, N.NetworkTCP) {
			inbound.runtimeTCP = newRuntimeNaiveTCP(inbound)
			if err := inbound.listener.BindRuntimeStreamHandler(inbound.runtimeTCP.acceptor); err != nil {
				return nil, err
			}
		}
		if common.Contains(inbound.network, N.NetworkUDP) {
			if err := inbound.listener.DeclareRuntimePacketTransport(); err != nil {
				return nil, err
			}
		}
	}

	if common.Contains(inbound.network, N.NetworkUDP) {
		if options.TLS == nil || !options.TLS.Enabled {
			return nil, E.New("TLS is required for QUIC server")
		}
	}
	if len(options.Users) == 0 {
		return nil, E.New("missing users")
	}
	if options.TLS != nil {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		inbound.tlsConfig = tlsConfig
	}
	return inbound, nil
}

func (n *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if n.runtime != nil {
		return n.PrepareRuntime(stage, scope)
	}
	if stage != adapter.StartStateStart {
		return nil
	}
	if n.tlsConfig != nil {
		err := n.tlsConfig.Start()
		if err != nil {
			return E.Cause(err, "create TLS config")
		}
		scope.Add(n.tlsConfig.Close)
	}
	scope.Add(n.listener.Close)
	if common.Contains(n.network, N.NetworkTCP) {
		tcpListener, err := n.listener.ListenTCP()
		if err != nil {
			return err
		}
		n.httpServer = &http.Server{
			//nolint:staticcheck
			Handler: h2c.NewHandler(n, &http2.Server{}),
			BaseContext: func(listener net.Listener) context.Context {
				return n.ctx
			},
		}
		listener := net.Listener(tcpListener)
		if n.tlsConfig != nil {
			if len(n.tlsConfig.NextProtos()) == 0 {
				n.tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
			} else if !common.Contains(n.tlsConfig.NextProtos(), http2.NextProtoTLS) {
				n.tlsConfig.SetNextProtos(append([]string{http2.NextProtoTLS}, n.tlsConfig.NextProtos()...))
			}
			listener = aTLS.NewListener(tcpListener, n.tlsConfig)
		}
		go func() {
			sErr := n.httpServer.Serve(listener)
			if sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
				n.logger.Error("http server serve error: ", sErr)
			}
		}()
		scope.Add(n.httpServer.Close)
	}

	if common.Contains(n.network, N.NetworkUDP) {
		http3Server, err := ConfigureHTTP3ListenerFunc(n.ctx, n.logger, n.listener, n, n.tlsConfig, n.options)
		if err == nil {
			scope.Add(http3Server.Close)
		} else if len(n.network) > 1 {
			n.logger.Warn(E.Cause(err, "naive http3 disabled"))
		} else {
			return err
		}
	}

	return nil
}

func (n *Inbound) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	owned, release, admitErr := n.runtime.enter(request.Context())
	if admitErr != nil {
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer release()
	request = request.WithContext(owned)
	ctx := log.ContextWithNewID(request.Context())
	if request.Method != "CONNECT" {
		rejectHTTP(writer, http.StatusBadRequest)
		n.badRequest(ctx, request, E.New("not CONNECT request"))
		return
	} else if request.Header.Get("Padding") == "" {
		rejectHTTP(writer, http.StatusBadRequest)
		n.badRequest(ctx, request, E.New("missing naive padding"))
		return
	}
	userName, password, authOk := badhttp.ParseBasicAuth(request.Header.Get("Proxy-Authorization"))
	if authOk {
		authOk = n.authenticator.Verify(userName, password)
	}
	if !authOk {
		rejectHTTP(writer, http.StatusProxyAuthRequired)
		n.badRequest(ctx, request, E.New("authorization failed"))
		return
	}
	writer.Header().Set("Padding", generatePaddingHeader())
	writer.WriteHeader(http.StatusOK)
	writer.(http.Flusher).Flush()

	hostPort := request.Header.Get("-connect-authority")
	if hostPort == "" {
		hostPort = request.URL.Host
		if hostPort == "" {
			hostPort = request.Host
		}
	}
	source := badhttp.SourceAddress(request)
	destination := M.ParseSocksaddr(hostPort).Unwrap()

	if hijacker, isHijacker := writer.(http.Hijacker); isHijacker {
		conn, reader, err := hijacker.Hijack()
		if err != nil {
			n.badRequest(ctx, request, E.New("hijack failed"))
			return
		}
		if cacheLen := reader.Reader.Buffered(); cacheLen > 0 {
			cache := buf.NewSize(cacheLen)
			_, err = cache.ReadFullFrom(reader.Reader, cacheLen)
			if err != nil {
				cache.Release()
				conn.Close()
				n.badRequest(ctx, request, E.Cause(err, "read cache"))
				return
			}
			conn = bufio.NewCachedConn(conn, cache)
		}
		n.newConnection(ctx, false, &naiveConn{Conn: conn}, userName, source, destination)
	} else {
		logical := &naiveH2Conn{reader: request.Body, writer: writer, flusher: writer.(http.Flusher), remoteAddress: source}
		var conn net.Conn = logical
		if n.runtime != nil {
			conn = &runtimeNaiveResponseConn{Conn: logical, writer: writer}
		}
		n.newConnection(ctx, true, conn, userName, source, destination)
	}
}

func (n *Inbound) newConnection(ctx context.Context, waitForClose bool, conn net.Conn, userName string, source M.Socksaddr, destination M.Socksaddr) {
	var closeCarrier N.CloseHandlerFunc
	if n.runtime != nil {
		var err error
		conn, closeCarrier, err = n.runtime.wrapConnection(ctx, conn, nil)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, nil, err)
			return
		}
	}

	if userName != "" {
		n.logger.InfoContext(ctx, "[", userName, "] inbound connection from ", source)
		n.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", destination)
	} else {
		n.logger.InfoContext(ctx, "inbound connection from ", source)
		n.logger.InfoContext(ctx, "inbound connection to ", destination)
	}
	var metadata adapter.InboundContext
	metadata.Inbound = n.Tag()
	metadata.InboundType = n.Type()
	//nolint:staticcheck
	metadata.InboundDetour = n.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.Source = source
	metadata.Destination = destination
	metadata.OriginDestination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
	metadata.User = userName
	if !waitForClose {
		n.router.RouteConnectionEx(ctx, conn, metadata, closeCarrier)
	} else {
		done := make(chan struct{})
		finish := N.OnceClose(func(it error) {
			if closeCarrier != nil {
				closeCarrier(it)
			}
			close(done)
		})
		if n.runtime != nil {
			// The owned carrier seals writes and interrupts the concrete response
			// before joining them. The legacy wrapper locks before Close and can
			// deadlock behind a flow-controlled Write before that interrupt is reached.
			n.router.RouteConnectionEx(ctx, conn, metadata, finish)
			<-done
			return
		}
		wrapper := v2rayhttp.NewHTTP2Wrapper(conn)
		n.router.RouteConnectionEx(ctx, wrapper, metadata, finish)
		<-done
		wrapper.CloseWrapper()
	}
}

func (n *Inbound) badRequest(ctx context.Context, request *http.Request, err error) {
	n.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", request.RemoteAddr))
}

func rejectHTTP(writer http.ResponseWriter, statusCode int) {
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		writer.WriteHeader(statusCode)
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		writer.WriteHeader(statusCode)
		return
	}
	if tcpConn, isTCP := common.Cast[*net.TCPConn](conn); isTCP {
		tcpConn.SetLinger(0)
	}
	conn.Close()
}
