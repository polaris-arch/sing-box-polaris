package api

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"golang.org/x/net/http2"
)

func RegisterService(registry *boxService.Registry) {
	boxService.Register[option.APIServiceOptions](registry, C.TypeAPI, NewService)
}

type Service struct {
	boxService.Adapter
	logger    log.ContextLogger
	options   option.APIServiceOptions
	listener  *listener.Listener
	tlsConfig tls.ServerConfig
	dashboard *dashboard
	runtime   *runtimeAPI
	legacy    *apiEndpoint
}

func NewService(ctx context.Context, logger log.ContextLogger, tag string, options option.APIServiceOptions) (adapter.Service, error) {
	if service.FromContext[adapter.RuntimeAPIProvider](ctx) != nil {
		options = adapter.NormalizeRuntimeAPIOptions(options)
	}
	s := &Service{
		Adapter: boxService.NewAdapter(C.TypeAPI, tag),
		logger:  logger,
		options: options,
		listener: listener.New(listener.Options{
			Exclusive: service.FromContext[adapter.RuntimeAPIProvider](ctx) != nil,
			Context:   ctx,
			Logger:    logger,
			Network:   []string{N.NetworkTCP},
			Listen:    options.ListenOptions,
		}),
	}
	if options.TLS != nil {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		s.tlsConfig = tlsConfig
	}
	if options.Dashboard != nil && options.Dashboard.Enabled {
		s.dashboard = newDashboard(ctx, logger, tag, *options.Dashboard)
	}
	if provider := service.FromContext[adapter.RuntimeAPIProvider](ctx); provider != nil {
		runtime, err := newRuntimeAPI(ctx, s, provider)
		if err != nil {
			return nil, err
		}
		s.runtime = runtime
	}
	return s, nil
}

func (s *Service) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStarted {
		return nil
	}
	if s.runtime != nil {
		return s.runtime.start(scope)
	}
	ctx := scope.Context()
	startedService := daemon.NewAttachedService(ctx)
	scope.Add(func() error {
		startedService.Close()
		return nil
	})
	grpcServer := daemon.NewServer(startedService, s.options.Secret)
	scope.Add(func() error {
		grpcServer.Stop()
		return nil
	})
	if s.dashboard != nil {
		scope.Add(s.dashboard.close)
		err := s.dashboard.start(ctx)
		if err != nil {
			return E.Cause(err, "start dashboard")
		}
	}
	if s.tlsConfig != nil {
		scope.Add(s.tlsConfig.Close)
		if err := s.startTLS(); err != nil {
			return err
		}
	}
	tcpListener, err := s.listener.ListenTCP()
	if err != nil {
		return err
	}
	if s.tlsConfig != nil {
		tcpListener = apiTLSListener{Listener: tcpListener, config: s.tlsConfig}
	}
	e := &apiEndpoint{listener: tcpListener, conns: make(map[*apiOwnedConn]struct{}), serveDone: make(chan struct{})}
	s.legacy = e
	scope.Add(e.close)
	e.startHandler(ctx, newHTTPHandler(s.logger, grpcServer, s.options, s.dashboard))
	return nil
}

// Both initial ingress owners use the same TLS lifecycle. Register its close
// before calling this: a failed Start may already own provider/watch work.
func (s *Service) startTLS() error {
	if err := s.tlsConfig.Start(); err != nil {
		return E.Cause(err, "create TLS config")
	}
	if !common.Contains(s.tlsConfig.NextProtos(), http2.NextProtoTLS) {
		s.tlsConfig.SetNextProtos(append([]string{http2.NextProtoTLS}, s.tlsConfig.NextProtos()...))
	}
	if !common.Contains(s.tlsConfig.NextProtos(), "http/1.1") {
		s.tlsConfig.SetNextProtos(append(s.tlsConfig.NextProtos(), "http/1.1"))
	}
	return nil
}

// closeHTTPListener closes the HTTP server and then the listener it serves.
// http.Server.Close also closes the listener once Serve has registered it, so
// a net.ErrClosed from the listener only confirms that the socket is gone. The
// listener is still closed explicitly because Serve runs in its own goroutine
// and may not have registered the socket yet.
func closeHTTPListener(httpServer *http.Server, listener io.Closer) error {
	httpErr := httpServer.Close()
	listenerErr := listener.Close()
	if errors.Is(listenerErr, net.ErrClosed) {
		listenerErr = nil
	}
	return E.Errors(httpErr, listenerErr)
}
