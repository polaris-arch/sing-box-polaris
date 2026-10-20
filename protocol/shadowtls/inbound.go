package shadowtls

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.ShadowTLSInboundOptions](registry, C.TypeShadowTLS, NewInbound)
}

type Inbound struct {
	runtime *inboundRuntime
	inbound.Adapter
	router     adapter.Router
	logger     logger.ContextLogger
	listener   *listener.Listener
	service    *shadowtls.Service
	references []string
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowTLSInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeShadowTLS, tag),
		router:  router,
		logger:  logger,
	}

	runtime, finishRuntimeConstruction, runtimeErr := newInboundRuntimeConstruction(ctx, func() error { return inbound.closeRuntimeProtocol() })
	defer finishRuntimeConstruction()
	if runtimeErr != nil { return nil, runtimeErr }
	inbound.runtime = runtime
	if runtime != nil { logger = runtime.wrapLogger(logger); inbound.logger = logger }

	if options.Version == 0 {
		options.Version = 1
	}

	var handshakeForServerName map[string]shadowtls.HandshakeConfig
	if options.Version > 1 {
		handshakeForServerName = make(map[string]shadowtls.HandshakeConfig)
		if options.HandshakeForServerName != nil {
			for _, entry := range options.HandshakeForServerName.Entries() {
				if entry.Value.Detour != "" {
					inbound.references = append(inbound.references, entry.Value.Detour)
				}
				handshakeDialer, err := dialer.New(ctx, entry.Value.DialerOptions, entry.Value.ServerIsDomain())
				if err != nil {
					return nil, err
				}
				handshakeForServerName[entry.Key] = shadowtls.HandshakeConfig{
					Server: entry.Value.ServerOptions.Build(),
					Dialer: runtimeHandshakeFor(inbound.runtime, handshakeDialer),
				}
			}
		}
	}
	serverIsDomain := options.Handshake.ServerIsDomain()
	if options.WildcardSNI != option.ShadowTLSWildcardSNIOff {
		serverIsDomain = true
	}
	handshakeDialer, err := dialer.New(ctx, options.Handshake.DialerOptions, serverIsDomain)
	if err != nil {
		return nil, err
	}
	if options.Handshake.Detour != "" {
		inbound.references = append(inbound.references, options.Handshake.Detour)
	}
	service, err := shadowtls.NewService(shadowtls.ServiceConfig{
		Version:  options.Version,
		Password: options.Password,
		Users: common.Map(options.Users, func(it option.ShadowTLSUser) shadowtls.User {
			return shadowtls.User(it)
		}),
		Handshake: shadowtls.HandshakeConfig{
			Server: options.Handshake.ServerOptions.Build(),
			Dialer: runtimeHandshakeFor(inbound.runtime, handshakeDialer),
		},
		HandshakeForServerName: handshakeForServerName,
		StrictMode:             options.StrictMode,
		WildcardSNI:            shadowtls.WildcardSNI(options.WildcardSNI),
		Handler:                (*inboundHandler)(inbound),
		Logger:                 logger,
	})
	if err != nil {
		return nil, err
	}
	inbound.service = service
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
	})
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if h.runtime != nil { return h.PrepareRuntime(stage, scope) }
	if stage != adapter.StartStateStart {
		return nil
	}
	err := h.listener.Start()
	if err != nil {
		return err
	}
	scope.Add(h.listener.Close)
	return nil
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx, release, err := h.runtime.enter(ctx)
	if err != nil { N.CloseOnHandshakeFailure(conn, onClose, err); return }
	defer release()
	if h.runtime != nil {
		carriers := &runtimeHandshakeCarriers{}
		ctx = context.WithValue(ctx, runtimeHandshakeKey{}, carriers)
		defer func() { if closeErr := carriers.close(); closeErr != nil { h.logger.ErrorContext(ctx, "handshake carrier cleanup incomplete: ", closeErr) } }()
	}
	err = h.service.NewConnection(adapter.WithContext(log.ContextWithNewID(ctx), &metadata), conn, metadata.Source, metadata.Destination, onClose)
	N.CloseOnHandshakeFailure(conn, onClose, err)
	if err != nil {
		if E.IsClosedOrCanceled(err) {
			h.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
		}
	}
}

type inboundHandler Inbound

func (h *inboundHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx, release, err := h.runtime.enter(ctx)
	if err != nil { N.CloseOnHandshakeFailure(conn, onClose, err); return }
	defer release()
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.Source = source
	metadata.Destination = destination
	if userName, _ := auth.UserFromContext[string](ctx); userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) References() []string {
	return append([]string(nil), h.references...)
}
