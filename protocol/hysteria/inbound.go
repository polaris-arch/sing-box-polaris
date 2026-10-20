package hysteria

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.HysteriaInboundOptions](registry, C.TypeHysteria, NewInbound)
}

type Inbound struct {
 runtime *inboundRuntime
 protocolTLS *inboundRuntimeTLS
	inbound.Adapter
	router       adapter.Router
	logger       log.ContextLogger
	listener     *listener.Listener
	tlsConfig    tls.ServerConfig
	service      *hysteria.Service[int]
	userNameList []string
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HysteriaInboundOptions) (adapter.Inbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
 udpFragmentDefault:=options.UDPFragmentDefault
 options, err := cloneInboundOptions(ctx, options)
 options.UDPFragmentDefault=udpFragmentDefault
 if err != nil { return nil,err }
 inbound := &Inbound{Adapter:inbound.NewAdapter(C.TypeHysteria,tag),router:router,logger:logger}
 runtime, finishRuntimeConstruction, runtimeErr := newInboundRuntimeConstruction(ctx, inbound.closeRuntimeProtocol)
 defer finishRuntimeConstruction()
 if runtimeErr != nil { return nil,runtimeErr }
 inbound.runtime = runtime
 if runtime != nil { logger=runtime.wrapLogger(logger);inbound.logger=logger;ctx=runtime.bindContext(ctx) }
 tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
 if err != nil { return nil,err }
 inbound.tlsConfig=tlsConfig
 inbound.listener=listener.New(listener.Options{Context:ctx,Logger:logger,Network:[]string{N.NetworkUDP},Listen:options.ListenOptions})
 if runtime != nil {
  if err:=inbound.listener.DeclareRuntimePacketTransport();err!=nil{return nil,err}
  inbound.protocolTLS=&inboundRuntimeTLS{ServerConfig:tlsConfig,runtime:runtime,listener:inbound.listener}
  tlsConfig=inbound.protocolTLS
 }


	var sendBps, receiveBps uint64
	if options.Up.Value() > 0 {
		sendBps = options.Up.Value()
	} else {
		sendBps = uint64(options.UpMbps) * hysteria.MbpsToBps
	}
	if options.Down.Value() > 0 {
		receiveBps = options.Down.Value()
	} else {
		receiveBps = uint64(options.DownMbps) * hysteria.MbpsToBps
	}
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	service, err := hysteria.NewService[int](hysteria.ServiceOptions{
		Context:       ctx,
		Logger:        logger,
		SendBPS:       sendBps,
		ReceiveBPS:    receiveBps,
		XPlusPassword: options.Obfs,
		TLSConfig:     tlsConfig,
		QUICOptions:   buildInboundQUICOptions(options),
		UDPTimeout:    udpTimeout,
		Handler:       inbound,
	})
	if err != nil {
		return nil, err
	}
	userList := make([]int, 0, len(options.Users))
	userNameList := make([]string, 0, len(options.Users))
	userPasswordList := make([]string, 0, len(options.Users))
	for index, user := range options.Users {
		userList = append(userList, index)
		userNameList = append(userNameList, user.Name)
		var password string
		if user.AuthString != "" {
			password = user.AuthString
		} else {
			password = string(user.Auth)
		}
		userPasswordList = append(userPasswordList, password)
	}
	service.UpdateUsers(userList, userPasswordList)
	inbound.service = service
	inbound.userNameList = userNameList
	return inbound, nil
}

func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
 ctx,release,err:=h.runtime.enter(ctx)
 if err!=nil{N.CloseOnHandshakeFailure(conn,onClose,err);return}
 defer release()
 if h.runtime!=nil {
  conn,onClose,err=h.runtime.wrapConnection(ctx,conn,onClose)
  if err!=nil{N.CloseOnHandshakeFailure(conn,onClose,err);return}
 }

	ctx = log.ContextWithNewID(ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.OriginDestination = h.listener.UDPAddr()
	metadata.Source = source
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
	userID, validUser := auth.UserFromContext[int](ctx)
 if !validUser || userID<0 || userID>=len(h.userNameList) { N.CloseOnHandshakeFailure(conn,onClose,net.ErrClosed);return }
	if userName := h.userNameList[userID]; userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
 ctx,release,err:=h.runtime.enter(ctx)
 if err!=nil{N.CloseOnHandshakeFailure(conn,onClose,err);return}
 defer release()
 if h.runtime!=nil {
  conn,onClose,err=h.runtime.wrapPacketConnection(ctx,conn,onClose)
  if err!=nil{N.CloseOnHandshakeFailure(conn,onClose,err);return}
 }

	ctx = log.ContextWithNewID(ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.OriginDestination = h.listener.UDPAddr()
	metadata.Source = source
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "inbound packet connection from ", metadata.Source)
	userID, validUser := auth.UserFromContext[int](ctx)
 if !validUser || userID<0 || userID>=len(h.userNameList) { N.CloseOnHandshakeFailure(conn,onClose,net.ErrClosed);return }
	if userName := h.userNameList[userID]; userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound packet connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
 if h.runtime!=nil{return h.PrepareRuntime(stage,scope)}
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		err := h.tlsConfig.Start()
		if err != nil {
			return err
		}
		scope.Add(h.tlsConfig.Close)
	}
	packetConn, err := h.listener.ListenUDP()
	if err != nil {
		return err
	}
	scope.Add(h.listener.Close)
	err = h.service.Start(packetConn)
	if err != nil {
		return err
	}
	scope.Add(h.service.Close)
	return nil
}
