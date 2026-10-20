//go:build with_quic

package v2rayquic

import (
	"context"
	"net"
	"os"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/transport/runtimeingress"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.V2RayServerTransport = (*Server)(nil)

type Server struct {
 runtime *runtimeServerState
	ctx          context.Context
	logger       logger.ContextLogger
	tlsConfig    tls.ServerConfig
	quicConfig   *quic.Config
	handler      adapter.V2RayServerTransportHandler
	udpListener  net.PacketConn
	quicListener qtls.Listener
}

func NewServer(ctx context.Context, logger logger.ContextLogger, options option.V2RayQUICOptions, tlsConfig tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (adapter.V2RayServerTransport, error) {
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery: !C.IsLinux && !C.IsWindows,
	}
	if len(tlsConfig.NextProtos()) == 0 {
		tlsConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	server := &Server{
		ctx:        ctx,
		logger:     logger,
		tlsConfig:  tlsConfig,
		quicConfig: quicConfig,
		handler:    handler,
	}
	return server, nil
}

func (s *Server) Network() []string {
	return []string{N.NetworkUDP}
}

func (s *Server) Serve(listener net.Listener) error {
	return os.ErrInvalid
}

func (s *Server) ServePacket(listener net.PacketConn) error {
	quicListener, err := qtls.Listen(listener, s.tlsConfig, s.quicConfig)
	if err != nil {
		return err
	}
	s.udpListener = listener
	s.quicListener = quicListener
	go s.acceptLoop()
	return nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.quicListener.Accept(s.ctx)
		if err != nil {
			return
		}
  owned,leave,ownershipErr:=runtimeingress.Acquire(conn.Context(),s.runtime!=nil)
  if ownershipErr!=nil{_=conn.CloseWithError(0,"retired session");continue}
  if s.runtime!=nil{s.runtime.connections.Add(1)}
		go func() {
   if s.runtime!=nil{defer s.runtime.connections.Done()};defer leave()
			hErr := s.streamAcceptLoopContext(owned,conn)
			if hErr != nil && !E.IsClosedOrCanceled(hErr) {
				s.logger.ErrorContext(conn.Context(), hErr)
			}
		}()
	}
}

func (s *Server) streamAcceptLoop(conn *quic.Conn) error { return s.streamAcceptLoopContext(conn.Context(),conn) }
func (s *Server) streamAcceptLoopContext(ctx context.Context,conn *quic.Conn) error {
	for {
		stream, err := conn.AcceptStream(s.ctx)
		if err != nil {
			return qtls.WrapError(err)
		}
  owned,release,err:=runtimeingress.Acquire(ctx,s.runtime!=nil)
  if err!=nil{stream.CancelRead(0);stream.CancelWrite(0);return err}
  if s.runtime!=nil{s.runtime.connections.Add(1)}
  go func(){if s.runtime!=nil{defer s.runtime.connections.Done()};defer release();s.handler.NewConnectionEx(owned,&StreamWrapper{Conn:conn,Stream:stream},M.SocksaddrFromNet(conn.RemoteAddr()),M.Socksaddr{},nil)}()
	}
}

func (s *Server) Close() error {
 if s.runtime!=nil{return s.RuntimeCloseAndWait()}
	return common.Close(s.udpListener, s.quicListener)
}
