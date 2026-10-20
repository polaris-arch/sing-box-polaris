package v2raygrpc

import (
	"context"
	"net"
	"os"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/transport/runtimeingress"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
 "google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	gM "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

var _ adapter.V2RayServerTransport = (*Server)(nil)

type Server struct {
	ctx     context.Context
	logger  logger.ContextLogger
	handler adapter.V2RayServerTransportHandler
	server  *grpc.Server
}

func NewServer(ctx context.Context, logger logger.ContextLogger, options option.V2RayGRPCOptions, tlsConfig tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (*Server, error) {
	var serverOptions []grpc.ServerOption
 var transportCredentials credentials.TransportCredentials
	if tlsConfig != nil {
		if !common.Contains(tlsConfig.NextProtos(), http2.NextProtoTLS) {
			tlsConfig.SetNextProtos(append([]string{"h2"}, tlsConfig.NextProtos()...))
		}
		transportCredentials=NewTLSTransportCredentials(tlsConfig)
	}
 if adapter.IsRuntimePreparation(ctx){transportCredentials=&runtimeServerCredentials{inner:transportCredentials}}
 if transportCredentials!=nil{serverOptions=append(serverOptions,grpc.Creds(transportCredentials))}
	if options.IdleTimeout > 0 {
		serverOptions = append(serverOptions, grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    time.Duration(options.IdleTimeout),
			Timeout: time.Duration(options.PingTimeout),
		}))
	}
	server := &Server{ctx, logger, handler, grpc.NewServer(serverOptions...)}
	RegisterGunServiceCustomNameServer(server.server, server, options.ServiceName)
	return server, nil
}

func (s *Server) Tun(server GunService_TunServer) error {
 incoming:=server.Context()
 if adapter.IsRuntimePreparation(s.ctx){
  remote,ok:=peer.FromContext(incoming);if !ok{return net.ErrClosed}
  authority,ok:=remote.AuthInfo.(*runtimeServerAuth);if !ok{return net.ErrClosed}
  incoming=adapter.ContextWithRuntimeOwnership(incoming,authority.context)
 }
 owned,release,err:=runtimeingress.Acquire(incoming,adapter.IsRuntimePreparation(s.ctx))
 if err!=nil{return err}
 defer release()
	conn := NewGRPCConn(server, nil)
	var source M.Socksaddr
	if remotePeer, loaded := peer.FromContext(server.Context()); loaded {
		source = M.SocksaddrFromNet(remotePeer.Addr)
	}
	if grpcMetadata, loaded := gM.FromIncomingContext(server.Context()); loaded {
		forwardFrom := strings.Join(grpcMetadata.Get("X-Forwarded-For"), ",")
		if forwardFrom != "" {
			for from := range strings.SplitSeq(forwardFrom, ",") {
				originAddr := M.ParseSocksaddr(from)
				if originAddr.IsValid() {
					source = originAddr.Unwrap()
				}
			}
		}
	}
	done := make(chan struct{})
	// Reserve before dispatch; the request's borrowed context cannot outlive
 // this handler without its own continuation.
 worker,finish,err:=runtimeingress.Acquire(owned,adapter.IsRuntimePreparation(s.ctx))
 if err!=nil{return err}
 go func(){defer finish();s.handler.NewConnectionEx(log.ContextWithNewID(worker), conn, source, M.Socksaddr{}, N.OnceClose(func(it error) {close(done)}))}()
	<-done
	return nil
}

func (s *Server) mustEmbedUnimplementedGunServiceServer() {
}

func (s *Server) Network() []string {
	return []string{N.NetworkTCP}
}

func (s *Server) Serve(listener net.Listener) error {
	return s.server.Serve(listener)
}

func (s *Server) ServePacket(listener net.PacketConn) error {
	return os.ErrInvalid
}

func (s *Server) Close() error {
	s.server.Stop()
	return nil
}
