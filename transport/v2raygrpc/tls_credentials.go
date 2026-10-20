package v2raygrpc

import (
	"context"
	"net"
	"os"

	"github.com/sagernet/sing-box/common/tls"
 "github.com/sagernet/sing-box/transport/runtimeingress"
	"github.com/sagernet/sing-box/common/httpclient"
	internal_credentials "github.com/sagernet/sing-box/transport/v2raygrpc/credentials"

	"google.golang.org/grpc/credentials"
)

type TLSTransportCredentials struct {
	config tls.Config
	boundary *httpclient.RuntimeTransportBoundary
}

func NewTLSTransportCredentials(config tls.Config) credentials.TransportCredentials {
	return &TLSTransportCredentials{config:config}
}

func (c *TLSTransportCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "tls",
	}
}

func (c *TLSTransportCredentials) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if c.boundary!=nil{leave,err:=c.boundary.Acquire();if err!=nil{return nil,nil,err};defer leave()}
	cfg := c.config.Clone()
	if cfg.ServerName() == "" {
		serverName, _, err := net.SplitHostPort(authority)
		if err != nil {
			serverName = authority
		}
		cfg.SetServerName(serverName)
	}
	conn, err := tls.ClientHandshake(ctx, rawConn, cfg)
	if err != nil {
		if c.boundary!=nil&&tls.IsRuntimeCleanupIncomplete(err){c.boundary.RecordClose(err)}
		return nil, nil, err
	}
	tlsInfo := credentials.TLSInfo{
		State:         conn.ConnectionState(),
		SecurityLevel: credentials.PrivacyAndIntegrity,
	}
	id := internal_credentials.SPIFFEIDFromState(conn.ConnectionState())
	if id != nil {
		tlsInfo.SPIFFEID = id
	}
	if c.boundary!=nil{guarded,err:=c.boundary.GuardConnection(conn);return guarded,tlsInfo,err}
	return conn,tlsInfo,nil
}

func (c *TLSTransportCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	serverConfig, isServer := c.config.(tls.ServerConfig)
	if !isServer {
		return nil, nil, os.ErrInvalid
	}
	conn, err := tls.ServerHandshake(runtimeingress.Context(context.Background(),rawConn), rawConn, serverConfig)
	if err != nil {
		rawConn.Close()
		return nil, nil, err
	}
	tlsInfo := credentials.TLSInfo{
		State:         conn.ConnectionState(),
		SecurityLevel: credentials.PrivacyAndIntegrity,
	}
	id := internal_credentials.SPIFFEIDFromState(conn.ConnectionState())
	if id != nil {
		tlsInfo.SPIFFEID = id
	}
	return internal_credentials.WrapSyscallConn(rawConn, conn), tlsInfo, nil
}

func (c *TLSTransportCredentials) Clone() credentials.TransportCredentials {
	return &TLSTransportCredentials{config:c.config.Clone(),boundary:c.boundary}
}

func (c *TLSTransportCredentials) OverrideServerName(serverNameOverride string) error {
	c.config.SetServerName(serverNameOverride)
	return nil
}
