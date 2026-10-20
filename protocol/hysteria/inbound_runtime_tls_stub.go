//go:build !with_quic

package hysteria

import (
 "errors"
 "github.com/sagernet/sing-box/common/listener"
 "github.com/sagernet/sing-box/common/tls"
)

type inboundRuntimeTLS struct {
 tls.ServerConfig
 runtime *inboundRuntime
 listener *listener.Listener
 transportOptions inboundQUICTransportOptions
}
func(c *inboundRuntimeTLS)waitReady()error{return errors.New("QUIC runtime adapter requires with_quic build")}

func(c *inboundRuntimeTLS)RuntimeValidate()error{return errors.New("QUIC runtime adapter requires with_quic build")}
