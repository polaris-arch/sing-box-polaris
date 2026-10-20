//go:build !with_quic

package hysteria2

import (
 "errors"
 "github.com/sagernet/sing-box/common/tls"
)
func newOutboundRuntimeTLS(config tls.Config,owner *outboundRuntime)(tls.Config,error){return nil,errors.New("ordinary QUIC runtime requires with_quic")}
