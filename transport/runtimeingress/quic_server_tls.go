package runtimeingress

import (
	"context"
	"sync"

	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
)

// QUICServerTLSOptions binds private QUIC acceptance to the inbound's
// existing listener, construction context and task owner.
type QUICServerTLSOptions struct {
	Listener                         *listener.Listener
	Context                          context.Context
	Failed                           <-chan struct{}
	RecordFailure                    func(error)
	RunTask                          func(context.Context, func(context.Context)) bool
	DisableVersionNegotiationPackets bool
	StatelessReset                   bool
}

// QUICServerTLS connects sing-quic's server hooks to private runtime ingress.
type QUICServerTLS struct {
	tls.ServerConfig
	options   QUICServerTLSOptions
	ready     chan struct{}
	readyOnce sync.Once
}

func NewQUICServerTLS(config tls.ServerConfig, options QUICServerTLSOptions) *QUICServerTLS {
	return &QUICServerTLS{ServerConfig: config, options: options}
}
