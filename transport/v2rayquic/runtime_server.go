//go:build with_quic

package v2rayquic

import (
	"context"
	"fmt"
	"sync"

	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/transport/runtimeingress"
)

type runtimeServerState struct {
	endpoint    *runtimeingress.QUICEndpoint
	acceptDone  chan struct{}
	connections sync.WaitGroup
}

func (s *Server) PrepareRuntimeServer(ctx context.Context, ingress *listener.Listener) error {
	endpoint, err := runtimeingress.ListenQUIC(ctx, ingress, s.tlsConfig, s.quicConfig, false)
	if err != nil {
		return err
	}
	s.runtime = &runtimeServerState{endpoint: endpoint, acceptDone: make(chan struct{})}
	s.quicListener = endpoint
	go func() { defer close(s.runtime.acceptDone); s.acceptLoop() }()
	return nil
}

func (s *Server) RuntimeCloseAndWait() error {
	if s.runtime == nil {
		return s.Close()
	}
	err := s.runtime.endpoint.Close()
	<-s.runtime.acceptDone
	s.runtime.connections.Wait()
	if err != nil {
		return fmt.Errorf("QUIC server endpoint cleanup incomplete: %v", err)
	}
	return nil
}
