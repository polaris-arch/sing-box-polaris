package shadowtls

import (
	"context"
	"net"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.ShadowTLSOutboundOptions](registry, C.TypeShadowTLS, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	client *shadowtls.Client
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowTLSOutboundOptions) (adapter.Outbound, error) {
	outbound := &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeShadowTLS, tag, []string{N.NetworkTCP}, options.DialerOptions),
	}
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}

	if options.Version == 0 {
		options.Version = 1
	}

	if options.Version == 3 && options.TLS.ECH != nil && options.TLS.ECH.Enabled {
		return nil, E.New("ShadowTLS session ID authentication cannot be combined with real ECH")
	}

	if options.Version == 1 {
		options.TLS.MinVersion = "1.2"
		options.TLS.MaxVersion = "1.2"
	}
	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}

	var tlsHandshakeFunc shadowtls.TLSHandshakeFunc
	switch options.Version {
	case 1, 2:
		tlsHandshakeFunc = func(ctx context.Context, conn net.Conn, _ shadowtls.TLSSessionIDGeneratorFunc) error {
			return common.Error(tls.ClientHandshake(ctx, conn, tlsConfig))
		}
	case 3:
		tlsHandshakeFunc, err = newV3TLSHandshake(tlsConfig, options.Password)
		if err != nil {
			return nil, err
		}
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	client, err := shadowtls.NewClient(shadowtls.ClientConfig{
		Version:      options.Version,
		Password:     options.Password,
		Server:       options.ServerOptions.Build(),
		Dialer:       outboundDialer,
		TLSHandshake: tlsHandshakeFunc,
		Logger:       logger,
	})
	if err != nil {
		return nil, err
	}
	outbound.client = client
	return outbound, nil
}

// Shared by the production outbound and its actual-v3 protocol regressions.
// The authenticator belongs to one dial; the caller's TLS configuration is immutable.
func newV3TLSHandshake(config tls.Config, password string) (shadowtls.TLSHandshakeFunc, error) {
	if _, ok := config.(tls.WithSessionIDGenerator); ok {
		return func(ctx context.Context, conn net.Conn, generator shadowtls.TLSSessionIDGeneratorFunc) error {
			connectionConfig := config.Clone()
			idConfig, ok := connectionConfig.(tls.WithSessionIDGenerator)
			if !ok {
				return E.New("TLS clone lost session ID generator support")
			}
			idConfig.SetSessionIDGenerator(generator)
			return common.Error(tls.ClientHandshake(ctx, conn, connectionConfig))
		}, nil
	}
	stdConfig, err := config.STDConfig()
	if err != nil {
		return nil, err
	}
	return shadowtls.DefaultTLSHandshakeFunc(password, stdConfig), nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return h.client.DialContext(ctx)
	default:
		return nil, os.ErrInvalid
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}
