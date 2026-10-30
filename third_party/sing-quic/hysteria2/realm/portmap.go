package realm

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	"github.com/libp2p/go-nat"
)

const (
	defaultPortMappingTimeout  = 10 * time.Second
	defaultPortMappingLifetime = 10 * time.Minute
	portMappingDescription     = "hysteria-realm"
	portMappingProtocol        = "udp"
)

type PortMappingOptions struct {
	// The caller owns this captured transport through terminal deletion.
	HTTPClient *http.Client
	Resolver   Resolver
	Timeout    time.Duration
	Lifetime   time.Duration
}

type PortMapper struct {
	gateway      nat.NAT
	logger       logger.Logger
	internalPort int
	timeout      time.Duration
	lifetime     time.Duration

	// Gateway calls are serialized. Closing cancels an in-flight renewal first,
	// then joins it before deleting the exact mapping; a late Add cannot escape.
	operation        sync.Mutex
	closed           bool
	cancel           context.CancelFunc
	ctx              context.Context
	closeOnce        sync.Once
	closeErr         error
	renewErr         error
	deleteContextErr error

	access       sync.Mutex
	externalAddr netip.AddrPort
}

func NewPortMapper(ctx context.Context, logger logger.Logger, internalPort uint16, options PortMappingOptions) (*PortMapper, error) {
	discover := nat.DiscoverGateway
	if options.HTTPClient != nil {
		discover = func(ctx context.Context) (nat.NAT, error) {
			var resolver func(context.Context, string) ([]net.IP, error)
			if options.Resolver != nil {
				resolver = func(ctx context.Context, host string) ([]net.IP, error) {
					addresses, err := options.Resolver(ctx, host, true, false)
					result := make([]net.IP, 0, len(addresses))
					for _, address := range addresses {
						address = address.Unmap()
						if address.Is4() {
							result = append(result, net.IP(address.AsSlice()))
						}
					}
					return result, err
				}
			}
			return nat.DiscoverGatewayWithHTTPClient(ctx, options.HTTPClient, resolver)
		}
	}
	return newPortMapper(ctx, logger, internalPort, options, discover)
}

// Instance-local dependency seam; production and tests share all mapper logic.
func newPortMapper(ctx context.Context, logger logger.Logger, internalPort uint16, options PortMappingOptions, discover func(context.Context) (nat.NAT, error)) (*PortMapper, error) {
	if internalPort == 0 {
		return nil, E.New("invalid internal port")
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultPortMappingTimeout
	}
	lifetime := options.Lifetime
	if lifetime <= 0 {
		lifetime = defaultPortMappingLifetime
	}
	discoverCtx, cancel := context.WithTimeout(ctx, timeout)
	gateway, err := discover(discoverCtx)
	discoveryCanceled := discoverCtx.Err()
	cancel()
	if discoveryCanceled != nil {
		// The pinned local go-nat returns only after all discovery producers
		// join. Cancellation forbids Add, but is no longer orphan-worker debt.
		return nil, errors.Join(err, discoveryCanceled)
	}
	if err != nil {
		return nil, E.Cause(err, "discover gateway")
	}
	if gateway == nil {
		return nil, E.New("gateway discovery returned no gateway")
	}
	mapper := &PortMapper{
		gateway:      gateway,
		logger:       logger,
		internalPort: int(internalPort),
		timeout:      timeout,
		lifetime:     lifetime,
	}
	mapper.ctx, mapper.cancel = context.WithCancel(context.Background())
	_, err = mapper.Renew(ctx)
	if err != nil {
		// An Add timeout may have created a mapping remotely. Delete and join
		// even when the external-address query or initial renewal failed.
		return nil, errors.Join(err, mapper.Close())
	}
	logger.Info("port mapping added via ", gateway.Type(), ", external address: ", mapper.ExternalAddr())
	return mapper, nil
}

func (m *PortMapper) Renew(ctx context.Context) (changed bool, resultErr error) {
	m.operation.Lock()
	defer m.operation.Unlock()
	m.access.Lock()
	closed := m.closed
	m.access.Unlock()
	if closed {
		return false, net.ErrClosed
	}
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	if m.ctx != nil {
		stopped := make(chan struct{})
		stop := context.AfterFunc(m.ctx, func() { defer close(stopped); cancel() })
		defer func() {
			if !stop() {
				<-stopped
			}
		}()
	}
	defer func() {
		if resultErr != nil && !(ctx.Err() != nil && errors.Is(resultErr, ctx.Err())) {
			m.access.Lock()
			m.renewErr = errors.Join(m.renewErr, resultErr)
			m.access.Unlock()
		}
	}()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if m.ctx != nil && m.ctx.Err() != nil {
		return false, m.ctx.Err()
	}
	externalPort, err := m.gateway.AddPortMapping(ctx, portMappingProtocol, m.internalPort, portMappingDescription, m.lifetime)
	if err != nil {
		return false, E.Cause(err, "add port mapping")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	// NAT's API has no context for this call. Keep it inside the joined
	// gateway operation; cancellation never certifies an unfinished call.
	var externalIP net.IP
	if gateway, ok := m.gateway.(interface {
		GetExternalAddressContext(context.Context) (net.IP, error)
	}); ok {
		externalIP, err = gateway.GetExternalAddressContext(ctx)
	} else {
		externalIP, err = m.gateway.GetExternalAddress()
	}
	if err != nil {
		return false, E.Cause(err, "get external address")
	}
	address, valid := netip.AddrFromSlice(externalIP)
	if !valid || address.IsUnspecified() || address.IsLoopback() || !address.Unmap().Is4() || externalPort <= 0 || externalPort > 65535 {
		return false, E.New("gateway returned unusable external address or port")
	}
	if err = ctx.Err(); err != nil {
		return false, err
	}
	externalAddr := netip.AddrPortFrom(address.Unmap(), uint16(externalPort))
	m.access.Lock()
	changed = externalAddr != m.externalAddr
	m.externalAddr = externalAddr
	m.access.Unlock()
	return changed, nil
}

func (m *PortMapper) ExternalAddr() netip.AddrPort {
	m.access.Lock()
	defer m.access.Unlock()
	return m.externalAddr
}

// KeepAlive retains the cold server/client API. Its cancellation bridge is
// joined by this call; Realm outbound runtime uses KeepAliveContext directly.
func (m *PortMapper) KeepAlive(done <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-done:
			cancel()
		case <-ctx.Done():
		}
	}()
	err := m.KeepAliveContext(ctx)
	cancel()
	<-joined
	if err != nil && m.logger != nil {
		m.logger.Debug(E.Cause(err, "remove port mapping"))
	}
}

// KeepAliveContext returns only after the current renewal and deletion finish.
// Renewal and delete errors are sticky even if a later renewal recovers.
func (m *PortMapper) KeepAliveContext(ctx context.Context) error {
	interval := m.lifetime / 2
	if interval <= 0 {
		interval = defaultPortMappingLifetime / 2
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	failing := false
	for {
		select {
		case <-ctx.Done():
			return m.Close()
		case <-ticker.C:
			changed, err := m.Renew(ctx)
			if ctx.Err() != nil {
				return m.Close()
			}
			if err != nil {
				if !failing && m.logger != nil {
					m.logger.Warn(E.Cause(err, "renew port mapping"))
				}
				failing = true
				continue
			}
			if m.logger != nil {
				if failing {
					m.logger.Info("port mapping recovered, external address: ", m.ExternalAddr())
				} else if changed {
					m.logger.Info("port mapping external address changed: ", m.ExternalAddr())
				}
			}
			failing = false
		}
	}
}

func (m *PortMapper) Close() error {
	m.closeOnce.Do(func() {
		m.access.Lock()
		m.closed = true
		if m.cancel != nil {
			m.cancel()
		}
		m.access.Unlock()
		m.operation.Lock()
		defer m.operation.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
		defer cancel()
		err := m.gateway.DeletePortMapping(ctx, portMappingProtocol, m.internalPort)
		if diagnostic, ok := m.gateway.(interface{ PortMappingDeleteContextError() error }); ok {
			m.deleteContextErr = diagnostic.PortMappingDeleteContextError()
			if err == nil && m.deleteContextErr != nil && m.logger != nil {
				m.logger.Debug("port mapping cleanup resolved after context elapsed: ", m.deleteContextErr)
			}
		}
		m.access.Lock()
		// Renew reports and retains operational history separately. A confirmed
		// deletion resolves its remote effects; only actual cleanup failure keeps
		// the resource charged after all operations have joined.
		if err != nil {
			m.closeErr = &portMappingCleanupError{err}
		}
		m.access.Unlock()
	})
	return m.closeErr
}

type portMappingCleanupError struct{ err error }

func (e *portMappingCleanupError) Error() string {
	return "NAT mapping cleanup incomplete: " + e.err.Error()
}
func (e *portMappingCleanupError) Unwrap() error                { return e.err }
func (*portMappingCleanupError) RuntimeCleanupIncomplete() bool { return true }
