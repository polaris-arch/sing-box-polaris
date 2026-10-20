package httpclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

var (
	_ adapter.HTTPClientManager = (*Manager)(nil)
	_ adapter.LifecycleService  = (*Manager)(nil)
	_ adapter.Referrer          = (*Manager)(nil)
)

// A Manager belongs to one immutable constructor registry/cohort. Preparing a
// candidate never mutates the live manager. Definitions are copied at creation;
// all allocating work and joins occur outside access.
type Manager struct {
	ctx                      context.Context
	logger                   log.ContextLogger
	access                   sync.Mutex
	defines                  map[string]option.HTTPClient
	sharedTransports         map[string]*sharedManagedTransport
	managedTransports        []*ManagedTransport
	defaultTag               string
	defaultTransport         *sharedManagedTransport
	defaultTransportFallback func() (*ManagedTransport, error)
	source                   adapter.RuntimeResourceSource
	fence                    *outbound.RuntimeIOFence
	admitOwned               func(context.Context) (context.Context, func(), error)
	closed                   bool
	prepared                 bool
	frozen                   bool
	constructionOwned        bool
	stopOnce                 sync.Once
	setupErr                 error
	closeErr                 error
}

type sharedManagedTransport struct {
	managed *ManagedTransport
	shared  *sharedState
}

func cloneHTTPClientOptions(ctx context.Context, options option.HTTPClientOptions) (option.HTTPClientOptions, error) {
	// Options supplies a tagged/version-aware JSON representation. Preserve
	// constructor-only flags, which deliberately are not part of that wire form.
	tag := options.Tag
	options.Tag = ""
	data, err := json.Marshal(options)
	if err != nil {
		return option.HTTPClientOptions{}, err
	}
	var clone option.HTTPClientOptions
	if err = json.UnmarshalContext(ctx, data, &clone); err != nil {
		return clone, err
	}
	clone.Tag = tag
	clone.DefaultOutbound = options.DefaultOutbound
	clone.DisableEmptyDirectCheck = options.DisableEmptyDirectCheck
	clone.ResolveOnDetour = options.ResolveOnDetour
	clone.DirectResolver = options.DirectResolver
	clone.TCPKeepAliveSystemDefaults = options.TCPKeepAliveSystemDefaults
	clone.UDPBindPort = options.UDPBindPort
	clone.UDPFragmentDefault = options.UDPFragmentDefault
	// Both version option objects can affect fallback, including programmatic
	// options that intentionally differ from the active JSON variant.
	clone.HTTP2Options = cloneHTTP2Options(options.HTTP2Options)
	clone.HTTP3Options = options.HTTP3Options
	clone.HTTP3Options.HTTP2Options = cloneHTTP2Options(options.HTTP3Options.HTTP2Options)
	return clone, nil
}

func cloneHTTP2Options(options option.HTTP2Options) option.HTTP2Options {
	if options.StreamReceiveWindow != nil {
		value := *options.StreamReceiveWindow
		options.StreamReceiveWindow = &value
	}
	if options.ConnectionReceiveWindow != nil {
		value := *options.ConnectionReceiveWindow
		options.ConnectionReceiveWindow = &value
	}
	return options
}

func NewManager(ctx context.Context, logger log.ContextLogger, clients []option.HTTPClient, defaultHTTPClient string) *Manager {
	m := &Manager{ctx: ctx, logger: logger, defines: make(map[string]option.HTTPClient), sharedTransports: make(map[string]*sharedManagedTransport), defaultTag: defaultHTTPClient}
	m.source, _ = adapter.RuntimeResourceSourceFromContext(ctx)
	m.fence = outbound.NewRuntimeIOFence(m.closeOwned)
	m.admitOwned, m.setupErr = outbound.RegisterRuntimeOwnedFence(ctx, m.fence)
	for _, client := range clients {
		copy, err := cloneHTTPClientOptions(ctx, client.Options())
		if err != nil {
			m.setupErr = errors.Join(m.setupErr, err)
			continue
		}
		copy.Tag = client.Tag
		m.defines[client.Tag] = option.HTTPClient(copy)
	}
	if m.defaultTag == "" && len(clients) > 0 {
		m.defaultTag = clients[0].Tag
	}
	if adapter.HasConstructionScope(ctx) {
		m.constructionOwned = true
		m.setupErr = errors.Join(m.setupErr, adapter.DeferConstructionCleanup(ctx, m.RuntimeCloseAndWait))
	}
	return m
}

func (m *Manager) Initialize(fallback func() (*ManagedTransport, error)) {
	m.access.Lock()
	defer m.access.Unlock()
	if m.closed || m.frozen {
		m.setupErr = errors.Join(m.setupErr, errors.New("HTTP manager initialization is sealed"))
		return
	}
	m.defaultTransportFallback = fallback
}
func (m *Manager) Name() string { return "http-client" }

// PrepareRuntime performs configuration construction only. No RoundTrip, dial,
// periodic producer or live-manager mutation occurs here. The caller already
// bound its candidate outbound/DNS/network registry and construction scope.
func (m *Manager) PrepareRuntime(fallback func() (*ManagedTransport, error)) error {
	if fallback != nil {
		m.Initialize(fallback)
	}
	m.access.Lock()
	err := m.setupErr
	closed := m.closed
	tags := make([]string, 0, len(m.defines))
	for tag := range m.defines {
		tags = append(tags, tag)
	}
	m.access.Unlock()
	if err != nil {
		return err
	}
	if closed {
		return net.ErrClosed
	}
	for _, tag := range tags {
		if _, err = m.resolveShared(m.ctx, tag); err != nil {
			return err
		}
	}
	if _, err = m.resolveDefault(); err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	if m.closed {
		return net.ErrClosed
	}
	m.prepared = true
	return nil
}

func (m *Manager) FreezeRuntime() error {
	m.access.Lock()
	defer m.access.Unlock()
	if m.closed {
		return net.ErrClosed
	}
	if m.setupErr != nil {
		return m.setupErr
	}
	if !m.prepared {
		return errors.New("HTTP manager has not been prepared")
	}
	m.frozen = true
	return nil
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if err := m.PrepareRuntime(nil); err != nil {
		return err
	}
	if !m.constructionOwned {
		scope.Add(m.RuntimeCloseAndWait)
	}
	return m.FreezeRuntime()
}

func (m *Manager) begin(ctx context.Context) (context.Context, func(), error) {
	m.access.Lock()
	setupErr := m.setupErr
	m.access.Unlock()
	if setupErr != nil {
		return nil, nil, setupErr
	}
	ctx, release, err := adapter.AcquireRuntimeOperation(ctx, m.source)
	if err != nil {
		return nil, nil, err
	}
	leave, err := m.fence.Acquire()
	if err != nil {
		release()
		return nil, nil, err
	}
	return ctx, func() { leave(); release() }, nil
}

func (m *Manager) DefaultTransport() adapter.HTTPTransport {
	shared, err := m.resolveDefault()
	if err != nil {
		return rejectingHTTPTransport{err: err}
	}
	return newSharedRef(shared.managed, shared.shared)
}

func (m *Manager) resolveDefault() (*sharedManagedTransport, error) {
	m.access.Lock()
	if m.closed {
		m.access.Unlock()
		return nil, net.ErrClosed
	}
	existing, tag, fallback := m.defaultTransport, m.defaultTag, m.defaultTransportFallback
	m.access.Unlock()
	if existing != nil {
		return existing, nil
	}
	if tag != "" {
		shared, err := m.resolveShared(m.ctx, tag)
		if err != nil {
			return nil, err
		}
		m.access.Lock()
		if !m.closed {
			m.defaultTransport = shared
		}
		closed := m.closed
		m.access.Unlock()
		if closed {
			return nil, net.ErrClosed
		}
		return shared, nil
	}
	if fallback == nil {
		return nil, errors.New("no default HTTP transport configured")
	}
	_, release, err := m.begin(m.ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	transport, err := fallback()
	if err != nil {
		return nil, err
	}
	shared := &sharedManagedTransport{managed: transport, shared: &sharedState{}}
	m.access.Lock()
	if m.closed {
		m.access.Unlock()
		m.recordClose(transport.RuntimeCloseAndWait())
		return nil, net.ErrClosed
	}
	if m.defaultTransport != nil {
		existing = m.defaultTransport
		m.access.Unlock()
		m.recordClose(transport.RuntimeCloseAndWait())
		return existing, nil
	}
	m.defaultTransport = shared
	m.managedTransports = append(m.managedTransports, transport)
	m.access.Unlock()
	return shared, nil
}

func (m *Manager) ResolveTransport(ctx context.Context, logger logger.ContextLogger, options option.HTTPClientOptions) (adapter.HTTPTransport, error) {
	owned, release, err := m.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if options.Tag != "" && !options.ResolveOnDetour {
		shared, err := m.resolveShared(owned, options.Tag)
		if err != nil {
			return nil, err
		}
		return newSharedRef(shared.managed, shared.shared), nil
	}
	if options.Tag != "" {
		m.access.Lock()
		define, ok := m.defines[options.Tag]
		m.access.Unlock()
		if !ok {
			return nil, E.New("http_client not found: ", options.Tag)
		}
		tag := options.Tag
		options = define.Options()
		options.Tag = tag
		options.ResolveOnDetour = true
	}
	// Preserve the candidate registry and receiving source, borrowing only the
	// caller's admitted ownership capabilities for this construction interval.
	transport, err := newManagedTransport(adapter.ContextWithRuntimeOwnership(m.ctx, owned), logger, options.Tag, options, m.admitOwned)
	if err != nil {
		return nil, err
	}
	if err = m.trackTransport(transport); err != nil {
		return nil, err
	}
	return transport, nil
}

func (m *Manager) trackTransport(t *ManagedTransport) error {
	m.access.Lock()
	if m.closed {
		m.access.Unlock()
		err := t.RuntimeCloseAndWait()
		m.recordClose(err)
		return errors.Join(net.ErrClosed, err)
	}
	m.managedTransports = append(m.managedTransports, t)
	m.access.Unlock()
	return nil
}

func (m *Manager) resolveShared(ctx context.Context, tag string) (*sharedManagedTransport, error) {
	owned, release, err := m.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	m.access.Lock()
	existing := m.sharedTransports[tag]
	define, ok := m.defines[tag]
	m.access.Unlock()
	if existing != nil {
		return existing, nil
	}
	if !ok {
		return nil, E.New("http_client not found: ", tag)
	}
	transport, err := newManagedTransport(adapter.ContextWithRuntimeOwnership(m.ctx, owned), m.logger, tag, define.Options(), m.admitOwned)
	if err != nil {
		return nil, E.Cause(err, "create shared http_client[", tag, "]")
	}
	shared := &sharedManagedTransport{managed: transport, shared: &sharedState{}}
	m.access.Lock()
	if m.closed {
		m.access.Unlock()
		m.recordClose(transport.RuntimeCloseAndWait())
		return nil, net.ErrClosed
	}
	if existing = m.sharedTransports[tag]; existing != nil {
		m.access.Unlock()
		m.recordClose(transport.RuntimeCloseAndWait())
		return existing, nil
	}
	m.sharedTransports[tag] = shared
	m.managedTransports = append(m.managedTransports, transport)
	m.access.Unlock()
	return shared, nil
}

func (m *Manager) ResetNetwork() {
	_, release, err := m.begin(m.ctx)
	if err != nil {
		return
	}
	defer release()
	m.access.Lock()
	transports := append([]*ManagedTransport(nil), m.managedTransports...)
	m.access.Unlock()
	for _, transport := range transports {
		transport.Reset()
	}
}

func (m *Manager) recordClose(err error) {
	if err == nil {
		return
	}
	m.access.Lock()
	m.closeErr = errors.Join(m.closeErr, err)
	m.access.Unlock()
}

func (m *Manager) closeOwned() error {
	m.access.Lock()
	m.closed = true
	transports := append([]*ManagedTransport(nil), m.managedTransports...)
	m.access.Unlock()
	for _, transport := range transports {
		transport.StopRuntimeOperations()
	}
	for _, transport := range transports {
		m.recordClose(transport.RuntimeCloseAndWait())
	}
	return nil
}
func (m *Manager) close() error { return m.RuntimeCloseAndWait() }
func (m *Manager) RuntimeCloseAndWait() error {
	err := m.fence.RuntimeCloseAndWait()
	m.access.Lock()
	defer m.access.Unlock()
	if m.closeErr != nil {
		return E.New("HTTP manager cleanup incomplete: ", errors.Join(err, m.closeErr))
	}
	return err
}

func (m *Manager) References() []string {
	m.access.Lock()
	transports := append([]*ManagedTransport(nil), m.managedTransports...)
	m.access.Unlock()
	var refs []string
	needDefault := false
	for _, t := range transports {
		if t.detour != "" {
			refs = append(refs, t.detour)
		} else if t.defaultOutbound {
			needDefault = true
		}
	}
	if needDefault {
		manager := service.FromContext[adapter.OutboundManager](m.ctx)
		if manager != nil {
			if outbound := manager.Default(); outbound != nil {
				refs = append(refs, outbound.Tag())
			}
		}
	}
	return refs
}

type rejectingHTTPTransport struct{ err error }

func (t rejectingHTTPTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, t.err }
func (rejectingHTTPTransport) CloseIdleConnections()                             {}
func (rejectingHTTPTransport) Reset()                                            {}

// Final shutdown cancels work without waiting on the callback stack that may
// request it. RuntimeCloseAndWait remains the sole completion certificate.
func (m *Manager) StopRuntimeOperations() {
	m.stopOnce.Do(func() { go func() { _ = m.fence.Close() }() })
}

// RuntimePreparedTransport borrows an already constructed transport only. A
// retained graph caller may use it for immutable source preparation without
// appending transports or resolving a new dependency into the live manager.
func (m *Manager) RuntimePreparedTransport(tag string) (adapter.HTTPTransport, error) {
	m.access.Lock()
	defer m.access.Unlock()
	if !m.frozen || m.closed {
		return nil, errors.New("HTTP transport inventory is not active and frozen")
	}
	var shared *sharedManagedTransport
	if tag == "" {
		shared = m.defaultTransport
	} else {
		shared = m.sharedTransports[tag]
	}
	if shared == nil {
		return nil, errors.New("requested HTTP transport was not prepared in the retained graph")
	}
	return shared.managed, nil
}
