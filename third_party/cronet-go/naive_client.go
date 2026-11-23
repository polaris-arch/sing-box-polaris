package cronet

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

var _ N.Dialer = (*NaiveClient)(nil)

type QUICCongestionControl string

const (
	QUICCongestionControlDefault QUICCongestionControl = ""
	QUICCongestionControlBBR     QUICCongestionControl = "TBBR"
	QUICCongestionControlBBRv2   QUICCongestionControl = "B2ON"
	// QUICHE selects Cubic on the QBIC tag only when the quic_default_to_bbr
	// reloadable flag is set, and Chromium builds it with that flag false; CQBC
	// is the client-only tag QuicSentPacketManager honors unconditionally.
	QUICCongestionControlCubic QUICCongestionControl = "CQBC"
	QUICCongestionControlReno  QUICCongestionControl = "RENO"
)

type clientState uint32

const (
	clientStateCreated clientState = iota
	clientStateDormant
	clientStateStarting
	clientStateRunning
	clientStateSealed
	clientStateClosing
	clientStateClosed
)

type NaiveClient struct {
	state                    atomic.Uint32
	lifecycle                sync.Mutex
	pending                  sync.WaitGroup
	callbacks                sync.WaitGroup
	nativeOperations         int
	onIdle                   func()
	reserveEngines           func(context.Context, int) (func(int), error)
	releaseEngines           func(int)
	closed                   chan struct{}
	closeError               error
	startError               error
	connections              map[*BidirectionalConn]struct{}
	ctx                      context.Context
	dialer                   N.Dialer
	logger                   logger.ContextLogger
	server                   *NaiveServer
	registry                 *NaiveServerRegistry
	concurrency              int
	receiveWindow            uint64
	trustedRootCertificates  string
	dnsResolver              DNSResolverFunc
	echEnabled               bool
	testForceUDPLoopback     bool
	quicEnabled              bool
	quicCongestionControl    QUICCongestionControl
	quicSessionReceiveWindow uint64
	counter                  atomic.Uint64
	started                  chan struct{}
	singleEngine             bool
	engines                  []Engine
	streamEngines            []StreamEngine
	activeConnections        sync.WaitGroup
	proxyWaitGroup           sync.WaitGroup
	proxyCancel              context.CancelFunc
}

// NaiveServer is the identity of one proxy server: the URL and headers of its
// streams and the DNS answers its engine resolves for it.
type NaiveServer struct {
	address            M.Socksaddr
	name               string
	url                string
	authorization      string
	extraHeaders       map[string]string
	echConfigList      []byte
	echQueryServerName string
	echMutex           sync.RWMutex
	registry           *NaiveServerRegistry
	entry              *naiveServerEntry
	isolationKey       string
	keep               bool
}

// Registries answer server names with addresses from this reserved block:
// never a real server, the in-process DNS server or a fake-IP pool.
var naiveSyntheticPrefix = netip.MustParsePrefix("240.0.0.0/4")

// NaiveServerRegistry lets clients with equal engine options share one engine
// across servers. Their DNS answers each registered server name with a unique
// synthetic address, from which their dial callbacks recover the real server.
// A registry outlives the clients created with it.
type NaiveServerRegistry struct {
	access    sync.Mutex
	names     map[string]*naiveServerEntry
	addresses map[netip.Addr]*naiveServerEntry
	sequence  uint32
}

// One resolution and connection context per registered server name.
type naiveServerEntry struct {
	server     *NaiveServer
	address    netip.Addr
	servers    int
	keeps      int
	streams    int
	relay      context.Context
	closeRelay context.CancelFunc
}

func naiveServerKey(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// Register adds a server for streams of clients created with this registry.
// A name already registered with another address or ECH setting is rejected;
// the caller keeps that server on a dedicated client.
func (r *NaiveServerRegistry) Register(config NaiveClientOptions) (*NaiveServer, error) {
	server, err := newNaiveServer(config)
	if err != nil {
		return nil, err
	}
	for key := range server.extraHeaders {
		// Chromium reads its control headers case-insensitively, so one server
		// could otherwise replace the isolation key of every stream it opens.
		if key == "" || key[0] == '-' || key[0] == ':' || strings.EqualFold(key, "host") {
			return nil, E.New("reserved header on shared server: ", key)
		}
	}
	name := naiveServerKey(server.name)
	r.access.Lock()
	defer r.access.Unlock()
	if r.sequence == 1<<28-2 {
		return nil, E.New("server registry exhausted")
	}
	r.sequence++
	entry := r.names[name]
	if entry == nil {
		// Chromium dials an IP literal host without DNS.
		address, err := netip.ParseAddr(name)
		if err != nil {
			address = netip.AddrFrom4([4]byte{240 | byte(r.sequence>>24), byte(r.sequence >> 16), byte(r.sequence >> 8), byte(r.sequence)})
		} else if naiveSyntheticPrefix.Contains(address) {
			return nil, E.New("reserved server address: ", address)
		}
		if r.names == nil {
			r.names = make(map[string]*naiveServerEntry)
			r.addresses = make(map[netip.Addr]*naiveServerEntry)
		}
		entry = &naiveServerEntry{server: server, address: address}
		entry.relay, entry.closeRelay = context.WithCancel(context.Background())
		r.names[name] = entry
		r.addresses[address] = entry
	} else if !strings.EqualFold(entry.server.address.AddrString(), server.address.AddrString()) ||
		naiveServerKey(entry.server.echQueryServerName) != naiveServerKey(server.echQueryServerName) || !bytes.Equal(entry.server.echConfigList, server.echConfigList) {
		return nil, E.New("server name ", server.name, " is registered with another address or ECH setting")
	}
	entry.servers++
	entry.keeps++
	server.registry = r
	server.entry = entry
	server.isolationKey = F.ToString("n", r.sequence)
	server.keep = true
	return server, nil
}

// Close unregisters the server. Its name stays registered until its last
// stream ends.
func (s *NaiveServer) Close() {
	s.registry.access.Lock()
	defer s.registry.access.Unlock()
	entry := s.entry
	if entry == nil {
		return
	}
	s.entry = nil
	entry.servers--
	if s.keep {
		entry.keeps--
	}
	s.registry.closeIdleLocked(entry, false)
}

// SetKeep sets whether idle connections stay open. Without keep, they close
// when the last stream ends. Servers with one name share their connections.
func (s *NaiveServer) SetKeep(keep bool) {
	s.registry.access.Lock()
	defer s.registry.access.Unlock()
	if s.entry == nil || s.keep == keep {
		return
	}
	s.keep = keep
	if keep {
		s.entry.keeps++
		return
	}
	s.entry.keeps--
	s.registry.closeIdleLocked(s.entry, false)
}

// CloseIdleConnections closes the connections of servers with this name
// unless they have an active stream.
func (s *NaiveServer) CloseIdleConnections() {
	s.registry.access.Lock()
	defer s.registry.access.Unlock()
	if s.entry != nil {
		s.registry.closeIdleLocked(s.entry, true)
	}
}

func (r *NaiveServerRegistry) closeIdleLocked(entry *naiveServerEntry, explicit bool) {
	if entry.streams != 0 || (entry.keeps != 0 && !explicit) {
		return
	}
	entry.closeRelay()
	if entry.servers == 0 {
		delete(r.names, naiveServerKey(entry.server.name))
		delete(r.addresses, entry.address)
	} else {
		entry.relay, entry.closeRelay = context.WithCancel(context.Background())
	}
}

func (r *NaiveServerRegistry) finishStream(entry *naiveServerEntry) {
	r.access.Lock()
	defer r.access.Unlock()
	entry.streams--
	r.closeIdleLocked(entry, false)
}

func (r *NaiveServerRegistry) wrapDNSResolver(resolver DNSResolverFunc, echEnabled bool, quicEnabled bool, l logger.ContextLogger) DNSResolverFunc {
	return func(ctx context.Context, request *mDNS.Msg) *mDNS.Msg {
		if len(request.Question) > 0 {
			question := request.Question[0]
			name := naiveServerKey(question.Name)
			if strings.HasPrefix(name, "_") {
				if _, serverName, found := strings.Cut(name, "._https."); found {
					name = serverName
				}
			}
			r.access.Lock()
			entry := r.names[name]
			r.access.Unlock()
			if entry != nil {
				switch question.Qtype {
				case mDNS.TypeA, mDNS.TypeAAAA:
					return synthesizeAddressResponse(request, entry.address)
				case mDNS.TypeHTTPS:
					if echEnabled {
						server := entry.server
						return wrapDNSResolverWithECH(resolver, server.name, server.echQueryServerName, server.getECHConfigList, quicEnabled, l)(ctx, request)
					}
				}
			}
		}
		return resolver(ctx, request)
	}
}

// relay maps a dialed address to its registered server and derives the
// physical connection's context, canceled with the server's connections.
func (r *NaiveServerRegistry) relay(ctx context.Context, destination M.Socksaddr) (context.Context, context.CancelFunc, M.Socksaddr, error) {
	r.access.Lock()
	entry := r.addresses[destination.Addr]
	var serverRelay context.Context
	if entry != nil {
		serverRelay = entry.relay
		port := destination.Port
		destination = entry.server.address
		destination.Port = port
	}
	r.access.Unlock()
	if entry == nil && naiveSyntheticPrefix.Contains(destination.Addr) {
		return nil, nil, destination, E.New("unregistered server address")
	}
	relayContext, relayCancel := context.WithCancel(ctx)
	if entry == nil {
		return relayContext, relayCancel, destination, nil
	}
	stop := context.AfterFunc(serverRelay, relayCancel)
	return relayContext, func() { stop(); relayCancel() }, destination, nil
}

type NaiveClientOptions struct {
	Context                  context.Context
	ServerAddress            M.Socksaddr
	ServerName               string
	Username                 string
	Password                 string
	InsecureConcurrency      int
	ReceiveWindow            uint64
	ExtraHeaders             map[string]string
	TrustedRootCertificates  string
	DNSResolver              DNSResolverFunc
	Logger                   logger.ContextLogger
	Dialer                   N.Dialer
	ECHEnabled               bool
	ECHConfigList            []byte
	ECHQueryServerName       string
	TestForceUDPLoopback     bool
	TestForceSingleEngine    bool
	QUIC                     bool
	QUICCongestionControl    QUICCongestionControl
	QUICSessionReceiveWindow uint64

	// OnIdle may run on a native callback thread and must not block on Close.
	OnIdle func()
	// ReserveEngines optionally reserves count engine slots atomically. An
	// error leaves the client retryable. On success, release returns slots
	// in one or more calls as unused slots or destroyed engines are freed.
	// Both callbacks must be nonblocking and may run under the lifecycle lock.
	ReserveEngines func(ctx context.Context, count int) (release func(int), err error)
	// Registry shares the engine across its servers, which open streams with
	// DialServerEarly. Its physical dials complete after the dial callback.
	Registry *NaiveServerRegistry
}

func NewNaiveClient(config NaiveClientOptions) (*NaiveClient, error) {
	err := checkLibrary()
	if err != nil {
		return nil, err
	}
	server, err := newNaiveServer(config)
	if err != nil {
		return nil, err
	}
	if config.DNSResolver == nil {
		return nil, E.New("DNSResolver is required")
	}

	concurrency := config.InsecureConcurrency
	if concurrency < 1 {
		concurrency = 1
	}

	ctx := config.Context
	if ctx == nil {
		ctx = context.Background()
	}

	dialer := config.Dialer
	if dialer == nil {
		dialer = N.SystemDialer
	}

	l := config.Logger
	if l == nil {
		l = logger.NOP()
	}

	return &NaiveClient{
		ctx:                      ctx,
		dialer:                   dialer,
		logger:                   l,
		server:                   server,
		registry:                 config.Registry,
		concurrency:              concurrency,
		trustedRootCertificates:  config.TrustedRootCertificates,
		dnsResolver:              config.DNSResolver,
		echEnabled:               config.ECHEnabled,
		testForceUDPLoopback:     config.TestForceUDPLoopback,
		singleEngine:             config.TestForceSingleEngine || runtime.GOOS == "ios",
		quicEnabled:              config.QUIC,
		quicCongestionControl:    config.QUICCongestionControl,
		receiveWindow:            config.ReceiveWindow,
		quicSessionReceiveWindow: config.QUICSessionReceiveWindow,
		started:                  make(chan struct{}),
		closed:                   make(chan struct{}),
		connections:              make(map[*BidirectionalConn]struct{}),
		onIdle:                   config.OnIdle,
		reserveEngines:           config.ReserveEngines,
	}, nil
}

func newNaiveServer(config NaiveClientOptions) (*NaiveServer, error) {
	if !config.ServerAddress.IsValid() {
		return nil, E.New("invalid server address")
	}

	serverName := config.ServerName
	if serverName == "" {
		serverName = config.ServerAddress.AddrString()
	}

	serverURL := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(serverName, F.ToString(config.ServerAddress.Port)),
	}

	var authorization string
	if config.Username != "" {
		authorization = "Basic " + base64.StdEncoding.EncodeToString(
			[]byte(config.Username+":"+config.Password))
	}

	echQueryServerName := config.ECHQueryServerName
	if echQueryServerName == "" {
		echQueryServerName = serverName
	}

	return &NaiveServer{
		address:            config.ServerAddress,
		name:               serverName,
		url:                serverURL.String(),
		authorization:      authorization,
		extraHeaders:       config.ExtraHeaders,
		echConfigList:      config.ECHConfigList,
		echQueryServerName: echQueryServerName,
	}, nil
}

// Start starts a new or prepared client without waiting for its first dial.
func (c *NaiveClient) Start() error {
	return c.start(c.ctx, false)
}

// StartOnDemand validates custom roots before the first dial starts the engine.
func (c *NaiveClient) StartOnDemand(ctx context.Context) error {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	if state := clientState(c.state.Load()); state != clientStateCreated {
		return startStateError(state)
	}
	if c.trustedRootCertificates != "" {
		var release func(int)
		if c.reserveEngines != nil {
			var err error
			release, err = c.reserveEngines(ctx, 1)
			if err != nil {
				return err
			}
		}
		valid := c.validateTrustedRoots()
		if release != nil {
			release(1)
		}
		if !valid {
			c.startError = E.New("failed to set trusted CA certificates")
			c.state.Store(uint32(clientStateClosed))
			close(c.started)
			close(c.closed)
			return c.startError
		}
	}
	c.state.Store(uint32(clientStateDormant))
	return nil
}

func (c *NaiveClient) validateTrustedRoots() bool {
	// An unstarted engine owns the verifier. Create and destroy it on
	// the same OS thread, as required by Cronet's thread checker.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	engine := NewEngine()
	defer engine.Destroy()
	return engine.SetTrustedRootCertificates(c.trustedRootCertificates)
}

func (c *NaiveClient) IsDormant() bool {
	return clientState(c.state.Load()) == clientStateDormant
}

func startStateError(state clientState) error {
	switch state {
	case clientStateDormant, clientStateStarting:
		return errors.New("start already in progress")
	case clientStateRunning:
		return errors.New("already started")
	default:
		return net.ErrClosed
	}
}

func (c *NaiveClient) start(ctx context.Context, onDemand bool) (startResult error) {
	c.lifecycle.Lock()
	state := clientState(c.state.Load())
	if onDemand && state != clientStateDormant {
		// The first dial owns startup. Other dials wait on started.
		c.lifecycle.Unlock()
		return nil
	}
	if state != clientStateCreated && state != clientStateDormant {
		c.lifecycle.Unlock()
		return startStateError(state)
	}
	engineCount := 1
	if c.concurrency > 1 && !c.singleEngine {
		engineCount = c.concurrency
	}
	if c.reserveEngines != nil {
		release, err := c.reserveEngines(ctx, engineCount)
		if err != nil {
			c.lifecycle.Unlock()
			return err
		}
		c.releaseEngines = release
	}
	c.state.Store(uint32(clientStateStarting))
	c.lifecycle.Unlock()

	var startError error
	var engines []Engine

	defer func() {
		if startError != nil {
			if c.releaseEngines != nil && len(engines) < engineCount {
				c.releaseEngines(engineCount - len(engines))
			}
			c.lifecycle.Lock()
			c.startError = startError
			c.state.Store(uint32(clientStateClosing))
			c.engines = engines
			close(c.started)
			c.lifecycle.Unlock()
			// Start owns unwind. Concurrent Close waits for this same completion.
			startResult = errors.Join(startResult, c.doClose())
		}
	}()

	proxyContext, proxyCancel := context.WithCancel(c.ctx)
	c.proxyCancel = proxyCancel

	dnsServerAddress := M.ParseSocksaddrHostPort("127.0.0.1", 53)
	dnsResolver := c.dnsResolver

	if c.registry != nil {
		dnsResolver = c.registry.wrapDNSResolver(dnsResolver, c.echEnabled, c.quicEnabled, c.logger)
	} else {
		if c.server.name != c.server.address.AddrString() {
			dnsResolver = wrapDNSResolverForServerRedirect(dnsResolver, c.server.name, c.server.address)
		}

		if c.echEnabled {
			dnsResolver = wrapDNSResolverWithECH(dnsResolver, c.server.name, c.server.echQueryServerName, c.server.getECHConfigList, c.quicEnabled, c.logger)
		}
	}

	tcpDialer := Dialer(func(address string, port uint16) int {
		if !c.beginCallback() {
			return NetErrorConnectionFailed.Code()
		}
		defer c.finishOperation(&c.callbacks)
		if address == dnsServerAddress.AddrString() && port == dnsServerAddress.Port {
			fd, conn, err := createSocketPair()
			if err != nil {
				c.logger.ErrorContext(c.ctx, "socket pair failed: ", err)
				return NetErrorConnectionFailed.Code()
			}

			c.proxyWaitGroup.Add(1)
			go func() {
				defer c.proxyWaitGroup.Done()
				_ = serveDNSStreamConn(proxyContext, conn, dnsResolver)
			}()

			return fd
		}

		destination := M.ParseSocksaddrHostPort(address, port)
		if c.registry != nil {
			relayContext, relayCancel, server, err := c.registry.relay(proxyContext, destination)
			if err != nil {
				c.logger.ErrorContext(c.ctx, "open TCP connection to ", destination, ": ", err)
				return NetErrorConnectionFailed.Code()
			}
			fd, pipeConn, err := createSocketPair()
			if err != nil {
				c.logger.ErrorContext(c.ctx, "socket pair failed: ", err)
				relayCancel()
				return NetErrorConnectionFailed.Code()
			}
			// The network thread serves every server: dial after returning.
			c.proxyWaitGroup.Add(1)
			go func() {
				defer c.proxyWaitGroup.Done()
				defer relayCancel()
				defer pipeConn.Close()
				c.logger.DebugContext(c.ctx, "open TCP connection to ", server)
				conn, err := c.dialer.DialContext(relayContext, N.NetworkTCP, server)
				if err != nil {
					c.logger.ErrorContext(c.ctx, "open TCP connection to ", server, ": ", err)
					return
				}
				bufio.CopyConn(relayContext, conn, pipeConn)
				conn.Close()
			}()
			return fd
		}
		c.logger.DebugContext(c.ctx, "open TCP connection to ", destination)
		conn, err := c.dialer.DialContext(proxyContext, N.NetworkTCP, destination)
		if err != nil {
			c.logger.ErrorContext(c.ctx, "open TCP connection to ", destination, ": ", err)
			return toNetError(err).Code()
		}

		if tcpConn, ok := N.CastReader[*net.TCPConn](conn); ok {
			fd, duplicateError := dupSocketFD(tcpConn)
			if duplicateError == nil {
				conn.Close()
				return fd
			}
		}

		c.logger.DebugContext(c.ctx, "relaying TCP connection to ", destination)
		fd, pipeConn, err := createSocketPair()
		if err != nil {
			c.logger.ErrorContext(c.ctx, "socket pair failed: ", err)
			conn.Close()
			return NetErrorConnectionFailed.Code()
		}

		c.proxyWaitGroup.Add(1)
		go func() {
			defer c.proxyWaitGroup.Done()
			bufio.CopyConn(proxyContext, conn, pipeConn)
			conn.Close()
			pipeConn.Close()
		}()

		return fd
	})

	udpDialer := UDPDialer(func(address string, port uint16) (fd int, localAddress string, localPort uint16, onClose func()) {
		if !c.beginCallback() {
			return NetErrorConnectionFailed.Code(), "", 0, nil
		}
		defer c.finishOperation(&c.callbacks)
		if address == dnsServerAddress.AddrString() && port == dnsServerAddress.Port {
			fd, conn, err := createPacketSocketPair(c.testForceUDPLoopback)
			if err != nil {
				c.logger.ErrorContext(c.ctx, "socket pair failed: ", err)
				return NetErrorConnectionFailed.Code(), "", 0, nil
			}
			localAddr := M.SocksaddrFromNet(conn.LocalAddr())
			if localAddr.IsValid() {
				localAddress = localAddr.AddrString()
				localPort = localAddr.Port
			}

			dnsContext, dnsCancel := context.WithCancel(proxyContext)
			c.proxyWaitGroup.Add(1)
			go func() {
				defer c.proxyWaitGroup.Done()
				defer dnsCancel()
				_ = serveDNSPacketConn(dnsContext, conn, dnsResolver)
			}()

			return fd, localAddress, localPort, dnsCancel
		}

		destination := M.ParseSocksaddrHostPort(address, port)
		if c.registry != nil {
			relayContext, relayCancel, server, err := c.registry.relay(proxyContext, destination)
			if err != nil {
				c.logger.ErrorContext(c.ctx, "open UDP connection to ", destination, ": ", err)
				return NetErrorConnectionFailed.Code(), "", 0, nil
			}
			fd, pipeConn, err := createPacketSocketPair(c.testForceUDPLoopback)
			if err != nil {
				c.logger.ErrorContext(c.ctx, "socket pair failed: ", err)
				relayCancel()
				return NetErrorConnectionFailed.Code(), "", 0, nil
			}
			// The real local address is unknown before the dial; Cronet only
			// reports this one back as the socket's own.
			localAddr := M.SocksaddrFromNet(pipeConn.LocalAddr())
			if localAddr.IsValid() {
				localAddress = localAddr.AddrString()
				localPort = localAddr.Port
			}
			c.proxyWaitGroup.Add(1)
			go func() {
				defer c.proxyWaitGroup.Done()
				defer relayCancel()
				c.logger.DebugContext(c.ctx, "open UDP connection to ", server)
				conn, err := c.dialer.DialContext(relayContext, N.NetworkUDP, server)
				if err != nil {
					c.logger.ErrorContext(c.ctx, "open UDP connection to ", server, ": ", err)
					pipeConn.Close()
					return
				}
				remoteAddress := M.SocksaddrFromNet(conn.RemoteAddr())
				_ = bufio.CopyPacketConn(relayContext, bufio.NewUnbindPacketConn(conn), bufio.NewUnbindPacketConnWithAddr(pipeConn.(net.Conn), remoteAddress))
			}()
			return fd, localAddress, localPort, relayCancel
		}
		c.logger.DebugContext(c.ctx, "open UDP connection to ", destination)
		conn, err := c.dialer.DialContext(proxyContext, N.NetworkUDP, destination)
		if err != nil {
			c.logger.ErrorContext(c.ctx, "open UDP connection to ", destination, ": ", err)
			return toNetError(err).Code(), "", 0, nil
		}

		localAddr := M.SocksaddrFromNet(conn.LocalAddr())
		if localAddr.IsValid() {
			localAddress = localAddr.AddrString()
			localPort = localAddr.Port
		}

		if udpConn, ok := N.CastReader[*net.UDPConn](conn); ok {
			fd, duplicateError := dupSocketFD(udpConn)
			if duplicateError == nil {
				conn.Close()
				return fd, localAddress, localPort, nil
			}
		}

		c.logger.DebugContext(c.ctx, "relaying UDP connection to ", destination)
		fd, pipeConn, err := createPacketSocketPair(c.testForceUDPLoopback)
		if err != nil {
			c.logger.ErrorContext(c.ctx, "socket pair failed: ", err)
			conn.Close()
			return NetErrorConnectionFailed.Code(), "", 0, nil
		}

		remoteAddress := M.SocksaddrFromNet(conn.RemoteAddr())
		packetConn := bufio.NewUnbindPacketConn(conn)
		pipePacketConn := bufio.NewUnbindPacketConnWithAddr(pipeConn.(net.Conn), remoteAddress)

		relayContext, relayCancel := context.WithCancel(proxyContext)
		c.proxyWaitGroup.Add(1)
		go func() {
			defer c.proxyWaitGroup.Done()
			defer relayCancel()
			_ = bufio.CopyPacketConn(relayContext, packetConn, pipePacketConn)
		}()

		return fd, localAddress, localPort, relayCancel
	})

	for i := 0; i < engineCount; i++ {
		var engine Engine
		engine, startError = c.startEngine(tcpDialer, udpDialer, dnsServerAddress)
		engines = append(engines, engine)
		if startError != nil {
			return startError
		}
	}

	c.engines = engines
	c.streamEngines = common.Map(engines, Engine.StreamEngine)

	c.lifecycle.Lock()
	c.state.Store(uint32(clientStateRunning))
	close(c.started)
	c.lifecycle.Unlock()
	if version := c.Version(); version != "" {
		c.logger.Info("NaiveProxy started, version: ", version)
	}
	return nil
}

func (c *NaiveClient) startEngine(tcpDialer Dialer, udpDialer UDPDialer, dnsServerAddress M.Socksaddr) (Engine, error) {
	engine := NewEngine()

	if c.trustedRootCertificates != "" {
		if !engine.SetTrustedRootCertificates(c.trustedRootCertificates) {
			return engine, E.New("failed to set trusted CA certificates")
		}
	}

	engine.SetDialer(tcpDialer)
	engine.SetUDPDialer(udpDialer)

	params := NewEngineParams()
	if c.quicEnabled {
		params.SetEnableQuic(true)
	} else {
		params.SetEnableQuic(false)
		params.SetEnableHTTP2(true)
	}

	paramsError := params.SetAsyncDNS(true)
	if paramsError == nil {
		paramsError = params.SetDNSServerOverride([]string{dnsServerAddress.String()})
	}
	if paramsError == nil {
		paramsError = params.SetUseDnsHttpsSvcb(c.echEnabled)
	}
	if paramsError == nil {
		if c.quicEnabled {
			streamReceiveWindow := c.receiveWindow
			sessionReceiveWindow := c.quicSessionReceiveWindow
			if runtime.GOOS == "ios" {
				// Same receive backlog bound as the HTTP/2 default below.
				if streamReceiveWindow == 0 {
					streamReceiveWindow = 2 * 1024 * 1024
				}
				if sessionReceiveWindow == 0 {
					sessionReceiveWindow = 4 * 1024 * 1024
				}
			}
			if streamReceiveWindow == 0 {
				streamReceiveWindow = 6 * 1024 * 1024
			}
			if sessionReceiveWindow == 0 {
				sessionReceiveWindow = 15 * 1024 * 1024
			}
			paramsError = params.SetQUICOptions("", string(c.quicCongestionControl), streamReceiveWindow, sessionReceiveWindow)
		} else {
			receiveWindow := c.receiveWindow
			if receiveWindow == 0 {
				if runtime.GOOS == "ios" {
					receiveWindow = 4 * 1024 * 1024
				} else {
					receiveWindow = 128 * 1024 * 1024
				}
			}
			paramsError = params.SetHTTP2Options(receiveWindow, receiveWindow/2)
		}
	}
	if paramsError == nil {
		paramsError = params.SetSocketPoolOptions(2048, 2048, 2040)
	}
	if paramsError != nil {
		params.Destroy()
		return engine, paramsError
	}

	result := engine.StartWithParams(params)
	params.Destroy()
	if result != ResultSuccess {
		return engine, E.New("failed to start engine: ", int(result))
	}
	return engine, nil
}

// Engine returns a borrowed raw handle. Callers must externally exclude Close
// for its entire use; prefer guarded client operations such as Version.
func (c *NaiveClient) Engine() Engine {
	if clientState(c.state.Load()) != clientStateRunning {
		return Engine{}
	}
	return c.engines[0]
}

func (c *NaiveClient) Version() string {
	if !c.beginOperation() {
		return ""
	}
	defer c.finishOperation(&c.pending)
	return c.engines[0].Version()
}

func (c *NaiveClient) CloseAllConnections() {
	c.closeAllConnections(Engine.CloseAllConnections)
}

func (c *NaiveClient) closeAllConnections(closeConnections func(Engine)) {
	if !c.beginOperation() {
		return
	}
	defer c.finishOperation(&c.pending)
	for _, engine := range c.engines {
		closeConnections(engine)
	}
}

func (c *NaiveClient) DialEarly(ctx context.Context, destination M.Socksaddr) (NaiveConn, error) {
	return c.dialEarly(ctx, c.server, "", destination, StreamEngine.CreateConn, (*BidirectionalConn).Start)
}

// DialServerEarly opens a stream through a server registered with the
// client's registry. Streams carry the server's isolation key, n1, n2 and so
// on; a nonempty isolationKey, another single DNS label, replaces it so that
// the stream shares no connection or cached state with other keys.
func (c *NaiveClient) DialServerEarly(ctx context.Context, server *NaiveServer, isolationKey string, destination M.Socksaddr) (NaiveConn, error) {
	return c.dialEarly(ctx, server, isolationKey, destination, StreamEngine.CreateConn, (*BidirectionalConn).Start)
}

// The function arguments are the exact native operations in production and
// deterministic barriers in source tests. No process-global mutable test hooks.
func (c *NaiveClient) dialEarly(ctx context.Context, server *NaiveServer, isolationKey string, destination M.Socksaddr,
	createConn func(StreamEngine, context.Context, logger.ContextLogger, bool, bool) *BidirectionalConn,
	startConn func(*BidirectionalConn, string, string, map[string]string, int, bool) error,
) (NaiveConn, error) {
	if server.registry != c.registry {
		return nil, E.New("server is not registered with the client registry")
	}
	state := clientState(c.state.Load())
	if state == clientStateDormant {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := c.ctx.Err(); err != nil {
			return nil, err
		}
		if err := c.start(ctx, true); err != nil {
			return nil, err
		}
		state = clientState(c.state.Load())
	}
	if state < clientStateRunning {
		select {
		case <-c.started:
			state = clientState(c.state.Load())
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.ctx.Done():
			return nil, c.ctx.Err()
		}
	}
	if state != clientStateRunning {
		// A terminal startup error is published before the closing state.
		if c.startError != nil {
			return nil, errors.Join(net.ErrClosed, c.startError)
		}
		return nil, net.ErrClosed
	}
	if !c.beginOperation() {
		return nil, net.ErrClosed
	}
	defer c.finishOperation(&c.pending)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	headers := map[string]string{
		"-connect-authority": destination.String(),
		"Padding":            generatePaddingHeader(),
	}
	if server.authorization != "" {
		headers["proxy-authorization"] = server.authorization
	}
	if c.quicEnabled {
		headers["-force-quic"] = "true"
	}
	for key, value := range server.extraHeaders {
		headers[key] = value
	}

	streamEngine := c.streamEngines[0]
	if isolationKey == "" {
		isolationKey = server.isolationKey
	}
	if c.concurrency > 1 {
		concurrencyIndex := int(c.counter.Add(1) % uint64(c.concurrency))
		if len(c.streamEngines) > 1 {
			streamEngine = c.streamEngines[concurrencyIndex]
		} else {
			if isolationKey == "" {
				isolationKey = "pool"
			}
			isolationKey = F.ToString(isolationKey, "-", concurrencyIndex)
		}
	}
	if isolationKey != "" {
		// Sessions, TLS resumption, Alt-Svc and host cache are keyed by it.
		headers["-network-isolation-key"] = F.ToString("https://", isolationKey, ":443")
	}
	var entry *naiveServerEntry
	if c.registry != nil {
		c.registry.access.Lock()
		entry = server.entry
		if entry != nil {
			entry.streams++
		}
		c.registry.access.Unlock()
		if entry == nil {
			return nil, net.ErrClosed
		}
	}
	conn := createConn(streamEngine, ctx, c.logger, true, false)
	c.trackConnection(conn, entry)
	err := startConn(conn, "CONNECT", server.url, headers, 0, false)
	if err != nil {
		return nil, err
	}
	trackedConn := &trackedNaiveConn{
		NaiveConn: NewNaiveConn(ctx, conn, c.logger),
	}
	return trackedConn, nil
}

func (c *NaiveClient) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, os.ErrInvalid
	}
	conn, err := c.DialEarly(ctx, destination)
	if err != nil {
		return nil, err
	}
	err = conn.HandshakeContext(ctx)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *NaiveClient) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (c *NaiveClient) Close() error {
	for {
		c.lifecycle.Lock()
		switch clientState(c.state.Load()) {
		case clientStateCreated, clientStateDormant:
			c.state.Store(uint32(clientStateClosed))
			close(c.started)
			close(c.closed)
			c.lifecycle.Unlock()
			return nil
		case clientStateStarting:
			// Start owns initialization and failure unwind. This waits for true
			// completion; it does not promise cancellation-bounded startup.
			c.lifecycle.Unlock()
			<-c.started
			continue
		case clientStateRunning, clientStateSealed:
			c.state.Store(uint32(clientStateClosing))
			c.lifecycle.Unlock()
			return c.doClose()
		default:
			c.lifecycle.Unlock()
			<-c.closed
			return c.closeError
		}
	}
}

func (c *NaiveClient) doClose() error {
	if c.proxyCancel != nil {
		c.proxyCancel()
	}
	// Both admission gates were sealed under lifecycle before reaching here.
	// No lock is held over native calls, callbacks, response waits or joins.
	c.pending.Wait()
	c.callbacks.Wait()
	c.lifecycle.Lock()
	connections := make([]*BidirectionalConn, 0, len(c.connections))
	for conn := range c.connections {
		connections = append(connections, conn)
	}
	c.lifecycle.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
	for _, engine := range c.engines {
		engine.CloseAllConnections()
	}
	c.proxyWaitGroup.Wait()
	c.activeConnections.Wait()
	var closeError error
	for _, engine := range c.engines {
		closeError = errors.Join(closeError, shutdownNaiveEngine(engine.Shutdown, engine.Destroy, c.releaseEngines))
	}
	c.lifecycle.Lock()
	c.closeError = closeError
	c.state.Store(uint32(clientStateClosed))
	close(c.closed)
	c.lifecycle.Unlock()
	return closeError
}

func (s *NaiveServer) getECHConfigList() []byte {
	s.echMutex.RLock()
	defer s.echMutex.RUnlock()
	return s.echConfigList
}

type trackedNaiveConn struct {
	NaiveConn
}

func (c *trackedNaiveConn) Upstream() any {
	return c.NaiveConn
}

func (c *trackedNaiveConn) ReaderReplaceable() bool {
	return true
}

func (c *trackedNaiveConn) WriterReplaceable() bool {
	return true
}
