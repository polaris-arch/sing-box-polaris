package hysteria2

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing-quic/hysteria"
	hyCC "github.com/sagernet/sing-quic/hysteria/congestion"
	"github.com/sagernet/sing-quic/hysteria2/internal/protocol"
	"github.com/sagernet/sing-quic/hysteria2/realm"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

const defaultHandshakeTimeout = 15 * time.Second

type ClientOptions struct {
	Context            context.Context
	Dialer             N.Dialer
	Logger             logger.Logger
	BrutalDebug        bool
	ServerAddress      M.Socksaddr
	ServerPorts        []string
	HopInterval        time.Duration
	HopIntervalMax     time.Duration
	SendBPS            uint64
	ReceiveBPS         uint64
	SalamanderPassword string
	GeckoPassword      string
	GeckoMinPacketSize int
	GeckoMaxPacketSize int
	Password           string
	TLSConfig          aTLS.Config
	QUICOptions        qtls.QUICOptions
	UDPDisabled        bool
	BBRProfile         string
	ChromeParrot       bool
	RealmOptions       *realm.Options
}

type Client struct {
	runtime clientRuntime

	ctx                context.Context
	dialer             N.Dialer
	logger             logger.Logger
	brutalDebug        bool
	serverAddr         M.Socksaddr
	serverPorts        []uint16
	hopInterval        time.Duration
	hopIntervalMax     time.Duration
	sendBPS            uint64
	receiveBPS         uint64
	salamanderPassword string
	geckoPassword      string
	geckoMinPacketSize int
	geckoMaxPacketSize int
	password           string
	tlsConfig          aTLS.Config
	quicConfig         *quic.Config
	udpDisabled        bool
	bbrProfile         congestion_meta2.Profile
	realmOptions       *realm.Options
	controlClient      *realm.ControlClient
	realmHooks         *realmClientHooks

	connAccess sync.Mutex
	conn       *clientQUICConnection
	closeIdle  atomic.Bool
	pending    *clientOffer
}

func NewClient(options ClientOptions) (*Client, error) {
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:                !options.UDPDisabled,
		InitialStreamReceiveWindow:     hysteria.DefaultStreamReceiveWindow,
		MaxStreamReceiveWindow:         hysteria.DefaultStreamReceiveWindow,
		InitialConnectionReceiveWindow: hysteria.DefaultConnReceiveWindow,
		MaxConnectionReceiveWindow:     hysteria.DefaultConnReceiveWindow,
		MaxIdleTimeout:                 hysteria.DefaultMaxIdleTimeout,
		KeepAlivePeriod:                hysteria.DefaultKeepAlivePeriod,
		ChromeParrot:                   options.ChromeParrot,
	}
	qtls.ApplyQUICOptions(quicConfig, options.QUICOptions)
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	bbrProfile := congestion_meta2.ProfileStandard
	if options.BBRProfile != "" {
		var err error
		bbrProfile, err = congestion_meta2.ParseProfile(options.BBRProfile)
		if err != nil {
			return nil, err
		}
	}
	if options.RealmOptions != nil {
		if len(options.ServerPorts) > 0 {
			return nil, E.New("realm and port hopping are mutually exclusive")
		}
		if options.RealmOptions.IPVersion != 0 && options.RealmOptions.IPVersion != 4 && options.RealmOptions.IPVersion != 6 {
			return nil, E.New("invalid IP version: ", options.RealmOptions.IPVersion)
		}
		if options.RealmOptions.IPVersion == 6 && options.RealmOptions.PortMapping != nil {
			return nil, E.New("port mapping requires IPv4")
		}
	}
	if options.GeckoPassword != "" {
		if options.GeckoMinPacketSize == 0 {
			options.GeckoMinPacketSize = geckoDefaultMinPacketSize
		}
		if options.GeckoMaxPacketSize == 0 {
			options.GeckoMaxPacketSize = geckoDefaultMaxPacketSize
		}
		if options.GeckoMinPacketSize <= 0 || options.GeckoMinPacketSize > options.GeckoMaxPacketSize || options.GeckoMaxPacketSize > geckoMaxOnWireSize {
			return nil, E.New("gecko: invalid packet size range")
		}
	}
	if options.RealmOptions != nil {
		copyOptions := *options.RealmOptions
		copyOptions.STUNServers = slices.Clone(options.RealmOptions.STUNServers)
		if options.RealmOptions.PortMapping != nil {
			mapping := *options.RealmOptions.PortMapping
			if mapping.Resolver == nil {
				mapping.Resolver = options.RealmOptions.Resolver
			}
			if mapping.HTTPClient != nil {
				mappingHTTP := *mapping.HTTPClient
				if mappingHTTP.Transport == nil {
					return nil, E.New("realm port mapping requires explicit captured HTTP transport")
				}
				mapping.HTTPClient = &mappingHTTP
			}
			copyOptions.PortMapping = &mapping
		}
		options.RealmOptions = &copyOptions
	}
	var serverPorts []uint16
	if len(options.ServerPorts) > 0 {
		var err error
		serverPorts, err = hysteria.ParsePorts(options.ServerPorts)
		if err != nil {
			return nil, err
		}
	}
	client := &Client{
		ctx:                options.Context,
		dialer:             options.Dialer,
		logger:             options.Logger,
		brutalDebug:        options.BrutalDebug,
		serverAddr:         options.ServerAddress,
		serverPorts:        serverPorts,
		hopInterval:        options.HopInterval,
		hopIntervalMax:     options.HopIntervalMax,
		sendBPS:            options.SendBPS,
		receiveBPS:         options.ReceiveBPS,
		salamanderPassword: options.SalamanderPassword,
		geckoPassword:      options.GeckoPassword,
		geckoMinPacketSize: options.GeckoMinPacketSize,
		geckoMaxPacketSize: options.GeckoMaxPacketSize,
		password:           options.Password,
		tlsConfig:          options.TLSConfig,
		quicConfig:         quicConfig,
		udpDisabled:        options.UDPDisabled,
		bbrProfile:         bbrProfile,
		realmOptions:       options.RealmOptions,
	}
	client.initRuntime()
	if options.RealmOptions != nil {
		clientHTTP := options.RealmOptions.HTTPClient
		if clientHTTP == nil {
			clientHTTP = http.DefaultClient
		}
		capturedHTTP := *clientHTTP
		transport := capturedHTTP.Transport
		if transport == nil {
			transport = http.DefaultTransport
		}
		capturedHTTP.Transport = &realmOwnedHTTPTransport{transport: transport, runtime: &client.runtime}
		client.realmOptions.HTTPClient = &capturedHTTP
		if mapping := client.realmOptions.PortMapping; mapping != nil && mapping.HTTPClient != nil {
			mapping.HTTPClient.Transport = &realmOwnedHTTPTransport{transport: mapping.HTTPClient.Transport, runtime: &client.runtime}
		}
		var err error
		client.controlClient, err = realm.NewControlClient(options.RealmOptions.ServerURL, options.RealmOptions.Token, &capturedHTTP)
		if err != nil {
			return nil, errors.Join(E.Cause(err, "create control client"), client.RuntimeCloseAndWait())
		}
	}
	return client, nil
}

func (c *Client) offer(ctx context.Context) (*clientQUICConnection, error) {
	c.connAccess.Lock()
	if c.runtime.closed.Load() {
		c.connAccess.Unlock()
		return nil, net.ErrClosed
	}
	conn := c.conn
	if conn != nil && conn.active() {
		c.connAccess.Unlock()
		return conn, nil
	}
	pending := c.pending
	if pending != nil {
		c.connAccess.Unlock()
		select {
		case <-pending.done:
			return pending.conn, pending.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	// A pending offer is shared by concurrent callers. Do not derive offerCtx
	// from the foreground request ctx: a timed-out request must stop waiting for
	// the shared result, but it must not tear down the background QUIC dial that
	// may still be reused by later requests. The connection attempt is owned by
	// the client lifetime context instead.
	offerCtx := c.ctx
	if offerCtx == nil {
		offerCtx = context.Background()
	}
	offerCtx, cancel := context.WithCancelCause(offerCtx)
	pending = &clientOffer{
		done:   make(chan struct{}),
		cancel: cancel,
	}
	c.pending = pending
	c.connAccess.Unlock()

	if !c.runtime.run(func() { c.completeOffer(pending, offerCtx) }) {
		pending.cancel(net.ErrClosed)
		c.connAccess.Lock()
		pending.err = net.ErrClosed
		if c.pending == pending {
			c.pending = nil
		}
		close(pending.done)
		c.connAccess.Unlock()
	}

	select {
	case <-pending.done:
		return pending.conn, pending.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Client) offerWithStream(ctx context.Context) (*clientQUICConnection, error) {
	for {
		conn, err := c.offer(ctx)
		if err != nil {
			return nil, err
		}
		if conn.acquireStream() {
			return conn, nil
		}
	}
}

func (c *Client) completeOffer(pending *clientOffer, offerCtx context.Context) {
	conn, err := c.offerNew(offerCtx)
	pending.cancel(nil)

	discardErr := err
	shouldDiscard := false
	c.connAccess.Lock()
	if pending.discarded {
		shouldDiscard = true
		if pending.cause != nil {
			discardErr = pending.cause
		}
		pending.err = discardErr
	} else {
		pending.conn = conn
		pending.err = err
		if err == nil {
			c.conn = conn
		}
	}
	if c.pending == pending {
		c.pending = nil
	}
	close(pending.done)
	c.connAccess.Unlock()

	if shouldDiscard && conn != nil {
		conn.closeWithError(discardErr)
	}
}

func (c *Client) offerNew(ctx context.Context) (*clientQUICConnection, error) {
	if c.realmOptions != nil {
		return c.offerNewRealm(ctx)
	}
	dialCtx := ctx
	hopCtx := c.ctx
	if hopCtx == nil {
		hopCtx = context.Background()
	}
	hopCtx, cancelHop := context.WithCancel(hopCtx)
	hopAdopted := false
	defer func() {
		if !hopAdopted {
			cancelHop()
		}
	}()
	firstDial := true
	dialFunc := func(serverAddr M.Socksaddr) (net.Conn, error) {
		currentCtx := hopCtx
		if firstDial {
			// The initial socket open belongs to the shared offer. Later port hops
			// belong to the live client connection and must outlive any one caller.
			currentCtx = dialCtx
			firstDial = false
		}
		udpConn, err := c.dialer.DialContext(currentCtx, "udp", serverAddr)
		if err != nil {
			return nil, err
		}
		if c.geckoPassword == "" && c.salamanderPassword == "" {
			return udpConn, nil
		}
		if c.geckoPassword != "" {
			return NewGeckoClientConn(udpConn, []byte(c.geckoPassword), c.geckoMinPacketSize, c.geckoMaxPacketSize), nil
		}
		return NewSalamanderClientConn(udpConn, []byte(c.salamanderPassword)), nil
	}
	var (
		rawConn net.Conn
		err     error
	)
	if len(c.serverPorts) == 0 {
		rawConn, err = dialFunc(c.serverAddr)
		if err != nil {
			return nil, err
		}
		if c.geckoPassword != "" || c.salamanderPassword != "" {
			qtls.SetDesiredBufferSizes(rawConn)
		}
	} else {
		rawConn, err = hysteria.NewHopConn(dialFunc, c.serverAddr, c.serverPorts, c.hopInterval, c.hopIntervalMax)
		if err != nil {
			return nil, err
		}
	}
	rawConn = &clientCancelableConn{Conn: rawConn, cancel: cancelHop}
	hopAdopted = true
	return c.authenticateAndWrap(ctx, rawConn, func(quicConnPtr **quic.Conn) (http.RoundTripper, error) {
		return qtls.CreateTransport(rawConn, quicConnPtr, c.tlsConfig, c.quicConfig)
	})
}

type realmFamilyConn struct {
	family         string
	ipv4           bool
	conn           net.PacketConn
	localAddresses []netip.AddrPort
}

func (c *Client) offerNewRealm(ctx context.Context) (resultConn *clientQUICConnection, resultErr error) {
	families, err := c.realmOpenFamilies(ctx)
	if err != nil {
		return nil, err
	}
	session := &clientRealmSession{client: c, families: families}
	adopted := false
	defer func() {
		if !adopted {
			resultErr = errors.Join(resultErr, session.Close())
		}
	}()
	var mappedFamily *realmFamilyConn
	joinMapperPrepare := func() {}
	if c.realmOptions.PortMapping != nil {
		for _, family := range families {
			if !family.ipv4 {
				continue
			}
			// Establish the IPv4 pinhole before STUN, preserving double-NAT
			// discovery semantics. The renewal belongs to this session already.
			var mapper realmPortMapper
			var mapErr error
			port := M.SocksaddrFromNet(family.conn.LocalAddr()).Port
			if c.realmHooks != nil && c.realmHooks.newMapper != nil {
				mapper, mapErr = c.realmHooks.newMapper(ctx, port, *c.realmOptions.PortMapping)
			} else {
				var nativeMapper *realm.PortMapper
				nativeMapper, mapErr = realm.NewPortMapper(ctx, c.logger, port, *c.realmOptions.PortMapping)
				if nativeMapper != nil {
					mapper = nativeMapper
				}
			}
			if mapErr != nil {
				var incomplete interface{ RuntimeCleanupIncomplete() bool }
				if errors.As(mapErr, &incomplete) && incomplete.RuntimeCleanupIncomplete() {
					c.runtime.recordClose(mapErr)
				}
				if mapper != nil {
					cleanupErr := mapper.Close()
					c.runtime.recordClose(cleanupErr)
					mapErr = errors.Join(mapErr, cleanupErr)
				}
				c.logger.Warn(E.Cause(mapErr, "port mapping unavailable; continuing without it"))
			} else if mapper == nil {
				return nil, errors.New("port mapper returned no mapping")
			} else {
				if err = session.startMapper(mapper); err != nil {
					return nil, err
				}
				joinMapperPrepare = linkRealmOfferCancellation(ctx, session.mapperCancel)
				defer joinMapperPrepare()
				mappedFamily = family
			}
			break
		}
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	surviving, localAddresses, err := c.realmDiscoverFamilies(ctx, families)
	if err != nil {
		return nil, err
	}
	if session.mapper != nil && slices.Contains(surviving, mappedFamily) {
		externalAddr := session.mapper.ExternalAddr()
		if !slices.Contains(localAddresses, externalAddr) {
			localAddresses = append(localAddresses, externalAddr)
		}
	} else if err = session.stopMapper(); err != nil {
		return nil, err
	}
	localMetadata, err := realm.GeneratePunchMetadata()
	if err != nil {
		return nil, E.Cause(err, "generate punch metadata")
	}
	response, err := c.controlClient.Connect(ctx, c.realmOptions.RealmID, localAddresses, localMetadata)
	if err != nil {
		return nil, E.Cause(err, "realm connect")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	winner, punchResult, err := c.realmRacePunch(ctx, surviving, response.Addresses, response.PunchMetadata)
	if err != nil {
		return nil, err
	}
	if winner != mappedFamily {
		if err = session.stopMapper(); err != nil {
			return nil, err
		}
	}
	packetConn := winner.conn
	if c.geckoPassword != "" || c.salamanderPassword != "" {
		qtls.SetDesiredBufferSizes(packetConn)
	}
	if c.geckoPassword != "" {
		packetConn = NewGeckoConn(packetConn, []byte(c.geckoPassword), c.geckoMinPacketSize, c.geckoMaxPacketSize)
	} else if c.salamanderPassword != "" {
		packetConn = NewSalamanderConn(packetConn, []byte(c.salamanderPassword))
	}
	packetConn = &realmSessionPacketConn{PacketConn: packetConn, session: session}
	peerAddr := M.SocksaddrFromNetIP(punchResult.PeerAddr)
	var conn *clientQUICConnection
	if c.realmHooks != nil && c.realmHooks.authenticate != nil {
		conn, err = c.realmHooks.authenticate(ctx, packetConn, peerAddr.UDPAddr())
	} else {
		conn, err = c.authenticateAndWrap(ctx, packetConn, func(quicConnPtr **quic.Conn) (http.RoundTripper, error) {
			return qtls.CreatePacketTransport(packetConn, peerAddr.UDPAddr(), quicConnPtr, c.tlsConfig, c.quicConfig)
		})
	}
	if err != nil {
		return nil, err
	}
	joinMapperPrepare()
	if err = ctx.Err(); err != nil {
		conn.closeWithError(err)
		return nil, err
	}
	adopted = true
	return conn, nil
}

func (c *Client) realmOpenFamilies(ctx context.Context) ([]*realmFamilyConn, error) {
	specs := []struct {
		family string
		ipv4   bool
		addr   M.Socksaddr
	}{
		{"v4", true, M.SocksaddrFrom(netip.IPv4Unspecified(), 0)},
		{"v6", false, M.SocksaddrFrom(netip.IPv6Unspecified(), 0)},
	}
	switch c.realmOptions.IPVersion {
	case 4:
		specs = specs[:1]
	case 6:
		specs = specs[1:]
	}
	conns := make([]*realmFamilyConn, len(specs))
	listenErrs := make([]error, len(specs))
	var wg sync.WaitGroup
	for i, spec := range specs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, listenErr := c.dialer.ListenPacket(ctx, spec.addr)
			if conn != nil {
				conn = &realmOwnedPacketConn{PacketConn: conn, runtime: &c.runtime}
			}
			if ctx.Err() != nil {
				listenErr = errors.Join(listenErr, ctx.Err())
			}
			if listenErr != nil || conn == nil {
				if conn != nil {
					listenErr = errors.Join(listenErr, conn.Close())
				}
				if listenErr == nil {
					listenErr = errors.New("Realm listener returned no carrier")
				}
				listenErrs[i] = E.Cause(listenErr, spec.family)
				return
			}
			conns[i] = &realmFamilyConn{family: spec.family, ipv4: spec.ipv4, conn: conn}
		}()
	}
	wg.Wait()
	var families []*realmFamilyConn
	var errs []error
	for i, family := range conns {
		if family != nil {
			families = append(families, family)
			continue
		}
		errs = append(errs, listenErrs[i])
	}
	if len(families) == 0 || ctx.Err() != nil {
		return nil, errors.Join(E.Cause(E.Errors(errs...), "listen UDP for realm"), ctx.Err(), closeRealmFamilies(families))
	}
	return families, nil
}

func (c *Client) realmDiscoverFamilies(ctx context.Context, families []*realmFamilyConn) ([]*realmFamilyConn, []netip.AddrPort, error) {
	var needIPv4, needIPv6 bool
	for _, family := range families {
		if family.ipv4 {
			needIPv4 = true
		} else {
			needIPv6 = true
		}
	}
	stunServers, err := realm.ResolveSTUNServers(ctx, c.realmOptions.STUNServers, c.realmOptions.Resolver, needIPv4, needIPv6)
	if err != nil {
		return nil, nil, errors.Join(E.Cause(err, "resolve STUN servers"), closeRealmFamilies(families))
	}
	type discoverResult struct {
		addrs []netip.AddrPort
		err   error
	}
	results := make([]discoverResult, len(families))
	var wg sync.WaitGroup
	for i, family := range families {
		wg.Add(1)
		go func() {
			defer wg.Done()
			servers := make([]netip.AddrPort, 0, len(stunServers))
			for _, server := range stunServers {
				if server.Addr().Is4() == family.ipv4 {
					servers = append(servers, server)
				}
			}
			addrs, discoverErr := c.realmDiscover(ctx, family.conn, servers)
			results[i] = discoverResult{addrs: addrs, err: discoverErr}
		}()
	}
	wg.Wait()
	var surviving []*realmFamilyConn
	var union []netip.AddrPort
	var errs []error
	var cleanupErr error
	for i, family := range families {
		result := results[i]
		if result.err != nil {
			errs = append(errs, E.Cause(result.err, family.family))
			cleanupErr = errors.Join(cleanupErr, family.conn.Close())
			continue
		}
		family.localAddresses = result.addrs
		surviving = append(surviving, family)
		union = append(union, result.addrs...)
	}
	if len(surviving) == 0 || ctx.Err() != nil || cleanupErr != nil {
		return nil, nil, errors.Join(E.Cause(E.Errors(errs...), "realm STUN discovery"), ctx.Err(), cleanupErr, closeRealmFamilies(surviving))
	}
	return surviving, union, nil
}

func (c *Client) realmRacePunch(
	ctx context.Context,
	families []*realmFamilyConn,
	peerAddresses []netip.AddrPort,
	metadata realm.PunchMetadata,
) (*realmFamilyConn, realm.PunchResult, error) {
	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()
	type outcome struct {
		family *realmFamilyConn
		result realm.PunchResult
		err    error
	}
	out := make(chan outcome, len(families))
	for _, family := range families {
		go func() {
			peers := make([]netip.AddrPort, 0, len(peerAddresses))
			for _, peer := range peerAddresses {
				if !peer.IsValid() {
					continue
				}
				peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
				if peer.Addr().Is4() == family.ipv4 {
					peers = append(peers, peer)
				}
			}
			punchResult, punchErr := c.realmPunch(raceCtx, family.conn, peers, metadata)
			out <- outcome{family: family, result: punchResult, err: punchErr}
		}()
	}
	var errs []error
	var winner *realmFamilyConn
	var winnerResult realm.PunchResult
	var cleanupErr error
	for pending := len(families); pending > 0; pending-- {
		result := <-out
		if winner == nil && result.err == nil && ctx.Err() == nil {
			winner, winnerResult = result.family, result.result
			raceCancel()
			// Interrupt every losing native read before waiting for any late
			// punch result. The channel is drained below: no detached losers.
			var losers []*realmFamilyConn
			for _, family := range families {
				if family != winner {
					losers = append(losers, family)
				}
			}
			cleanupErr = errors.Join(cleanupErr, closeRealmFamilies(losers))
		} else if result.err != nil {
			errs = append(errs, E.Cause(result.err, result.family.family))
		}
	}
	if winner != nil && ctx.Err() == nil && cleanupErr == nil {
		return winner, winnerResult, nil
	}
	return nil, realm.PunchResult{}, errors.Join(E.Cause(E.Errors(errs...), "realm punch"), ctx.Err(), cleanupErr, closeRealmFamilies(families))
}

func (c *Client) authenticateAndWrap(ctx context.Context, rawConn io.Closer, createTransport func(quicConnPtr **quic.Conn) (http.RoundTripper, error)) (*clientQUICConnection, error) {
	var quicConn *quic.Conn
	http3Transport, err := createTransport(&quicConn)
	if err != nil {
		return nil, c.closeFailedAuthentication(rawConn, http3Transport, quicConn, nil, err)
	}
	request := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: "https",
			Host:   protocol.URLHost,
			Path:   protocol.URLPath,
		},
		Header: make(http.Header),
	}
	protocol.AuthRequestToHeader(request.Header, protocol.AuthRequest{Auth: c.password, Rx: c.receiveBPS})
	handshakeTimeout := c.tlsConfig.HandshakeTimeout()
	if handshakeTimeout <= 0 {
		handshakeTimeout = defaultHandshakeTimeout
	}
	authCtx, authCancel := context.WithTimeout(ctx, handshakeTimeout)
	defer authCancel()
	response, err := http3Transport.RoundTrip(request.WithContext(authCtx))
	var body io.ReadCloser
	if response != nil && response.Body != nil {
		body = newRealmHTTPBody(authCtx, response.Body, &c.runtime)
		response.Body = body
	}
	if err != nil {
		return nil, c.closeFailedAuthentication(rawConn, http3Transport, quicConn, body, err)
	}
	if response == nil || body == nil {
		return nil, c.closeFailedAuthentication(rawConn, http3Transport, quicConn, body, errors.New("authentication returned no response body"))
	}
	if closeErr := body.Close(); closeErr != nil {
		return nil, c.closeFailedAuthentication(rawConn, http3Transport, quicConn, nil, c.runtime.recordClose(closeErr))
	}
	if response.StatusCode != protocol.StatusAuthOK {
		return nil, c.closeFailedAuthentication(rawConn, http3Transport, quicConn, nil, E.New("authentication failed, status code: ", response.StatusCode))
	}
	if quicConn == nil {
		return nil, c.closeFailedAuthentication(rawConn, http3Transport, nil, nil, errors.New("authentication returned no QUIC connection"))
	}
	authResponse := protocol.AuthResponseFromHeader(response.Header)
	actualTx := authResponse.Rx
	if actualTx == 0 || actualTx > c.sendBPS {
		actualTx = c.sendBPS
	}
	if !authResponse.RxAuto && actualTx > 0 {
		quicConn.SetCongestionControl(hyCC.NewBrutalSender(actualTx, quicConn.InitialPacketSize(), c.brutalDebug, c.logger))
	} else {
		quicConn.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(
			quicConn.InitialPacketSize(),
			c.bbrProfile,
		))
	}
	conn := &clientQUICConnection{
		quicConn:      quicConn,
		rawConn:       rawConn,
		httpTransport: http3Transport,
		connDone:      make(chan struct{}),
		udpDisabled:   !authResponse.UDPEnabled,
		udpConnMap:    make(map[uint32]*udpPacketConn),
		closeIdle:     &c.closeIdle,
	}
	c.runtime.register(conn)
	if !c.udpDisabled {
		c.runConnectionTask(conn, func() { c.loopMessages(conn) })
	}
	c.runConnectionTask(conn, func() {
		<-quicConn.Context().Done()
		conn.closeWithError(context.Cause(quicConn.Context()))
	})
	return conn, nil
}

func (c *Client) DialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.offerWithStream(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.quicConn.OpenStream()
	if err != nil {
		conn.releaseStream(false)
		return nil, err
	}
	return &clientConn{
		Stream:      stream,
		parent:      conn,
		destination: destination,
		keepSession: qtls.KeepSessionFromContext(ctx),
	}, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if c.udpDisabled {
		return nil, os.ErrInvalid
	}
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	if conn.udpDisabled {
		return nil, E.New("UDP disabled by server")
	}
	var sessionID uint32
	clientPacketConn := newUDPPacketConn(c.ctx, conn.quicConn, func() {
		conn.releaseUDPSession(sessionID)
	})
	conn.access.Lock()
	select {
	case <-conn.connDone:
		conn.access.Unlock()
		return nil, E.Errors(conn.connErr, os.ErrClosed)
	default:
	}
	sessionID = conn.udpSessionID
	conn.udpSessionID++
	conn.udpConnMap[sessionID] = clientPacketConn
	conn.access.Unlock()
	clientPacketConn.sessionID = sessionID
	return clientPacketConn, nil
}

func (c *Client) CloseWithError(err error) error {
	c.connAccess.Lock()
	conn := c.conn
	c.conn = nil
	pending := c.pending
	if pending != nil {
		pending.discarded = true
		pending.cause = err
	}
	c.connAccess.Unlock()

	if pending != nil {
		pending.cancel(err)
	}
	if conn != nil {
		conn.closeWithError(err)
		conn.closeTransport()
		return conn.transportErr
	}
	return nil
}

func (c *Client) SetKeepIdleConnections(keep bool) {
	c.closeIdle.Store(!keep)
	if !keep {
		c.CloseIdleConnections()
	}
}

func (c *Client) CloseIdleConnections() {
	c.connAccess.Lock()
	conn := c.conn
	c.connAccess.Unlock()
	if conn == nil {
		return
	}
	conn.access.Lock()
	closed := conn.streams == 0 && len(conn.udpConnMap) == 0 && conn.markClosedLocked(os.ErrClosed)
	conn.access.Unlock()
	if closed {
		conn.closeTransport()
	}
}

type clientOffer struct {
	done      chan struct{}
	cancel    func(error)
	conn      *clientQUICConnection
	err       error
	discarded bool
	cause     error
}

type clientQUICConnection struct {
	runtimeOwner  *clientRuntime
	transportOnce sync.Once
	transportErr  error

	quicConn      *quic.Conn
	rawConn       io.Closer
	httpTransport http.RoundTripper
	connDone      chan struct{}
	connErr       error
	udpDisabled   bool
	access        sync.RWMutex
	udpConnMap    map[uint32]*udpPacketConn
	udpSessionID  uint32
	streams       int
	closeIdle     *atomic.Bool
}

func (c *clientQUICConnection) active() bool {
	select {
	case <-c.quicConn.Context().Done():
		return false
	default:
	}
	select {
	case <-c.connDone:
		return false
	default:
	}
	return true
}

func (c *clientQUICConnection) acquireStream() bool {
	c.access.Lock()
	defer c.access.Unlock()
	select {
	case <-c.connDone:
		return false
	default:
	}
	c.streams++
	return true
}

func (c *clientQUICConnection) releaseStream(keepSession bool) {
	c.access.Lock()
	c.streams--
	closed := c.closeIdle.Load() && !keepSession && c.streams == 0 && len(c.udpConnMap) == 0 && c.markClosedLocked(os.ErrClosed)
	c.access.Unlock()
	if closed {
		c.closeTransport()
	}
}

func (c *clientQUICConnection) releaseUDPSession(sessionID uint32) {
	c.access.Lock()
	delete(c.udpConnMap, sessionID)
	closed := c.closeIdle.Load() && c.streams == 0 && len(c.udpConnMap) == 0 && c.markClosedLocked(os.ErrClosed)
	c.access.Unlock()
	if closed {
		c.closeTransport()
	}
}

func (c *clientQUICConnection) markClosedLocked(err error) bool {
	select {
	case <-c.connDone:
		return false
	default:
	}
	c.connErr = err
	close(c.connDone)
	return true
}

func (c *clientQUICConnection) closeWithError(err error) {
	c.access.Lock()
	if !c.markClosedLocked(err) {
		c.access.Unlock()
		return
	}
	udpConnMap := c.udpConnMap
	c.udpConnMap = make(map[uint32]*udpPacketConn)
	c.access.Unlock()
	c.closeTransport()
	for _, udpConn := range udpConnMap {
		udpConn.closeWithError(err)
	}
}

func (c *clientQUICConnection) closeTransport() {
	c.transportOnce.Do(func() {
		var closers []func() error
		if c.quicConn != nil {
			closers = append(closers, func() error { return c.quicConn.CloseWithError(0, "") })
		}
		if closer, ok := c.httpTransport.(io.Closer); ok {
			closers = append(closers, closer.Close)
		}
		if c.rawConn != nil {
			closers = append(closers, c.rawConn.Close)
		}
		c.transportErr = joinClientClosers(closers...)
		if c.runtimeOwner != nil {
			c.runtimeOwner.retire(c, c.transportErr)
		}
	})
}

type clientConn struct {
	*quic.Stream
	parent         *clientQUICConnection
	destination    M.Socksaddr
	keepSession    bool
	requestWritten bool
	responseRead   bool
	closeOnce      sync.Once
}

func (c *clientConn) NeedHandshake() bool {
	return !c.requestWritten
}

func (c *clientConn) Read(p []byte) (n int, err error) {
	if c.responseRead {
		n, err = c.Stream.Read(p)
		return n, qtls.WrapError(err)
	}
	status, errorMessage, err := protocol.ReadTCPResponse(c.Stream)
	if err != nil {
		return 0, qtls.WrapError(err)
	}
	if !status {
		err = E.New("remote error: ", errorMessage)
		return
	}
	c.responseRead = true
	n, err = c.Stream.Read(p)
	return n, qtls.WrapError(err)
}

func (c *clientConn) Write(p []byte) (n int, err error) {
	if !c.requestWritten {
		buffer := protocol.WriteTCPRequest(c.destination.String(), p)
		defer buffer.Release()
		_, err = c.Stream.Write(buffer.Bytes())
		if err != nil {
			return
		}
		c.requestWritten = true
		return len(p), nil
	}
	n, err = c.Stream.Write(p)
	return n, qtls.WrapError(err)
}

func (c *clientConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) Close() error {
	c.Stream.CancelRead(0)
	err := c.Stream.Close()
	// quic-go's Stream.Close does not unblock a Write blocked on flow control,
	// but a past write deadline does; buffered data and the FIN are unaffected.
	c.Stream.SetWriteDeadline(time.Now())
	c.closeOnce.Do(func() { c.parent.releaseStream(c.keepSession) })
	return err
}
