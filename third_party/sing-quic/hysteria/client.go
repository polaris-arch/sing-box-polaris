package hysteria

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	qtls "github.com/sagernet/sing-quic"
	hyCC "github.com/sagernet/sing-quic/hysteria/congestion"
	"github.com/sagernet/sing/common/debug"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type ClientOptions struct {
	Context       context.Context
	Dialer        N.Dialer
	Logger        logger.Logger
	BrutalDebug   bool
	ServerAddress M.Socksaddr
	ServerPorts   []string
	HopInterval   time.Duration
	SendBPS       uint64
	ReceiveBPS    uint64
	XPlusPassword string
	Password      string
	TLSConfig     aTLS.Config
	QUICOptions   qtls.QUICOptions
	UDPDisabled   bool

	ProbeAdmission *qtls.ClientProbeAdmission
}

type Client struct {
	runtime clientRuntime

	ctx           context.Context
	dialer        N.Dialer
	logger        logger.Logger
	brutalDebug   bool
	serverAddr    M.Socksaddr
	serverPorts   []uint16
	hopInterval   time.Duration
	sendBPS       uint64
	receiveBPS    uint64
	xplusPassword string
	password      string
	tlsConfig     aTLS.Config
	quicConfig    *quic.Config
	udpDisabled   bool

	probeAdmission *qtls.ClientProbeAdmission

	connAccess sync.Mutex
	conn       *clientQUICConnection
	closeIdle  atomic.Bool
	pending    *clientOffer
}

func NewClient(options ClientOptions) (*Client, error) {
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:                true,
		InitialStreamReceiveWindow:     DefaultStreamReceiveWindow,
		MaxStreamReceiveWindow:         DefaultStreamReceiveWindow,
		InitialConnectionReceiveWindow: DefaultConnReceiveWindow,
		MaxConnectionReceiveWindow:     DefaultConnReceiveWindow,
		MaxIdleTimeout:                 DefaultMaxIdleTimeout,
		KeepAlivePeriod:                DefaultKeepAlivePeriod,
	}
	qtls.ApplyQUICOptions(quicConfig, options.QUICOptions)
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{DefaultALPN})
	}
	if options.SendBPS == 0 {
		return nil, E.New("missing upload speed")
	} else if options.SendBPS < MinSpeedBPS {
		return nil, E.New("invalid upload speed")
	}
	if options.ReceiveBPS == 0 {
		return nil, E.New("missing download speed")
	} else if options.ReceiveBPS < MinSpeedBPS {
		return nil, E.New("invalid download speed")
	}
	var serverPorts []uint16
	if len(options.ServerPorts) > 0 {
		var err error
		serverPorts, err = ParsePorts(options.ServerPorts)
		if err != nil {
			return nil, err
		}
	}
	client := &Client{
		ctx:           options.Context,
		dialer:        options.Dialer,
		logger:        options.Logger,
		brutalDebug:   options.BrutalDebug,
		serverAddr:    options.ServerAddress,
		serverPorts:   serverPorts,
		hopInterval:   options.HopInterval,
		sendBPS:       options.SendBPS,
		receiveBPS:    options.ReceiveBPS,
		xplusPassword: options.XPlusPassword,
		password:      options.Password,
		tlsConfig:     options.TLSConfig,
		quicConfig:    quicConfig,
		udpDisabled:   options.UDPDisabled,

		probeAdmission: options.ProbeAdmission,
	}
	client.initRuntime()
	return client, nil
}

func ParsePorts(serverPorts []string) ([]uint16, error) {
	var portList []uint16
	for _, portRange := range serverPorts {
		if !strings.Contains(portRange, ":") {
			return nil, E.New("bad port range: ", portRange)
		}
		subIndex := strings.Index(portRange, ":")
		var (
			start, end uint64
			err        error
		)
		if subIndex > 0 {
			start, err = strconv.ParseUint(portRange[:subIndex], 10, 16)
			if err != nil {
				return nil, E.Cause(err, "bad port range: ", portRange)
			}
		}
		if subIndex == len(portRange)-1 {
			end = math.MaxUint16
		} else {
			end, err = strconv.ParseUint(portRange[subIndex+1:], 10, 16)
			if err != nil {
				return nil, E.Cause(err, "bad port range: ", portRange)
			}
		}
		for i := start; i <= end; i++ {
			portList = append(portList, uint16(i))
		}
	}
	return portList, nil
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
	if c.probeAdmission != nil {
		if err := ctx.Err(); err != nil {
			c.connAccess.Unlock()
			return nil, err
		}
	}
	pending := c.pending
	var offerCtx context.Context
	if pending == nil {
		// The client owns the attempt even when a caller stops waiting.
		ownerCtx := c.ctx
		if ownerCtx == nil {
			ownerCtx = context.Background()
		}
		var cancel context.CancelCauseFunc
		offerCtx, cancel = context.WithCancelCause(ownerCtx)
		pending = &clientOffer{done: make(chan struct{}), cancel: cancel}
		c.pending = pending
	}
	if c.probeAdmission != nil {
		defer pending.probeWaiters.Add(ctx)()
	}
	c.connAccess.Unlock()

	if offerCtx != nil && !c.runtime.run(func() { c.completeOffer(pending, offerCtx) }) {
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
	policy := c.probeAdmission
	dialCtx := offerCtx
	var firstDialDone func(net.Conn, error)
	var refused bool
	if policy != nil {
		dialCtx = policy.Context(offerCtx, pending.probeWaiters.AllBackground)
		firstDialDone = func(conn net.Conn, err error) {
			refused = conn == nil && policy.IsForegroundSlot(err)
		}
	}
	conn, err := c.offerNew(dialCtx, firstDialDone)
	c.connAccess.Lock()
	if refused && !pending.discarded && !c.runtime.closed.Load() && offerCtx.Err() == nil &&
		!pending.probeWaiters.AllBackground(policy.IsBackground) {
		// The slot refusal happened before opening the first UDP carrier.
		c.connAccess.Unlock()
		conn, err = c.offerNew(policy.Context(offerCtx, nil), nil)
		c.connAccess.Lock()
	}
	discardErr := err
	shouldDiscard := false
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
	c.connAccess.Unlock()
	pending.cancel(nil)
	close(pending.done)

	if shouldDiscard && conn != nil {
		conn.closeWithError(discardErr)
	}
}

func (c *Client) offerNew(ctx context.Context, firstDialDone func(net.Conn, error)) (*clientQUICConnection, error) {
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
	firstDial := func(serverAddr M.Socksaddr) (net.Conn, error) {
		conn, err := c.dialer.DialContext(ctx, "udp", serverAddr)
		if firstDialDone != nil {
			firstDialDone(conn, err)
		}
		return conn, err
	}
	dialFunc := func(serverAddr M.Socksaddr) (net.Conn, error) {
		var udpConn net.Conn
		var err error
		if firstDial != nil {
			// The initial socket open belongs to the shared offer. Later port hops
			// belong to the live client connection and must outlive any one caller.
			udpConn, err = firstDial(serverAddr)
			firstDial = nil
		} else {
			udpConn, err = c.dialer.DialContext(hopCtx, "udp", serverAddr)
		}
		if err != nil {
			return nil, err
		}
		if c.xplusPassword == "" {
			return udpConn, nil
		}
		return NewXPlusClientConn(udpConn, []byte(c.xplusPassword)), nil
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
		if c.xplusPassword != "" {
			qtls.SetDesiredBufferSizes(rawConn)
		}
	} else {
		rawConn, err = NewHopConn(dialFunc, c.serverAddr, c.serverPorts, c.hopInterval, 0)
		if err != nil {
			return nil, err
		}
	}
	rawConn = &clientCancelableConn{Conn: rawConn, cancel: cancelHop}
	hopAdopted = true
	quicConn, err := qtls.Dial(ctx, rawConn, c.tlsConfig, c.quicConfig)
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	watchDone := make(chan struct{})
	stopWatch := context.AfterFunc(ctx, func() {
		defer close(watchDone)
		_ = quicConn.CloseWithError(0, "")
	})
	defer func() {
		if !stopWatch() {
			<-watchDone
		}
	}()
	controlStream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	_ = controlStream.SetDeadline(time.Now().Add(ProtocolTimeout))
	err = WriteClientHello(controlStream, ClientHello{
		SendBPS: c.sendBPS,
		RecvBPS: c.receiveBPS,
		Auth:    c.password,
	})
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	serverHello, err := ReadServerHello(controlStream)
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	_ = controlStream.SetDeadline(time.Time{})
	if !serverHello.OK {
		rawConn.Close()
		return nil, E.New("remote error: ", serverHello.Message)
	}
	if serverHello.RecvBPS == 0 {
		rawConn.Close()
		return nil, E.New("invalid receive bandwidth from server")
	}
	quicConn.SetCongestionControl(hyCC.NewBrutalSender(min(serverHello.RecvBPS, c.sendBPS), quicConn.InitialPacketSize(), c.brutalDebug, c.logger))
	conn := &clientQUICConnection{
		quicConn:    quicConn,
		rawConn:     rawConn,
		connDone:    make(chan struct{}),
		udpDisabled: !(quicConn.ConnectionState().SupportsDatagrams.Local && quicConn.ConnectionState().SupportsDatagrams.Remote),
		udpConnMap:  make(map[uint32]*udpPacketConn),
		closeIdle:   &c.closeIdle,
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

func (c *Client) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if c.udpDisabled {
		return nil, os.ErrInvalid
	}
	conn, err := c.offerWithStream(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.releaseStream(false)
	if conn.udpDisabled {
		return nil, E.New("UDP disabled by server")
	}
	stream, err := conn.quicConn.OpenStream()
	if err != nil {
		return nil, err
	}
	buffer := WriteClientRequest(ClientRequest{
		UDP:  true,
		Host: destination.AddrString(),
		Port: destination.Port,
	}, nil)
	_, err = stream.Write(buffer.Bytes())
	buffer.Release()
	if err != nil {
		stream.Close()
		return nil, err
	}
	response, err := ReadServerResponse(stream)
	if err != nil {
		stream.Close()
		return nil, err
	}
	if !response.OK {
		stream.Close()
		return nil, E.New("remote error: ", response.Message)
	}
	clientPacketConn := newUDPPacketConn(c.ctx, conn.quicConn, func() {
		stream.CancelRead(0)
		stream.Close()
		conn.releaseUDPSession(response.UDPSessionID)
	})
	conn.access.Lock()
	select {
	case <-conn.connDone:
		conn.access.Unlock()
		stream.Close()
		return nil, E.Errors(conn.connErr, os.ErrClosed)
	default:
	}
	if debug.Enabled {
		if _, connExists := conn.udpConnMap[response.UDPSessionID]; connExists {
			conn.access.Unlock()
			stream.Close()
			return nil, E.New("udp session id duplicated")
		}
	}
	conn.udpConnMap[response.UDPSessionID] = clientPacketConn
	conn.access.Unlock()
	clientPacketConn.sessionID = response.UDPSessionID
	c.runConnectionTask(conn, func() {
		holdBuffer := make([]byte, 1024)
		for {
			_, hErr := stream.Read(holdBuffer)
			if hErr != nil {
				break
			}
		}
		clientPacketConn.closeWithError(E.Cause(net.ErrClosed, "hold stream closed"))
	})
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

	probeWaiters qtls.ClientProbeWaiters
}

type clientQUICConnection struct {
	runtimeOwner  *clientRuntime
	transportOnce sync.Once
	transportErr  error

	quicConn    *quic.Conn
	rawConn     io.Closer
	connDone    chan struct{}
	connErr     error
	udpDisabled bool
	access      sync.RWMutex
	udpConnMap  map[uint32]*udpPacketConn
	streams     int
	closeIdle   *atomic.Bool
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
		c.transportErr = errors.Join(c.quicConn.CloseWithError(0, ""), c.rawConn.Close())
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
	response, err := ReadServerResponse(c.Stream)
	if err != nil {
		return 0, qtls.WrapError(err)
	}
	if !response.OK {
		err = E.New("remote error: ", response.Message)
		return
	}
	c.responseRead = true
	n, err = c.Stream.Read(p)
	return n, qtls.WrapError(err)
}

func (c *clientConn) Write(p []byte) (n int, err error) {
	if !c.requestWritten {
		buffer := WriteClientRequest(ClientRequest{
			UDP:  false,
			Host: c.destination.AddrString(),
			Port: c.destination.Port,
		}, p)
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
	// quic-go reports an already reset send side after completing the stream.
	// That reset is a terminal result for this logical connection.
	var reset *quic.StreamError
	if err != nil && errors.As(context.Cause(c.Stream.Context()), &reset) && reset.StreamID == c.StreamID() {
		return nil
	}
	return err
}
