package tuic

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type ClientOptions struct {
	Context           context.Context
	Dialer            N.Dialer
	ServerAddress     M.Socksaddr
	TLSConfig         aTLS.Config
	QUICOptions       qtls.QUICOptions
	UUID              [16]byte
	Password          string
	CongestionControl string
	UDPStream         bool
	ZeroRTTHandshake  bool
	Heartbeat         time.Duration
	ProbeAdmission    *qtls.ClientProbeAdmission
}

type Client struct {
	runtime clientRuntime

	ctx               context.Context
	dialer            N.Dialer
	serverAddr        M.Socksaddr
	tlsConfig         aTLS.Config
	quicConfig        *quic.Config
	uuid              [16]byte
	password          string
	congestionControl string
	udpStream         bool
	zeroRTTHandshake  bool
	heartbeat         time.Duration
	probeAdmission    *qtls.ClientProbeAdmission

	connAccess sync.Mutex
	conn       *clientQUICConnection
	closeIdle  atomic.Bool
	pending    *clientOffer
}

func NewClient(options ClientOptions) (*Client, error) {
	if options.Heartbeat == 0 {
		options.Heartbeat = 10 * time.Second
	}
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery: !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:         true,
		MaxIncomingUniStreams:   1 << 60,
	}
	qtls.ApplyQUICOptions(quicConfig, options.QUICOptions)
	switch options.CongestionControl {
	case "":
		options.CongestionControl = "cubic"
	case "cubic", "new_reno", "bbr":
	default:
		return nil, E.New("unknown congestion control algorithm: ", options.CongestionControl)
	}
	client := &Client{
		ctx:               options.Context,
		dialer:            options.Dialer,
		serverAddr:        options.ServerAddress,
		tlsConfig:         options.TLSConfig,
		quicConfig:        quicConfig,
		uuid:              options.UUID,
		password:          options.Password,
		congestionControl: options.CongestionControl,
		udpStream:         options.UDPStream,
		zeroRTTHandshake:  options.ZeroRTTHandshake,
		heartbeat:         options.Heartbeat,
		probeAdmission:    options.ProbeAdmission,
	}
	client.initRuntime()
	return client, nil
}

func (c *Client) offer(ctx context.Context) (*clientQUICConnection, error) {
	c.connAccess.Lock()
	if c.runtime.closed.Load() {
		c.connAccess.Unlock()
		return nil, net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		c.connAccess.Unlock()
		return nil, err
	}
	conn := c.conn
	if conn != nil && conn.active() {
		c.connAccess.Unlock()
		return conn, nil
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
		leave := pending.probeWaiters.Add(ctx)
		defer leave()
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
	if policy != nil {
		dialCtx = policy.Context(offerCtx, pending.probeWaiters.AllBackground)
	}
	conn, err := c.offerNew(dialCtx)
	c.connAccess.Lock()
	if policy != nil && !pending.discarded && !c.runtime.closed.Load() && offerCtx.Err() == nil &&
		policy.IsForegroundSlot(err) && !pending.probeWaiters.AllBackground(policy.IsBackground) {
		// Admit one foreground attempt while that demand is live. After this
		// point, caller cancellation just stops waiting, as for any owned dial.
		c.connAccess.Unlock()
		conn, err = c.offerNew(policy.Context(offerCtx, nil))
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

func (c *Client) offerNew(ctx context.Context) (*clientQUICConnection, error) {
	udpConn, err := c.dialer.DialContext(ctx, "udp", c.serverAddr)
	if err != nil {
		return nil, err
	}
	var quicConn *quic.Conn
	if c.zeroRTTHandshake {
		quicConn, err = qtls.DialEarly(ctx, udpConn, c.tlsConfig, c.quicConfig)
	} else {
		quicConn, err = qtls.Dial(ctx, udpConn, c.tlsConfig, c.quicConfig)
	}
	if err != nil {
		udpConn.Close()
		return nil, E.Cause(err, "open connection")
	}
	setCongestion(c.ctx, quicConn, c.congestionControl)
	conn := &clientQUICConnection{
		quicConn:   quicConn,
		rawConn:    udpConn,
		connDone:   make(chan struct{}),
		udpConnMap: make(map[uint16]*udpPacketConn),
		closeIdle:  &c.closeIdle,
	}
	c.runtime.register(conn)
	c.runConnectionTask(conn, func() {
		hErr := c.clientHandshake(quicConn)
		if hErr != nil {
			conn.closeWithError(hErr)
		}
	})
	if c.udpStream {
		c.runConnectionTask(conn, func() { c.loopUniStreams(conn) })
	}
	c.runConnectionTask(conn, func() { c.loopMessages(conn) })
	c.runConnectionTask(conn, func() { c.loopHeartbeats(conn) })
	return conn, nil
}

func (c *Client) clientHandshake(conn *quic.Conn) error {
	authStream, err := conn.OpenUniStream()
	if err != nil {
		return E.Cause(err, "open handshake stream")
	}
	defer authStream.Close()
	handshakeState := conn.ConnectionState()
	tuicAuthToken, err := handshakeState.TLS.ExportKeyingMaterial(string(c.uuid[:]), []byte(c.password), 32)
	if err != nil {
		return E.Cause(err, "export keying material")
	}
	authRequest := buf.NewSize(AuthenticateLen)
	authRequest.WriteByte(Version)
	authRequest.WriteByte(CommandAuthenticate)
	authRequest.Write(c.uuid[:])
	authRequest.Write(tuicAuthToken)
	return common.Error(authStream.Write(authRequest.Bytes()))
}

func (c *Client) loopHeartbeats(conn *clientQUICConnection) {
	ticker := time.NewTicker(c.heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-conn.connDone:
			return
		case <-ticker.C:
			err := conn.quicConn.SendDatagram([]byte{Version, CommandHeartbeat})
			if err != nil {
				conn.closeWithError(E.Cause(err, "send heartbeat"))
			}
		}
	}
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
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	var sessionID uint16
	clientPacketConn := newUDPPacketConn(c.ctx, conn.quicConn, c.udpStream, false, func() {
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
	done         chan struct{}
	cancel       func(error)
	conn         *clientQUICConnection
	err          error
	discarded    bool
	cause        error
	probeWaiters qtls.ClientProbeWaiters
}

type clientQUICConnection struct {
	runtimeOwner *clientRuntime
	transportOnce sync.Once
	transportErr error

	quicConn     *quic.Conn
	rawConn      io.Closer
	connDone     chan struct{}
	connErr      error
	access       sync.RWMutex
	udpConnMap   map[uint16]*udpPacketConn
	udpSessionID uint16
	streams      int
	closeIdle    *atomic.Bool
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

func (c *clientQUICConnection) releaseUDPSession(sessionID uint16) {
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
	c.udpConnMap = make(map[uint16]*udpPacketConn)
	c.access.Unlock()
	c.closeTransport()
	for _, udpConn := range udpConnMap {
		udpConn.closeWithError(err)
	}
}

func (c *clientQUICConnection) closeTransport() {
	c.transportOnce.Do(func() {
		c.transportErr = errors.Join(c.quicConn.CloseWithError(0, ""), c.rawConn.Close())
		if c.runtimeOwner!=nil{c.runtimeOwner.retire(c,c.transportErr)}
	})
}

type clientConn struct {
	*quic.Stream
	parent         *clientQUICConnection
	destination    M.Socksaddr
	keepSession    bool
	requestWritten bool
	closeOnce      sync.Once
}

func (c *clientConn) NeedHandshake() bool {
	return !c.requestWritten
}

func (c *clientConn) Read(b []byte) (n int, err error) {
	n, err = c.Stream.Read(b)
	return n, qtls.WrapError(err)
}

func (c *clientConn) Write(b []byte) (n int, err error) {
	if !c.requestWritten {
		request := buf.NewSize(2 + AddressSerializer.AddrPortLen(c.destination) + len(b))
		defer request.Release()
		request.WriteByte(Version)
		request.WriteByte(CommandConnect)
		err = AddressSerializer.WriteAddrPort(request, c.destination)
		if err != nil {
			return
		}
		request.Write(b)
		_, err = c.Stream.Write(request.Bytes())
		if err != nil {
			c.parent.closeWithError(E.Cause(err, "create new connection"))
			return 0, qtls.WrapError(err)
		}
		c.requestWritten = true
		return len(b), nil
	}
	n, err = c.Stream.Write(b)
	return n, qtls.WrapError(err)
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

func (c *clientConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) RemoteAddr() net.Addr {
	return c.destination
}
