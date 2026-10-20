package tuic

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"github.com/gofrs/uuid/v5"
)

type ServiceOptions struct {
	Context           context.Context
	Logger            logger.Logger
	TLSConfig         aTLS.ServerConfig
	QUICOptions       qtls.QUICOptions
	CongestionControl string
	AuthTimeout       time.Duration
	ZeroRTTHandshake  bool
	Heartbeat         time.Duration
	UDPTimeout        time.Duration
	Handler           ServiceHandler
}

type ServiceHandler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

type Service[U comparable] struct {
	ctx               context.Context
	logger            logger.Logger
	tlsConfig         aTLS.ServerConfig
	heartbeat         time.Duration
	quicConfig        *quic.Config
	userMap           map[[16]byte]U
	passwordMap       map[U]string
	congestionControl string
	authTimeout       time.Duration
	udpTimeout        time.Duration
	handler           ServiceHandler

	quicListener io.Closer
}

func NewService[U comparable](options ServiceOptions) (*Service[U], error) {
	if options.AuthTimeout == 0 {
		options.AuthTimeout = 3 * time.Second
	}
	if options.Heartbeat == 0 {
		options.Heartbeat = 10 * time.Second
	}
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery: !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:         true,
		Allow0RTT:               options.ZeroRTTHandshake,
		MaxIncomingStreams:      1 << 60,
		MaxIncomingUniStreams:   1 << 60,
		DisablePathManager:      true,
	}
	qtls.ApplyQUICOptions(quicConfig, options.QUICOptions)
	switch options.CongestionControl {
	case "":
		options.CongestionControl = "cubic"
	case "cubic", "new_reno", "bbr":
	default:
		return nil, E.New("unknown congestion control algorithm: ", options.CongestionControl)
	}
	return &Service[U]{
		ctx:               options.Context,
		logger:            options.Logger,
		tlsConfig:         options.TLSConfig,
		heartbeat:         options.Heartbeat,
		quicConfig:        quicConfig,
		userMap:           make(map[[16]byte]U),
		congestionControl: options.CongestionControl,
		authTimeout:       options.AuthTimeout,
		udpTimeout:        options.UDPTimeout,
		handler:           options.Handler,
	}, nil
}

func (s *Service[U]) UpdateUsers(userList []U, uuidList [][16]byte, passwordList []string) {
	userMap := make(map[[16]byte]U)
	passwordMap := make(map[U]string)
	for index := range userList {
		userMap[uuidList[index]] = userList[index]
		passwordMap[userList[index]] = passwordList[index]
	}
	s.userMap = userMap
	s.passwordMap = passwordMap
}

func (s *Service[U]) Start(conn net.PacketConn) error {
	if !s.quicConfig.Allow0RTT {
		listener, err := qtls.Listen(conn, s.tlsConfig, s.quicConfig)
		if err != nil {
			return err
		}
		s.quicListener = listener
		if !qtls.RunServerTask(s.tlsConfig, s.ctx, func(context.Context) {
			for {
				connection, hErr := listener.Accept(s.ctx)
				if hErr != nil {
					if E.IsClosedOrCanceled(hErr) || errors.Is(hErr, quic.ErrServerClosed) {
						s.logger.Debug(E.Cause(hErr, "listener closed"))
					} else {
						s.logger.Error(E.Cause(hErr, "listener closed"))
					}
					return
				}
				ctx, contextErr := qtls.ServerConnectionContext(s.tlsConfig, s.ctx, connection)
				if contextErr != nil { _ = connection.CloseWithError(0, ""); continue }
				if !qtls.RunServerTask(s.tlsConfig, ctx, func(context.Context) { s.handleConnection(ctx, connection) }) {
					_ = connection.CloseWithError(0, "")
				}
			}
		}) { _ = listener.Close(); return net.ErrClosed }
	} else {
		listener, err := qtls.ListenEarly(conn, s.tlsConfig, s.quicConfig)
		if err != nil {
			return err
		}
		s.quicListener = listener
		if !qtls.RunServerTask(s.tlsConfig, s.ctx, func(context.Context) {
			for {
				connection, hErr := listener.Accept(s.ctx)
				if hErr != nil {
					if E.IsClosedOrCanceled(hErr) || errors.Is(hErr, quic.ErrServerClosed) {
						s.logger.Debug(E.Cause(hErr, "listener closed"))
					} else {
						s.logger.Error(E.Cause(hErr, "listener closed"))
					}
					return
				}
				ctx, contextErr := qtls.ServerConnectionContext(s.tlsConfig, s.ctx, connection)
				if contextErr != nil { _ = connection.CloseWithError(0, ""); continue }
				if !qtls.RunServerTask(s.tlsConfig, ctx, func(context.Context) { s.handleConnection(ctx, connection) }) {
					_ = connection.CloseWithError(0, "")
				}
			}
		}) { _ = listener.Close(); return net.ErrClosed }
	}
	return nil
}

func (s *Service[U]) Close() error {
	return common.Close(
		s.quicListener,
	)
}

func (s *Service[U]) handleConnection(ctx context.Context, connection *quic.Conn) {
	setCongestion(ctx, connection, s.congestionControl)
	session := &serverSession[U]{
		Service:    s,
		ctx:        ctx,
		quicConn:   connection,
		connDone:   make(chan struct{}),
		authDone:   make(chan struct{}),
		udpConnMap: make(map[uint16]*udpPacketConn),
	}
	session.handle()
}

type serverSession[U comparable] struct {
	*Service[U]
	ctx        context.Context
	quicConn   *quic.Conn
	connAccess sync.Mutex
	connDone   chan struct{}
	connErr    error
	authAccess sync.Mutex
	authDone   chan struct{}
	authUser   U
	udpAccess  sync.RWMutex
	udpConnMap map[uint16]*udpPacketConn
}

func (s *serverSession[U]) handle() {
	if s.ctx.Done() != nil {
		if !qtls.RunServerTask(s.tlsConfig, s.ctx, func(context.Context) {
			select {
			case <-s.ctx.Done():
				s.closeWithError(s.ctx.Err())
			case <-s.connDone:
			}
		}) { s.closeWithError(net.ErrClosed); return }
	}
	if !qtls.RunServerTask(s.tlsConfig, s.ctx, func(context.Context) { s.loopUniStreams() }) { s.closeWithError(net.ErrClosed); return }
	if !qtls.RunServerTask(s.tlsConfig, s.ctx, func(context.Context) { s.loopStreams() }) { s.closeWithError(net.ErrClosed); return }
	if !qtls.RunServerTask(s.tlsConfig, s.ctx, func(context.Context) { s.loopMessages() }) { s.closeWithError(net.ErrClosed); return }
	if !qtls.RunServerTask(s.tlsConfig, s.ctx, func(context.Context) { s.handleAuthTimeout() }) { s.closeWithError(net.ErrClosed); return }
	if !qtls.RunServerTask(s.tlsConfig, s.ctx, func(context.Context) { s.loopHeartbeats() }) { s.closeWithError(net.ErrClosed); return }
}

func (s *serverSession[U]) loopUniStreams() {
	for {
		uniStream, err := s.quicConn.AcceptUniStream(s.ctx)
		if err != nil {
			return
		}
		if !qtls.RunServerTask(s.tlsConfig, s.ctx, func(context.Context) {
			err := s.handleUniStream(uniStream)
			if err != nil {
				s.closeWithError(E.Cause(err, "handle uni stream"))
			}
		}) { uniStream.CancelRead(0); return }
	}
}

func (s *serverSession[U]) handleUniStream(stream *quic.ReceiveStream) error {
	defer stream.CancelRead(0)
	buffer := buf.New()
	defer buffer.Release()
	_, err := buffer.ReadAtLeastFrom(stream, 2)
	if err != nil {
		return E.Cause(err, "read request")
	}
	version := buffer.Byte(0)
	if version != Version {
		return E.New("unknown version ", buffer.Byte(0))
	}
	command := buffer.Byte(1)
	switch command {
	case CommandAuthenticate:
		if buffer.Len() < AuthenticateLen {
			_, err = buffer.ReadFullFrom(stream, AuthenticateLen-buffer.Len())
			if err != nil {
				return E.Cause(err, "authentication: read request")
			}
		}
		var userUUID [16]byte
		copy(userUUID[:], buffer.Range(2, 2+16))
		user, loaded := s.userMap[userUUID]
		if !loaded {
			return E.New("authentication: unknown user ", uuid.UUID(userUUID))
		}
		handshakeState := s.quicConn.ConnectionState()
		tuicToken, err := handshakeState.TLS.ExportKeyingMaterial(string(userUUID[:]), []byte(s.passwordMap[user]), 32)
		if err != nil {
			return E.Cause(err, "authentication: export keying material")
		}
		if !bytes.Equal(tuicToken, buffer.Range(2+16, 2+16+32)) {
			return E.New("authentication: token mismatch")
		}
		s.authAccess.Lock()
		defer s.authAccess.Unlock()
		select {
		case <-s.authDone:
			return E.New("authentication: multiple authentication requests")
		default:
		}
		s.authUser = user
		close(s.authDone)
		return nil
	case CommandPacket:
		select {
		case <-s.connDone:
			return s.connErr
		case <-s.authDone:
		}
		message := allocMessage()
		err = readUDPMessage(message, io.MultiReader(bytes.NewReader(buffer.From(2)), stream))
		if err != nil {
			message.releaseMessage()
			return err
		}
		s.handleUDPMessage(message, true)
		return nil
	case CommandDissociate:
		select {
		case <-s.connDone:
			return s.connErr
		case <-s.authDone:
		}
		if buffer.Len() > 4 {
			return E.New("invalid dissociate message")
		}
		var sessionID uint16
		err = binary.Read(io.MultiReader(bytes.NewReader(buffer.From(2)), stream), binary.BigEndian, &sessionID)
		if err != nil {
			return err
		}
		s.udpAccess.RLock()
		udpConn, loaded := s.udpConnMap[sessionID]
		s.udpAccess.RUnlock()
		if loaded {
			udpConn.closeWithError(E.New("remote closed"))
			s.udpAccess.Lock()
			delete(s.udpConnMap, sessionID)
			s.udpAccess.Unlock()
		}
		return nil
	default:
		return E.New("unknown command ", command)
	}
}

func (s *serverSession[U]) handleAuthTimeout() {
	select {
	case <-s.connDone:
	case <-s.authDone:
	case <-time.After(s.authTimeout):
		s.closeWithError(E.New("authentication timeout"))
	}
}

func (s *serverSession[U]) loopStreams() {
	for {
		stream, err := s.quicConn.AcceptStream(s.ctx)
		if err != nil {
			return
		}
		if !qtls.RunServerTask(s.tlsConfig, s.ctx, func(ctx context.Context) {
			err := s.handleStream(ctx, stream)
			if err != nil {
				stream.CancelRead(0)
				stream.Close()
				s.logger.Error(E.Cause(err, "handle stream request"))
			}
		}) { stream.CancelRead(0); stream.CancelWrite(0); return }
	}
}

func (s *serverSession[U]) handleStream(ctx context.Context, stream *quic.Stream) error {
	buffer := buf.NewSize(2 + M.MaxSocksaddrLength)
	defer buffer.Release()
	_, err := buffer.ReadAtLeastFrom(stream, 2)
	if err != nil {
		return E.Cause(err, "read request")
	}
	version, _ := buffer.ReadByte()
	if version != Version {
		return E.New("unknown version ", buffer.Byte(0))
	}
	command, _ := buffer.ReadByte()
	if command != CommandConnect {
		return E.New("unsupported stream command ", command)
	}
	destination, err := AddressSerializer.ReadAddrPort(io.MultiReader(buffer, stream))
	if err != nil {
		return E.Cause(err, "read request destination")
	}
	select {
	case <-s.connDone:
		return s.connErr
	case <-s.authDone:
	}
	var conn net.Conn = &serverConn{
		Stream:      stream,
		destination: destination,
	}
	if !buffer.IsEmpty() {
		conn = bufio.NewCachedConn(conn, buffer.ToOwned())
	}
	s.handler.NewConnectionEx(auth.ContextWithUser(ctx, s.authUser), conn, M.SocksaddrFromNet(s.quicConn.RemoteAddr()).Unwrap(), destination, nil)
	return nil
}

func (s *serverSession[U]) loopHeartbeats() {
	ticker := time.NewTicker(s.heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-s.connDone:
			return
		case <-ticker.C:
			err := s.quicConn.SendDatagram([]byte{Version, CommandHeartbeat})
			if err != nil {
				s.closeWithError(E.Cause(err, "send heartbeat"))
			}
		}
	}
}

func (s *serverSession[U]) closeWithError(err error) {
	s.connAccess.Lock()
	defer s.connAccess.Unlock()
	select {
	case <-s.connDone:
		return
	default:
		s.connErr = err
		close(s.connDone)
	}
	if E.IsClosedOrCanceled(err) {
		s.logger.Debug(E.Cause(err, "connection failed"))
	} else {
		s.logger.Error(E.Cause(err, "connection failed"))
	}
	s.udpAccess.Lock()
	udpConnMap := s.udpConnMap
	s.udpConnMap = make(map[uint16]*udpPacketConn)
	s.udpAccess.Unlock()
	for _, udpConn := range udpConnMap {
		udpConn.closeWithError(err)
	}
	_ = s.quicConn.CloseWithError(0, "")
}

type serverConn struct {
	*quic.Stream
	destination M.Socksaddr
}

func (c *serverConn) Read(p []byte) (n int, err error) {
	n, err = c.Stream.Read(p)
	return n, qtls.WrapError(err)
}

func (c *serverConn) Write(p []byte) (n int, err error) {
	n, err = c.Stream.Write(p)
	return n, qtls.WrapError(err)
}

func (c *serverConn) LocalAddr() net.Addr {
	return c.destination
}

func (c *serverConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverConn) Close() error {
	c.Stream.CancelRead(0)
	err := c.Stream.Close()
	// quic-go's Stream.Close does not unblock a Write blocked on flow control,
	// but a past write deadline does; buffered data and the FIN are unaffected.
	c.Stream.SetWriteDeadline(time.Now())
	return err
}
