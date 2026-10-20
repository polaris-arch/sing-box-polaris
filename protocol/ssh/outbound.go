package ssh

import (
	"bytes"
	"context"
	"encoding/base64"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service/filemanager"

	"golang.org/x/crypto/ssh"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.SSHOutboundOptions](registry, C.TypeSSH, NewOutbound)
}

var (
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
	_ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	runtimeSource adapter.RuntimeResourceSource
	runtimeFences *outbound.RuntimeIOFenceSet
	runtimeStop context.Context
	runtimeCancel context.CancelFunc
	runtimeCleanup func() error
	constructionCleanup bool
	clientOpening chan struct{}
	clientSealed bool
	clientWatchers sync.WaitGroup
	logger            logger.ContextLogger
	dialer            N.Dialer
	serverAddr        M.Socksaddr
	user              string
	hostKey           []ssh.PublicKey
	hostKeyAlgorithms []string
	cipher            []string
	mac               []string
	kexAlgorithm      []string
	clientVersion     string
	authMethod        []ssh.AuthMethod
	clientAccess      sync.Mutex
	clientConn        net.Conn
	client            *ssh.Client
	streams           int
	closeIdle         bool
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SSHOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter:           outbound.NewAdapterWithDialerOptions(C.TypeSSH, tag, []string{N.NetworkTCP}, options.DialerOptions),
		logger:            logger,
		dialer:            outboundDialer,
		serverAddr:        options.ServerOptions.Build(),
		user:              options.User,
		hostKeyAlgorithms: options.HostKeyAlgorithms,
		cipher:            options.Cipher,
		mac:               options.MAC,
		kexAlgorithm:      options.KexAlgorithm,
		clientVersion:     options.ClientVersion,
	}
	if outbound.serverAddr.Port == 0 {
		outbound.serverAddr.Port = 22
	}
	if outbound.user == "" {
		outbound.user = "root"
	}
	if outbound.clientVersion == "" {
		outbound.clientVersion = randomVersion()
	}
	if options.Password != "" {
		outbound.authMethod = append(outbound.authMethod, ssh.Password(options.Password))
	}
	if len(options.PrivateKey) > 0 || options.PrivateKeyPath != "" {
		var privateKey []byte
		if len(options.PrivateKey) > 0 {
			privateKey = []byte(strings.Join(options.PrivateKey, "\n"))
		} else {
			var err error
			privateKey, err = filemanager.ReadFile(ctx, os.ExpandEnv(options.PrivateKeyPath))
			if err != nil {
				return nil, E.Cause(err, "read private key")
			}
		}
		var signer ssh.Signer
		var err error
		if options.PrivateKeyPassphrase == "" {
			signer, err = ssh.ParsePrivateKey(privateKey)
		} else {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(privateKey, []byte(options.PrivateKeyPassphrase))
		}
		if err != nil {
			return nil, E.Cause(err, "parse private key")
		}
		outbound.authMethod = append(outbound.authMethod, ssh.PublicKeys(signer))
	}
	if len(options.HostKey) > 0 {
		for _, hostKey := range options.HostKey {
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKey))
			if err != nil {
				return nil, E.Cause(err, "parse host key: ", hostKey)
			}
			outbound.hostKey = append(outbound.hostKey, key)
		}
	}
	outbound.initRuntime(ctx)
	if err := ctx.Err(); err != nil { _ = outbound.runtimeCleanup(); return nil, err }
	registered, err := registerSSHCleanup(ctx, outbound.runtimeCleanup)
	outbound.constructionCleanup = registered
	if err != nil { return nil, err }
	return outbound, nil
}

func randomVersion() string {
	version := "SSH-2.0-OpenSSH_"
	if rand.Intn(2) == 0 {
		version += "7." + strconv.Itoa(rand.Intn(10))
	} else {
		version += "8." + strconv.Itoa(rand.Intn(9))
	}
	return version
}

func (s *Outbound) connect(ctx context.Context) (*ssh.Client, error) {
	for {
		s.clientAccess.Lock()
		if s.clientSealed { s.clientAccess.Unlock(); return nil, net.ErrClosed }
		if s.client != nil {
			s.streams++
			client := s.client; s.clientAccess.Unlock(); return client, nil
		}
		if opening := s.clientOpening; opening != nil {
			s.clientAccess.Unlock()
			select { case <-opening: continue; case <-ctx.Done(): return nil, ctx.Err(); case <-s.runtimeStop.Done(): return nil, net.ErrClosed }
		}
		opening := make(chan struct{})
		s.clientOpening = opening
		s.clientAccess.Unlock()
		// The single-flight gate protects publication only. No mutex spans
		// DNS, dialing, handshake, SSH waits or raw connection close.
		return s.openClient(ctx, opening)
	}
}

func (s *Outbound) openClient(ctx context.Context, opening chan struct{}) (*ssh.Client, error) {
	defer func() {
		s.clientAccess.Lock(); s.clientOpening = nil; close(opening); s.clientAccess.Unlock()
	}()
	creation, err := s.runtimeFences.Begin()
	if err != nil { return nil, err }; defer creation.Done()
	if s.runtimeSource != nil {
		ctx, err = outbound.ContextForRuntimeOwnedSession(ctx, s.runtimeSource)
		if err != nil { return nil, err }
	}
	ctx, cancel := context.WithCancel(ctx)
	cancelDone := make(chan struct{})
	stopOwner := context.AfterFunc(s.runtimeStop, func() { defer close(cancelDone); cancel() })
	defer func() { if !stopOwner() { <-cancelDone }; cancel() }()
	raw, err := s.dialer.DialContext(ctx, N.NetworkTCP, s.serverAddr)
	if err != nil {
		if raw != nil { _, fence := outbound.WrapRuntimeOwnedConn(raw); s.runtimeFences.Record(fence.RuntimeCloseAndWait()) }
		return nil, err
	}
	conn, fence := outbound.WrapRuntimeOwnedConn(raw)
	if err := creation.Register(fence); err != nil { return nil, err }
	handshakeDone := make(chan struct{})
	stopHandshake := context.AfterFunc(ctx, func() { defer close(handshakeDone); _ = fence.Close() })
	stopAndJoin := func() { if !stopHandshake() { <-handshakeDone } }
	hostKeys := append([]ssh.PublicKey(nil), s.hostKey...)
	config := &ssh.ClientConfig{
		User:              s.user,
		Auth:              s.authMethod,
		ClientVersion:     s.clientVersion,
		HostKeyAlgorithms: s.hostKeyAlgorithms,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if len(hostKeys) == 0 {
				return nil
			}
			serverKey := key.Marshal()
			for _, hostKey := range hostKeys {
				if bytes.Equal(serverKey, hostKey.Marshal()) {
					return nil
				}
			}
			return E.New("host key mismatch, server send ", key.Type(), " ", base64.StdEncoding.EncodeToString(serverKey))
		},
	}
	if len(s.cipher) > 0 {
		config.Ciphers = s.cipher
	}
	if len(s.mac) > 0 {
		config.MACs = s.mac
	}
	if len(s.kexAlgorithm) > 0 {
		config.KeyExchanges = s.kexAlgorithm
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, s.serverAddr.Addr.String(), config)
	stopAndJoin()
	if err != nil {
		s.runtimeFences.Record(fence.RuntimeCloseAndWait())
		return nil, E.Cause(err, "connect to ssh server")
	}
	client := ssh.NewClient(clientConn, chans, reqs)
	s.clientAccess.Lock()
	if s.clientSealed || ctx.Err() != nil {
		s.clientAccess.Unlock()
		_ = client.Close()
		s.runtimeFences.Record(fence.RuntimeCloseAndWait())
		if err := ctx.Err(); err != nil { return nil, err }
		return nil, net.ErrClosed
	}
	s.clientConn, s.client, s.streams = conn, client, 1
	s.clientWatchers.Add(1)
	s.clientAccess.Unlock()
	go func() {
		defer s.clientWatchers.Done()
		_ = client.Wait()
		s.runtimeFences.Record(fence.RuntimeCloseAndWait())
		s.clientAccess.Lock()
		if s.client == client { s.client = nil; s.clientConn = nil }
		s.clientAccess.Unlock()
	}()
	return client, nil
}

func (s *Outbound) InterfaceUpdated(ctx context.Context) {
	_, release, err := adapter.AcquireRuntimeOperation(ctx, s.runtimeSource)
	if err != nil { return }
	s.clientAccess.Lock()
	conn := s.clientConn; s.client = nil; s.clientConn = nil
	s.clientAccess.Unlock()
	_ = common.Close(conn)
	release()
}

func (s *Outbound) MultiplexEnabled() bool {
	return true
}

func (s *Outbound) SetKeepIdleConnections(keep bool) {
	_, release, err := adapter.AcquireRuntimeOperation(context.Background(), s.runtimeSource)
	if err != nil { return }; defer release()
	s.clientAccess.Lock()
	s.closeIdle = !keep
	s.clientAccess.Unlock()
	if !keep {
		s.CloseIdleConnections()
	}
}

func (s *Outbound) CloseIdleConnections() {
	_, release, err := adapter.AcquireRuntimeOperation(context.Background(), s.runtimeSource)
	if err != nil { return }; defer release()
	s.clientAccess.Lock()
	if s.client == nil || s.streams > 0 {
		s.clientAccess.Unlock()
		return
	}
	clientConn := s.clientConn
	s.client = nil
	s.clientConn = nil
	s.clientAccess.Unlock()
	common.Close(clientConn)
}

func (s *Outbound) releaseStream(client *ssh.Client, keepSession bool) {
	s.clientAccess.Lock()
	if s.client != client {
		s.clientAccess.Unlock()
		return
	}
	s.streams--
	if !s.closeIdle || keepSession || s.streams > 0 {
		s.clientAccess.Unlock()
		return
	}
	clientConn := s.clientConn
	s.client = nil
	s.clientConn = nil
	s.clientAccess.Unlock()
	common.Close(clientConn)
}

func (s *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize { return nil }
	if err := scope.Context().Err(); err != nil { _ = s.runtimeCleanup(); return err }
	if s.constructionCleanup { return nil }
	var err error
	s.constructionCleanup, err = registerSSHCleanup(adapter.ContextWithConstructionScope(scope.Context(), scope), s.runtimeCleanup)
	return err
}

func (s *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return outbound.DialRuntimeConn(ctx, s.runtimeSource, func(ctx context.Context) (net.Conn, error) {
		return s.dialContext(ctx, network, destination)
	})
}

func (s *Outbound) dialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	client, err := s.connect(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := client.DialContext(ctx, network, destination.String())
	if err != nil {
		s.releaseStream(client, false)
		return nil, err
	}
	keepSession := adapter.KeepSessionFromContext(ctx)
	return &chanConnWrapper{Conn: conn, onClose: func() { s.releaseStream(client, keepSession) }}, nil
}

func (s *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return outbound.ListenRuntimePacket(ctx, s.runtimeSource, func(ctx context.Context) (net.PacketConn, error) {
		return s.listenPacket(ctx, destination)
	})
}

func (s *Outbound) listenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

type chanConnWrapper struct {
	net.Conn
	closeOnce sync.Once
	onClose   func()
	closeErr error
}

func (c *chanConnWrapper) Close() error {
	c.closeOnce.Do(func() { c.closeErr = c.Conn.Close(); c.onClose() })
	return c.closeErr
}

func (c *chanConnWrapper) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *chanConnWrapper) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *chanConnWrapper) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}
