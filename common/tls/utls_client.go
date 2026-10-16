//go:build with_utls

package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tlsfragment"
	"github.com/sagernet/sing-box/common/tlsspoof"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service/filemanager"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type UTLSClientConfig struct {
	ctx                   context.Context
	config                *utls.Config
	serverName            string
	disableSNI            bool
	verifyServerName      bool
	handshakeTimeout      time.Duration
	id                    utls.ClientHelloID
	sessionIDGenerator    func([]byte, []byte) error
	fragment              bool
	fragmentFallbackDelay time.Duration
	recordFragment        bool
	spoof                 string
	spoofMethod           tlsspoof.Method
}

func (c *UTLSClientConfig) ServerName() string {
	return c.serverName
}

func (c *UTLSClientConfig) SetServerName(serverName string) {
	c.serverName = serverName
	if c.disableSNI {
		c.config.ServerName = ""
		if c.verifyServerName {
			c.config.InsecureServerNameToVerify = serverName
		} else {
			c.config.InsecureServerNameToVerify = ""
		}
		return
	}
	c.config.ServerName = serverName
}

func (c *UTLSClientConfig) NextProtos() []string {
	return c.config.NextProtos
}

func (c *UTLSClientConfig) SetNextProtos(nextProto []string) {
	if len(nextProto) == 1 && nextProto[0] == http2.NextProtoTLS {
		nextProto = append(nextProto, "http/1.1")
	}
	c.config.NextProtos = nextProto
}

func (c *UTLSClientConfig) HandshakeTimeout() time.Duration {
	return c.handshakeTimeout
}

func (c *UTLSClientConfig) SetHandshakeTimeout(timeout time.Duration) {
	c.handshakeTimeout = timeout
}

func (c *UTLSClientConfig) STDConfig() (*STDConfig, error) {
	return nil, E.New("unsupported usage for uTLS")
}

func (c *UTLSClientConfig) Client(conn net.Conn) (Conn, error) {
	if c.fragment || c.recordFragment {
		conn = tf.NewConn(conn, c.ctx, c.fragment, c.recordFragment, c.fragmentFallbackDelay)
	}
	conn, err := applyTLSSpoof(conn, c.spoof, c.spoofMethod)
	if err != nil {
		return nil, err
	}
	return &utlsALPNWrapper{utlsConnWrapper: utlsConnWrapper{utls.UClient(conn, c.config.Clone(), c.id)}, nextProtocols: c.config.NextProtos, sessionIDGenerator: c.sessionIDGenerator, realECH: len(c.config.EncryptedClientHelloConfigList) > 0}, nil
}

func (c *UTLSClientConfig) SetSessionIDGenerator(generator func(clientHello []byte, sessionID []byte) error) {
	c.sessionIDGenerator = generator
}

func (c *UTLSClientConfig) Clone() Config {
	cloned := &UTLSClientConfig{
		ctx:                   c.ctx,
		config:                c.config.Clone(),
		serverName:            c.serverName,
		disableSNI:            c.disableSNI,
		verifyServerName:      c.verifyServerName,
		handshakeTimeout:      c.handshakeTimeout,
		id:                    c.id,
		sessionIDGenerator:    c.sessionIDGenerator,
		fragment:              c.fragment,
		fragmentFallbackDelay: c.fragmentFallbackDelay,
		recordFragment:        c.recordFragment,
		spoof:                 c.spoof,
		spoofMethod:           c.spoofMethod,
	}
	cloned.SetServerName(cloned.serverName)
	return cloned
}

func (c *UTLSClientConfig) ECHConfigList() []byte {
	return c.config.EncryptedClientHelloConfigList
}

func (c *UTLSClientConfig) SetECHConfigList(EncryptedClientHelloConfigList []byte) {
	c.config.EncryptedClientHelloConfigList = EncryptedClientHelloConfigList
}

type utlsConnWrapper struct {
	*utls.UConn
}

func (c *utlsConnWrapper) ConnectionState() tls.ConnectionState {
	state := c.Conn.ConnectionState()
	//nolint:staticcheck
	return tls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		CurveID:                     tls.CurveID(state.CurveID),
		ECHAccepted:                 state.ECHAccepted,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
	}
}

func (c *utlsConnWrapper) Upstream() any {
	return c.UConn
}

func (c *utlsConnWrapper) ReaderReplaceable() bool {
	return c.ConnectionState().HandshakeComplete
}

func (c *utlsConnWrapper) WriterReplaceable() bool {
	return c.ConnectionState().HandshakeComplete
}

// Preparation uses public UConn state and Conn.HandshakeContext. Calling the
// latter after preparation deliberately avoids UConn's second BuildHandshakeState,
// which would regenerate an ECH outer hello after the ShadowTLS authenticator.
// Conn retains uTLS's installed handshakeFn, cancellation, verification and locks.
type utlsALPNWrapper struct {
	utlsConnWrapper
	nextProtocols      []string
	sessionIDGenerator func([]byte, []byte) error
	realECH            bool
	handshakeMu        sync.Mutex
	handshakeComplete  atomic.Bool
}

func (c *utlsALPNWrapper) HandshakeContext(ctx context.Context) (ret error) {
	if c.handshakeComplete.Load() {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Install cancellation before waiting for preparation. A canceled concurrent
	// caller must not remain blocked behind another connection handshake.
	stop := context.AfterFunc(ctx, func() { _ = c.NetConn().Close() })
	defer func() {
		if !stop() {
			ret = ctx.Err()
		}
	}()
	c.handshakeMu.Lock()
	defer c.handshakeMu.Unlock()
	if c.handshakeComplete.Load() {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	if c.sessionIDGenerator != nil && c.realECH {
		return E.New("ShadowTLS session ID authentication cannot be combined with real ECH")
	}
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	if len(c.nextProtocols) > 0 {
		for _, extension := range c.Extensions {
			if alpn, ok := extension.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = c.nextProtocols
				break
			}
		}
		if err := c.BuildHandshakeState(); err != nil {
			return err
		}
	}
	if c.sessionIDGenerator != nil {
		hello := c.HandshakeState.Hello
		hello.SessionId = make([]byte, 32)
		if err := c.MarshalClientHello(); err != nil {
			return err
		}
		if err := c.sessionIDGenerator(hello.Raw, hello.SessionId); err != nil {
			return E.Cause(err, "generate TLS session ID")
		}
		if err := c.MarshalClientHello(); err != nil {
			return err
		}
	}
	ret = c.Conn.HandshakeContext(ctx)
	if ret == nil {
		c.handshakeComplete.Store(true)
	}
	return ret
}

func (c *utlsALPNWrapper) Handshake() error {
	return c.HandshakeContext(context.Background())
}

func (c *utlsALPNWrapper) Read(b []byte) (int, error) {
	if err := c.HandshakeContext(context.Background()); err != nil {
		return 0, err
	}
	return c.UConn.Read(b)
}

func (c *utlsALPNWrapper) Write(b []byte) (int, error) {
	if err := c.HandshakeContext(context.Background()); err != nil {
		return 0, err
	}
	return c.UConn.Write(b)
}

func NewUTLSClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions) (Config, error) {
	return newUTLSClient(ctx, logger, serverAddress, options, false)
}

func newUTLSClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions, allowEmptyServerName bool) (Config, error) {
	var serverName string
	if options.ServerName != "" {
		serverName = options.ServerName
	} else if serverAddress != "" {
		serverName = serverAddress
	}
	if serverName == "" && !options.Insecure && !allowEmptyServerName {
		return nil, errMissingServerName
	}

	if len(options.CurvePreferences) > 0 {
		return nil, E.New("curve_preferences is unsupported with uTLS; key exchange groups belong to the selected fingerprint")
	}
	var tlsConfig utls.Config
	tlsConfig.Time = ntp.TimeFuncFromContext(ctx)
	tlsConfig.RootCAs = adapter.RootPoolFromContext(ctx)
	if options.Insecure {
		tlsConfig.InsecureSkipVerify = options.Insecure
	} else if options.DisableSNI {
		if options.Reality != nil && options.Reality.Enabled {
			return nil, E.New("disable_sni is unsupported in reality")
		}
	}
	if len(options.CertificateSHA256) > 0 || len(options.CertificatePublicKeySHA256) > 0 {
		if len(options.Certificate) > 0 || options.CertificatePath != "" {
			return nil, E.New("certificate_sha256 or certificate_public_key_sha256 is conflict with certificate or certificate_path")
		}
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return VerifyPinnedCertificate(options.CertificateSHA256, options.CertificatePublicKeySHA256, rawCerts)
		}
	}
	if len(options.ALPN) > 0 {
		tlsConfig.NextProtos = options.ALPN
	}
	if options.MinVersion != "" {
		minVersion, err := ParseTLSVersion(options.MinVersion)
		if err != nil {
			return nil, E.Cause(err, "parse min_version")
		}
		tlsConfig.MinVersion = minVersion
	}
	if options.MaxVersion != "" {
		maxVersion, err := ParseTLSVersion(options.MaxVersion)
		if err != nil {
			return nil, E.Cause(err, "parse max_version")
		}
		tlsConfig.MaxVersion = maxVersion
	}
	if options.CipherSuites != nil {
	find:
		for _, cipherSuite := range options.CipherSuites {
			for _, tlsCipherSuite := range tls.CipherSuites() {
				if cipherSuite == tlsCipherSuite.Name {
					tlsConfig.CipherSuites = append(tlsConfig.CipherSuites, tlsCipherSuite.ID)
					continue find
				}
			}
			return nil, E.New("unknown cipher_suite: ", cipherSuite)
		}
	}
	var certificate []byte
	if len(options.Certificate) > 0 {
		certificate = []byte(strings.Join(options.Certificate, "\n"))
	} else if options.CertificatePath != "" {
		content, err := filemanager.ReadFile(ctx, options.CertificatePath)
		if err != nil {
			return nil, E.Cause(err, "read certificate")
		}
		certificate = content
	}
	if len(certificate) > 0 {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(certificate) {
			return nil, E.New("failed to parse certificate:\n\n", string(certificate))
		}
		tlsConfig.RootCAs = certPool
	}
	var clientCertificate []byte
	if len(options.ClientCertificate) > 0 {
		clientCertificate = []byte(strings.Join(options.ClientCertificate, "\n"))
	} else if options.ClientCertificatePath != "" {
		content, err := filemanager.ReadFile(ctx, options.ClientCertificatePath)
		if err != nil {
			return nil, E.Cause(err, "read client certificate")
		}
		clientCertificate = content
	}
	var clientKey []byte
	if len(options.ClientKey) > 0 {
		clientKey = []byte(strings.Join(options.ClientKey, "\n"))
	} else if options.ClientKeyPath != "" {
		content, err := filemanager.ReadFile(ctx, options.ClientKeyPath)
		if err != nil {
			return nil, E.Cause(err, "read client key")
		}
		clientKey = content
	}
	if len(clientCertificate) > 0 && len(clientKey) > 0 {
		keyPair, err := utls.X509KeyPair(clientCertificate, clientKey)
		if err != nil {
			return nil, E.Cause(err, "parse client x509 key pair")
		}
		tlsConfig.Certificates = []utls.Certificate{keyPair}
	} else if len(clientCertificate) > 0 || len(clientKey) > 0 {
		return nil, E.New("client certificate and client key must be provided together")
	}
	var handshakeTimeout time.Duration
	if options.HandshakeTimeout > 0 {
		handshakeTimeout = options.HandshakeTimeout.Build()
	} else {
		handshakeTimeout = C.TCPTimeout
	}
	spoof, spoofMethod, err := parseTLSSpoofOptions(serverName, options)
	if err != nil {
		return nil, err
	}
	id, err := uTLSClientHelloID(options.UTLS.Fingerprint)
	if err != nil {
		return nil, err
	}
	var config Config = &UTLSClientConfig{
		ctx:                   ctx,
		config:                &tlsConfig,
		serverName:            serverName,
		disableSNI:            options.DisableSNI,
		verifyServerName:      options.DisableSNI && !options.Insecure,
		handshakeTimeout:      handshakeTimeout,
		id:                    id,
		fragment:              options.Fragment,
		fragmentFallbackDelay: time.Duration(options.FragmentFallbackDelay),
		recordFragment:        options.RecordFragment,
		spoof:                 spoof,
		spoofMethod:           spoofMethod,
	}
	config.SetServerName(serverName)
	if options.ECH != nil && options.ECH.Enabled {
		if options.Reality != nil && options.Reality.Enabled {
			return nil, E.New("Reality is conflict with ECH")
		}
		config, err = parseECHClientConfig(ctx, config.(ECHCapableConfig), options)
		if err != nil {
			return nil, err
		}
	}
	if (options.KernelRx || options.KernelTx) && !common.PtrValueOrDefault(options.Reality).Enabled {
		if !C.IsLinux {
			return nil, E.New("kTLS is only supported on Linux")
		}
		config = &KTLSClientConfig{
			Config:   config,
			logger:   logger,
			kernelTx: options.KernelTx,
			kernelRx: options.KernelRx,
		}
	}
	return config, nil
}

var (
	randomFingerprint     utls.ClientHelloID
	randomizedFingerprint utls.ClientHelloID
)

func init() {
	modernFingerprints := []utls.ClientHelloID{
		utls.HelloChrome_Auto,
		utls.HelloFirefox_Auto,
		utls.HelloEdge_Auto,
		utls.HelloSafari_Auto,
		utls.HelloIOS_Auto,
	}
	randomFingerprint = modernFingerprints[rand.Intn(len(modernFingerprints))]

	weights := utls.DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	weights.FirstKeyShare_Set_CurveP256 = 0
	randomizedFingerprint = utls.HelloRandomized
	randomizedFingerprint.Seed, _ = utls.NewPRNGSeed()
	randomizedFingerprint.Weights = &weights
}

func uTLSClientHelloID(name string) (utls.ClientHelloID, error) {
	if name == "" {
		name = "chrome"
	}
	if name == "random" {
		return randomFingerprint, nil
	}
	if name == "randomized" {
		return randomizedFingerprint, nil
	}
	for _, profile := range utlsProfiles {
		if profile.ID == name {
			return profile.Hello, nil
		}
	}
	for _, alias := range utlsLegacyAliases {
		if alias == name {
			return utls.HelloChrome_Auto, nil
		}
	}
	return utls.ClientHelloID{}, E.New("unknown uTLS fingerprint: ", name)
}
