package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	stdTLS "crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	aTLS "github.com/sagernet/sing/common/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

func apiTestCertificate(t *testing.T) (option.InboundTLSOptions, *x509.CertPool) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	privateKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(certificate)) {
		t.Fatal("fixture certificate")
	}
	return option.InboundTLSOptions{Enabled: true, Certificate: []string{certificate}, Key: []string{privateKey}}, roots
}

type apiTLSCloseObserver struct {
	tls.ServerConfig
	closes    atomic.Int32
	stallPeer atomic.Value
	stallRead chan struct{}
}

func (c *apiTLSCloseObserver) Close() error { c.closes.Add(1); return c.ServerConfig.Close() }

func (c *apiTLSCloseObserver) Server(raw net.Conn) (aTLS.Conn, error) {
	return c.ServerConfig.Server(&apiTLSReadObserver{Conn: raw, owner: c})
}

type apiTLSReadObserver struct {
	net.Conn
	owner *apiTLSCloseObserver
}

func (c *apiTLSReadObserver) Read(p []byte) (int, error) {
	if watched := c.owner.stallPeer.Load(); watched != nil && watched.(string) == c.RemoteAddr().String() {
		select {
		case c.owner.stallRead <- struct{}{}:
		default:
		}
	}
	return c.Conn.Read(p)
}

func TestRuntimeAPIInitialTLSKeepsRealGRPCAndRejectsPlaintext(t *testing.T) {
	options, roots := apiTestCertificate(t)
	instance, api, _ := newHandoffBox(t, "tls-secret", options)
	observer := &apiTLSCloseObserver{ServerConfig: api.tlsConfig, stallRead: make(chan struct{}, 1)}
	api.tlsConfig = observer
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancelRPC := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancelRPC)
	if api.runtime != nil || api.legacy == nil {
		t.Fatal("initial TLS must use its real legacy ingress, without a runtime grant")
	}
	address := api.listener.TCPListener().Addr().String()
	conn, err := grpc.NewClient(address,
		grpc.WithTransportCredentials(credentials.NewTLS(&stdTLS.Config{RootCAs: roots, ServerName: "localhost", MinVersion: stdTLS.VersionTLS12})),
		grpc.WithUnaryInterceptor(daemon.NewClientAuthUnaryInterceptor("tls-secret")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := daemon.NewStartedServiceClient(conn)
	version, err := client.GetVersion(ctx, &emptypb.Empty{})
	if err != nil || version.GetVersion() == "" {
		t.Fatalf("real initial TLS version RPC: %v", err)
	}
	plainConn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithUnaryInterceptor(daemon.NewClientAuthUnaryInterceptor("tls-secret")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plainConn.Close() })
	plainCtx, cancel := context.WithTimeout(ctx, time.Second)
	_, err = daemon.NewStartedServiceClient(plainConn).GetVersion(plainCtx, &emptypb.Empty{})
	cancel()
	if err == nil {
		t.Fatal("configured TLS silently served authenticated h2c")
	}
	badPeer := &stdTLS.Config{RootCAs: x509.NewCertPool(), ServerName: "localhost", MinVersion: stdTLS.VersionTLS12}
	if peer, err := stdTLS.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, badPeer); err == nil {
		_ = peer.Close()
		t.Fatal("untrusted TLS peer succeeded")
	}
	// Keep a real incomplete ClientHello in net/http's read loop. Closing the
	// owner must join that loop as well as already-dispatched gRPC handlers.
	stalled, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stalled.Close() })
	observer.stallPeer.Store(stalled.LocalAddr().String())
	if _, err := stalled.Write([]byte{0x16, 0x03, 0x03, 0, 5}); err != nil {
		t.Fatal(err)
	}
	// Accept alone is insufficient: a Close that wrongly waits for the
	// handshake lock can pass if the read loop has not entered it yet.
	dashboardWait(t, observer.stallRead, "real TLS handshake entered its physical Read")
	endpoint := api.legacy
	deadline := time.Now().Add(5 * time.Second)
	for {
		found := false
		endpoint.mu.Lock()
		for carrier := range endpoint.conns {
			found = found || carrier.RemoteAddr().String() == stalled.LocalAddr().String()
		}
		endpoint.mu.Unlock()
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("real TLS carrier was not accepted")
		}
		time.Sleep(time.Millisecond)
	}
	if err := instance.CloseWithResult(); err != nil {
		t.Fatal(err)
	}
	if observer.closes.Load() != 1 {
		t.Fatal("TLS provider not closed exactly once")
	}
	dashboardWait(t, endpoint.serveDone, "TLS owner and read/handshake workers joined")
	_ = stalled.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := stalled.Read(make([]byte, 1)); err == nil {
		t.Fatal("stalled TLS carrier remained open")
	}
}

func TestRuntimeAPILegacyTLSWatcherWarningKeepsCachedCertificateAndJoinsStop(t *testing.T) {
	options, roots := apiTestCertificate(t)
	certificatePath := filepath.Join(t.TempDir(), "certificate.pem")
	if err := os.WriteFile(certificatePath, []byte(options.Certificate[0]), 0o600); err != nil {
		t.Fatal(err)
	}
	options.Certificate, options.CertificatePath = nil, certificatePath
	logPath := filepath.Join(t.TempDir(), "tls.log")
	instance, api, _ := newHandoffBoxWithLog(t, "tls-secret", &option.LogOptions{Level: "warn", Output: logPath, DisableColor: true}, options)
	observer := &apiTLSCloseObserver{ServerConfig: api.tlsConfig}
	api.tlsConfig = observer
	// Rotation watches the containing directory, so removing only the file
	// legitimately remains watchable. Remove this fixture's exclusive parent
	// too: native Add on that required target must fail during the real Start.
	// Legacy initial TLS deliberately warns and retains its parsed certificate;
	// it has no runtime grant that would make this watcher failure fatal.
	if err := os.Remove(certificatePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Dir(certificatePath)); err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatalf("legacy watcher warning prevented startup: %v", err)
	}
	warning, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(strings.ToUpper(string(warning)), "WARN") || !strings.Contains(string(warning), "create fsnotify watcher:") {
		t.Fatalf("real legacy watcher warning missing: %q %v", warning, err)
	}
	t.Logf("observed native watcher warning: %s", strings.TrimSpace(string(warning)))
	if _, err := os.Stat(certificatePath); !os.IsNotExist(err) {
		t.Fatalf("removed certificate unexpectedly available: %v", err)
	}
	if api.runtime != nil || api.legacy == nil || observer.closes.Load() != 0 {
		t.Fatal("legacy warning changed eligibility or closed the live TLS config")
	}
	address := api.listener.TCPListener().Addr().String()
	conn, err := grpc.NewClient(address,
		grpc.WithTransportCredentials(credentials.NewTLS(&stdTLS.Config{RootCAs: roots, ServerName: "localhost", MinVersion: stdTLS.VersionTLS12})),
		grpc.WithUnaryInterceptor(daemon.NewClientAuthUnaryInterceptor("tls-secret")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	version, err := daemon.NewStartedServiceClient(conn).GetVersion(ctx, &emptypb.Empty{})
	if err != nil || version.GetVersion() == "" {
		t.Fatalf("authenticated TLS RPC did not use cached certificate: %v", err)
	}
	endpoint := api.legacy
	endpoint.mu.Lock()
	accepted := len(endpoint.conns)
	endpoint.mu.Unlock()
	if accepted == 0 {
		t.Fatal("cached-certificate RPC did not retain its actual owned carrier")
	}
	if err := instance.CloseWithResult(); err != nil {
		t.Fatal(err)
	}
	dashboardWait(t, endpoint.serveDone, "legacy warning server and owned TLS read tails joined")
	endpoint.mu.Lock()
	remaining := len(endpoint.conns)
	endpoint.mu.Unlock()
	if observer.closes.Load() != 1 || remaining != 0 {
		t.Fatalf("legacy stop did not close TLS config/carriers: closes=%d carriers=%d", observer.closes.Load(), remaining)
	}
	requireNotAccepting(t, address)
	t.Log("cached certificate authenticated RPC completed; Stop joined owned server/carriers and closed TLS config exactly once")
}

func TestRuntimeAPIRealTLSProviderStartFailureClosesBeforeReturning(t *testing.T) {
	// A missing shared provider is constructed through the ordinary legacy
	// TLS path, then fails in sharedCertificateProvider.Start. Unlike a watcher
	// warning, this real TLS Start error must unwind the registered cleanup.
	options := option.InboundTLSOptions{Enabled: true, CertificateProvider: &option.CertificateProviderOptions{Tag: "api-missing-provider"}}
	instance, api, _ := newHandoffBox(t, "tls-secret", options)
	observer := &apiTLSCloseObserver{ServerConfig: api.tlsConfig}
	api.tlsConfig = observer
	err := instance.Start()
	if err == nil || !strings.Contains(err.Error(), "create TLS config") || !strings.Contains(err.Error(), "certificate provider not found: api-missing-provider") {
		t.Fatalf("real shared-provider Start failure lost: %v", err)
	}
	if api.runtime != nil || observer.closes.Load() != 1 || api.listener.TCPListener() != nil || api.legacy != nil {
		t.Fatal("failed legacy TLS Start retained config or published a listener/serve worker")
	}
	if err := instance.CloseWithResult(); err != nil || observer.closes.Load() != 1 {
		t.Fatalf("failed Start cleanup was not complete and idempotent: %v closes=%d", err, observer.closes.Load())
	}
	t.Logf("real TLS Start failure observed, cleanup complete before return and no listener/serve worker published: %v", err)
}

func TestRuntimeAPIHotTLSRemainsUnsupported(t *testing.T) {
	_, api, ctx, content := handoffBox(t, "plain")
	client := handoffClient(t, api.listener.TCPListener().Addr().String(), "plain")
	caps, err := client.GetRuntimeCapabilities(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	options, _ := apiTestCertificate(t)
	wire, err := json.Marshal(options)
	if err != nil {
		t.Fatal(err)
	}
	candidate := strings.Replace(content, `"listen_port":0,`, `"listen_port":0,"tls":`+string(wire)+`,`, 1)
	if candidate == content {
		t.Fatal("TLS change absent")
	}
	plan, err := client.PlanRuntimeConfig(ctx, &daemon.PlanRuntimeConfigRequest{ContractVersion: 1, Expected: caps.Active, ExpectedControlRevision: caps.ControlRevision, ConfigContent: candidate})
	if err != nil || plan.GetApplicable() || len(plan.GetErrors()) == 0 {
		t.Fatalf("hot TLS contract: %v %+v", err, plan)
	}
	for _, issue := range plan.Errors {
		if issue.Code != "RESTART_REQUIRED" {
			t.Fatalf("unexpected TLS refusal: %+v", issue)
		}
	}
}

// Pause only after the real TLS implementation completed the handshake. The
// stop goroutine and successful wrapper publication race after the same gate;
// neither side is ordered after the other's Conn access.
type apiSuccessfulHandshakeGate struct {
	tls.ServerConfig
	arrived chan struct{}
	release <-chan struct{}
}

func (c *apiSuccessfulHandshakeGate) Server(raw net.Conn) (aTLS.Conn, error) {
	conn, err := c.ServerConfig.Server(raw)
	if err != nil {
		return nil, err
	}
	return &apiSuccessfulHandshakeConn{Conn: conn, arrived: c.arrived, release: c.release}, nil
}

type apiSuccessfulHandshakeConn struct {
	aTLS.Conn
	arrived chan<- struct{}
	release <-chan struct{}
}

func (c *apiSuccessfulHandshakeConn) HandshakeContext(ctx context.Context) error {
	if err := c.Conn.HandshakeContext(ctx); err != nil {
		return err
	}
	c.arrived <- struct{}{}
	select {
	case <-c.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestRuntimeAPIRealSuccessfulTLSHandshakeOverlapsStopAndJoins(t *testing.T) {
	options, roots := apiTestCertificate(t)
	instance, api, _ := newHandoffBox(t, "tls-secret", options)
	release := make(chan struct{})
	var releaseOnce sync.Once
	open := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(open)
	const peers = 8
	gate := &apiSuccessfulHandshakeGate{ServerConfig: api.tlsConfig, arrived: make(chan struct{}, peers), release: release}
	api.tlsConfig = gate
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	address := api.listener.TCPListener().Addr().String()
	clients := make([]*stdTLS.Conn, 0, peers)
	for range peers {
		peer, err := stdTLS.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, &stdTLS.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{"h2"}})
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, peer)
		t.Cleanup(func() { _ = peer.Close() })
	}
	for range peers {
		select {
		case <-gate.arrived:
		case <-time.After(5 * time.Second):
			t.Fatal("real successful TLS handshake did not reach stop overlap")
		}
	}
	stopped := make(chan error, 1)
	go func() { <-release; stopped <- instance.CloseWithResult() }()
	open()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stop failed to join successful TLS handshake/read tails")
	}
	dashboardWait(t, api.legacy.serveDone, "successful TLS/Stop overlap server joined")
	for _, peer := range clients {
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := peer.Read(make([]byte, 1)); err == nil {
			t.Fatal("TLS carrier survived joined stop")
		}
	}
}

type apiTLSStartBarrier struct {
	tls.ServerConfig
	entered, stop, done chan struct{}
	once                sync.Once
}

func (c *apiTLSStartBarrier) Start() error {
	close(c.entered)
	defer close(c.done)
	<-c.stop
	return errors.New("TLS start stopped")
}

func (c *apiTLSStartBarrier) Close() error { c.once.Do(func() { close(c.stop) }); <-c.done; return nil }

func TestRuntimeAPIStopJoinsAnInFlightTLSStart(t *testing.T) {
	_, api, _ := newHandoffBox(t, "tls-secret")
	provider := &apiTLSStartBarrier{entered: make(chan struct{}), stop: make(chan struct{}), done: make(chan struct{})}
	api.tlsConfig = provider
	scope := adapter.NewScope(context.Background(), api.logger)
	t.Cleanup(func() { _ = scope.Close() })
	started := make(chan error, 1)
	go func() { started <- api.Start(adapter.StartStateStarted, scope) }()
	dashboardWait(t, provider.entered, "real TLS Start task entered")
	// Even the old wrong wait-before-Close order must fail without leaving
	// this regression's provider task stuck in a test cleanup.
	t.Cleanup(func() { _ = provider.Close() })
	closed := make(chan error, 1)
	go func() { closed <- api.runtime.close() }()
	dashboardWait(t, provider.done, "TLS Close unblocked and joined Start")
	select {
	case err := <-started:
		if err == nil {
			t.Fatal("stopped Start succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("API Start worker not joined")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("API close waited before closing partial TLS provider")
	}
	if api.listener.TCPListener() != nil {
		t.Fatal("stopped TLS start published listener")
	}
}
