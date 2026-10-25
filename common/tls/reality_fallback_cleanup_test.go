//go:build with_utls

package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	utls "github.com/refraction-networking/utls"
)

func TestRuntimeTLSFailureRefractionOriginalPendingNegative(t *testing.T) {
	raw := newRuntimeFailureRaw()
	guarded, inner := outbound.WrapRuntimeOwnedConn(raw)
	transport := &runtimeHandshakeConn{Conn: guarded, fence: inner}
	// Actual pinned refraction UConn, without a handshake. This independently
	// proves its opaque Close contract; the next test covers real TLS/H2 fallback.
	provider := utls.UClient(transport, &utls.Config{}, utls.HelloChrome_Auto)
	_, outer := outbound.WrapRuntimeOwnedConn(provider)
	first := outer.RuntimeCloseAndWait()
	if !IsRuntimeCleanupIncomplete(first) {
		t.Fatalf("old path did not retain intermediate pending: %v", first)
	}
	if err := inner.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
	if outer.RuntimeCloseAndWait() != first || raw.closes.Load() != 1 {
		t.Fatal("old sticky close mechanism differs")
	}
}

func TestRuntimeTLSFailureRefractionPairBeforeAndAfterClose(t *testing.T) {
	for _, early := range []bool{false, true} {
		raw := newRuntimeFailureRaw()
		guarded, inner := outbound.WrapRuntimeOwnedConn(raw)
		transport := &runtimeHandshakeConn{Conn: guarded, fence: inner}
		provider := utls.UClient(transport, &utls.Config{}, utls.HelloChrome_Auto)
		if early {
			_ = provider.Close()
		}
		cause := errors.New("controlled provider authentication failure")
		if err := runtimeProviderFailure(provider, transport, cause); err != cause {
			t.Fatal(err)
		}
		if raw.closes.Load() != 1 {
			t.Fatal("physical close count differs")
		}
	}
}

// Root trust is process-global in crypto/x509. Isolate the temporary fallback
// root to this one child test; never change host trust or weaken verification.
func TestRuntimeTLSFailureRealityTrustedFallbackAndAdmission(t *testing.T) {
	const childKey = "POLARIS_TEST_REALITY_TRUSTED_FALLBACK_CHILD"
	if os.Getenv(childKey) != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, executable, "-test.run=^TestRuntimeTLSFailureRealityTrustedFallbackAndAdmission$", "-test.v", "-test.timeout=15s")
		cmd.Env = append(os.Environ(), childKey+"=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated trusted fallback: %v\n%s", err, output)
		}
		if !strings.Contains(string(output), "REALITY_FALLBACK_OLD_RETAINS_NEW_RELEASES") {
			t.Fatal("child did not prove both real fallback paths")
		}
		t.Log("isolated child: real refraction TLS1.3/H2 fallback, old opaque reservation retained, new reservation released")
		return
	}
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",x509usefallbackroots=1")
	cert := newPinnedTestCertificate(t, "localhost")
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	x509.SetFallbackRoots(roots)
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.TLS == nil || r.TLS.Version != stdtls.VersionTLS13 {
			t.Error("fallback did not use real H2/TLS1.3")
		}
		requests.Add(1)
		_, _ = io.WriteString(w, "controlled fallback only")
	}))
	server.EnableHTTP2 = true
	server.TLS = &stdtls.Config{Certificates: []stdtls.Certificate{cert.Certificate}, MinVersion: stdtls.VersionTLS13, MaxVersion: stdtls.VersionTLS13, CurvePreferences: []stdtls.CurveID{stdtls.X25519}}
	server.StartTLS()
	defer server.Close()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, legacy := range []bool{true, false} {
		before := requests.Load()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		config, err := NewRealityClient(ctx, logger.NOP(), "localhost", option.OutboundTLSOptions{
			ServerName: "localhost", ALPN: []string{"h2"},
			UTLS:    &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome_155"},
			Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), ShortID: "21"},
		})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		actual := config.(interface {
			ClientHandshake(context.Context, net.Conn) (Conn, error)
		})
		wrapper := &runtimeFailureConfig{handshake: func(ctx context.Context, conn net.Conn) (Conn, error) {
			if legacy {
				raw, ok := conn.(*runtimeHandshakeConn)
				if !ok {
					t.Fatal("missing exact raw constructor carrier")
				}
				// Exact old construction shape: no private completion token. All provider,
				// fallback HTTP2, physical-carrier and admission code stays production.
				conn = &runtimeHandshakeConn{Conn: raw.Conn}
			}
			return actual.ClientHandshake(ctx, conn)
		}}
		var ownerCloses atomic.Int32
		source, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "actual-reality-failed-admission", Sequence: 1}, nil, func() error { ownerCloses.Add(1); return nil })
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		var physical *realityVisionObservedConn
		connected, err := outbound.DialRuntimeConn(ctx, source, func(ctx context.Context) (net.Conn, error) {
			raw, e := (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			if e != nil {
				return nil, e
			}
			_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
			physical = &realityVisionObservedConn{Conn: raw}
			return clientHandshakeOwned(ctx, physical, wrapper)
		})
		cancel()
		if connected != nil || err == nil {
			t.Fatal("non-Reality peer admitted as a valid proxy")
		}
		if requests.Load() != before+1 {
			t.Fatalf("real fallback GET not observed exactly once: %d", requests.Load()-before)
		}
		snapshot := source.CleanupSnapshot()
		if !snapshot.Available {
			t.Fatal("quiescent owner snapshot unavailable")
		}
		source.Seal()
		waitLimit := 2 * time.Second
		if legacy {
			waitLimit = 50 * time.Millisecond
		}
		observer, stop := context.WithTimeout(context.Background(), waitLimit)
		closedErr := source.WaitClosed(observer)
		stop()
		if legacy {
			if !IsRuntimeCleanupIncomplete(err) || snapshot.References != 1 || !errors.Is(closedErr, context.DeadlineExceeded) || ownerCloses.Load() != 0 {
				t.Fatalf("old failed admission not reproduced: %v refs=%d drain=%v", err, snapshot.References, closedErr)
			}
		} else if !errors.Is(err, errRealityVerification) || IsRuntimeCleanupIncomplete(err) || snapshot.References != 0 || closedErr != nil || ownerCloses.Load() != 1 {
			t.Fatalf("new failure cause/cleanup/ref mismatch: %v refs=%d drain=%v", err, snapshot.References, closedErr)
		}
		if physical == nil || physical.closes.Load() != 1 {
			t.Fatal("real raw connection not closed exactly once")
		}
	}
	t.Log("REALITY_FALLBACK_OLD_RETAINS_NEW_RELEASES")
}

func TestRuntimeTLSFailureActualStandardAndUTLSCancellation(t *testing.T) {
	for _, useUTLS := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		options := option.OutboundTLSOptions{Enabled: true, ServerName: "localhost"}
		if useUTLS {
			options.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome_155"}
		}
		config, err := NewClient(ctx, logger.NOP(), "localhost", options)
		if err != nil {
			t.Fatal(err)
		}
		client, server := net.Pipe()
		source := new(runtimeFailureSource)
		done := make(chan error, 1)
		go func() {
			_, e := outbound.DialRuntimeConn(ctx, source, func(ctx context.Context) (net.Conn, error) { return clientHandshakeOwned(ctx, client, config) })
			done <- e
		}()
		// Consume a real ClientHello so cancellation interrupts an active handshake,
		// not merely the initial context precondition. No credentials/remote peer.
		hello := make([]byte, 65536)
		_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err = server.Read(hello); err != nil {
			cancel()
			client.Close()
			server.Close()
			t.Fatal(err)
		}
		cancel()
		select {
		case err = <-done:
		case <-time.After(3 * time.Second):
			client.Close()
			server.Close()
			t.Fatal("active handshake cancellation did not join")
		}
		server.Close()
		if !errors.Is(err, context.Canceled) || IsRuntimeCleanupIncomplete(err) || source.refs.Load() != 0 {
			t.Fatalf("cancellation cleanup/cause differs: %v refs=%d", err, source.refs.Load())
		}
	}
}

func TestRuntimeTLSFailureRealityUntrustedBeforeFallback(t *testing.T) {
	cert := newPinnedTestCertificate(t, "localhost")
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	server.EnableHTTP2 = true
	server.TLS = &stdtls.Config{Certificates: []stdtls.Certificate{cert.Certificate}, MinVersion: stdtls.VersionTLS13, MaxVersion: stdtls.VersionTLS13, CurvePreferences: []stdtls.CurveID{stdtls.X25519}}
	server.StartTLS()
	defer server.Close()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	config, err := NewRealityClient(ctx, logger.NOP(), "localhost", option.OutboundTLSOptions{
		ServerName: "localhost", ALPN: []string{"h2"}, UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome_155"},
		Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), ShortID: "21"},
	})
	if err != nil {
		t.Fatal(err)
	}
	source := new(runtimeFailureSource)
	_, err = outbound.DialRuntimeConn(ctx, source, func(ctx context.Context) (net.Conn, error) {
		raw, e := (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
		if e != nil {
			return nil, e
		}
		return clientHandshakeOwned(ctx, raw, config)
	})
	var untrusted x509.UnknownAuthorityError
	if !errors.As(err, &untrusted) || IsRuntimeCleanupIncomplete(err) || source.refs.Load() != 0 || requests.Load() != 0 {
		t.Fatalf("untrusted TLS reached fallback or retained admission: %v refs=%d requests=%d", err, source.refs.Load(), requests.Load())
	}
}
