//go:build with_utls

package tls

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"

	meta "github.com/metacubex/utls"
	utls "github.com/refraction-networking/utls"
)

type realityHandshakeCase struct {
	profile                string
	wrongKey               bool
	clientALPN, serverALPN []string
	camouflageALPN         []string
	cloneALPN              []string
	negotiated             string
	reject                 bool
	vision, owned          bool
}

// Authentication alone did not cover Vision's concrete provider adapter. These
// cases use the real refraction REALITY wrapper, Meta server and (optionally)
// the exact scoped runtime inspection/fences before an inner TLS1.3 exchange.
func TestRealityVisionActualHandshakeAndDirect(t *testing.T) {
	for _, profile := range []string{"chrome_155", "safari_26_3"} {
		for _, owned := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/owned-%v", profile, owned), func(t *testing.T) {
				realityHandshakeExchange(t, realityHandshakeCase{profile: profile, vision: true, owned: owned})
			})
		}
	}
}

func TestRealityVisionRejectsWrongKeyBeforePayload(t *testing.T) {
	realityHandshakeExchange(t, realityHandshakeCase{profile: "chrome_155", vision: true, owned: true, wrongKey: true, reject: true})
}

func realityVisionStream(ctx context.Context, secured Conn, certificate pinnedTestCertificate, server bool) (net.Conn, *vless.VisionConn, error) {
	var vision *vless.VisionConn
	err := WithRuntimeTLSInspection(secured, func(native net.Conn) error {
		var err error
		vision, err = vless.NewVisionConn(secured, native, [16]byte{3, 7, 11}, logger.NOP())
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	runtime.GC()
	var inner *stdtls.Conn
	if server {
		inner = stdtls.Server(vision, &stdtls.Config{Certificates: []stdtls.Certificate{certificate.Certificate}, MinVersion: stdtls.VersionTLS13})
	} else {
		roots := x509.NewCertPool()
		roots.AddCert(certificate.Leaf)
		inner = stdtls.Client(vision, &stdtls.Config{ServerName: "localhost", RootCAs: roots, MinVersion: stdtls.VersionTLS13})
	}
	return inner, vision, inner.HandshakeContext(ctx)
}

func realityVisionWasDirect(vision *vless.VisionConn) bool {
	// Test-only observation of the actual pinned algorithm, not a replacement
	// constructor/mocked success. Both network directions must have switched.
	value := reflect.ValueOf(vision).Elem()
	return value.FieldByName("directRead").Bool() && value.FieldByName("directWrite").Bool()
}

// Controlled TLS1.3 camouflage plus the actual Meta REALITY server and the real
// refraction client. Payload admission and the observed wire are both checked.
func TestRealityUpstreamClientMetaServerActualHandshake(t *testing.T) {
	for _, tc := range []realityHandshakeCase{
		{profile: "chrome_155"}, {profile: "safari_26_3"}, {profile: "chrome_155", wrongKey: true, reject: true},
	} {
		t.Run(fmt.Sprintf("%s/wrong-key-%v", tc.profile, tc.wrongKey), func(t *testing.T) { realityHandshakeExchange(t, tc) })
	}
}

func TestRealityExplicitALPNWireAndClone(t *testing.T) {
	for _, tc := range []struct {
		name string
		realityHandshakeCase
	}{
		{"http1-only", realityHandshakeCase{profile: "chrome_155", clientALPN: []string{"http/1.1"}, serverALPN: []string{"h2", "http/1.1"}, negotiated: "http/1.1"}},
		{"custom", realityHandshakeCase{profile: "safari_26_3", clientALPN: []string{"polaris-test/1"}, serverALPN: []string{"polaris-test/1"}, negotiated: "polaris-test/1"}},
		{"mismatch", realityHandshakeCase{profile: "chrome_155", clientALPN: []string{"client-only/1"}, serverALPN: []string{"server-only/1"}, camouflageALPN: []string{"client-only/1"}, reject: true}},
		{"server-policy-independent-of-camouflage", realityHandshakeCase{profile: "chrome_155", clientALPN: []string{"h2", "http/1.1"}, serverALPN: []string{"http/1.1", "h2"}, camouflageALPN: []string{"h2", "http/1.1"}, negotiated: "http/1.1"}},
		{"server-long-alpn-exceeds-camouflage", realityHandshakeCase{profile: "chrome_155", clientALPN: []string{"h2", strings.Repeat("p", 200)}, serverALPN: []string{strings.Repeat("p", 200)}, camouflageALPN: []string{"h2"}, negotiated: strings.Repeat("p", 200)}},
		{"server-shorter-alpn-keeps-camouflage-budget", realityHandshakeCase{profile: "chrome_155", clientALPN: []string{"h2", strings.Repeat("p", 200)}, serverALPN: []string{"h2"}, camouflageALPN: []string{strings.Repeat("p", 200)}, negotiated: "h2"}},
		{"clone-set-next-protos", realityHandshakeCase{profile: "chrome_155", clientALPN: []string{"original-only/1"}, cloneALPN: []string{"clone-only/1"}, serverALPN: []string{"clone-only/1"}, negotiated: "clone-only/1"}},
	} {
		t.Run(tc.name, func(t *testing.T) { realityHandshakeExchange(t, tc.realityHandshakeCase) })
	}
}

func realityHandshakeExchange(t *testing.T, tc realityHandshakeCase) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cert := newPinnedTestCertificate(t, "localhost")
	camouflage, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer camouflage.Close()
	camouflageDone := make(chan struct{})
	camouflageHello := make(chan []string, 1)
	camouflageALPN := tc.camouflageALPN
	if camouflageALPN == nil {
		camouflageALPN = tc.serverALPN
	}
	realityHandshakeError := make(chan string, 1)
	go func() {
		defer close(camouflageDone)
		c, err := camouflage.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		secured := stdtls.Server(c, &stdtls.Config{
			Certificates: []stdtls.Certificate{cert.Certificate}, NextProtos: camouflageALPN,
			GetConfigForClient: func(hello *stdtls.ClientHelloInfo) (*stdtls.Config, error) {
				camouflageHello <- append([]string(nil), hello.SupportedProtos...)
				return nil, nil
			},
			MinVersion: stdtls.VersionTLS13, MaxVersion: stdtls.VersionTLS13, CurvePreferences: []stdtls.CurveID{stdtls.X25519},
		})
		if secured.Handshake() == nil {
			_, _ = io.Copy(io.Discard, secured)
		}
	}()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var short [8]byte
	short[0] = 0x21
	server := &RealityServerConfig{config: &meta.RealityConfig{
		Type: "tcp", Dest: camouflage.Addr().String(), PrivateKey: private.Bytes(),
		ServerNames: map[string]bool{"localhost": true}, ShortIds: map[[8]byte]bool{short: true},
		Log: func(format string, args ...any) {
			if strings.Contains(format, "hs.handshake() err:") {
				select {
				case realityHandshakeError <- fmt.Sprintf(format, args...):
				default:
				}
			}
		}, DialContext: (&net.Dialer{}).DialContext,
	}}
	server.config.SessionTicketsDisabled = true
	server.config.NextProtos = tc.serverALPN
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	type result struct {
		wire       []byte
		negotiated string
		payload    bool
		err        error
	}
	serverDone := make(chan result, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			serverDone <- result{err: err}
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		wire, err := firstTLSRecord(c)
		if err != nil {
			serverDone <- result{err: err}
			return
		}
		carrier := &replayHelloConn{c, io.MultiReader(bytes.NewReader(wire), c)}
		observed := &realityVisionObservedConn{Conn: carrier}
		var secured Conn
		if tc.owned {
			secured, err = serverHandshakeOwned(ctx, observed, server)
		} else {
			secured, err = server.ServerHandshake(ctx, carrier)
		}
		r := result{wire: wire, err: err}
		if err == nil {
			defer secured.Close()
			r.negotiated = secured.ConnectionState().NegotiatedProtocol
			var stream net.Conn = secured
			var vision *vless.VisionConn
			if tc.vision {
				stream, vision, r.err = realityVisionStream(ctx, secured, cert, true)
				if r.err != nil {
					serverDone <- r
					return
				}
			}
			b := make([]byte, 4)
			_, r.err = io.ReadFull(stream, b)
			r.payload = r.err == nil
			if r.err == nil && string(b) != "ping" {
				r.err = errors.New("REALITY payload mismatch")
			}
			if r.err == nil {
				_, r.err = stream.Write([]byte("pong"))
			}
			if r.err == nil && tc.vision && !realityVisionWasDirect(vision) {
				r.err = errors.New("REALITY Vision server did not enter direct mode")
			}
			if tc.vision && tc.owned {
				r.err = errors.Join(r.err, verifyRealityVisionRetirement(secured, observed))
			}
		}
		serverDone <- r
	}()
	public := private.PublicKey().Bytes()
	if tc.wrongKey {
		wrong, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		public = wrong.PublicKey().Bytes()
	}
	config, err := NewRealityClient(ctx, logger.NOP(), "localhost", option.OutboundTLSOptions{
		ServerName: "localhost", ALPN: tc.clientALPN,
		UTLS:    &option.OutboundUTLSOptions{Enabled: true, Fingerprint: tc.profile},
		Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: base64.RawURLEncoding.EncodeToString(public), ShortID: "21"},
	})
	if err != nil {
		t.Fatal(err)
	}
	original := config
	expectedALPN := tc.clientALPN
	if tc.cloneALPN != nil {
		config = config.Clone()
		config.SetNextProtos(tc.cloneALPN)
		expectedALPN = tc.cloneALPN
	}
	c, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	var secured Conn
	var clientErr error
	observed := &realityVisionObservedConn{Conn: c}
	if tc.owned {
		secured, clientErr = clientHandshakeOwned(ctx, observed, config)
	} else {
		secured, clientErr = config.(interface {
			ClientHandshake(context.Context, net.Conn) (Conn, error)
		}).ClientHandshake(ctx, c)
	}
	admitted := clientErr == nil
	if admitted && !tc.reject {
		if secured.ConnectionState().CurveID != stdtls.X25519 {
			t.Error("REALITY did not negotiate classical X25519")
		}
		if expectedALPN != nil && secured.ConnectionState().NegotiatedProtocol != tc.negotiated {
			t.Errorf("client ALPN %q != %q", secured.ConnectionState().NegotiatedProtocol, tc.negotiated)
		}
		var stream net.Conn = secured
		var vision *vless.VisionConn
		if tc.vision {
			stream, vision, clientErr = realityVisionStream(ctx, secured, cert, false)
		}
		if clientErr == nil {
			_, clientErr = stream.Write([]byte("ping"))
		}
		if clientErr == nil {
			b := make([]byte, 4)
			_, clientErr = io.ReadFull(stream, b)
			if clientErr == nil && string(b) != "pong" {
				clientErr = errors.New("REALITY reply mismatch")
			}
		}
		if clientErr == nil && tc.vision && !realityVisionWasDirect(vision) {
			clientErr = errors.New("REALITY Vision client did not enter direct mode")
		}
		if tc.vision && tc.owned {
			clientErr = errors.Join(clientErr, verifyRealityVisionRetirement(secured, observed))
		}
	}
	if admitted {
		_ = secured.Close()
	}
	c.Close()
	listener.Close()
	camouflage.Close()
	var r result
	select {
	case r = <-serverDone:
	case <-ctx.Done():
		t.Fatal("REALITY server did not retire")
	}
	select {
	case <-camouflageDone:
	case <-ctx.Done():
		t.Fatal("camouflage server did not retire")
	}
	if expectedALPN != nil {
		if len(r.wire) < 5 {
			t.Fatal("missing actual ClientHello wire")
		}
		hello := utls.UnmarshalClientHello(r.wire[5:])
		if hello == nil || !slices.Equal(hello.AlpnProtocols, expectedALPN) {
			t.Fatalf("wire ALPN does not preserve requested %v: %+v", expectedALPN, hello)
		}
	}
	if !slices.Equal(original.NextProtos(), tc.clientALPN) {
		t.Fatal("handshake or clone mutated original ALPN config")
	}
	if tc.cloneALPN != nil && !slices.Equal(config.NextProtos(), tc.cloneALPN) {
		t.Fatal("clone ALPN mutated")
	}
	if tc.camouflageALPN != nil && tc.reject {
		// The target explicitly accepts the offered ALPN. A failure here must
		// come from REALITY's own disjoint NextProtos, not the camouflage site.
		select {
		case offered := <-camouflageHello:
			if !slices.Equal(offered, expectedALPN) {
				t.Fatalf("camouflage saw wrong wire ALPN %v", offered)
			}
		default:
			t.Fatal("camouflage ClientHello was not observed")
		}
		select {
		case reason := <-realityHandshakeError:
			if !strings.Contains(reason, "unsupported application protocols") {
				t.Fatalf("unrelated REALITY rejection: %s", reason)
			}
		default:
			t.Fatal("missing actual REALITY ALPN rejection")
		}
	}
	if tc.reject {
		if admitted || r.payload {
			t.Fatalf("negative REALITY admitted=%v payload=%v client=%v server=%v", admitted, r.payload, clientErr, r.err)
		}
		return
	}
	if clientErr != nil || r.err != nil {
		t.Fatalf("actual REALITY handshake client=%v server=%v", clientErr, r.err)
	}
	if expectedALPN != nil && r.negotiated != tc.negotiated {
		t.Fatalf("server ALPN %q != %q", r.negotiated, tc.negotiated)
	}
}
