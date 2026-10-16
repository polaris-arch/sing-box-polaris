//go:build with_utls

package tls

import (
	"bytes"
	"context"
	"crypto/sha256"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	utls "github.com/refraction-networking/utls"
)

func TestUTLSMappedProfilesAreRealAndMatchSchema(t *testing.T) {
	field, _ := reflect.TypeFor[option.OutboundUTLSOptions]().FieldByName("Fingerprint")
	ids := strings.Split(field.Tag.Get("enum"), ",")
	_, profiles, aliases := fingerprintProfiles()
	got := map[string]bool{}
	for _, p := range profiles {
		if got[p.ID] || p.Client == "" || p.TemplateVersion == "" {
			t.Fatalf("invalid profile %+v", p)
		}
		got[p.ID] = true
		id, err := uTLSClientHelloID(p.ID)
		if err != nil {
			t.Fatal(err)
		}
		if p.ID != "randomized" {
			if _, err := utls.UTLSIdToSpec(id); err != nil {
				t.Fatalf("%s: %v", p.ID, err)
			}
		}
	}
	for _, alias := range aliases {
		got[alias] = true
	}
	if len(got) != len(ids) {
		t.Fatalf("schema/profile count %d != %d", len(got), len(ids))
	}
	for _, id := range ids {
		if !got[id] {
			t.Fatalf("schema-only ID %s", id)
		}
	}
	for name, want := range map[string]utls.ClientHelloID{"": utls.HelloChrome_155, "chrome": utls.HelloChrome_155, "safari": utls.HelloSafari_26_3, "firefox": utls.HelloFirefox_148} {
		id, err := uTLSClientHelloID(name)
		if err != nil || id.Str() != want.Str() {
			t.Fatalf("%s did not select %s: %v/%v", name, want.Str(), id, err)
		}
	}
	for _, name := range []string{"none", "disabled", "default", "safari_15_3", "safari_15_5", "chrome_999", "CHROME"} {
		if _, err := uTLSClientHelloID(name); err == nil {
			t.Fatalf("invented ID %s accepted", name)
		}
	}
	for _, alias := range aliases {
		id, err := uTLSClientHelloID(alias)
		if err != nil || id.Str() != utls.HelloChrome_Auto.Str() {
			t.Fatal("legacy alias changed", alias)
		}
	}
	for range 5 {
		id, _ := uTLSClientHelloID("random")
		if id.Str() != randomFingerprint.Str() {
			t.Fatal("random reselected in same process")
		}
		randomized, _ := uTLSClientHelloID("randomized")
		if randomized.Seed != randomizedFingerprint.Seed || randomized.Weights != randomizedFingerprint.Weights {
			t.Fatal("randomized seed changed")
		}
	}
}

type replayHelloConn struct {
	net.Conn
	reader io.Reader
}

func (c *replayHelloConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func firstTLSRecord(c net.Conn) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(c, header); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(header[3:]))
	if header[0] != 22 || n < 39 || n > 16384 {
		return nil, fmt.Errorf("invalid first TLS record")
	}
	record := make([]byte, 5+n)
	copy(record, header)
	_, err := io.ReadFull(c, record[5:])
	return record, err
}

// Capture the actual wire record before the controlled TLS server consumes it.
func profileExchange(t *testing.T, config Config, serverConfig *stdtls.Config, implicit bool) (stdtls.ConnectionState, []byte, error) {
	t.Helper()
	// TLS 1.3 mutual authentication can exchange client Finished/application
	// data concurrently with the server's NewSessionTicket flight. A zero
	// buffer net.Pipe deadlocks that valid full-duplex exchange. Use the same
	// bounded local TCP transport as the actual REALITY/ShadowTLS fixtures.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	deadline := time.Now().Add(5 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)
	type result struct {
		wire []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		defer server.Close()
		wire, err := firstTLSRecord(server)
		if err != nil {
			done <- result{wire, err}
			return
		}
		secured := stdtls.Server(&replayHelloConn{server, io.MultiReader(bytes.NewReader(wire), server)}, serverConfig)
		err = secured.Handshake()
		if err == nil {
			b := make([]byte, 4)
			_, err = io.ReadFull(secured, b)
			if err == nil && string(b) != "ping" {
				err = fmt.Errorf("unexpected payload")
			}
			if err == nil {
				_, err = secured.Write([]byte("pong"))
			}
		}
		done <- result{wire, err}
	}()
	wrapped, err := config.Client(client)
	if err != nil {
		client.Close()
		r := <-done
		return stdtls.ConnectionState{}, r.wire, err
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if !implicit {
		err = wrapped.HandshakeContext(ctx)
	}
	if err == nil {
		_, err = wrapped.Write([]byte("ping"))
	}
	if err == nil {
		buf := make([]byte, 4)
		_, err = io.ReadFull(wrapped, buf)
		if err == nil && string(buf) != "pong" {
			err = fmt.Errorf("payload mismatch")
		}
	}
	state := wrapped.ConnectionState()
	client.Close()
	r := <-done
	if err == nil {
		err = r.err
	}
	return state, r.wire, err
}

func profileClient(t *testing.T, id string, opts option.OutboundTLSOptions) *UTLSClientConfig {
	t.Helper()
	opts.Enabled = true
	opts.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: id}
	c, err := NewUTLSClient(context.Background(), logger.NOP(), "localhost", opts)
	if err != nil {
		t.Fatal(err)
	}
	return c.(*UTLSClientConfig)
}

func TestUTLSProfilesActualTLSAndNegotiatedGroup(t *testing.T) {
	cert := newPinnedTestCertificate(t, "localhost")
	for _, test := range []struct {
		id      string
		version uint16
		group   stdtls.CurveID
	}{
		{"chrome_155", stdtls.VersionTLS13, stdtls.X25519MLKEM768},
		{"safari_26_3", stdtls.VersionTLS13, stdtls.X25519MLKEM768},
		{"firefox_148", stdtls.VersionTLS13, stdtls.X25519MLKEM768},
		{"chrome_133", stdtls.VersionTLS13, stdtls.X25519MLKEM768},
		{"safari_16_0", stdtls.VersionTLS13, stdtls.X25519},
		{"chrome_155", stdtls.VersionTLS13, stdtls.X25519},
		{"chrome_155", stdtls.VersionTLS12, stdtls.X25519},
		{"safari_26_3", stdtls.VersionTLS12, stdtls.X25519},
		{"random", stdtls.VersionTLS13, stdtls.X25519},
		{"randomized", stdtls.VersionTLS13, stdtls.X25519},
	} {
		t.Run(fmt.Sprintf("%s/%x/%d", test.id, test.version, test.group), func(t *testing.T) {
			c := profileClient(t, test.id, option.OutboundTLSOptions{ServerName: "localhost", Certificate: []string{cert.certificatePEM}, ALPN: []string{"http/1.1"}})
			state, wire, err := profileExchange(t, c, &stdtls.Config{Certificates: []stdtls.Certificate{cert.Certificate}, MinVersion: test.version, MaxVersion: test.version, CurvePreferences: []stdtls.CurveID{test.group}, NextProtos: []string{"http/1.1"}}, false)
			if err != nil {
				t.Fatal(err)
			}
			if state.Version != test.version || state.NegotiatedProtocol != "http/1.1" || state.CurveID != test.group {
				t.Fatalf("actual negotiated state %+v", state)
			}
			spec, err := (&utls.Fingerprinter{}).FingerprintClientHello(wire)
			if err != nil {
				t.Fatal(err)
			}
			if test.id == "chrome_155" && test.version == stdtls.VersionTLS13 {
				var signatures, anchors bool
				for _, extension := range spec.Extensions {
					if sig, ok := extension.(*utls.SignatureAlgorithmsExtension); ok {
						signatures = slices.Contains(sig.SupportedSignatureAlgorithms, utls.MLDSA44) && slices.Contains(sig.SupportedSignatureAlgorithms, utls.MLDSA65) && slices.Contains(sig.SupportedSignatureAlgorithms, utls.MLDSA87)
					}
					if anchor, ok := extension.(*utls.TrustAnchorsExtension); ok {
						anchors = len(anchor.TrustAnchorIDs) == 28
					}
				}
				if !signatures || !anchors {
					t.Fatal("Chrome155 actual wire lost MLDSA/TrustAnchors")
				}
			}
		})
	}
}

func TestUTLSSessionIDGeneratorCloneAndImplicitHandshake(t *testing.T) {
	cert := newPinnedTestCertificate(t, "localhost")
	original := profileClient(t, "chrome_155", option.OutboundTLSOptions{ServerName: "localhost", Certificate: []string{cert.certificatePEM}})
	clone := original.Clone().(*UTLSClientConfig)
	calls := 0
	want := bytes.Repeat([]byte{0x45}, 32)
	clone.SetSessionIDGenerator(func(raw, id []byte) error {
		calls++
		if len(raw) < 71 || len(id) != 32 || !bytes.Equal(raw[39:71], make([]byte, 32)) {
			return fmt.Errorf("session ID input was not zeroed")
		}
		copy(id, want)
		return nil
	})
	if original.sessionIDGenerator != nil {
		t.Fatal("clone modified shared generator")
	}
	state, wire, err := profileExchange(t, clone, &stdtls.Config{Certificates: []stdtls.Certificate{cert.Certificate}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !state.HandshakeComplete || calls != 1 || len(wire) < 76 || !bytes.Equal(wire[44:76], want) {
		t.Fatalf("actual session ID lost: calls=%d", calls)
	}
}

func TestUTLSSessionIDFailureCancellationAndCloneECH(t *testing.T) {
	c := profileClient(t, "chrome_155", option.OutboundTLSOptions{ServerName: "localhost", Insecure: true})
	c.SetECHConfigList([]byte{1, 2, 3})
	clone := c.Clone().(*UTLSClientConfig)
	clone.SetECHConfigList([]byte{4, 5})
	if !bytes.Equal(c.ECHConfigList(), []byte{1, 2, 3}) {
		t.Fatal("ECH clone changed original")
	}
	c.SetECHConfigList(nil)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	wrapped, err := c.Client(left)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(wrapped.HandshakeContext(ctx), context.Canceled) {
		t.Fatal("canceled handshake admitted")
	}
	failure := errors.New("session generator failure")
	c.SetSessionIDGenerator(func([]byte, []byte) error { return failure })
	wrapped, err = c.Client(left)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(wrapped.HandshakeContext(context.Background()), failure) {
		t.Fatal("session generator error lost")
	}
}

func TestUTLSPinningSNIAndIgnoredCurveControl(t *testing.T) {
	cert := newPinnedTestCertificate(t, "localhost")
	pin := sha256.Sum256(cert.Certificate.Certificate[0])
	for _, good := range []bool{true, false} {
		digest := pin[:]
		if !good {
			wrong := sha256.Sum256([]byte("wrong"))
			digest = wrong[:]
		}
		c := profileClient(t, "chrome_155", option.OutboundTLSOptions{ServerName: "localhost", CertificateSHA256: [][]byte{digest}})
		_, _, err := profileExchange(t, c, &stdtls.Config{Certificates: []stdtls.Certificate{cert.Certificate}}, false)
		if (err == nil) != good {
			t.Fatalf("pin admission good=%v error=%v", good, err)
		}
	}
	c := profileClient(t, "safari_26_3", option.OutboundTLSOptions{ServerName: "localhost", DisableSNI: true, Certificate: []string{cert.certificatePEM}})
	_, wire, err := profileExchange(t, c, &stdtls.Config{Certificates: []stdtls.Certificate{cert.Certificate}}, false)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := (&utls.Fingerprinter{}).FingerprintClientHello(wire)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range spec.Extensions {
		if sni, ok := e.(*utls.SNIExtension); ok && sni.ServerName != "" {
			t.Fatal("disabled SNI appeared on wire")
		}
	}
	_, err = NewUTLSClient(context.Background(), logger.NOP(), "localhost", option.OutboundTLSOptions{UTLS: &option.OutboundUTLSOptions{Enabled: true}, CurvePreferences: []option.CurvePreference{29}})
	if err == nil || !strings.Contains(err.Error(), "curve_preferences") {
		t.Fatal("ignored curve control accepted")
	}
}

func TestRealityFiltersTemplatePQButPreservesClassicalShare(t *testing.T) {
	for _, profile := range []string{"chrome_155", "safari_26_3", "firefox_148", "chrome_133"} {
		id, err := uTLSClientHelloID(profile)
		if err != nil {
			t.Fatal(err)
		}
		left, right := net.Pipe()
		u := utls.UClient(left, &utls.Config{ServerName: "localhost"}, id)
		if err := u.BuildHandshakeState(); err != nil {
			t.Fatal(err)
		}
		filterRealityKeyShares(u)
		if err := u.BuildHandshakeState(); err != nil {
			t.Fatal(err)
		}
		classical := false
		for _, extension := range u.Extensions {
			if curves, ok := extension.(*utls.SupportedCurvesExtension); ok && slices.Contains(curves.Curves, utls.X25519MLKEM768) {
				t.Fatal("REALITY advertised hybrid group")
			}
			if shares, ok := extension.(*utls.KeyShareExtension); ok {
				for _, share := range shares.KeyShares {
					if share.Group == utls.X25519MLKEM768 {
						t.Fatal("REALITY retained hybrid share")
					}
					if share.Group == utls.X25519 {
						classical = true
					}
				}
			}
		}
		if !classical || u.HandshakeState.State13.KeyShareKeys.Ecdhe == nil {
			t.Fatal("REALITY lost classical authentication key")
		}
		left.Close()
		right.Close()
	}
	verifier := new(realityVerifier)
	if verifier.VerifyPeerCertificate(nil, nil) == nil || verifier.VerifyPeerCertificate([][]byte{{0, 1, 2}}, nil) == nil {
		t.Fatal("malformed peer certificate accepted")
	}
}

func TestFingerprintProfilesJSONIsStableWithinProcess(t *testing.T) {
	a, err := FingerprintCapabilitiesJSON()
	if err != nil {
		t.Fatal(err)
	}
	b, err := FingerprintCapabilitiesJSON()
	if err != nil {
		t.Fatal(err)
	}
	if a != b || !json.Valid([]byte(a)) {
		t.Fatal("capabilities reselected templates or malformed JSON")
	}
}

func TestUTLSRealECHHandshakeAndSessionIDConflict(t *testing.T) {
	configPEM, keyPEM, err := ECHKeygenDefault("public.example")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := parseECHKeys([]byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	cert := newPinnedTestCertificate(t, "localhost")
	for _, id := range []string{"chrome_155", "safari_26_3"} {
		t.Run(id, func(t *testing.T) {
			c := profileClient(t, id, option.OutboundTLSOptions{ServerName: "localhost", MinVersion: "1.3", Certificate: []string{cert.certificatePEM}, ECH: &option.OutboundECHOptions{Enabled: true, Config: []string{configPEM}}})
			t.Run("accepted", func(t *testing.T) {
				state, _, err := profileExchange(t, c, &stdtls.Config{Certificates: []stdtls.Certificate{cert.Certificate}, MinVersion: stdtls.VersionTLS13, EncryptedClientHelloKeys: keys}, false)
				if err != nil {
					t.Fatal(err)
				}
				if !state.ECHAccepted {
					t.Fatal("real ECH was not accepted")
				}
			})
			t.Run("session-id-conflict", func(t *testing.T) {
				c.SetSessionIDGenerator(func([]byte, []byte) error { t.Error("unsupported ECH authenticator invoked"); return nil })
				left, right := net.Pipe()
				defer left.Close()
				defer right.Close()
				wrapped, err := c.Client(left)
				if err != nil {
					t.Fatal(err)
				}
				err = wrapped.HandshakeContext(context.Background())
				if err == nil || !strings.Contains(err.Error(), "real ECH") {
					t.Fatalf("ECH/sessionID conflict not rejected: %v", err)
				}
			})
		})
	}
}

func TestUTLSHostnameAndMutualTLS(t *testing.T) {
	serverCert := newPinnedTestCertificate(t, "localhost")
	clientCert := newPinnedTestCertificate(t, "client.invalid")
	for _, name := range []string{"chrome_155", "safari_26_3"} {
		t.Run(name, func(t *testing.T) {
			server := &stdtls.Config{Certificates: []stdtls.Certificate{serverCert.Certificate}, ClientAuth: stdtls.RequireAnyClientCert,
				VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
					if len(raw) != 1 || !bytes.Equal(raw[0], clientCert.Certificate.Certificate[0]) {
						return errors.New("wrong mutual TLS identity")
					}
					return nil
				}}
			t.Run("good", func(t *testing.T) {
				good := profileClient(t, name, option.OutboundTLSOptions{ServerName: "localhost", Certificate: []string{serverCert.certificatePEM}, ClientCertificate: []string{clientCert.certificatePEM}, ClientKey: []string{clientCert.privateKeyPEM}})
				if _, _, err := profileExchange(t, good, server, false); err != nil {
					t.Fatal(err)
				}
			})
			t.Run("missing-client-identity", func(t *testing.T) {
				missing := profileClient(t, name, option.OutboundTLSOptions{ServerName: "localhost", Certificate: []string{serverCert.certificatePEM}})
				if _, _, err := profileExchange(t, missing, server, false); err == nil {
					t.Fatal("missing client identity admitted")
				}
			})
			t.Run("wrong-hostname", func(t *testing.T) {
				wrongHost := profileClient(t, name, option.OutboundTLSOptions{ServerName: "wrong.invalid", Certificate: []string{serverCert.certificatePEM}})
				if _, _, err := profileExchange(t, wrongHost, &stdtls.Config{Certificates: []stdtls.Certificate{serverCert.Certificate}}, false); err == nil {
					t.Fatal("wrong server hostname admitted")
				}
			})
		})
	}
}

func TestUTLSConcurrentWaitingHandshakeCancellation(t *testing.T) {
	c := profileClient(t, "chrome_155", option.OutboundTLSOptions{ServerName: "localhost", Insecure: true})
	left, right := net.Pipe()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(5 * time.Second))
	_ = right.SetDeadline(time.Now().Add(5 * time.Second))
	wrapped, err := c.Client(left)
	if err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	wire := make(chan error, 1)
	go func() { first <- wrapped.HandshakeContext(context.Background()) }()
	go func() { _, err := firstTLSRecord(right); wire <- err }()
	if err := <-wire; err != nil {
		left.Close()
		<-first
		t.Fatal(err)
	}
	second := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { second <- wrapped.HandshakeContext(ctx) }()
	cancel()
	select {
	case err := <-second:
		if !errors.Is(err, context.Canceled) {
			t.Error("waiting cancellation lost", err)
		}
	case <-time.After(time.Second):
		t.Error("canceled caller remained blocked behind handshake")
	}
	left.Close()
	select {
	case <-first:
	case <-time.After(time.Second):
		t.Error("original handshake did not retire")
	}
}

func TestUTLSExplicitALPNUpsertAbsentAndPSKLast(t *testing.T) {
	// Fixed seed AND an explicitly no-ALPN generator: absence is deterministic,
	// independent of the random process seed that hid the original regression.
	id := utls.HelloRandomizedNoALPN
	id.Seed = &utls.PRNGSeed{}
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		t.Fatal(err)
	}
	for _, ext := range spec.Extensions {
		if _, ok := ext.(*utls.ALPNExtension); ok {
			t.Fatal("fixture unexpectedly has ALPN")
		}
	}
	cert := newPinnedTestCertificate(t, "localhost")
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprintf("explicit-%v", explicit), func(t *testing.T) {
			original := profileClient(t, "randomized", option.OutboundTLSOptions{ServerName: "localhost", Certificate: []string{cert.certificatePEM}})
			original.id = id
			config := original.Clone().(*UTLSClientConfig)
			want := ""
			if explicit {
				config.SetNextProtos([]string{"polaris-fixed/1"})
				want = "polaris-fixed/1"
			}
			state, wire, err := profileExchange(t, config, &stdtls.Config{Certificates: []stdtls.Certificate{cert.Certificate}, NextProtos: []string{"polaris-fixed/1"}}, false)
			if err != nil {
				t.Fatal(err)
			}
			if state.NegotiatedProtocol != want {
				t.Fatalf("actual ALPN %q != %q", state.NegotiatedProtocol, want)
			}
			hello := utls.UnmarshalClientHello(wire[5:])
			if hello == nil || (explicit && !slices.Equal(hello.AlpnProtocols, []string{want})) || (!explicit && len(hello.AlpnProtocols) != 0) {
				t.Fatal("actual wire did not preserve explicit/default ALPN")
			}
			if len(original.NextProtos()) != 0 {
				t.Fatal("clone mutated original ALPN")
			}
		})
	}
	psk := &utls.UtlsPreSharedKeyExtension{}
	extensions := []utls.TLSExtension{&utls.SNIExtension{}, psk}
	if !reflect.DeepEqual(upsertUTLSALPN(append([]utls.TLSExtension(nil), extensions...), nil), extensions) {
		t.Fatal("no override changed original template")
	}
	extensions = upsertUTLSALPN(extensions, []string{"http/1.1"})
	extensions = insertUTLSExtension(extensions, &utls.GREASEEncryptedClientHelloExtension{})
	if extensions[len(extensions)-1] != psk {
		t.Fatal("new ALPN/ECH extension moved PSK from last")
	}
}
