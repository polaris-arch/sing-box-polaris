//go:build with_utls

package shadowtls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	boxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	shadow "github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Every connection goes through the actual v3 service, including ClientHello
// HMAC validation and frame authentication, to a separate plaintext TCP echo peer.
// No third-party network or wall-clock sleeps are needed.
type v3Fixture struct {
	ctx                      context.Context
	cancel                   context.CancelFunc
	server, camouflage, echo net.Listener
	roots                    string
	wires                    chan []byte
	users                    map[string]bool
	handlerCalls, echoCalls  atomic.Int32
	connections              sync.Map
	workers                  sync.WaitGroup
	stop                     sync.Once
}

func newV3Fixture(t *testing.T, users []shadow.User) *v3Fixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	f := &v3Fixture{ctx: ctx, cancel: cancel, wires: make(chan []byte, 32), users: make(map[string]bool)}
	t.Cleanup(f.close)
	for _, user := range users {
		f.users[user.Name] = true
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	f.roots = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	certificate := stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	listen := func() net.Listener {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	f.camouflage = listen()
	f.echo = listen()
	f.server = listen()
	f.accept(f.camouflage, func(c net.Conn) {
		secured := stdtls.Server(c, &stdtls.Config{Certificates: []stdtls.Certificate{certificate}, MinVersion: stdtls.VersionTLS13, MaxVersion: stdtls.VersionTLS13, NextProtos: []string{"http/1.1"}, CurvePreferences: []stdtls.CurveID{stdtls.X25519}})
		if secured.HandshakeContext(ctx) == nil {
			_, _ = io.Copy(io.Discard, secured)
		}
	})
	f.accept(f.echo, func(c net.Conn) { f.echoCalls.Add(1); _, _ = io.Copy(c, c) })
	service, err := shadow.NewService(shadow.ServiceConfig{Version: 3, Users: users, StrictMode: true,
		Handshake: shadow.HandshakeConfig{Server: M.SocksaddrFromNet(f.camouflage.Addr()), Dialer: N.SystemDialer}, Handler: f, Logger: logger.NOP()})
	if err != nil {
		t.Fatal(err)
	}
	f.accept(f.server, func(c net.Conn) {
		record, err := v3FirstRecord(c)
		if err != nil {
			return
		}
		select {
		case f.wires <- record:
		case <-ctx.Done():
			return
		}
		replay := &v3ReplayConn{Conn: c, reader: io.MultiReader(bytes.NewReader(record), c)}
		_ = service.NewConnection(ctx, replay, M.SocksaddrFromNet(c.RemoteAddr()), M.Socksaddr{}, nil)
	})
	return f
}

func (f *v3Fixture) accept(listener net.Listener, handle func(net.Conn)) {
	f.workers.Add(1)
	go func() {
		defer f.workers.Done()
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			f.connections.Store(c, struct{}{})
			if f.ctx.Err() != nil {
				f.connections.Delete(c)
				c.Close()
				return
			}
			_ = c.SetDeadline(time.Now().Add(8 * time.Second))
			f.workers.Add(1)
			go func() { defer f.workers.Done(); defer f.connections.Delete(c); defer c.Close(); handle(c) }()
		}
	}()
}

func (f *v3Fixture) close() {
	f.stop.Do(func() {
		f.cancel()
		for _, listener := range []net.Listener{f.server, f.camouflage, f.echo} {
			if listener != nil {
				listener.Close()
			}
		}
		f.connections.Range(func(key, value any) bool { key.(net.Conn).Close(); return true })
		f.workers.Wait()
	})
}

func (f *v3Fixture) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	// Only the actual service sets the authenticated user before calling us.
	f.handlerCalls.Add(1)
	name, _ := auth.UserFromContext[string](ctx)
	if !f.users[name] {
		return
	}
	dst, err := (&net.Dialer{}).DialContext(ctx, "tcp", f.echo.Addr().String())
	if err != nil {
		return
	}
	defer dst.Close()
	_ = dst.SetDeadline(time.Now().Add(8 * time.Second))
	done := make(chan struct{})
	go func() { defer close(done); _, _ = io.Copy(conn, dst); conn.Close() }()
	_, _ = io.Copy(dst, conn)
	dst.Close()
	<-done
}

type v3ReplayConn struct {
	net.Conn
	reader io.Reader
}

func (c *v3ReplayConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func v3FirstRecord(conn net.Conn) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(header[3:]))
	if header[0] != 22 || n < 71 || n > 16384 {
		return nil, fmt.Errorf("invalid ClientHello record length %d", n)
	}
	frame := make([]byte, 5+n)
	copy(frame, header)
	_, err := io.ReadFull(conn, frame[5:])
	return frame, err
}

// Independent verification of the on-wire session authenticator. Copying and
// zeroing its four HMAC bytes matches the wire protocol, not a production helper.
func v3WireAuthenticated(frame []byte, password string) bool {
	if len(frame) < 76 || frame[43] != 32 {
		return false
	}
	hello := bytes.Clone(frame[5:])
	tag := bytes.Clone(hello[67:71])
	clear(hello[67:71])
	mac := hmac.New(sha1.New, []byte(password))
	mac.Write(hello)
	return hmac.Equal(tag, mac.Sum(nil)[:4])
}

func v3WireHasGREASEECH(frame []byte) bool {
	if len(frame) < 76 {
		return false
	}
	raw := frame[5:]
	pos := 39 + int(raw[38])
	if pos+2 > len(raw) {
		return false
	}
	pos += 2 + int(binary.BigEndian.Uint16(raw[pos:]))
	if pos >= len(raw) {
		return false
	}
	pos += 1 + int(raw[pos])
	if pos+2 > len(raw) {
		return false
	}
	end := pos + 2 + int(binary.BigEndian.Uint16(raw[pos:]))
	pos += 2
	if end != len(raw) {
		return false
	}
	for pos+4 <= end {
		kind, n := binary.BigEndian.Uint16(raw[pos:]), int(binary.BigEndian.Uint16(raw[pos+2:]))
		pos += 4
		if pos+n > end {
			return false
		}
		if kind == 0xfe0d && n > 0 {
			return true
		}
		pos += n
	}
	return false
}

func v3Config(t *testing.T, f *v3Fixture, profile string) (boxtls.Config, error) {
	t.Helper()
	return boxtls.NewUTLSClient(f.ctx, logger.NOP(), "localhost", option.OutboundTLSOptions{ServerName: "localhost", Certificate: []string{f.roots}, ALPN: []string{"http/1.1"}, UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: profile}})
}

func v3Client(t *testing.T, f *v3Fixture, password string, handshake shadow.TLSHandshakeFunc) *shadow.Client {
	t.Helper()
	client, err := shadow.NewClient(shadow.ClientConfig{Version: 3, Password: password, Server: M.SocksaddrFromNet(f.server.Addr()), StrictMode: true, TLSHandshake: handshake, Logger: logger.NOP()})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func v3RoundTrip(ctx context.Context, client *shadow.Client, payload []byte) error {
	conn, err := client.DialContext(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = conn.Write(payload); err != nil {
		return err
	}
	reply := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, reply); err != nil {
		return err
	}
	if !bytes.Equal(reply, payload) {
		return errors.New("actual v3 bidirectional forwarding changed payload")
	}
	return nil
}

func v3AssertBaseGenerator(t *testing.T, config boxtls.Config, sentinel error) {
	t.Helper()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn, err := config.Client(left)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = conn.HandshakeContext(ctx); !errors.Is(err, sentinel) {
		t.Fatalf("shared TLS config generator was mutated: %v", err)
	}
}

func TestShadowTLSV3ActualAuthenticationAndForwarding(t *testing.T) {
	for _, profile := range []string{"chrome_155", "safari_26_3"} {
		t.Run(profile, func(t *testing.T) {
			f := newV3Fixture(t, []shadow.User{{Name: "accepted", Password: "correct-password"}})
			config, err := v3Config(t, f, profile)
			if err != nil {
				t.Fatal(err)
			}
			sentinel := errors.New("original generator retained")
			config.(boxtls.WithSessionIDGenerator).SetSessionIDGenerator(func([]byte, []byte) error { return sentinel })
			handshake, err := newV3TLSHandshake(config, "correct-password")
			if err != nil {
				t.Fatal(err)
			}
			payload := bytes.Repeat([]byte("actual-v3-forwarding/"), 2000) // multiple authenticated frames
			if err = v3RoundTrip(f.ctx, v3Client(t, f, "correct-password", handshake), payload); err != nil {
				t.Fatal(err)
			}
			f.close()
			if f.handlerCalls.Load() != 1 || f.echoCalls.Load() != 1 {
				t.Fatalf("missing authenticated route/echo: %d/%d", f.handlerCalls.Load(), f.echoCalls.Load())
			}
			var wire []byte
			select {
			case wire = <-f.wires:
			default:
				t.Fatal("missing actual v3 ClientHello")
			}
			if !v3WireAuthenticated(wire, "correct-password") {
				t.Fatal("actual ClientHello HMAC invalid")
			}
			if profile == "chrome_155" && !v3WireHasGREASEECH(wire) {
				t.Fatal("Chrome155 GREASE ECH missing from actual v3 wire")
			}
			v3AssertBaseGenerator(t, config, sentinel)
		})
	}
}

func TestShadowTLSV3RejectsWrongPasswordAndTamperedSession(t *testing.T) {
	for _, name := range []string{"wrong-password", "tampered-session"} {
		t.Run(name, func(t *testing.T) {
			f := newV3Fixture(t, []shadow.User{{Name: "accepted", Password: "correct-password"}})
			config, err := v3Config(t, f, "chrome_155")
			if err != nil {
				t.Fatal(err)
			}
			handshake, err := newV3TLSHandshake(config, "correct-password")
			if err != nil {
				t.Fatal(err)
			}
			password := "wrong-password"
			if name == "tampered-session" {
				password = "correct-password"
				original := handshake
				handshake = func(ctx context.Context, c net.Conn, generator shadow.TLSSessionIDGeneratorFunc) error {
					return original(ctx, c, func(hello, sid []byte) error {
						if err := generator(hello, sid); err != nil {
							return err
						}
						sid[len(sid)-1] ^= 1
						return nil
					})
				}
			}
			client := v3Client(t, f, password, handshake)
			conn, err := client.DialContext(f.ctx)
			if conn != nil {
				conn.Close()
			}
			f.close()
			if err == nil {
				t.Fatal("unauthenticated v3 client admitted")
			}
			if f.handlerCalls.Load() != 0 || f.echoCalls.Load() != 0 {
				t.Fatal("unauthenticated v3 traffic reached forwarding target")
			}
			select {
			case wire := <-f.wires:
				if v3WireAuthenticated(wire, "correct-password") {
					t.Fatal("negative wire still authenticated")
				}
			default:
				t.Fatal("negative case never sent actual ClientHello")
			}
		})
	}
}

func TestShadowTLSV3ConcurrentConfigIsolation(t *testing.T) {
	const count = 4
	users := make([]shadow.User, count)
	for i := range users {
		users[i] = shadow.User{Name: fmt.Sprintf("user-%d", i), Password: fmt.Sprintf("independent-password-%d", i)}
	}
	f := newV3Fixture(t, users)
	config, err := v3Config(t, f, "chrome_155")
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("shared generator retained")
	config.(boxtls.WithSessionIDGenerator).SetSessionIDGenerator(func([]byte, []byte) error { return sentinel })
	handshake, err := newV3TLSHandshake(config, "")
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, count)
	start := make(chan struct{})
	for i, user := range users {
		client := v3Client(t, f, user.Password, handshake)
		go func() {
			<-start
			results <- v3RoundTrip(f.ctx, client, bytes.Repeat([]byte(fmt.Sprintf("client-%d/", i)), 4200))
		}()
	}
	close(start)
	for range count {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	f.close()
	if f.handlerCalls.Load() != count || f.echoCalls.Load() != count {
		t.Fatalf("independent authenticated routes %d/%d", f.handlerCalls.Load(), f.echoCalls.Load())
	}
	matched := make(map[string]int)
	for range count {
		select {
		case wire := <-f.wires:
			for _, user := range users {
				if v3WireAuthenticated(wire, user.Password) {
					matched[user.Name]++
				}
			}
			if !v3WireHasGREASEECH(wire) {
				t.Error("concurrent Chrome155 GREASE ECH missing")
			}
		default:
			t.Fatal("concurrent actual wire missing")
		}
	}
	for _, user := range users {
		if matched[user.Name] != 1 {
			t.Errorf("connection generator/password crossed for %s: %d", user.Name, matched[user.Name])
		}
	}
	v3AssertBaseGenerator(t, config, sentinel)
}

func TestShadowTLSV3RejectsRealECH(t *testing.T) {
	_, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "", option.ShadowTLSOutboundOptions{Version: 3,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true, ECH: &option.OutboundECHOptions{Enabled: true}, UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome_155"}}}})
	if err == nil || !strings.Contains(err.Error(), "real ECH") {
		t.Fatalf("actual v3 outbound did not reject real ECH: %v", err)
	}
}
