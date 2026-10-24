//go:build with_utls

package vless

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"runtime"
	"testing"
	"time"

	meta "github.com/metacubex/utls"
	refraction "github.com/refraction-networking/utls"
	"github.com/sagernet/sing/common/logger"
)

type visionHandshakeConn interface {
	net.Conn
	HandshakeContext(context.Context) error
}
type visionProviderFactory func(net.Conn, *x509.CertPool) visionHandshakeConn

func visionTestCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func visionProviderFactories() map[string]visionProviderFactory {
	return map[string]visionProviderFactory{
		"standard-Conn": func(c net.Conn, pool *x509.CertPool) visionHandshakeConn {
			return tls.Client(c, &tls.Config{ServerName: "localhost", RootCAs: pool, MinVersion: tls.VersionTLS13})
		},
		"meta-Conn": func(c net.Conn, pool *x509.CertPool) visionHandshakeConn {
			return meta.Client(c, &meta.Config{ServerName: "localhost", RootCAs: pool, MinVersion: meta.VersionTLS13})
		},
		"meta-UConn": func(c net.Conn, pool *x509.CertPool) visionHandshakeConn {
			return meta.UClient(c, &meta.Config{ServerName: "localhost", RootCAs: pool, MinVersion: meta.VersionTLS13}, meta.HelloChrome_Auto)
		},
		"refraction-Conn": func(c net.Conn, pool *x509.CertPool) visionHandshakeConn {
			return refraction.Client(c, &refraction.Config{ServerName: "localhost", RootCAs: pool, MinVersion: refraction.VersionTLS13})
		},
		"refraction-UConn": func(c net.Conn, pool *x509.CertPool) visionHandshakeConn {
			return refraction.UClient(c, &refraction.Config{ServerName: "localhost", RootCAs: pool, MinVersion: refraction.VersionTLS13}, refraction.HelloChrome_Auto)
		},
	}
}

// This wrapper checks the same advertised CastReader contract as the product's
// REALITY wrapper. Actual REALITY authentication is separately tested in core.
type visionReplaceableProvider struct{ net.Conn }

func (c visionReplaceableProvider) Upstream() any         { return c.Conn }
func (visionReplaceableProvider) ReaderReplaceable() bool { return true }

func TestVisionTLSProvidersActualHandshakeAndDirect(t *testing.T) {
	for name, factory := range visionProviderFactories() {
		for _, wrapped := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/wrapped-%v", name, wrapped), func(t *testing.T) { visionProviderExchange(t, factory, wrapped, false, tls.VersionTLS13, 0) })
		}
	}
}

func TestVisionTLSProvidersRejectBadCertificate(t *testing.T) {
	for name, factory := range visionProviderFactories() {
		t.Run(name, func(t *testing.T) { visionProviderExchange(t, factory, false, true, tls.VersionTLS13, 0) })
	}
}

type visionLimitedReadConn struct {
	net.Conn
	limit  int
	vision *VisionConn
}

func (c *visionLimitedReadConn) Read(p []byte) (int, error) {
	limit := c.limit
	if limit < 0 {
		limit = -limit
	} else if c.vision == nil || !c.vision.filterTLS(nil).enableXTLS {
		limit = 0
	}
	if limit > 0 && len(p) > limit {
		p = p[:limit]
	}
	return c.Conn.Read(p)
}

func TestVisionTLSFragmentedDetectionFallsBackSafely(t *testing.T) {
	for name, factory := range visionProviderFactories() {
		t.Run(name, func(t *testing.T) { visionProviderExchange(t, factory, true, false, tls.VersionTLS13, -32) })
	}
}

func TestVisionTLS12RemainsRecordMode(t *testing.T) {
	for name, factory := range visionProviderFactories() {
		t.Run(name, func(t *testing.T) { visionProviderExchange(t, factory, false, false, tls.VersionTLS12, 0) })
	}
}

func TestVisionTLSFragmentedProviderBuffers(t *testing.T) {
	for name, factory := range visionProviderFactories() {
		t.Run(name, func(t *testing.T) { visionProviderExchange(t, factory, true, false, tls.VersionTLS13, 32) })
	}
}

func TestVisionUTLSNilProvidersRejected(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	for _, conn := range []net.Conn{(*meta.Conn)(nil), (*meta.UConn)(nil), &meta.UConn{}, (*refraction.Conn)(nil), (*refraction.UConn)(nil), &refraction.UConn{}} {
		if result, err := NewVisionConn(a, conn, [16]byte{}, logger.NOP()); err == nil || result != nil {
			t.Fatal("nil provider admitted")
		}
	}
}

func visionProviderExchange(t *testing.T, factory visionProviderFactory, wrapped, badCertificate bool, innerVersion uint16, readLimit int) {
	t.Helper()
	certificate, roots := visionTestCertificate(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	uuid := [16]byte{1, 3, 5, 7}
	payload := bytes.Repeat([]byte("actual-inner-TLS13-over-Vision/"), 4096)
	serverDone := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		provider := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})
		if err = provider.HandshakeContext(ctx); err != nil {
			serverDone <- err
			return
		}
		protocol := &visionLimitedReadConn{Conn: provider, limit: readLimit}
		vision, err := NewVisionConn(protocol, provider, uuid, logger.NOP())
		protocol.vision = vision
		if err != nil {
			serverDone <- err
			return
		}
		inner := tls.Server(vision, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: innerVersion, MaxVersion: innerVersion})
		if err = inner.HandshakeContext(ctx); err != nil {
			serverDone <- err
			return
		}
		actual := make([]byte, len(payload))
		_, err = io.ReadFull(inner, actual)
		if err == nil && !bytes.Equal(actual, payload) {
			err = errors.New("server payload mismatch")
		}
		if err == nil {
			_, err = inner.Write(actual)
		}
		if err == nil && (vision.directRead != (innerVersion == tls.VersionTLS13 && readLimit >= 0) || vision.directWrite != (innerVersion == tls.VersionTLS13 && readLimit >= 0)) {
			err = errors.New("server Vision direct/record mode differs from detected TLS state")
		}
		serverDone <- err
	}()
	c, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if badCertificate {
		roots = x509.NewCertPool()
	}
	provider := factory(c, roots)
	err = provider.HandshakeContext(ctx)
	if badCertificate {
		if err == nil {
			t.Error("untrusted outer certificate admitted")
		}
		_ = c.Close()
	} else if err == nil {
		var inspected net.Conn = provider
		if wrapped {
			inspected = visionReplaceableProvider{provider}
		}
		var vision *VisionConn
		protocol := &visionLimitedReadConn{Conn: provider, limit: readLimit}
		vision, err = NewVisionConn(protocol, inspected, uuid, logger.NOP())
		protocol.vision = vision
		if err == nil {
			runtime.GC()
			inner := tls.Client(vision, &tls.Config{ServerName: "localhost", RootCAs: roots, MinVersion: innerVersion, MaxVersion: innerVersion})
			err = inner.HandshakeContext(ctx)
			if err == nil {
				runtime.GC()
				_, err = inner.Write(payload)
			}
			if err == nil {
				actual := make([]byte, len(payload))
				_, err = io.ReadFull(inner, actual)
				if err == nil && !bytes.Equal(actual, payload) {
					err = errors.New("client payload mismatch")
				}
			}
			if err == nil && (vision.directRead != (innerVersion == tls.VersionTLS13 && readLimit >= 0) || vision.directWrite != (innerVersion == tls.VersionTLS13 && readLimit >= 0)) {
				err = errors.New("client Vision direct/record mode differs from detected TLS state")
			}
			if err == nil && vision.tlsOwner == nil {
				err = errors.New("provider owner was not retained")
			}
		}
	}
	_ = c.Close()
	_ = listener.Close()
	select {
	case serverErr := <-serverDone:
		if !badCertificate && (err != nil || serverErr != nil) {
			t.Fatalf("actual TLS/Vision exchange: client=%v server=%v", err, serverErr)
		}
	case <-ctx.Done():
		t.Fatal("TLS/Vision server not joined")
	}
}
