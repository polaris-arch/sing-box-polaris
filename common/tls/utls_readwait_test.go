//go:build with_utls && badlinkname

package tls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	stdtls "crypto/tls"
	"encoding/binary"
	"hash"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/badtls"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"

	meta "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
)

// Independent TLS 1.3 HKDF label encoding, rather than comparing two calls to
// the same private function. This checks read-wait and same-library key updates,
// not Linux kernel offload availability or a peer KeyUpdate exchange.
func testTLS13Expand(t *testing.T, h func() hash.Hash, secret []byte, label string, size int) []byte {
	t.Helper()
	label = "tls13 " + label
	info := make([]byte, 2, 4+len(label))
	binary.BigEndian.PutUint16(info, uint16(size))
	info = append(info, byte(len(label)))
	info = append(info, label...)
	info = append(info, 0)
	result := make([]byte, size)
	if _, err := io.ReadFull(hkdf.Expand(h, secret, info), result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestTLSReadWaitAndCipherMethodsStayInOwningLibrary(t *testing.T) {
	certificate := newPinnedTestCertificate(t, "localhost")
	for _, library := range []string{"std", "meta", "refraction"} {
		t.Run(library, func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			deadline := time.Now().Add(5 * time.Second)
			_ = left.SetDeadline(deadline)
			_ = right.SetDeadline(deadline)
			done := make(chan error, 1)
			go func() {
				server := stdtls.Server(right, &stdtls.Config{Certificates: []stdtls.Certificate{certificate.Certificate}, MinVersion: stdtls.VersionTLS13})
				err := server.Handshake()
				if err == nil {
					_, err = server.Write([]byte("read-wait"))
				}
				done <- err
			}()
			var client Conn
			switch library {
			case "std":
				client = stdtls.Client(left, &stdtls.Config{ServerName: "localhost", InsecureSkipVerify: true})
			case "meta":
				client = &realityConnWrapper{Conn: meta.Client(left, &meta.Config{ServerName: "localhost", InsecureSkipVerify: true})}
			default:
				config := profileClient(t, "chrome_155", option.OutboundTLSOptions{ServerName: "localhost", Insecure: true})
				var err error
				client, err = config.Client(left)
				if err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()
			if err := client.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			raw, err := badtls.NewRawConn(client)
			if err != nil {
				t.Fatal("actual connection layout/registry", err)
			}
			wrapped, err := badtls.NewReadWaitConn(client)
			if err != nil {
				t.Fatal(err)
			}
			reader := wrapped.(*badtls.ReadWaitConn)
			reader.InitializeReadWaiter(N.ReadWaitOptions{})
			buffer, err := reader.WaitReadBuffer()
			if err != nil {
				t.Fatal("actual read-wait record", err)
			}
			if string(buffer.Bytes()) != "read-wait" {
				t.Error("read-wait payload changed")
			}
			buffer.Release()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			id := client.ConnectionState().CipherSuite
			h := sha256.New
			size := 16
			if id == stdtls.TLS_AES_256_GCM_SHA384 {
				h = sha512.New384
				size = 32
			}
			if id == stdtls.TLS_CHACHA20_POLY1305_SHA256 {
				size = 32
			}
			for _, half := range []*badtls.RawHalfConn{raw.In, raw.Out} {
				half.Lock()
				before := bytes.Clone(*half.TrafficSecret)
				key, iv, err := half.TrafficKey(id, before)
				if err != nil || !bytes.Equal(key, testTLS13Expand(t, h, before, "key", size)) || !bytes.Equal(iv, testTLS13Expand(t, h, before, "iv", 12)) {
					half.Unlock()
					t.Fatal("owning-library traffic key mismatch", err)
				}
				if err := half.AdvanceTrafficSecret(id, 0); err != nil {
					half.Unlock()
					t.Fatal(err)
				}
				if !bytes.Equal(*half.TrafficSecret, testTLS13Expand(t, h, before, "traffic upd", h().Size())) {
					half.Unlock()
					t.Fatal("owning-library traffic secret mismatch")
				}
				if _, _, err := half.TrafficKey(0xffff, before); err == nil {
					half.Unlock()
					t.Fatal("unknown cipher admitted")
				}
				if err := half.AdvanceTrafficSecret(0xffff, 0); err == nil {
					half.Unlock()
					t.Fatal("unknown cipher update admitted")
				}
				half.Unlock()
			}
		})
	}
}
