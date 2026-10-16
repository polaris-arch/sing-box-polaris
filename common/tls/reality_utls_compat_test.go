//go:build with_utls

package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	stdtls "crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	meta "github.com/metacubex/utls"
)

// A controlled TLS1.3 camouflage endpoint and the actual MetaCubeX REALITY
// server exercise upstream-client compatibility, not just a prepared spec.
func TestRealityUpstreamClientMetaServerActualHandshake(t *testing.T) {
	for _, tc := range []struct {
		profile  string
		wrongKey bool
	}{{"chrome_155", false}, {"safari_26_3", false}, {"chrome_155", true}} {
		t.Run(fmt.Sprintf("%s/wrong-key-%v", tc.profile, tc.wrongKey), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cert := newPinnedTestCertificate(t, "localhost")
			camouflage, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer camouflage.Close()
			camouflageDone := make(chan struct{})
			go func() {
				defer close(camouflageDone)
				c, err := camouflage.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				secured := stdtls.Server(c, &stdtls.Config{Certificates: []stdtls.Certificate{cert.Certificate}, MinVersion: stdtls.VersionTLS13, MaxVersion: stdtls.VersionTLS13})
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
				Log: func(string, ...any) {}, DialContext: (&net.Dialer{}).DialContext,
			}}
			server.config.SessionTicketsDisabled = true
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			serverDone := make(chan error, 1)
			go func() {
				c, err := listener.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				secured, err := server.ServerHandshake(ctx, c)
				if err == nil {
					buf := make([]byte, 4)
					_, err = io.ReadFull(secured, buf)
					if err == nil && string(buf) != "ping" {
						err = errors.New("REALITY payload mismatch")
					}
					if err == nil {
						_, err = secured.Write([]byte("pong"))
					}
				}
				serverDone <- err
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
				ServerName: "localhost", UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: tc.profile},
				Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: base64.RawURLEncoding.EncodeToString(public), ShortID: "21"},
			})
			if err != nil {
				t.Fatal(err)
			}
			c, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			secured, clientErr := config.(interface {
				ClientHandshake(context.Context, net.Conn) (Conn, error)
			}).ClientHandshake(ctx, c)
			wrongKeyAdmitted := tc.wrongKey && clientErr == nil
			if wrongKeyAdmitted {
				_ = secured.Close()
			}
			if clientErr == nil && !tc.wrongKey {
				if secured.ConnectionState().CurveID != stdtls.X25519 {
					t.Error("REALITY did not negotiate classical X25519")
				}
				_, clientErr = secured.Write([]byte("ping"))
				if clientErr == nil {
					buf := make([]byte, 4)
					_, clientErr = io.ReadFull(secured, buf)
					if clientErr == nil && string(buf) != "pong" {
						clientErr = errors.New("REALITY reply mismatch")
					}
				}
			}
			c.Close()
			listener.Close()
			camouflage.Close()
			serverErr := <-serverDone
			select {
			case <-camouflageDone:
			case <-ctx.Done():
				t.Error("camouflage server did not retire")
			}
			if tc.wrongKey {
				if wrongKeyAdmitted || clientErr == nil {
					t.Fatal("wrong key accepted")
				}
				return
			}
			if clientErr != nil || serverErr != nil {
				t.Fatalf("actual REALITY handshake client=%v server=%v", clientErr, serverErr)
			}
		})
	}
}
