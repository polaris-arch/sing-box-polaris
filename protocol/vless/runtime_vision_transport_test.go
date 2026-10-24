//go:build with_utls

package vless

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	coretls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayhttpupgrade"
	"github.com/sagernet/sing-box/transport/v2raywebsocket"
	vl "github.com/sagernet/sing-vmess/vless"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/ws"
)

type visionTransportDialer struct{ net.Dialer }

func (d *visionTransportDialer) DialContext(ctx context.Context, network string, addr M.Socksaddr) (net.Conn, error) {
	return d.Dialer.DialContext(ctx, network, addr.String())
}
func (*visionTransportDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

// Real HTTP upgrades and a payload roundtrip establish that this is not a
// network/authentication failure. A transport lease must not be unwrapped to
// bypass its fence merely because the underlying carrier uses supported TLS.
func TestRuntimeVisionRejectsActualUpgradedTransports(t *testing.T) {
	for _, kind := range []string{"ws", "httpupgrade"} {
		for _, profile := range []string{"", "chrome_155"} {
			t.Run(fmt.Sprintf("%s/profile-%s", kind, profile), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				keyPEM, certPEM, err := coretls.GenerateCertificate(nil, nil, time.Now, "localhost", time.Now().Add(time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				cert, err := stdtls.X509KeyPair(certPEM, keyPEM)
				if err != nil {
					t.Fatal(err)
				}
				payload := []byte("real-upgraded-transport-roundtrip")
				done := make(chan error, 1)
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var conn net.Conn
					var err error
					if kind == "ws" {
						conn, _, _, err = ws.UpgradeHTTP(r, w)
						if err == nil {
							conn = v2raywebsocket.NewConn(conn, nil, ws.StateServerSide)
						}
					} else {
						// HTTPUpgrade has no payload framing after the HTTP 101.
						c, rw, hijackErr := w.(http.Hijacker).Hijack()
						conn, err = c, hijackErr
						if err == nil {
							_, err = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
							if err == nil {
								err = rw.Flush()
							}
						}
					}
					if err != nil {
						done <- err
						return
					}
					defer conn.Close()
					got := make([]byte, len(payload))
					_, err = io.ReadFull(conn, got)
					if err == nil && !bytes.Equal(got, payload) {
						err = fmt.Errorf("upgraded request bytes changed")
					}
					if err == nil {
						_, err = conn.Write(got)
					}
					done <- err
				}))
				server.TLS = &stdtls.Config{Certificates: []stdtls.Certificate{cert}, MinVersion: stdtls.VersionTLS13}
				server.StartTLS()
				defer server.Close()
				logger := log.NewNOPFactory().Logger()
				options := option.OutboundTLSOptions{Enabled: true, ServerName: "localhost", Certificate: []string{string(certPEM)}}
				if profile != "" {
					options.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: profile}
				}
				config, err := coretls.NewClient(ctx, logger, "localhost", options)
				if err != nil {
					t.Fatal(err)
				}
				addr := M.SocksaddrFromNet(server.Listener.Addr())
				var transport adapter.V2RayClientTransport
				if kind == "ws" {
					transport, err = v2raywebsocket.NewClient(ctx, &visionTransportDialer{}, addr, option.V2RayWebsocketOptions{Path: "/"}, config)
				} else {
					transport, err = v2rayhttpupgrade.NewClient(ctx, &visionTransportDialer{}, addr, option.V2RayHTTPUpgradeOptions{Path: "/"}, config)
				}
				if err != nil {
					t.Fatal(err)
				}
				defer transport.Close()
				conn, err := transport.DialContext(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if _, err = conn.Write(payload); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(payload))
				if _, err = io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("actual upgraded exchange: %v", err)
				}
				dialer := &vlessDialer{flow: vl.FlowVision, logger: logger}
				if _, err = dialer.dialEarlyRuntimeConn(conn, M.ParseSocksaddr("127.0.0.1:443")); err == nil || !strings.Contains(err.Error(), "initialize vision: vision: not a valid supported TLS connection") {
					t.Fatalf("transport must not acquire TLS inspection through an opaque ownership boundary: %v", err)
				}
				select {
				case err = <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal("upgraded peer not joined")
				}
			})
		}
	}
}
