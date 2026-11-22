//go:build with_naive_outbound

package boxruntime

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func TestRuntimeNaiveShareRequiresEquivalentAcyclicDependencies(t *testing.T) {
	base := option.NaiveOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "192.0.2.1", ServerPort: 443},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{Enabled: true},
		},
	}
	for _, test := range []struct {
		name   string
		change func(*option.NaiveOutboundOptions)
		both   bool
		cycle  bool
		share  bool
	}{
		{name: "duplicate", share: true},
		{name: "different credentials", change: func(o *option.NaiveOutboundOptions) { o.Password = "other" }},
		{name: "different congestion control", change: func(o *option.NaiveOutboundOptions) { o.QUICCongestionControl = "cubic" }},
		{name: "detour", both: true, change: func(o *option.NaiveOutboundOptions) { o.Detour = "carrier" }},
		{name: "external roots", both: true, change: func(o *option.NaiveOutboundOptions) { o.TLS.CertificatePath = "roots.pem" }},
		{name: "external ECH", both: true, change: func(o *option.NaiveOutboundOptions) {
			o.TLS.ECH = &option.OutboundECHOptions{Enabled: true, ConfigPath: "ech.pem"}
		}},
		{name: "hidden dialer option", both: true, change: func(o *option.NaiveOutboundOptions) { o.UDPBindPort = 12345 }},
		{name: "multiple engines", both: true, change: func(o *option.NaiveOutboundOptions) { o.InsecureConcurrency = 2 }},
		{name: "DNS depends on first alias", cycle: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			first, second := base, base
			firstTLS, secondTLS := *base.TLS, *base.TLS
			first.TLS, second.TLS = &firstTLS, &secondTLS
			if test.change != nil {
				test.change(&second)
				if test.both {
					test.change(&first)
				}
			}
			options := option.Options{Outbounds: []option.Outbound{
				{Type: C.TypeNaive, Tag: "first", Options: &first},
				{Type: C.TypeNaive, Tag: "second", Options: &second},
				{Type: C.TypeDirect, Tag: "carrier", Options: &option.DirectOutboundOptions{}},
				{Type: C.TypeNaive, Tag: "singleton", Options: &option.NaiveOutboundOptions{
					ServerOptions: option.ServerOptions{Server: "192.0.2.99", ServerPort: 443}, OutboundTLSOptionsContainer: base.OutboundTLSOptionsContainer,
				}},
			}}
			if test.cycle {
				options.DNS = &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{
					Servers: []option.DNSServerOptions{{
						Type: C.DNSTypeUDP, Tag: "resolver",
						Options: &option.RemoteDNSServerOptions{
							RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{DialerOptions: option.DialerOptions{Detour: "first"}},
							DNSServerAddressOptions:  option.DNSServerAddressOptions{Server: "192.0.2.53"},
						},
					}},
				}}
			}
			nodes, configs, err := runtimeConfigNodes(t.Context(), runtimeResolveGraphDefaults(options))
			require.NoError(t, err)
			name := configs["outbound:first"].naiveClient
			require.Equal(t, name, configs["outbound:second"].naiveClient)
			require.Empty(t, configs["outbound:singleton"].naiveClient)
			require.Equal(t, test.share, name != "")
			if test.share {
				cohorts, err := runtimegraph.DependencyCohorts(nodes)
				require.NoError(t, err)
				for _, cohort := range cohorts {
					if slices.Contains(cohort.Members, name) {
						require.ElementsMatch(t, []string{name, "outbound:first", "outbound:second"}, cohort.Members)
						return
					}
				}
				t.Fatal("physical client has no ownership cohort")
			}
		})
	}
}

func TestRuntimeNaiveSharedClientThroughPublication(t *testing.T) {
	for _, h3 := range []bool{false, true} {
		protocol := 2
		if h3 {
			protocol = 3
		}
		t.Run(fmt.Sprint("h", protocol), func(t *testing.T) {
			port, root, peers := runtimeNaiveEchoProxy(t, protocol)
			config := func(socksPort int, includeFirst bool, password string) []byte {
				alias := func(tag string) string {
					return fmt.Sprintf(`{"type":"naive","tag":%q,"server":"127.0.0.1","server_port":%d,"quic":%t,"username":"test","password":%q,"tls":{"enabled":true,"certificate":%q}},`, tag, port, h3, password, root)
				}
				insertion := alias("proxy-b")
				if includeFirst {
					insertion = alias("proxy-a") + insertion
				}
				configuration := bytes.Replace(runtimeTestConfig(socksPort, "example.org"), []byte(`"outbounds":[`), []byte(`"outbounds":[`+insertion), 1)
				return bytes.Replace(configuration, []byte(`"outbounds":["a","b"],"default":"a"`), []byte(`"outbounds":["proxy-b","a","b"],"default":"proxy-b"`), 1)
			}
			f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "example.org"), nil)
			naive.RegisterOutbound(service.FromContext[adapter.OutboundRegistry](f.ctx).(*outbound.Registry))
			require.NoError(t, json.UnmarshalContext(f.ctx, config(1080, true, "test"), &options.Options))
			instance, err := New(options)
			require.NoError(t, err)
			f.box = instance
			t.Cleanup(func() { require.NoError(t, instance.CloseWithResult()) })
			require.NotNil(t, instance.runtime)
			f.start(t)
			runtimeTestPublishPrivatePlatformClosure(t, f)

			lease, view := f.acquire(t)
			first, found := view.outbounds.Outbound("proxy-a")
			require.True(t, found)
			second, found := view.outbounds.Outbound("proxy-b")
			require.True(t, found)
			require.IsType(t, (*naive.Outbound)(nil), first)
			require.IsType(t, (*naive.Outbound)(nil), second)
			require.NotSame(t, first, second)
			require.Equal(t, "proxy-a", first.Tag())
			require.Equal(t, "proxy-b", second.Tag())
			require.Equal(t, C.TypeNaive, first.Type())
			require.NotSame(t, view.histories["proxy-a"], view.histories["proxy-b"])
			owner := view.componentIDs["outbound:proxy-a"]
			require.Equal(t, owner, view.componentIDs["outbound:proxy-b"])
			resets := 0
			instance.runtime.VisitRuntimeNetwork(t.Context(), func(_ context.Context, member adapter.Outbound, _ adapter.Router) {
				if member == first || member == second {
					resets++
				}
			})
			require.Equal(t, 1, resets)

			echo := func(conn net.Conn) {
				t.Helper()
				deadline, _ := runtimeTestContext(t).Deadline()
				require.NoError(t, conn.SetDeadline(deadline))
				_, err := conn.Write([]byte("a"))
				require.NoError(t, err)
				response := make([]byte, 1)
				_, err = io.ReadFull(conn, response)
				require.NoError(t, err)
				require.Equal(t, "a", string(response))
			}
			dial := func(tag string) (net.Conn, string) {
				t.Helper()
				out, ok := instance.Outbound().Outbound(tag)
				require.True(t, ok)
				ctx := runtimeTestContext(t)
				conn, err := out.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("example.org", 443))
				require.NoError(t, err)
				t.Cleanup(func() { _ = conn.Close() })
				echo(conn)
				select {
				case peer := <-peers:
					return conn, peer
				case <-ctx.Done():
					t.Fatal("proxy did not observe CONNECT")
					return nil, ""
				}
			}
			firstConn, firstPeer := dial("proxy-a")
			secondConn, secondPeer := dial("proxy-b")
			require.Equal(t, firstPeer, secondPeer, "aliases opened separate physical proxy connections")

			apply := func(content []byte) RuntimeConfigOperation {
				t.Helper()
				_, request := f.plan(t, content)
				operation, err := instance.applyRuntimeConfig(t.Context(), "actor-a", request)
				require.NoError(t, err)
				return operation
			}
			require.Equal(t, "COMMITTED_DURABILITY_PENDING", apply(config(1081, true, "test")).State)
			nextLease, next := f.acquire(t)
			require.Equal(t, owner, next.componentIDs["outbound:proxy-b"])
			borrowed, _ := next.outbounds.Outbound("proxy-b")
			require.Same(t, second, borrowed)
			nextLease.Release()

			require.Equal(t, "COMMITTED_DURABILITY_PENDING", apply(config(1081, false, "test")).State)
			_, singleton := f.acquire(t)
			require.NotEqual(t, owner, singleton.componentIDs["outbound:proxy-b"])
			require.NotContains(t, singleton.componentIDs, "outbound:proxy-a")
			old := runtimeTestResource(t, f, owner)
			runtimeTestWait(t, old.owner.Retiring(), "old Naive group retirement")
			lease.Release()
			echo(firstConn)
			echo(secondConn)
			require.NoError(t, firstConn.Close())
			require.NoError(t, secondConn.Close())
			require.NoError(t, old.owner.WaitClosed(runtimeTestContext(t)))

			before := f.identity()
			f.setConstructorHook(func(member *runtimeTestSocks) error {
				if member.Tag() == "a" {
					return errors.New("abort after preparing the replacement Naive group")
				}
				return nil
			})
			failed := apply(config(1082, true, "different"))
			require.True(t, strings.HasPrefix(failed.State, "ABORT"), "%+v", failed)
			require.Equal(t, before, f.identity())
			conn, _ := dial("proxy-b")
			require.NoError(t, conn.Close())
		})
	}
}

func runtimeNaiveEchoProxy(t *testing.T, protocol int) (port int, root string, peers <-chan string) {
	t.Helper()
	connections := make(chan string, 4)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.ProtoMajor != protocol {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		flusher := w.(http.Flusher)
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		connections <- r.RemoteAddr
		var b [1]byte
		for {
			if _, err := io.ReadFull(r.Body, b[:]); err != nil {
				return
			}
			if _, err := w.Write(b[:]); err != nil {
				return
			}
			flusher.Flush()
		}
	})
	// Chromium enforces certificate validity and an IP SAN for this numeric
	// proxy address. Keep the self-signed trust anchor local to the test.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Naive loopback test"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require.NoError(t, err)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	root = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if protocol == 2 {
		server := httptest.NewUnstartedServer(handler)
		server.TLS = tlsConfig
		server.EnableHTTP2 = true
		server.StartTLS()
		t.Cleanup(server.Close)
		return server.Listener.Addr().(*net.TCPAddr).Port, root, connections
	}
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	h3 := &http3.Server{TLSConfig: tlsConfig, Handler: handler}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h3.Serve(packetConn)
	}()
	t.Cleanup(func() {
		_ = h3.Close()
		_ = packetConn.Close()
		<-done
	})
	return packetConn.LocalAddr().(*net.UDPAddr).Port, root, connections
}
