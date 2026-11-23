//go:build with_naive_outbound

package boxruntime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	mdns "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

const (
	runtimeNaiveProxyHost = "proxy.naive.test"
	runtimeNaiveProbeHost = "probe.naive.test"
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
		detour string
		share  bool
	}{
		{name: "duplicate", share: true},
		{name: "different server", share: true, change: func(o *option.NaiveOutboundOptions) {
			o.Server, o.Password, o.TLS.ServerName = "192.0.2.2", "other", "other.test"
			o.ExtraHeaders = badoption.HTTPHeader{"X-Member": {"other"}}
		}},
		{name: "control header", change: func(o *option.NaiveOutboundOptions) {
			o.ExtraHeaders = badoption.HTTPHeader{"-Network-Isolation-Key": {"https://n1:443"}}
		}},
		{name: "different congestion control", change: func(o *option.NaiveOutboundOptions) { o.QUICCongestionControl = "cubic" }},
		{name: "detour", both: true, change: func(o *option.NaiveOutboundOptions) { o.Detour = "carrier" }},
		{name: "external roots", both: true, change: func(o *option.NaiveOutboundOptions) { o.TLS.CertificatePath = "roots.pem" }},
		{name: "external ECH", both: true, change: func(o *option.NaiveOutboundOptions) {
			o.TLS.ECH = &option.OutboundECHOptions{Enabled: true, ConfigPath: "ech.pem"}
		}},
		{name: "hidden dialer option", both: true, change: func(o *option.NaiveOutboundOptions) { o.UDPBindPort = 12345 }},
		{name: "multiple engines", both: true, change: func(o *option.NaiveOutboundOptions) { o.InsecureConcurrency = 2 }},
		{name: "DNS depends on first member", detour: "first"},
		{name: "DNS late-binds a group of members", detour: "select", share: true},
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
					ServerOptions: option.ServerOptions{Server: "192.0.2.99", ServerPort: 443}, OutboundTLSOptionsContainer: base.OutboundTLSOptionsContainer, QUIC: true,
				}},
			}}
			if test.detour != "" {
				options.Outbounds = append(options.Outbounds, option.Outbound{Type: C.TypeSelector, Tag: "select", Options: &option.SelectorOutboundOptions{Outbounds: []string{"first", "second"}}})
				options.DNS = &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{
					Servers: []option.DNSServerOptions{{
						Type: C.DNSTypeUDP, Tag: "resolver",
						Options: &option.RemoteDNSServerOptions{
							RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{DialerOptions: option.DialerOptions{Detour: test.detour}},
							DNSServerAddressOptions:  option.DNSServerAddressOptions{Server: "192.0.2.53"},
						},
					}, {
						Type: C.DNSTypeUDP, Tag: "bootstrap",
						Options: &option.RemoteDNSServerOptions{DNSServerAddressOptions: option.DNSServerAddressOptions{Server: "192.0.2.54"}},
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
				// The client survives member changes: it depends on no member.
				cohorts, err := runtimegraph.DependencyCohorts(nodes)
				require.NoError(t, err)
				for _, cohort := range cohorts {
					if slices.Contains(cohort.Members, name) {
						require.Equal(t, []string{name}, cohort.Members)
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
			dnsPort, dnsQueries := runtimeNaiveDNS(t)
			port, root, sessions := runtimeNaiveEchoProxy(t, protocol)
			// proxy-a and proxy-b are different servers of one engine group.
			// proxy-c names proxy-a's server with another address, so it keeps a
			// dedicated engine.
			config := func(socksPort int, includeFirst bool, password string) []byte {
				member := func(tag string, server string, password string) string {
					return fmt.Sprintf(`{"type":"naive","tag":%q,"server":%q,"server_port":%d,"quic":%t,"username":"test","password":%q,"domain_resolver":{"server":"native-resolver","disable_cache":true},"tls":{"enabled":true,"server_name":%q,"certificate":%q}},`, tag, server, port, h3, password, runtimeNaiveProxyHost, root)
				}
				insertion := member("proxy-b", runtimeNaiveProxyHost, password) + member("proxy-c", "conflict.naive.test", "c")
				if includeFirst {
					// After proxy-b: the first outbound is the default route.
					insertion += member("proxy-a", runtimeNaiveProxyHost, "a")
				}
				configuration := bytes.Replace(runtimeTestConfig(socksPort, "example.org"), []byte(`"outbounds":[`), []byte(`"outbounds":[`+insertion), 1)
				configuration = bytes.Replace(configuration, []byte(`"servers":[`), fmt.Appendf(nil, `"servers":[{"type":"udp","tag":"native-resolver","server":"127.0.0.1","server_port":%d},`, dnsPort), 1)
				return bytes.Replace(configuration, []byte(`"outbounds":["a","b"],"default":"a"`), []byte(`"outbounds":["proxy-b","a","b"],"default":"proxy-b"`), 1)
			}
			f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "example.org"), nil)
			naive.RegisterOutbound(service.FromContext[adapter.OutboundRegistry](f.ctx).(*outbound.Registry))
			require.NoError(t, json.UnmarshalContext(f.ctx, config(1080, true, "b"), &options.Options))
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
			conflict, found := view.outbounds.Outbound("proxy-c")
			require.True(t, found)
			require.IsType(t, (*naive.Outbound)(nil), first)
			require.IsType(t, (*naive.Outbound)(nil), second)
			require.NotSame(t, first, second)
			require.Equal(t, "proxy-a", first.Tag())
			require.Equal(t, "proxy-b", second.Tag())
			require.Equal(t, C.TypeNaive, first.Type())
			require.NotSame(t, view.histories["proxy-a"], view.histories["proxy-b"])
			require.NotEqual(t, view.componentIDs["outbound:proxy-a"], view.componentIDs["outbound:proxy-b"])
			engine := func(member adapter.Outbound) adapter.RuntimeResourceID {
				t.Helper()
				owner, shared := member.(adapter.RuntimeSharedConnectionOwner).RuntimeSharedConnectionOwner()
				require.True(t, shared)
				return owner
			}
			owner := engine(first)
			require.Equal(t, owner, engine(second))
			_, shared := conflict.(adapter.RuntimeSharedConnectionOwner).RuntimeSharedConnectionOwner()
			require.False(t, shared, "a conflicting server name joined the shared engine")
			resets := 0
			instance.runtime.VisitRuntimeNetwork(t.Context(), func(_ context.Context, member adapter.Outbound, _ adapter.Router) {
				if member == first || member == second {
					resets++
				}
			})
			require.Equal(t, 1, resets)

			session := func(ctx context.Context) uint64 {
				t.Helper()
				select {
				case id := <-sessions:
					return id
				case <-ctx.Done():
					t.Fatal("proxy did not observe CONNECT")
					return 0
				}
			}
			probe := func(tag string) uint64 {
				t.Helper()
				ctx := runtimeTestContext(t)
				probe, connected, err := instance.AcquireRuntimeURLTest(ctx, tag)
				require.NoError(t, err)
				require.True(t, connected)
				defer probe.Release()
				require.Equal(t, tag, probe.Outbound().Tag())
				require.Same(t, view.histories[tag], probe.History())
				delay, err := urltest.URLTest(probe.Context(), "http://"+runtimeNaiveProbeHost+"/", probe.Outbound())
				require.NoError(t, err)
				result := &adapter.URLTestHistory{Time: time.Now(), Delay: delay}
				require.True(t, probe.IsCurrent())
				require.True(t, urltest.PublishRuntimeResult(probe.Context(), probe.Epoch(), tag, result))
				require.Equal(t, result, probe.History().LoadURLTestHistory(tag))
				return session(ctx)
			}
			firstCold := probe("proxy-a")
			firstQueries := dnsQueries.Load()
			require.Positive(t, firstQueries, "first cold member never queried the captured resolver")
			secondCold := probe("proxy-b")
			secondQueries := dnsQueries.Load()
			require.Greater(t, secondQueries, firstQueries, "second cold member never queried the captured resolver")
			require.NotEqual(t, firstCold, secondCold, "cold members shared a temporary session")
			require.Nil(t, view.histories["proxy-a"].LoadURLTestHistory("proxy-b"))
			require.Nil(t, view.histories["proxy-b"].LoadURLTestHistory("proxy-a"))

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
			dial := func(tag string) (net.Conn, uint64) {
				t.Helper()
				out, ok := instance.Outbound().Outbound(tag)
				require.True(t, ok)
				ctx := runtimeTestContext(t)
				conn, err := out.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("example.org", 443))
				require.NoError(t, err)
				t.Cleanup(func() { _ = conn.Close() })
				echo(conn)
				return conn, session(ctx)
			}
			firstConn, firstSession := dial("proxy-a")
			require.NotContains(t, []uint64{firstCold, secondCold}, firstSession, "cold probe warmed the active slot")
			// A warm probe runs on the shared engine under its member's isolation key.
			secondWarm := probe("proxy-b")
			require.NotEqual(t, firstSession, secondWarm, "members shared a session")
			secondConn, secondSession := dial("proxy-b")
			require.Equal(t, secondWarm, secondSession, "member did not reuse its own session")

			apply := func(content []byte) RuntimeConfigOperation {
				t.Helper()
				_, request := f.plan(t, content)
				operation, err := instance.applyRuntimeConfig(t.Context(), "actor-a", request)
				require.NoError(t, err)
				return operation
			}
			require.Equal(t, "COMMITTED_DURABILITY_PENDING", apply(config(1081, true, "b")).State)
			nextLease, next := f.acquire(t)
			require.Equal(t, view.componentIDs["outbound:proxy-b"], next.componentIDs["outbound:proxy-b"])
			borrowed, _ := next.outbounds.Outbound("proxy-b")
			require.Same(t, second, borrowed)
			nextLease.Release()

			// Changing one member rebuilds only it: the engine and the other
			// member, with its history, are retained.
			require.Equal(t, "COMMITTED_DURABILITY_PENDING", apply(config(1081, true, "changed")).State)
			changedLease, changed := f.acquire(t)
			require.Equal(t, view.componentIDs["outbound:proxy-a"], changed.componentIDs["outbound:proxy-a"])
			require.Same(t, view.histories["proxy-a"], changed.histories["proxy-a"])
			require.NotEqual(t, view.componentIDs["outbound:proxy-b"], changed.componentIDs["outbound:proxy-b"])
			changedSecond, _ := changed.outbounds.Outbound("proxy-b")
			require.Equal(t, owner, engine(changedSecond))
			changedLease.Release()

			require.Equal(t, "COMMITTED_DURABILITY_PENDING", apply(config(1081, false, "changed")).State)
			_, removed := f.acquire(t)
			require.Equal(t, changed.componentIDs["outbound:proxy-b"], removed.componentIDs["outbound:proxy-b"])
			require.NotContains(t, removed.componentIDs, "outbound:proxy-a")
			old := runtimeTestResource(t, f, view.componentIDs["outbound:proxy-a"])
			runtimeTestWait(t, old.owner.Retiring(), "removed Naive member retirement")
			lease.Release()
			echo(firstConn)
			echo(secondConn)
			require.NoError(t, firstConn.Close())
			require.NoError(t, secondConn.Close())
			require.NoError(t, old.owner.WaitClosed(runtimeTestContext(t)))
			require.Equal(t, owner, engine(changedSecond))

			before := f.identity()
			f.setConstructorHook(func(member *runtimeTestSocks) error {
				if member.Tag() == "a" {
					return errors.New("abort after preparing the replacement Naive members")
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

func runtimeNaiveDNS(t *testing.T) (int, *atomic.Int32) {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	var queries atomic.Int32
	started := make(chan struct{})
	server := &mdns.Server{
		PacketConn:        conn,
		NotifyStartedFunc: func() { close(started) },
		Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, request *mdns.Msg) {
			reply := new(mdns.Msg).SetReply(request)
			if len(request.Question) == 1 {
				q := request.Question[0]
				if strings.EqualFold(q.Name, runtimeNaiveProxyHost+".") && q.Qtype == mdns.TypeA {
					queries.Add(1)
					reply.Answer = []mdns.RR{&mdns.A{
						Hdr: mdns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: q.Qclass, Ttl: 60},
						A:   net.IPv4(127, 0, 0, 1),
					}}
				}
			}
			_ = w.WriteMsg(reply)
		}),
	}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	t.Cleanup(func() {
		require.NoError(t, server.Shutdown())
		require.NoError(t, <-done)
	})
	runtimeTestWait(t, started, "Naive DNS resolver listening")
	return conn.LocalAddr().(*net.UDPAddr).Port, &queries
}

func runtimeNaiveEchoProxy(t *testing.T, protocol int) (port int, root string, sessions <-chan uint64) {
	t.Helper()
	type sessionKey struct{}
	var nextSession atomic.Uint64
	connectionContext := func(ctx context.Context) context.Context {
		return context.WithValue(ctx, sessionKey{}, nextSession.Add(1))
	}
	connections := make(chan uint64, 4)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.ProtoMajor != protocol {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		flusher := w.(http.Flusher)
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		connections <- r.Context().Value(sessionKey{}).(uint64)
		authority := r.Header.Get("-connect-authority")
		if authority == "" {
			authority = r.URL.Host
		}
		if authority == "" {
			authority = r.Host
		}
		if authority == runtimeNaiveProbeHost+":80" {
			// The short HEAD request and response each occupy one Naive frame.
			var header [3]byte
			if _, err := io.ReadFull(r.Body, header[:]); err != nil {
				return
			}
			length := int(binary.BigEndian.Uint16(header[:2]))
			frame := make([]byte, length+int(header[2]))
			if _, err := io.ReadFull(r.Body, frame); err != nil {
				return
			}
			request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(frame[:length])))
			if err != nil || request.Method != http.MethodHead {
				return
			}
			const response = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
			binary.BigEndian.PutUint16(header[:2], uint16(len(response)))
			header[2] = 0
			_, _ = w.Write(append(header[:], response...))
			flusher.Flush()
			return
		}
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
	// Use a short-lived certificate for the proxy name resolved by the DNS stub.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Naive loopback test"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		DNSNames:              []string{runtimeNaiveProxyHost},
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
		server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context { return connectionContext(ctx) }
		server.StartTLS()
		t.Cleanup(server.Close)
		return server.Listener.Addr().(*net.TCPAddr).Port, root, connections
	}
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	h3 := &http3.Server{
		TLSConfig:   tlsConfig,
		Handler:     handler,
		ConnContext: func(ctx context.Context, _ *quic.Conn) context.Context { return connectionContext(ctx) },
	}
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
