package transport

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

type runtimeDNSFailClose struct {
	net.Conn
	calls      atomic.Int32
	panicClose bool
}

func (c *runtimeDNSFailClose) Close() error {
	c.calls.Add(1)
	if c.panicClose {
		panic("close failed")
	}
	return net.ErrClosed
}

func TestDNSCarrierCleanupUncertaintyReachesTerminalOwner(t *testing.T) {
	for _, panicClose := range []bool{false, true} {
		raw := &runtimeDNSFailClose{panicClose: panicClose}
		m := newQueryMultiplexer(queryMultiplexerOptions{context: context.Background(), dial: func(context.Context) (net.Conn, error) { return raw, nil }})
		conn, err := m.options.dial(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close() // Includes generic pool's void close callback behavior.
		_ = conn.Close()
		err = m.Close()
		if err == nil || !runtimeDNSCleanupIncomplete(err) {
			t.Fatal("carrier failure was discarded", err)
		}
		if errors.Is(err, net.ErrClosed) {
			t.Fatal("Scope could filter uncertainty as ordinary closed")
		}
		if raw.calls.Load() != 1 {
			t.Fatal("cleanup was not one-shot")
		}
	}
}

type runtimeDoHTestDialer struct {
	N.Dialer
	tlsDialer stdtls.Dialer
	dials     atomic.Int32
}

func (d *runtimeDoHTestDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dials.Add(1)
	return d.tlsDialer.DialContext(ctx, network, destination.String())
}

func TestHTTPSProbeQueriesUseDedicatedConnections(t *testing.T) {
	arrived := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		var question mDNS.Msg
		if err != nil || question.Unpack(body) != nil || len(question.Question) != 1 || request.ProtoMajor != 2 {
			http.Error(writer, "invalid DoH request", http.StatusBadRequest)
			return
		}
		if question.Question[0].Name == "wait.example." {
			close(arrived)
			<-request.Context().Done()
			return
		}
		var response mDNS.Msg
		response.SetReply(&question)
		payload, err := response.Pack()
		if err != nil {
			http.Error(writer, "invalid response", http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", MimeType)
		_, _ = writer.Write(payload)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	destination, err := url.Parse(server.URL + "/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	config := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	config.NextProtos = []string{"h2"}
	dialer := &runtimeDoHTestDialer{tlsDialer: stdtls.Dialer{Config: config}}
	const tag = "dns-probe-exit-0"
	transport := NewHTTPSRaw(dns.NewTransportAdapterWithRemoteOptions(C.DNSTypeHTTPS, tag, option.RemoteDNSServerOptions{}), nil, dialer, destination, http.Header{}, M.ParseSocksaddr(destination.Host), nil)
	t.Cleanup(func() {
		if err := transport.RuntimeCloseAndWait(); err != nil {
			t.Error(err)
		}
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	scoped := urltest.ContextWithLegacyPoolProbeDNS(ctx, tag)
	other := urltest.ContextWithLegacyPoolProbeDNS(ctx, "dns-probe-exit-1")
	question := new(mDNS.Msg).SetQuestion("test.example.", mDNS.TypeA)
	for _, queryCtx := range []context.Context{ctx, other, scoped, scoped, ctx} {
		if _, err := transport.Exchange(queryCtx, question); err != nil {
			t.Fatal(err)
		}
	}
	if n := dialer.dials.Load(); n != 3 {
		t.Fatalf("expected one shared connection and two dedicated connections, got %d", n)
	}

	done := make(chan error, 1)
	go func() {
		_, err := transport.Exchange(scoped, new(mDNS.Msg).SetQuestion("wait.example.", mDNS.TypeA))
		done <- err
	}()
	select {
	case <-arrived:
	case <-ctx.Done():
		t.Fatal("dedicated exchange did not arrive")
	}
	transport.Reset()
	select {
	case err := <-done:
		if !errors.Is(err, urltest.ErrProbeNotRun) {
			t.Fatalf("reset should defer the dedicated exchange, got %v", err)
		}
	case <-ctx.Done():
		t.Fatal("reset left the dedicated exchange running")
	}
	if _, err := transport.Exchange(scoped, question); err != nil {
		t.Fatal(err)
	}
	transport.transportAccess.Lock()
	pending := len(transport.probeTransports)
	transport.transportAccess.Unlock()
	if pending != 0 {
		t.Fatalf("%d completed dedicated transports remain", pending)
	}
}
