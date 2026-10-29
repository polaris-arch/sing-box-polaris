package box

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
)

func runtimeResourceEncode(t *testing.T, f *runtimeTestFixture, options option.Options) []byte {
	t.Helper()
	content, err := json.MarshalContext(f.ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func runtimeResourceNew(t *testing.T, f *runtimeTestFixture, options Options) {
	t.Helper()
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.box = instance
	if instance.runtime == nil {
		t.Fatal("public initial eligibility did not select graph constructor")
	}
	t.Cleanup(func() {
		if err := instance.closeRuntimeResourcesContext(runtimeTestContext(t)); err != nil {
			t.Error(err)
		}
		if err := instance.CloseWithResult(); err != nil {
			t.Error(err)
		}
	})
}

// All traffic below uses in-memory net.Pipe peers. No DNS, socket or external
// HTTP service participates in these production Plan/Apply/transport tests.
func runtimeResourceHTTPPipe(t *testing.T, body string) net.Conn {
	t.Helper()
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = peer.Close() })
	go func() {
		defer peer.Close()
		request, err := http.ReadRequest(bufio.NewReader(peer))
		if err != nil {
			return
		}
		_ = request.Body.Close()
		_, _ = fmt.Fprintf(peer, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	}()
	return client
}

func runtimeResourceRequest(t *testing.T, lease adapter.RuntimeLease, transport http.RoundTripper) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(adapter.ContextWithRuntimeLease(runtimeTestContext(t), lease), http.MethodGet, "http://192.0.2.5/resource", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	return response
}

func TestRuntimeHTTPNamedSameTagReplacementRetainsOldStreamingBodyAndPersistenceDebt(t *testing.T) {
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "epoch.test"), func(o *runtimeTestSocks) error {
		tag := o.Tag()
		o.dialHook = func(context.Context, string, M.Socksaddr) (net.Conn, error) {
			return runtimeResourceHTTPPipe(t, tag), nil
		}
		return nil
	})
	options.HTTPClients = []option.HTTPClient{{Tag: "fetch", Version: 1, Detour: "a"}}
	options.Route.DefaultHTTPClient = "fetch"
	runtimeResourceNew(t, f, options)
	var persist atomic.Int32
	if err := f.box.BindRuntimePersistenceOptions(func(RuntimeIdentity, []byte) error {
		if persist.Add(1) == 1 {
			return errors.New("injected durability failure")
		}
		return nil
	}, "owner_acknowledged", true); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	oldLease, oldView := f.acquire(t)
	oldManager := oldView.httpClients
	transport, err := oldManager.RuntimePreparedTransport("fetch")
	if err != nil {
		t.Fatal(err)
	}
	response := runtimeResourceRequest(t, oldLease, transport)
	oldResource := runtimeTestResource(t, f, oldView.componentIDs["http-manager"])
	options.HTTPClients[0].Detour = "b"
	_, apply := f.plan(t, runtimeResourceEncode(t, f, options.Options))
	result := runtimeTestReceiveApply(t, runtimeTestApplyAsync(f, context.Background(), apply))
	if result.State != "COMMITTED_DURABILITY_PENDING" {
		t.Fatalf("lost committed debt: %+v", result)
	}
	newLease, newView := f.acquire(t)
	if newView.httpClients == oldManager || newView.componentIDs["http-manager"] == oldView.componentIDs["http-manager"] {
		t.Fatal("same tag reused old HTTP owner")
	}
	oldLease.Release()
	select {
	case <-oldResource.owner.Closed():
		t.Fatal("old response body lost its resource reservation")
	default:
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "a" {
		t.Fatalf("old epoch body: %q, %v", body, err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	current, err := newView.httpClients.RuntimePreparedTransport("fetch")
	if err != nil {
		t.Fatal(err)
	}
	newResponse := runtimeResourceRequest(t, newLease, current)
	body, err = io.ReadAll(newResponse.Body)
	if err != nil || string(body) != "b" {
		t.Fatalf("new epoch body: %q, %v", body, err)
	}
	_ = newResponse.Body.Close()
	manager := newView.httpClients
	retry, err := f.box.retryRuntimePersistence(context.Background(), "actor-a", RuntimePersistenceRetry{ContractVersion: RuntimeConfigContractVersion, TransactionID: result.TransactionID, Active: result.Active, PersistenceMode: result.PersistenceMode})
	if err != nil || !retry.Durable {
		t.Fatalf("persistence tail: %+v, %v", retry, err)
	}
	_, after := f.acquire(t)
	if after.httpClients != manager || persist.Load() != 2 {
		t.Fatal("persistence retry reconstructed live HTTP resources")
	}
}

func TestRuntimeResourceEligibilityAndBuildStubsArePrecise(t *testing.T) {
	for _, test := range []struct {
		name    string
		options option.Options
		path    string
	}{
		{"duplicate HTTP", option.Options{HTTPClients: []option.HTTPClient{{Tag: "a"}, {Tag: "a"}}}, "http_clients[1]"},
		{"missing HTTP", option.Options{Route: &option.RouteOptions{DefaultHTTPClient: "absent"}}, "route.default_http_client"},
		{"missing provider HTTP", option.Options{CertificateProviders: []option.CertificateProvider{{Type: "cloudflare-origin-ca", Tag: "cert", Options: &option.CloudflareOriginCACertificateProviderOptions{HTTPClient: &option.HTTPClientOptions{Tag: "absent"}}}}}, "certificate_providers[0].http_client"},
		{"unknown provider", option.Options{CertificateProviders: []option.CertificateProvider{{Type: "future", Options: &struct{}{}}}}, "certificate_providers[0]"},
		{"missing Tailscale endpoint", option.Options{CertificateProviders: []option.CertificateProvider{{Type: "tailscale", Options: &option.TailscaleCertificateProviderOptions{Endpoint: "absent"}}}}, "certificate_providers[0].endpoint"},
		{"privileged clock", option.Options{NTP: &option.NTPOptions{Enabled: true, WriteToSystem: true}}, "ntp.write_to_system"},
	} {
		t.Run(test.name, func(t *testing.T) {
			problems := runtimeResourceEligibility(context.Background(), test.options)
			if !slices.ContainsFunc(problems, func(p RuntimePlanError) bool { return p.Path == test.path }) {
				t.Fatalf("missing precise path %s: %+v", test.path, problems)
			}
		})
	}
	for _, item := range []struct {
		kind      string
		available bool
		options   any
	}{
		{"acme", false, &option.ACMECertificateProviderOptions{}},
		{"tailscale", certificate.RuntimeTailscaleAvailable, &option.TailscaleCertificateProviderOptions{Endpoint: "tail"}},
	} {
		options := option.Options{CertificateProviders: []option.CertificateProvider{{Type: item.kind, Tag: "cert", Options: item.options}}, Endpoints: []option.Endpoint{{Type: "tailscale", Tag: "tail"}}}
		problems := runtimeResourceEligibility(context.Background(), options)
		stub := slices.ContainsFunc(problems, func(p RuntimePlanError) bool { return p.Code == "PENDING_ADAPTER" })
		if stub == item.available {
			t.Fatalf("%s build stub inventory: %+v", item.kind, problems)
		}
	}
}

func TestRuntimeResourcePublicChangesAndIrreversibleClockBoundary(t *testing.T) {
	for _, pair := range [][2]string{
		{`{}`, `{"http_clients":[{"tag":"fetch","version":1}],"route":{"default_http_client":"fetch"}}`},
		{`{"http_clients":[{"tag":"fetch","version":1}]}`, `{}`},
		{`{}`, `{"ntp":{"enabled":true,"server":"192.0.2.123"}}`},
		{`{"ntp":{"enabled":true,"server":"192.0.2.123"}}`, `{}`},
		{`{}`, `{"certificate_providers":[]}`},
	} {
		if _, problems := runtimeDailyStructuralChanges(runtimeBoundaryJSON(t, pair[0]), runtimeBoundaryJSON(t, pair[1])); len(problems) != 0 {
			t.Fatal(problems)
		}
	}
	for _, candidate := range []string{`{}`, `{"ntp":{"enabled":true,"write_to_system":false}}`, `{"ntp":{"enabled":true,"write_to_system":true,"server":"new.invalid"}}`} {
		_, problems := runtimeDailyStructuralChanges(runtimeBoundaryJSON(t, `{"ntp":{"enabled":true,"write_to_system":true}}`), runtimeBoundaryJSON(t, candidate))
		if len(problems) != 1 || problems[0].Code != "RESTART_REQUIRED" || problems[0].Path != "ntp.write_to_system" {
			t.Fatal("irreversible write silently weakened", problems)
		}
	}
}

// This deliberately nonresponsive, entirely in-memory carrier makes the NTP
// cancellation/retirement path observable without contacting a time source.
type runtimeResourceClockConn struct {
	once   sync.Once
	closed chan struct{}
}

func (c *runtimeResourceClockConn) Read([]byte) (int, error)       { <-c.closed; return 0, net.ErrClosed }
func (c *runtimeResourceClockConn) Write(p []byte) (int, error)    { return len(p), nil }
func (c *runtimeResourceClockConn) Close() error                   { c.once.Do(func() { close(c.closed) }); return nil }
func (*runtimeResourceClockConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*runtimeResourceClockConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (*runtimeResourceClockConn) SetDeadline(time.Time) error      { return nil }
func (*runtimeResourceClockConn) SetReadDeadline(time.Time) error  { return nil }
func (*runtimeResourceClockConn) SetWriteDeadline(time.Time) error { return nil }

func TestRuntimeNTPEnableSourceReplacementDisableClosesActualOldExchange(t *testing.T) {
	carriers := make(chan *runtimeResourceClockConn, 8)
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "clock.test"), func(o *runtimeTestSocks) error {
		o.dialHook = func(_ context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
			if network != "udp" {
				return nil, errors.New("fixture only permits NTP")
			}
			conn := &runtimeResourceClockConn{closed: make(chan struct{})}
			carriers <- conn
			return conn, nil
		}
		return nil
	})
	runtimeResourceNew(t, f, options)
	f.start(t)
	_, before := f.acquire(t)
	var previous *runtimeResourceClockConn
	for _, server := range []string{"192.0.2.123", "192.0.2.124", ""} {
		if server == "" {
			options.NTP = nil
		} else {
			options.NTP = &option.NTPOptions{Enabled: true, Server: server, Detour: "a"}
		}
		_, apply := f.plan(t, runtimeResourceEncode(t, f, options.Options))
		operation := runtimeTestReceiveApply(t, runtimeTestApplyAsync(f, context.Background(), apply))
		if operation.Active.Revision != apply.Expected.Revision+1 {
			t.Fatalf("clock change not committed: %+v", operation)
		}
		_, current := f.acquire(t)
		for _, name := range []string{"http-manager", "outbound:a", "dns-transport:resolver"} {
			if current.componentIDs[name] == before.componentIDs[name] {
				t.Fatalf("clock change retained captured consumer %s", name)
			}
		}
		if previous != nil {
			runtimeTestWait(t, previous.closed, "old NTP exchange close")
		}
		if server != "" {
			select {
			case previous = <-carriers:
			case <-runtimeTestContext(t).Done():
				t.Fatal("new clock never sampled after publication")
			}
		} else {
			if _, exists := current.componentIDs["ntp"]; exists {
				t.Fatal("disabled clock retained NTP allocation")
			}
			select {
			case <-carriers:
				t.Fatal("disabled clock sampled")
			default:
			}
		}
		before = current
	}
}

func TestRuntimeHTTPMissingDependencyAndUnknownEnginePreserveActive(t *testing.T) {
	f := newRuntimeTestFixture(t, runtimeTestConfig(1080, "bad.test"), nil)
	f.start(t)
	before := f.identity()
	for _, fragment := range []string{
		`"http_clients":[{"tag":"fetch","detour":"absent"}]`,
		`"http_clients":[{"tag":"fetch","domain_resolver":"absent"}]`,
		`"http_clients":[{"tag":"fetch","engine":"future"}]`,
	} {
		base := strings.TrimSuffix(strings.TrimSpace(string(runtimeTestConfig(1080, "bad.test"))), "}")
		plan, err := f.box.planRuntimeConfig(context.Background(), "actor-a", before, []byte(base+","+fragment+"}"))
		if err != nil || plan.Applicable || len(plan.Errors) == 0 || f.identity() != before {
			t.Fatalf("invalid HTTP candidate changed graph: %+v %v", plan, err)
		}
	}
}

func TestRuntimeHTTPConsumerClosureChangesUseNewExactAllocations(t *testing.T) {
	for _, change := range []string{"add", "remove", "default", "resolver", "detour", "route-final"} {
		t.Run(change, func(t *testing.T) {
			f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "closure.test"), nil)
			if change != "add" && change != "route-final" {
				options.HTTPClients = []option.HTTPClient{{Tag: "one", Version: 1, Detour: "a", DomainResolver: &option.DomainResolveOptions{Server: "resolver"}}, {Tag: "two", Version: 1, Detour: "b"}}
				options.Route.DefaultHTTPClient = "one"
			}
			runtimeResourceNew(t, f, options)
			f.start(t)
			_, old := f.acquire(t)
			switch change {
			case "add":
				options.HTTPClients = []option.HTTPClient{{Tag: "one", Version: 1, Detour: "a"}}
				options.Route.DefaultHTTPClient = "one"
			case "remove":
				options.HTTPClients = nil
				options.Route.DefaultHTTPClient = ""
			case "default":
				options.Route.DefaultHTTPClient = "two"
			case "resolver":
				options.DNS.Servers[0].Options.(*option.RemoteDNSServerOptions).Server = "192.0.2.54"
			case "detour":
				options.Outbounds[0].Options.(*option.SOCKSOutboundOptions).ServerPort = 1081
			case "route-final":
				options.Route.Final = "b"
			}
			_, request := f.plan(t, runtimeResourceEncode(t, f, options.Options))
			operation := runtimeTestReceiveApply(t, runtimeTestApplyAsync(f, context.Background(), request))
			if operation.Active.Revision != request.Expected.Revision+1 {
				t.Fatalf("not published: %+v", operation)
			}
			_, current := f.acquire(t)
			for _, name := range []string{"http-manager", "route-router"} {
				if old.componentIDs[name] == current.componentIDs[name] {
					t.Fatalf("%s retained captured %s", change, name)
				}
			}
		})
	}
}

func TestRuntimeProviderOnlyInboundEditsKeepOtherListenerFieldsStructural(t *testing.T) {
	before := runtimeBoundaryJSON(t, `{"inbounds":[{"type":"http","tag":"tls","listen_port":8443,"tls":{"enabled":true,"certificate_provider":"old"}},{"type":"socks","tag":"plain"}]}`)
	for _, test := range []struct {
		after   string
		allowed bool
	}{
		{`{"inbounds":[{"type":"http","tag":"tls","listen_port":8443,"tls":{"enabled":true,"certificate_provider":"new"}},{"type":"socks","tag":"plain"}]}`, true},
		{`{"inbounds":[{"type":"http","tag":"tls","listen_port":8444,"tls":{"enabled":true,"certificate_provider":"new"}},{"type":"socks","tag":"plain"}]}`, false},
		{`{"inbounds":[{"type":"http","tag":"tls","listen_port":8443,"tls":{"enabled":false,"certificate_provider":"new"}},{"type":"socks","tag":"plain"}]}`, false},
	} {
		_, problems := runtimeDailyStructuralChanges(before, runtimeBoundaryJSON(t, test.after))
		if (len(problems) == 0) != test.allowed {
			t.Fatal("provider-only listener boundary mismatch", problems)
		}
	}
}
