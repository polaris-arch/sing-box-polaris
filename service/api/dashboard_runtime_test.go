package api

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	boxCertificate "github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

func dashboardTestZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for path, content := range entries {
		entry, err := writer.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(entry, content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func dashboardWait(t *testing.T, done <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: " + description)
	}
}

type dashboardTestFiles struct {
	filemanager.Manager
	rename func(string, string) error
}

func (m *dashboardTestFiles) Rename(before, after string) error {
	if m.rename != nil {
		return m.rename(before, after)
	}
	return m.Manager.Rename(before, after)
}

func dashboardFileContext(t *testing.T) (context.Context, *dashboardTestFiles) {
	t.Helper()
	ctx := filemanager.WithDefault(context.Background(), "", t.TempDir(), os.Getuid(), os.Getgid())
	files := &dashboardTestFiles{Manager: service.FromContext[filemanager.Manager](ctx)}
	return service.ContextWith[filemanager.Manager](ctx, files), files
}

func dashboardRuntimeContent(path, url string, port uint16, detour string) string {
	return fmt.Sprintf(`{"log":{"disabled":true},"dns":{"servers":[{"type":"udp","tag":"resolver","server":"192.0.2.53"}],"final":"resolver"},"outbounds":[{"type":"direct","tag":"direct"},{"type":"selector","tag":"download-path","outbounds":["direct"],"default":"direct"}],"route":{"final":"download-path"},"services":[{"type":"api","listen":"127.0.0.1","listen_port":%d,"dashboard":{"enabled":true,"path":%q,"download_url":%q,"http_client":{"detour":%q}}}]}`, port, path, url, detour)
}

func dashboardRuntimeBox(t *testing.T, ctx context.Context, path, url string, port uint16, detour string) (*box.Box, *Service) {
	t.Helper()
	if runtime.GOOS == "android" || runtime.GOOS == "windows" {
		t.Skip("native certificate/power boundary requires its platform fixture")
	}
	outbounds := outbound.NewRegistry()
	direct.RegisterOutbound(outbounds)
	group.RegisterSelector(outbounds)
	transports := dns.NewTransportRegistry()
	transport.RegisterUDP(transports)
	services := boxService.NewRegistry()
	RegisterService(services)
	ctx = box.Context(ctx, inbound.NewRegistry(), outbounds, endpoint.NewRegistry(), transports, services, boxCertificate.NewRegistry())
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, &runtimeAPIPlatform{})
	content := dashboardRuntimeContent(path, url, port, detour)
	var options option.Options
	if err := json.UnmarshalContext(ctx, []byte(content), &options); err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := instance.CloseWithResult(); err != nil {
			t.Error(err)
		}
	})
	registered, found := service.FromContext[adapter.ServiceManager](ctx).Get("0")
	if !found {
		t.Fatal("default API service missing")
	}
	return instance, registered.(*Service)
}

func TestRuntimeDashboardColdFirstFetchUsesPublishedGraph(t *testing.T) {
	archive := dashboardTestZip(t, map[string]string{"dashboard/index.html": "cold-localhost"})
	requested, published := make(chan struct{}), make(chan struct{})
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) == 1 {
			close(requested)
		}
		w.Header().Set("Etag", "cold-v1")
		_, _ = w.Write(archive)
	}))
	t.Cleanup(server.Close)
	ctx, files := dashboardFileContext(t)
	path := filepath.Join(t.TempDir(), "dashboard")
	var once sync.Once
	files.rename = func(before, after string) error {
		err := files.Manager.Rename(before, after)
		if err == nil && after == path {
			once.Do(func() { close(published) })
		}
		return err
	}
	instance, api := dashboardRuntimeBox(t, ctx, path, server.URL, 0, "download-path")
	if count.Load() != 0 {
		t.Fatal("candidate construction performed HTTP I/O")
	}
	failures := make(chan string, 4)
	api.dashboard.logger = &dashboardFailureLogger{ContextLogger: api.dashboard.logger, failures: failures}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	// A failed first admission would wait the unchanged 24-hour interval, not
	// satisfy these explicit request/publication barriers.
	select {
	case <-requested:
	case failure := <-failures:
		t.Fatalf("first managed download failed: %s", failure)
	case <-time.After(5 * time.Second):
		t.Fatal("first managed download produced neither request nor error")
	}
	dashboardWait(t, published, "first managed directory publication")
	content, err := os.ReadFile(filepath.Join(path, "index.html"))
	if err != nil || string(content) != "cold-localhost" {
		t.Fatalf("published dashboard: %q %v", content, err)
	}
	if count.Load() != 1 || api.dashboard.provider == nil || instance.RuntimeCapabilities().FullConfiguration {
		t.Fatal("cold adapter boundary changed")
	}
	if err := instance.CloseWithResult(); err != nil {
		t.Fatal(err)
	}
	dashboardWait(t, api.dashboard.done, "dashboard worker joined before graph drain")
}

func TestRuntimeDashboardStartFailureJoinsWorker(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	t.Cleanup(server.Close)
	ctx, _ := dashboardFileContext(t)
	instance, api := dashboardRuntimeBox(t, ctx, filepath.Join(t.TempDir(), "dashboard"), server.URL, uint16(occupied.Addr().(*net.TCPAddr).Port), "download-path")
	if err := instance.Start(); err == nil {
		t.Fatal("occupied listener unexpectedly started")
	}
	if err := instance.CloseWithResult(); err != nil {
		t.Fatal(err)
	}
	if api.dashboard.done == nil {
		t.Fatal("dashboard worker startup leg not exercised")
	}
	dashboardWait(t, api.dashboard.done, "worker after API start failure")
}

type dashboardEventLog struct {
	sync.Mutex
	events []string
}

func (e *dashboardEventLog) add(event string) {
	e.Lock()
	defer e.Unlock()
	e.events = append(e.events, event)
}

func (e *dashboardEventLog) snapshot() []string {
	e.Lock()
	defer e.Unlock()
	return append([]string(nil), e.events...)
}

type dashboardTestTransport struct {
	id        string
	events    *dashboardEventLog
	roundTrip func(*http.Request) (*http.Response, error)
}

func (t *dashboardTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.roundTrip(r)
}
func (t *dashboardTestTransport) CloseIdleConnections() { t.events.add("idle:" + t.id) }
func (*dashboardTestTransport) Reset()                  {}

type dashboardTestProvider struct {
	sync.Mutex
	current  *dashboardTestTransport
	active   int
	acquired int
}

func (p *dashboardTestProvider) AcquireDashboardHTTP(ctx context.Context, _ string) (adapter.RuntimeDashboardHTTPLease, error) {
	p.Lock()
	defer p.Unlock()
	p.active++
	p.acquired++
	return &dashboardTestLease{ctx: ctx, transport: p.current, provider: p}, nil
}

func (p *dashboardTestProvider) selectTransport(transport *dashboardTestTransport) {
	p.Lock()
	defer p.Unlock()
	p.current = transport
}

func (p *dashboardTestProvider) counts() (int, int) {
	p.Lock()
	defer p.Unlock()
	return p.active, p.acquired
}

type dashboardTestLease struct {
	ctx       context.Context
	transport *dashboardTestTransport
	provider  *dashboardTestProvider
	once      sync.Once
}

func (l *dashboardTestLease) Context() context.Context         { return l.ctx }
func (l *dashboardTestLease) Transport() adapter.HTTPTransport { return l.transport }
func (l *dashboardTestLease) Release() {
	l.once.Do(func() {
		l.transport.events.add("release:" + l.transport.id)
		l.provider.Lock()
		l.provider.active--
		l.provider.Unlock()
	})
}

type dashboardTestBody struct {
	io.Reader
	close func() error
}

func (b *dashboardTestBody) Close() error {
	if b.close != nil {
		return b.close()
	}
	return nil
}

func TestDashboardFetchLeaseCoversRedirectBodyAndIdle(t *testing.T) {
	first := dashboardTestZip(t, map[string]string{"index.html": "graph-one"})
	second := dashboardTestZip(t, map[string]string{"index.html": "graph-two"})
	events := &dashboardEventLog{}
	entered, resume := make(chan struct{}), make(chan struct{})
	one := &dashboardTestTransport{id: "one", events: events}
	one.roundTrip = func(r *http.Request) (*http.Response, error) {
		events.add("request:one:" + r.URL.Path)
		if r.URL.Path == "/redirect" {
			return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"/archive"}}, Body: io.NopCloser(bytes.NewReader(nil))}, nil
		}
		reader := &dashboardBarrierReader{reader: bytes.NewReader(first), entered: entered, resume: resume, ctx: r.Context()}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: &dashboardTestBody{Reader: reader, close: func() error { events.add("body:one"); return nil }}}, nil
	}
	two := &dashboardTestTransport{id: "two", events: events}
	two.roundTrip = func(_ *http.Request) (*http.Response, error) {
		events.add("request:two")
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(second))}, nil
	}
	provider := &dashboardTestProvider{current: one}
	ctx, _ := dashboardFileContext(t)
	ctx = service.ContextWith[adapter.RuntimeDashboardHTTPProvider](ctx, provider)
	d := newDashboard(ctx, log.NewNOPFactory().Logger(), "0", option.APIDashboardOptions{Path: filepath.Join(t.TempDir(), "dashboard"), DownloadURL: "http://fixture.test/redirect"})
	result := make(chan error, 1)
	go func() { result <- d.fetch(context.Background()) }()
	dashboardWait(t, entered, "old graph body")
	provider.selectTransport(two)
	if active, acquired := provider.counts(); active != 1 || acquired != 1 {
		t.Fatalf("lease not retained over body: %d/%d", active, acquired)
	}
	close(resume)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if active, _ := provider.counts(); active != 0 {
		t.Fatal("lease retained while timer idle")
	}
	seen := events.snapshot()
	if len(seen) < 3 || seen[len(seen)-3] != "body:one" || seen[len(seen)-2] != "idle:one" || seen[len(seen)-1] != "release:one" {
		t.Fatalf("cleanup order: %v", seen)
	}
	if err := d.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(d.path, "index.html"))
	if err != nil || string(content) != "graph-two" {
		t.Fatalf("next fetch did not use new graph: %s %v", content, err)
	}
	if active, acquired := provider.counts(); active != 0 || acquired != 2 {
		t.Fatalf("graph leases: %d/%d", active, acquired)
	}
}

type dashboardBarrierReader struct {
	reader  io.Reader
	entered chan struct{}
	resume  chan struct{}
	ctx     context.Context
	once    sync.Once
}

func (r *dashboardBarrierReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.entered) })
	select {
	case <-r.resume:
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	}
	return r.reader.Read(p)
}

// Test-only bounded error capture: production logging/transport guards remain
// untouched, while a failed first fetch cannot be disguised as a timer timeout.
type dashboardFailureLogger struct {
	log.ContextLogger
	failures chan string
}

func (l *dashboardFailureLogger) Error(args ...any) {
	select {
	case l.failures <- fmt.Sprint(args...):
	default:
	}
}

func TestRuntimeDashboardEmptyDirectGuardRemainsEnforced(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	t.Cleanup(server.Close)
	ctx, _ := dashboardFileContext(t)
	instance, api := dashboardRuntimeBox(t, ctx, filepath.Join(t.TempDir(), "dashboard"), server.URL, 0, "direct")
	failures := make(chan string, 4)
	api.dashboard.logger = &dashboardFailureLogger{ContextLogger: api.dashboard.logger, failures: failures}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case failure := <-failures:
		if !strings.Contains(failure, "detour to an empty direct outbound makes no sense") {
			t.Fatalf("unexpected guard: %s", failure)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("missing explicit empty-direct guard")
	}
	if requests.Load() != 0 {
		t.Fatal("invalid detour reached HTTP server")
	}
	if err := instance.CloseWithResult(); err != nil {
		t.Fatal(err)
	}
	dashboardWait(t, api.dashboard.done, "invalid-detour worker joined")
}

// Only the failure point is injected; the Box, prepared graph, dashboard and
// localhost HTTP transfer are real. This does not admit a TLS configuration.
type dashboardFailAfterDownload struct {
	tls.ServerConfig
	requested <-chan struct{}
}

func (f dashboardFailAfterDownload) Start() error {
	select {
	case <-f.requested:
		return errors.New("synthetic API stage failure after active dashboard download")
	case <-time.After(5 * time.Second):
		return errors.New("no HTTP request before injected API failure")
	}
}

func TestRuntimeDashboardActiveDownloadCanceledOnStartFailure(t *testing.T) {
	requested, canceled := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(requested)
		<-r.Context().Done()
		close(canceled)
	}))
	t.Cleanup(server.Close)
	ctx, _ := dashboardFileContext(t)
	instance, api := dashboardRuntimeBox(t, ctx, filepath.Join(t.TempDir(), "dashboard"), server.URL, 0, "download-path")
	api.tlsConfig = dashboardFailAfterDownload{requested: requested}
	if err := instance.Start(); err == nil || !strings.Contains(err.Error(), "synthetic API stage failure after active dashboard download") {
		t.Fatalf("missing observed-request failure barrier: %v", err)
	}
	dashboardWait(t, requested, "observed real download before failure")
	dashboardWait(t, canceled, "actual HTTP request cancellation")
	dashboardWait(t, api.dashboard.done, "active worker joined after failed Start")
	if err := instance.CloseWithResult(); err != nil {
		t.Fatal(err)
	}
}

// These observers only forward the real admission and transport. They expose
// graph identity and request/body lifetime barriers without a synthetic graph.
type dashboardFetchObservation struct {
	identity    adapter.RuntimeRevision
	transport   adapter.HTTPTransport
	bodyRead    chan struct{}
	released    chan struct{}
	readOnce    sync.Once
	releaseOnce sync.Once
}
type dashboardObservingProvider struct {
	adapter.RuntimeDashboardHTTPProvider
	observed chan *dashboardFetchObservation
}

func (p dashboardObservingProvider) AcquireDashboardHTTP(ctx context.Context, tag string) (adapter.RuntimeDashboardHTTPLease, error) {
	lease, err := p.RuntimeDashboardHTTPProvider.AcquireDashboardHTTP(ctx, tag)
	if err != nil || lease == nil {
		return lease, err
	}
	observation := &dashboardFetchObservation{transport: lease.Transport(), bodyRead: make(chan struct{}), released: make(chan struct{})}
	if graph, ok := adapter.RuntimeLeaseFromContext(lease.Context()); ok {
		observation.identity = graph.View().Identity()
	}
	select {
	case p.observed <- observation:
	default:
	}
	return &dashboardObservedLease{RuntimeDashboardHTTPLease: lease, observation: observation}, nil
}

type dashboardObservedLease struct {
	adapter.RuntimeDashboardHTTPLease
	observation *dashboardFetchObservation
}

func (l *dashboardObservedLease) Transport() adapter.HTTPTransport {
	return dashboardObservedTransport{HTTPTransport: l.observation.transport, observation: l.observation}
}

func (l *dashboardObservedLease) Release() {
	l.RuntimeDashboardHTTPLease.Release()
	l.observation.releaseOnce.Do(func() { close(l.observation.released) })
}

type dashboardObservedTransport struct {
	adapter.HTTPTransport
	observation *dashboardFetchObservation
}

func (t dashboardObservedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := t.HTTPTransport.RoundTrip(r)
	if response != nil && response.Body != nil {
		response.Body = dashboardObservedBody{ReadCloser: response.Body, observation: t.observation}
	}
	return response, err
}

type dashboardObservedBody struct {
	io.ReadCloser
	observation *dashboardFetchObservation
}

func (b dashboardObservedBody) Read(p []byte) (int, error) {
	b.observation.readOnce.Do(func() { close(b.observation.bodyRead) })
	return b.ReadCloser.Read(p)
}

func dashboardObserveFetches(d *dashboard) <-chan *dashboardFetchObservation {
	observed := make(chan *dashboardFetchObservation, 8)
	d.provider = dashboardObservingProvider{RuntimeDashboardHTTPProvider: d.provider, observed: observed}
	return observed
}

func dashboardNextFetch(t *testing.T, observed <-chan *dashboardFetchObservation) *dashboardFetchObservation {
	t.Helper()
	select {
	case item := <-observed:
		return item
	case <-time.After(5 * time.Second):
		t.Fatal("missing real dashboard fetch admission")
		return nil
	}
}

func TestRuntimeDashboardActiveBodyNormalAndConnectionManagerClose(t *testing.T) {
	for _, mode := range []string{"normal_close", "close_all"} {
		t.Run(mode, func(t *testing.T) {
			canceled := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				<-r.Context().Done()
				close(canceled)
			}))
			t.Cleanup(server.Close)
			ctx, _ := dashboardFileContext(t)
			instance, api := dashboardRuntimeBox(t, ctx, filepath.Join(t.TempDir(), "dashboard"), server.URL, 0, "download-path")
			observed := dashboardObserveFetches(api.dashboard)
			if err := instance.Start(); err != nil {
				t.Fatal(err)
			}
			fetch := dashboardNextFetch(t, observed)
			dashboardWait(t, fetch.bodyRead, "actual response body read")
			if mode == "close_all" {
				manager := service.FromContext[adapter.ConnectionManager](api.dashboard.ctx)
				if manager == nil {
					t.Fatal("real connection manager missing")
				}
				manager.CloseAll()
				dashboardWait(t, fetch.released, "interrupted request lease release")
			}
			if err := instance.CloseWithResult(); err != nil {
				t.Fatal(err)
			}
			dashboardWait(t, fetch.released, "shutdown request lease release")
			dashboardWait(t, canceled, "actual server cancellation")
			dashboardWait(t, api.dashboard.done, "dashboard worker joined")
		})
	}
}

// A narrow real Box/HTTP fixture, not a reproduction of the App's 68-inbound
// generated configuration. The first actual download spans a graph commit;
// the next fetch must use the new current graph and its newly prepared client.
func TestRuntimeDashboardRealDownloadSpansHOTCommit(t *testing.T) {
	firstArchive := dashboardTestZip(t, map[string]string{"index.html": "graph-one"})
	secondArchive := dashboardTestZip(t, map[string]string{"index.html": "graph-two"})
	finishFirst := make(chan struct{})
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestCount.Add(1) == 1 {
			w.Header().Set("Etag", "graph-one")
			_, _ = w.Write(firstArchive[:2])
			w.(http.Flusher).Flush()
			select {
			case <-finishFirst:
				_, _ = w.Write(firstArchive[2:])
			case <-r.Context().Done():
			}
			return
		}
		w.Header().Set("Etag", "graph-two")
		_, _ = w.Write(secondArchive)
	}))
	t.Cleanup(server.Close)
	ctx, _ := dashboardFileContext(t)
	path := filepath.Join(t.TempDir(), "dashboard")
	instance, api := dashboardRuntimeBox(t, ctx, path, server.URL, 0, "download-path")
	if err := instance.BindRuntimePersistence(func(box.RuntimeIdentity, []byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	observed := dashboardObserveFetches(api.dashboard)
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	first := dashboardNextFetch(t, observed)
	dashboardWait(t, first.bodyRead, "old graph real HTTP body")
	before := instance.RuntimeCapabilities().Identity
	if first.identity.Revision != before.Revision || first.identity.Incarnation != before.Incarnation {
		t.Fatal("initial fetch did not borrow current published graph")
	}
	content := dashboardRuntimeContent(path, server.URL, 0, "download-path")
	candidate := strings.Replace(content, `"type":"direct","tag":"direct"`, `"type":"direct","tag":"direct","connect_timeout":"5s"`, 1)
	if candidate == content {
		t.Fatal("dependency change missing")
	}
	plan, err := instance.PlanRuntimeConfig(context.Background(), "dashboard-test", before, []byte(candidate))
	if err != nil || !plan.Applicable {
		t.Fatalf("real dependency plan: %+v %v", plan, err)
	}
	operation, err := instance.ApplyRuntimeConfig(context.Background(), "dashboard-test", box.RuntimeConfigApply{ContractVersion: box.RuntimeConfigContractVersion, PlanID: plan.PlanID, TransactionID: plan.TransactionID, Expected: plan.Expected, CandidateDigest: plan.CandidateDigest, AcceptedImpactDigest: plan.ImpactDigest})
	if err != nil || operation.State != "COMMITTED" || operation.Active.Revision != before.Revision+1 {
		t.Fatalf("real HOT commit: %+v %v", operation, err)
	}
	select {
	case <-first.released:
		t.Fatal("old fetch released before held body completed")
	default:
	}
	close(finishFirst)
	dashboardWait(t, first.released, "old graph download completed")
	// Join the periodic scheduler after its first completed fetch. Explicitly
	// trigger the same fetch path below rather than sleep for its 24h interval.
	api.dashboard.cancel()
	dashboardWait(t, api.dashboard.done, "test scheduler joined")
	if content, err := os.ReadFile(filepath.Join(path, "index.html")); err != nil || string(content) != "graph-one" {
		t.Fatalf("old graph download result: %q %v", content, err)
	}
	if err := api.dashboard.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := dashboardNextFetch(t, observed)
	dashboardWait(t, second.released, "new graph download completed")
	if second.identity.Incarnation != before.Incarnation || second.identity.Revision != operation.Active.Revision || second.transport == first.transport {
		t.Fatal("next fetch reused old graph admission or replaced dependency transport")
	}
	if content, err := os.ReadFile(filepath.Join(path, "index.html")); err != nil || string(content) != "graph-two" {
		t.Fatalf("new graph download result: %q %v", content, err)
	}
	if requestCount.Load() != 2 || instance.RuntimeCapabilities().FullConfiguration {
		t.Fatal("unexpected download count or expanded capability")
	}
	if err := instance.CloseWithResult(); err != nil {
		t.Fatal(err)
	}
}
