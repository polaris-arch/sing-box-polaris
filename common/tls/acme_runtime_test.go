//go:build with_acme

package tls

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
)

type acmeResourceDirectoryManager struct {
	filemanager.Manager
	directory string
}

func (m acmeResourceDirectoryManager) BasePath(path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(m.directory, path)
}

func (m acmeResourceDirectoryManager) ConfigurationDirectoryPath(path string) string {
	if path == "" {
		path = "."
	}
	return m.BasePath(path)
}

func TestACMEFileStorageKeepsResourceDirectoryAndDefaultStorage(t *testing.T) {
	resources := t.TempDir()
	protected := t.TempDir()
	t.Chdir(protected)
	t.Setenv("POLARIS_ACME_EMPTY", "")
	ctx := service.ContextWith[filemanager.Manager](context.Background(), acmeResourceDirectoryManager{directory: resources})
	previous := certmagic.Default.Storage
	t.Cleanup(func() { certmagic.Default.Storage = previous })
	defaultStorage := &certmagic.FileStorage{Path: filepath.Join(".local", "share", "certmagic")}
	certmagic.Default.Storage = defaultStorage
	configStorage := func(ctx context.Context, directory string) certmagic.Storage {
		t.Helper()
		_, lifecycle, err := startACME(ctx, log.NewNOPFactory().Logger(), option.InboundACMEOptions{DataDirectory: directory, Domain: []string{"fixture.invalid"}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = lifecycle.Close() })
		return lifecycle.(*acmeWrapper).cfg.Storage
	}
	storage := configStorage(ctx, "")
	if storage == defaultStorage || storage.(*certmagic.FileStorage).Path != filepath.Join(resources, defaultStorage.Path) {
		t.Fatal("default file storage was not privately resolved", storage)
	}
	if certmagic.Default.Storage != defaultStorage || filepath.IsAbs(defaultStorage.Path) {
		t.Fatal("process-wide default storage was modified")
	}
	if err := storage.Store(ctx, "fixture/test", []byte("resource")); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(filepath.Join(resources, defaultStorage.Path, "fixture", "test")); err != nil || string(content) != "resource" {
		t.Fatalf("stored certificate resource = %q, %v", content, err)
	}
	if _, err := os.Stat(filepath.Join(protected, defaultStorage.Path)); !os.IsNotExist(err) {
		t.Fatalf("protected cwd received certificate storage: %v", err)
	}
	if storage := configStorage(ctx, "$POLARIS_ACME_EMPTY").(*certmagic.FileStorage); storage.Path != resources {
		t.Fatalf("expanded empty data directory = %q; want %q", storage.Path, resources)
	}
	if configStorage(context.Background(), "") != defaultStorage {
		t.Fatal("unset resource directory changed default storage")
	}
	if storage := configStorage(context.Background(), "$POLARIS_ACME_EMPTY").(*certmagic.FileStorage); storage.Path != "" {
		t.Fatalf("unset resource directory changed expanded empty path: %q", storage.Path)
	}
	opaque := &acmeFixtureStorage{}
	certmagic.Default.Storage = opaque
	if configStorage(ctx, "") != opaque {
		t.Fatal("custom opaque default storage was replaced")
	}
}

type acmeFixtureStorage struct {
	calls atomic.Int32
	load  func(context.Context, string) ([]byte, error)
}

func (s *acmeFixtureStorage) Store(context.Context, string, []byte) error { s.calls.Add(1); return nil }

func (s *acmeFixtureStorage) Load(ctx context.Context, key string) ([]byte, error) {
	s.calls.Add(1)
	if s.load != nil {
		return s.load(ctx, key)
	}
	return nil, fs.ErrNotExist
}
func (s *acmeFixtureStorage) Delete(context.Context, string) error { s.calls.Add(1); return nil }
func (s *acmeFixtureStorage) Exists(context.Context, string) bool  { s.calls.Add(1); return false }
func (s *acmeFixtureStorage) List(context.Context, string, bool) ([]string, error) {
	s.calls.Add(1)
	return nil, nil
}

func (s *acmeFixtureStorage) Stat(context.Context, string) (certmagic.KeyInfo, error) {
	s.calls.Add(1)
	return certmagic.KeyInfo{}, fs.ErrNotExist
}
func (s *acmeFixtureStorage) Lock(context.Context, string) error   { s.calls.Add(1); return nil }
func (s *acmeFixtureStorage) Unlock(context.Context, string) error { s.calls.Add(1); return nil }

type acmeFixtureTransport func(*http.Request) (*http.Response, error)

func (f acmeFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func acmeRuntimeFixture(t *testing.T, storage certmagic.Storage, synchronous bool, client *http.Client) (*RuntimeACME, *adapter.Scope) {
	t.Helper()
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "acme-fixture", Sequence: 1}, nil, scope.Close)
	if err != nil {
		t.Fatal(err)
	}
	construction, err := owner.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	ctx := adapter.ContextWithRuntimePreparation(adapter.ContextWithRuntimeResourceSource(adapter.ContextWithConstructionScope(scope.Context(), scope), owner))
	if client == nil {
		client = &http.Client{Transport: acmeFixtureTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("fixture prevents network") })}
	}
	runtime, err := NewRuntimeACME(ctx, log.NewNOPFactory().Logger(), certmagic.Config{Storage: storage}, certmagic.ACMEIssuer{CA: "https://acme.invalid/directory", Agreed: true}, client, []string{"example.invalid"}, "", synchronous)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		owner.Seal()
		construction.Release()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = owner.WaitClosed(ctx)
	})
	return runtime, scope
}

func prepareACMEFixture(t *testing.T, r *RuntimeACME) {
	t.Helper()
	for _, stage := range adapter.ListStartStages {
		if err := r.PrepareRuntime(stage, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func acmeAwait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ACME lifecycle watchdog")
	}
}

func TestRuntimeACMEConstructionAndPreparationHaveNoIssuanceEffects(t *testing.T) {
	storage := new(acmeFixtureStorage)
	r, _ := acmeRuntimeFixture(t, storage, true, nil)
	directory := filepath.Join(t.TempDir(), "not-created")
	r.directory = directory
	prepareACMEFixture(t, r)
	if storage.calls.Load() != 0 {
		t.Fatal("private preparation touched ACME storage")
	}
	if _, err := os.Stat(directory); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("private preparation created ACME directory", err)
	}
	if err := r.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
	r.RuntimeActivate()
	if storage.calls.Load() != 0 {
		t.Fatal("activation after abort performed issuance")
	}
}

func TestRuntimeACMECloseJoinsActualManagementStorageTail(t *testing.T) {
	entered, finish := make(chan struct{}), make(chan struct{})
	var once sync.Once
	storage := &acmeFixtureStorage{load: func(ctx context.Context, _ string) ([]byte, error) {
		once.Do(func() { close(entered) })
		<-finish
		return nil, ctx.Err()
	}}
	r, _ := acmeRuntimeFixture(t, storage, false, nil)
	prepareACMEFixture(t, r)
	r.RuntimeActivate()
	acmeAwait(t, entered)
	_ = r.fence.Close()
	closed := make(chan struct{})
	go func() { _ = r.RuntimeCloseAndWait(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("close certified a still-running storage method")
	default:
	}
	acmeAwait(t, r.ctx.Done())
	close(finish)
	acmeAwait(t, closed)
	before := storage.calls.Load()
	guarded := guardACMEStorage(storage, r.callbacks, nil)
	if _, err := guarded.Load(context.Background(), "late-handler"); err == nil {
		t.Fatal("late challenge storage callback admitted")
	}
	if storage.calls.Load() != before {
		t.Fatal("late callback touched retired storage")
	}
}

func TestRuntimeACMESynchronousStageFailureIsStickyAndCannotActivate(t *testing.T) {
	failure := errors.New("fixture storage unavailable")
	storage := &acmeFixtureStorage{load: func(context.Context, string) ([]byte, error) { return nil, failure }}
	r, _ := acmeRuntimeFixture(t, storage, true, nil)
	prepareACMEFixture(t, r)
	first := r.StageRuntime(context.Background())
	if first == nil {
		t.Fatal("failed first certificate accepted")
	}
	calls := storage.calls.Load()
	if second := r.StageRuntime(context.Background()); second != first {
		t.Fatal("stage outcome replaced")
	}
	r.RuntimeActivate()
	r.mu.Lock()
	started := r.started
	r.mu.Unlock()
	if started || r.config.Load() != nil || storage.calls.Load() != calls {
		t.Fatal("failed synchronous stage published or reissued")
	}
}

func TestRuntimeACMEStagePanicCannotCertifyCleanup(t *testing.T) {
	storage := &acmeFixtureStorage{load: func(context.Context, string) ([]byte, error) { panic("fixture storage panic") }}
	r, _ := acmeRuntimeFixture(t, storage, true, nil)
	prepareACMEFixture(t, r)
	func() { defer func() { _ = recover() }(); _ = r.StageRuntime(context.Background()) }()
	if err := r.RuntimeCloseAndWait(); err == nil || !IsRuntimeCleanupIncomplete(err) {
		t.Fatal("partial stage panic became clean retirement", err)
	}
}

func TestRuntimeACMEBackgroundCleanupHTTPHasOwnedContextUntilBodyClose(t *testing.T) {
	observed := make(chan struct{})
	var expected adapter.RuntimeResourceID
	client := &http.Client{Transport: acmeFixtureTransport(func(request *http.Request) (*http.Response, error) {
		if _, ok := adapter.RuntimeResourceLeaseFromContext(request.Context(), expected); !ok {
			return nil, errors.New("callback lost exact provider owner")
		}
		close(observed)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Request: request}, nil
	})}
	r, _ := acmeRuntimeFixture(t, new(acmeFixtureStorage), false, client)
	expected = r.source.ID()
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.invalid", nil)
	response, err := r.HTTPClient().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	acmeAwait(t, observed)
	_ = r.fence.Close()
	closed := make(chan struct{})
	go func() { _ = r.RuntimeCloseAndWait(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("cleanup forgot response-body callback ownership")
	default:
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	acmeAwait(t, closed)
}

type acmeCleanupFailureSolver struct{}

func (acmeCleanupFailureSolver) Present(context.Context, acme.Challenge) error { return nil }
func (acmeCleanupFailureSolver) CleanUp(context.Context, acme.Challenge) error {
	return context.Canceled
}

func TestRuntimeACMEIgnoredSolverCleanupErrorRemainsNonFilterable(t *testing.T) {
	r, scope := acmeRuntimeFixture(t, new(acmeFixtureStorage), false, nil)
	solver := &runtimeACMEDNSSolver{inner: acmeCleanupFailureSolver{}, owner: r}
	if err := solver.CleanUp(context.Background(), acme.Challenge{}); !errors.Is(err, context.Canceled) {
		t.Fatal("fixture cleanup did not fail", err)
	}
	err := scope.Close()
	if err == nil || errors.Is(err, context.Canceled) {
		t.Fatal("Scope filtered external cleanup uncertainty", err)
	}
}

func TestRuntimeACMEAsyncDomainFailureDoesNotBlockOtherDomains(t *testing.T) {
	var keys []string
	storage := &acmeFixtureStorage{load: func(_ context.Context, key string) ([]byte, error) {
		keys = append(keys, key)
		return nil, errors.New("fixture cache unavailable")
	}}
	r, _ := acmeRuntimeFixture(t, storage, false, nil)
	r.domains = []string{"first.invalid", "second.invalid"}
	prepareACMEFixture(t, r)
	if r.RuntimeExternalEffects() {
		t.Fatal("async prepublication stage incorrectly classified as issuing")
	}
	if err := r.StageRuntime(context.Background()); err != nil || len(keys) != 0 {
		t.Fatal("async transaction stage had issuance effects", err)
	}
	if err := r.refresh(context.Background()); err == nil {
		t.Fatal("domain cache failures hidden")
	}
	first, second := false, false
	for _, key := range keys {
		first = first || strings.Contains(key, "first.invalid")
		second = second || strings.Contains(key, "second.invalid")
	}
	if !first || !second {
		t.Fatal("failed named domain prevented later management", keys)
	}
	if r.config.Load() == nil {
		t.Fatal("named async domain snapshot unavailable")
	}
}
