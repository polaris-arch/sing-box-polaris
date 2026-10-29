package originca

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/internal/runtimegraph"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/caddyserver/certmagic"
)

type originStorageFixture struct {
	mu       sync.Mutex
	values   map[string][]byte
	writes   int
	failures map[int]error
	lock     func(context.Context) error
}

func (s *originStorageFixture) Store(_ context.Context, key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes++
	s.values[key] = append([]byte(nil), value...)
	return s.failures[s.writes]
}

func (s *originStorageFixture) Load(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.values[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), v...), nil
}

func (s *originStorageFixture) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, key)
	return nil
}

func (s *originStorageFixture) Exists(_ context.Context, key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.values[key]
	return ok
}

func (*originStorageFixture) List(context.Context, string, bool) ([]string, error) { return nil, nil }

func (*originStorageFixture) Stat(context.Context, string) (certmagic.KeyInfo, error) {
	return certmagic.KeyInfo{}, nil
}

func (s *originStorageFixture) Lock(ctx context.Context, _ string) error {
	if s.lock != nil {
		return s.lock(ctx)
	}
	return nil
}
func (*originStorageFixture) Unlock(context.Context, string) error { return nil }
func originStorageKeys(resource certmagic.CertificateResource) []string {
	return []string{certmagic.StorageKeys.SitePrivateKey("fixture", resource.NamesKey()), certmagic.StorageKeys.SiteCert("fixture", resource.NamesKey()), certmagic.StorageKeys.SiteMeta("fixture", resource.NamesKey())}
}

func TestOriginCACacheFailureRestoresExactExistingKeyAndCertificate(t *testing.T) {
	resource := certmagic.CertificateResource{SANs: []string{"example.invalid"}, CertificatePEM: []byte("new-cert"), PrivateKeyPEM: []byte("new-key")}
	keys := originStorageKeys(resource)
	storage := &originStorageFixture{values: map[string][]byte{}, failures: map[int]error{2: errors.New("partial certificate write")}}
	for i, key := range keys {
		storage.values[key] = []byte{byte(i + 1)}
	}
	if err := storeCertificateResource(context.Background(), storage, "fixture", resource); err == nil {
		t.Fatal("storage error hidden")
	}
	for i, key := range keys {
		value, err := storage.Load(context.Background(), key)
		if err != nil || len(value) != 1 || value[0] != byte(i+1) {
			t.Fatal("old certificate transaction damaged", key, value, err)
		}
	}
}

func TestOriginCACacheFailureRemovesOnlyNewPartialKeys(t *testing.T) {
	resource := certmagic.CertificateResource{SANs: []string{"example.invalid"}, CertificatePEM: []byte("new-cert"), PrivateKeyPEM: []byte("new-key")}
	storage := &originStorageFixture{values: map[string][]byte{}, failures: map[int]error{2: errors.New("partial certificate write")}}
	if err := storeCertificateResource(context.Background(), storage, "fixture", resource); err == nil {
		t.Fatal("storage error hidden")
	}
	if len(storage.values) != 0 {
		t.Fatal("partial new keys survived failed storage transaction")
	}
}

func TestOriginCACacheRestorationFailureIsOpaqueAndSticky(t *testing.T) {
	resource := certmagic.CertificateResource{SANs: []string{"example.invalid"}, CertificatePEM: []byte("new-cert"), PrivateKeyPEM: []byte("new-key")}
	storage := &originStorageFixture{values: map[string][]byte{}, failures: map[int]error{2: errors.New("partial write"), 3: context.Canceled}}
	for _, key := range originStorageKeys(resource) {
		storage.values[key] = []byte("old")
	}
	err := storeCertificateResource(context.Background(), storage, "fixture", resource)
	var incomplete *originCACompensationError
	if !errors.As(err, &incomplete) || errors.Is(err, context.Canceled) {
		t.Fatal("restoration uncertainty is absent or filterable", err)
	}
	service := &Service{runtime: new(runtimeOriginCA)}
	service.recordRuntimeCleanup(err)
	if service.runtime.closeErr == nil {
		t.Fatal("owner forgot storage compensation failure")
	}
}

func TestOriginCAPrivatePreparationDoesNotAcquireStorageLock(t *testing.T) {
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "origin-ca-fixture", Sequence: 1}, nil, scope.Close)
	if err != nil {
		t.Fatal(err)
	}
	ctx := adapter.ContextWithRuntimeResourceSource(adapter.ContextWithConstructionScope(scope.Context(), scope), owner)
	called := false
	service := &Service{storage: &originStorageFixture{values: map[string][]byte{}, lock: func(context.Context) error { called = true; return errors.New("fixture lock unavailable") }}, logger: log.NewNOPFactory().Logger()}
	if err := service.initializeRuntime(ctx); err != nil {
		t.Fatal(err)
	}
	for _, stage := range adapter.ListStartStages {
		if err := service.PrepareRuntime(stage, scope); err != nil {
			t.Fatal(err)
		}
	}
	if called {
		t.Fatal("private Origin CA preparation performed issuance")
	}
	if err := service.StageRuntime(context.Background()); err == nil {
		t.Fatal("failed certificate issuance accepted")
	}
	if !called {
		t.Fatal("explicit stage did not invoke issuance")
	}
	service.RuntimeActivate()
	service.runtime.mu.Lock()
	started := service.runtime.done != nil
	service.runtime.mu.Unlock()
	if started {
		t.Fatal("failed synchronous issuance activated renewal")
	}
	if err := service.RuntimeCloseAndWait(); err != nil {
		t.Fatal(err)
	}
	owner.Seal()
	if err := owner.WaitClosed(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOriginCACloseWaitsForActualStageStorageCall(t *testing.T) {
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	owner, err := runtimegraph.NewResourceOwner(context.Background(), adapter.RuntimeResourceID{Incarnation: "origin-ca-fixture", Sequence: 2}, nil, scope.Close)
	if err != nil {
		t.Fatal(err)
	}
	ctx := adapter.ContextWithRuntimeResourceSource(adapter.ContextWithConstructionScope(scope.Context(), scope), owner)
	entered, finish := make(chan struct{}), make(chan struct{})
	service := &Service{storage: &originStorageFixture{values: map[string][]byte{}, lock: func(ctx context.Context) error { close(entered); <-finish; return ctx.Err() }}, logger: log.NewNOPFactory().Logger()}
	if err := service.initializeRuntime(ctx); err != nil {
		t.Fatal(err)
	}
	for _, stage := range adapter.ListStartStages {
		if err := service.PrepareRuntime(stage, scope); err != nil {
			t.Fatal(err)
		}
	}
	stageDone := make(chan error, 1)
	go func() { stageDone <- service.StageRuntime(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("stage did not reach storage")
	}
	_ = service.runtime.fence.Close()
	select {
	case <-service.runtime.ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("close did not cancel stage")
	}
	closed := make(chan error, 1)
	go func() { closed <- service.RuntimeCloseAndWait() }()
	select {
	case <-closed:
		t.Fatal("close forgot blocked storage call")
	default:
	}
	close(finish)
	select {
	case err := <-stageDone:
		if err == nil {
			t.Fatal("canceled stage succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stage did not finish")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("close did not join actual stage")
	}
	owner.Seal()
	wait, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := owner.WaitClosed(wait); err != nil {
		t.Fatal(err)
	}
}

type originRequestCountFixture struct{ calls atomic.Int64 }

func (f *originRequestCountFixture) RoundTrip(*http.Request) (*http.Response, error) {
	f.calls.Add(1)
	return nil, errors.New("fixture issuance reached HTTP")
}

func originServiceWithStorageFixture(storage certmagic.Storage, transport *originRequestCountFixture) *Service {
	resource := certmagic.CertificateResource{SANs: []string{"example.invalid"}}
	return &Service{
		storage: storage, httpClient: &http.Client{Transport: transport},
		logger: log.NewNOPFactory().Logger(), ctx: context.Background(), timeFunc: time.Now,
		storageIssuerKey: "fixture", storageNamesKey: resource.NamesKey(), storageLockKey: "issuer",
		domain: resource.SANs, requestType: option.CloudflareOriginCARequestTypeOriginECC,
		runtime: new(runtimeOriginCA),
	}
}

type originCacheReadFailureFixture struct {
	certmagic.Storage
	err       error
	afterLock bool
	locked    bool
}

func (f *originCacheReadFailureFixture) Load(ctx context.Context, key string) ([]byte, error) {
	if !f.afterLock || f.locked {
		return nil, f.err
	}
	return f.Storage.Load(ctx, key)
}

func (f *originCacheReadFailureFixture) Lock(ctx context.Context, key string) error {
	if err := f.Storage.Lock(ctx, key); err != nil {
		return err
	}
	f.locked = true
	return nil
}

func TestOriginCAUnsafeCacheNeverReachesHTTPBeforeOrAfterLock(t *testing.T) {
	for _, afterLock := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "held-lock"}[afterLock], func(t *testing.T) {
			base := &originStorageFixture{values: map[string][]byte{}}
			// Even a join containing an external NotExist must prioritize the
			// opaque safety marker rather than silently turning it into a miss.
			err := errors.Join(os.ErrNotExist, originStorageUnsafe(errors.Join(context.Canceled, os.ErrClosed)))
			storage := &originCacheReadFailureFixture{Storage: base, err: err, afterLock: afterLock}
			transport := new(originRequestCountFixture)
			s := originServiceWithStorageFixture(storage, transport)
			if err = s.initializeCertificate(t.Context()); !originStorageIsUnsafe(err) || transport.calls.Load() != 0 {
				t.Fatal("unsafe cache proceeded to actual issuance", err, transport.calls.Load())
			}
			if s.runtime.closeErr == nil {
				t.Fatal("runtime owner forgot cache safety uncertainty")
			}
			scope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
			scope.Add(func() error { return s.runtime.closeErr })
			if err = scope.Close(); !originStorageIsUnsafe(err) {
				t.Fatal("Scope erased safety error as canceled/closed", err)
			}
			if base.writes != 0 {
				t.Fatal("unsafe cache modified preimages")
			}
		})
	}
}

func TestOriginCAOrdinaryMissingOrCorruptCacheStillAttemptsRefresh(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "corrupt"}[corrupt], func(t *testing.T) {
			storage := &originStorageFixture{values: map[string][]byte{}}
			resource := certmagic.CertificateResource{SANs: []string{"example.invalid"}}
			if corrupt {
				for _, key := range originStorageKeys(resource) {
					storage.values[key] = []byte("bad key pair")
				}
			}
			transport := new(originRequestCountFixture)
			s := originServiceWithStorageFixture(storage, transport)
			err := s.initializeCertificate(t.Context())
			if err == nil || originStorageIsUnsafe(err) || transport.calls.Load() != 1 || s.runtime.closeErr != nil {
				t.Fatal("ordinary cache retry policy changed", err, transport.calls.Load(), s.runtime.closeErr)
			}
		})
	}
}

func TestOriginCAUnsafePreimageNeverBecomesNotExistOrWrites(t *testing.T) {
	base := &originStorageFixture{values: map[string][]byte{}}
	storage := &originCacheReadFailureFixture{Storage: base, err: errors.Join(os.ErrNotExist, originStorageUnsafe(os.ErrClosed))}
	resource := certmagic.CertificateResource{SANs: []string{"example.invalid"}, CertificatePEM: []byte("new-cert"), PrivateKeyPEM: []byte("new-key")}
	err := storeCertificateResource(t.Context(), storage, "fixture", resource)
	if !originStorageIsUnsafe(err) || base.writes != 0 {
		t.Fatal("unsafe preimage was ignored as missing", err, base.writes)
	}
}
