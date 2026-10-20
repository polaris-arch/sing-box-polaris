//go:build with_acme

package tls

import (
 "context"
 "crypto/tls"
 "errors"
 "fmt"
 "net"
 "net/http"
 "reflect"
 "sync"
 "sync/atomic"
 "time"
 "unsafe"

 "github.com/sagernet/sing-box/adapter"
 "github.com/sagernet/sing-box/adapter/certificate"
 "github.com/sagernet/sing-box/adapter/outbound"
 "github.com/sagernet/sing/common/logger"
 "github.com/sagernet/sing/service/filemanager"

 "github.com/caddyserver/certmagic"
 "go.uber.org/zap"
 "go.uber.org/zap/zapcore"
)

// RuntimeACME is the concrete certmagic owner, not a second resource manager.
// The pinned cache Stop joins only its maintenance loop; jm jobs and challenge
// handlers have separate lifetimes. HOT therefore uses a stopped empty cache
// and one owned synchronous management loop. Each cycle makes a fresh cache,
// retaining certmagic's ARI, OCSP, renewal, account and solver behavior without
// submitting unjoinable work to the process-global job manager. OnDemand is
// absent in this configuration and must stay absent in the resulting Config.
// Challenge handler tails retain only a private config, socket and guarded
// logger/storage; every callback into owner state is sealed and joined.
type RuntimeACME struct {
 ctx context.Context
 cancel context.CancelFunc
 source adapter.RuntimeResourceSource
 fence *outbound.RuntimeIOFence
 callbacks *outbound.RuntimeIOFence
 beginCallback func(context.Context) (context.Context, func(), error)
 beginOwned func(context.Context) (context.Context, func(), error)
 template certmagic.Config
 issuer certmagic.ACMEIssuer
 httpClient *http.Client
 domains []string
 directory string
 synchronous bool
 config atomic.Pointer[certmagic.Config]
 cache *certmagic.Cache // only the serialized stage/refresh worker accesses this pointer
 challenge atomic.Pointer[certmagic.Config]
 logger *zap.Logger
 mu sync.Mutex
 prepared bool
 stopped bool
 started bool
 done chan struct{}
 stageDone chan struct{}
 stageErr error
 stageReturned bool
 ready bool
 closeErr error
}

func NewRuntimeACME(ctx context.Context, log logger.Logger, template certmagic.Config, issuer certmagic.ACMEIssuer, client *http.Client, domains []string, directory string, synchronous bool) (*RuntimeACME, error) {
 source, ok := adapter.RuntimeResourceSourceFromContext(ctx)
 if !ok || !adapter.HasConstructionScope(ctx) { return nil, errors.New("runtime ACME requires its constructor resource and scope") }
 ctx, cancel := context.WithCancel(ctx)
 r := &RuntimeACME{ctx: ctx, cancel: cancel, source: source, template: template, issuer: issuer, httpClient: client, domains: append([]string(nil), domains...), directory: directory, synchronous: synchronous}
 r.callbacks = outbound.NewRuntimeIOFence(nil)
 r.logger = zap.New(zapcore.NewCore(zapcore.NewConsoleEncoder(ACMEEncoderConfig()), &ACMELogWriter{Logger: log, Fence: r.callbacks}, zap.DebugLevel))
 callback, err := outbound.RegisterRuntimeOwnedFence(ctx,r.callbacks)
 if err != nil { cancel(); return nil,err }
 r.beginCallback = callback
 if client != nil {
  copy := *client
  transport := client.Transport
  if transport == nil { transport = http.DefaultTransport }
  copy.Transport = &runtimeACMETransport{inner:transport,owner:r}
  r.httpClient = &copy
 }
 r.fence = outbound.NewRuntimeIOFence(r.closeOwned)
 begin, err := outbound.RegisterRuntimeOwnedFence(ctx, r.fence)
 if err != nil { cancel(); return nil, err }
 r.beginOwned = begin
 return r, nil
}

func (r *RuntimeACME) RuntimeResourceID() adapter.RuntimeResourceID { return r.source.ID() }
func (r *RuntimeACME) RuntimeValidate() error {
 if r == nil || r.source == nil || r.fence == nil { return errors.New("ACME has no staged owner") }
 if len(r.domains) == 0 { return errors.New("ACME has no configured domains") }
 return nil
}
func (r *RuntimeACME) PrepareRuntime(stage adapter.StartStage, _ *adapter.Scope) error {
 if err := r.RuntimeValidate(); err != nil { return err }
 r.mu.Lock()
 defer r.mu.Unlock()
 if r.stopped { return net.ErrClosed }
 if stage == adapter.StartStateStarted { r.prepared = true }
 return r.ctx.Err()
}

// StageRuntime is the explicit effectful transaction stage. The legacy inline
// provider must have certificates before publication. A failed transaction can
// remove candidate listeners/challenges and stop workers, but cannot unissue a
// CA certificate or erase an account registration. Successful cache artifacts
// are intentionally preserved for retry; they are not a restored external world.
func (r *RuntimeACME) StageRuntime(ctx context.Context) error {
 if !r.synchronous { return nil }
 leave, err := r.fence.Acquire()
 if err != nil { return err }
 defer leave()
 r.mu.Lock()
 if !r.prepared || r.stopped { r.mu.Unlock(); return errors.New("ACME is not prepared for transaction staging") }
 if r.stageDone != nil { done := r.stageDone; r.mu.Unlock(); <-done; r.mu.Lock(); err := r.stageErr; r.mu.Unlock(); return err }
 r.stageDone = make(chan struct{})
 done := r.stageDone
 r.stageErr = errors.New("ACME stage did not complete")
 r.mu.Unlock()
 defer close(done)
 stageContext, cancel := context.WithCancel(r.ctx)
 stop := context.AfterFunc(ctx, cancel)
 defer func() { stop(); cancel() }()
 err = r.refresh(stageContext)
 r.mu.Lock()
 r.stageErr, r.stageReturned, r.ready = err, true, err == nil
 r.mu.Unlock()
 return err
}

// RuntimeActivate runs after the transaction has published, outside its guard.
// It may start a goroutine; it must never be a PublishPrepared callback.
func (r *RuntimeACME) RuntimeActivate() {
 r.mu.Lock()
 if r.started || r.stopped || !r.prepared || (r.synchronous && !r.ready) { r.mu.Unlock(); return }
 r.started = true
 r.done = make(chan struct{})
 done, ready := r.done, r.ready
 r.mu.Unlock()
 go r.run(done, ready)
}
func (r *RuntimeACME) RuntimeStop() { r.mu.Lock(); r.stopped = true; r.mu.Unlock(); r.cancel() }
func (r *RuntimeACME) CompensateRuntime() error { return r.RuntimeCloseAndWait() }
func (r *RuntimeACME) RuntimeCloseAndWait() error { return r.fence.RuntimeCloseAndWait() }
func (r *RuntimeACME) closeOwned() error {
 r.RuntimeStop()
 r.mu.Lock(); stage, done := r.stageDone, r.done; r.mu.Unlock()
 if stage != nil { <-stage }
 if done != nil { <-done }
 // Do not seal storage before synchronous solver cleanup has released locks.
 callbackErr := r.callbacks.RuntimeCloseAndWait()
 r.mu.Lock()
 err := r.closeErr
 if r.stageDone != nil && !r.stageReturned { err = errors.Join(err, errors.New("ACME stage completion is unknown")) }
 r.mu.Unlock()
 return NewRuntimeCleanupError(errors.Join(err, callbackErr))
}
func (r *RuntimeACME) run(done chan struct{}, ready bool) {
 defer close(done)
 defer func() { if value := recover(); value != nil { r.mu.Lock(); r.closeErr = errors.Join(r.closeErr, fmt.Errorf("ACME management panicked: %v", value)); r.mu.Unlock() } }()
 delay := time.Duration(0)
 if ready { delay = certmagic.DefaultRenewCheckInterval }
 retry := time.Minute
 for {
  timer := time.NewTimer(delay)
  select { case <-r.ctx.Done(): timer.Stop(); return; case <-timer.C: }
  err := r.refresh(r.ctx)
  if r.ctx.Err() != nil { return }
  if err != nil {
   r.logger.Error("certificate management failed", zap.Error(err))
   delay = retry
   retry = min(retry * 2, time.Hour)
  } else { delay = certmagic.DefaultRenewCheckInterval; retry = time.Minute }
 }
}

func (r *RuntimeACME) refresh(ctx context.Context) error {
 ctx, release, err := r.beginOwned(ctx)
 if err != nil { return err }
 defer release()
 if r.directory != "" { if err := filemanager.MkdirAll(ctx, r.directory, 0o700); err != nil { return err } }
 // The maintenance loop is stopped while the cache is still empty, before it
 // can acquire configuration, storage, issuer or graph-facing callbacks.
 cache := certmagic.NewCache(certmagic.CacheOptions{GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return nil, errors.New("runtime ACME uses owned synchronous maintenance") }, Logger: r.logger})
 cache.Stop()
 template := r.template
 template.Logger = r.logger
 cfg := certmagic.New(cache, template)
 cfg.OnDemand = nil
 cfg.OnEvent = nil
 cfg.CertSelection = nil
 cfg.Logger = r.logger
 cfg.Storage = guardACMEStorage(cfg.Storage, r.callbacks, r.recordCleanup)
 issuer := r.issuer
 issuer.Logger = r.logger
 if solver, ok := issuer.DNS01Solver.(*certmagic.DNS01Solver); ok {
  copy := &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{
   DNSProvider: solver.DNSProvider, TTL: solver.TTL,
   PropagationDelay: solver.PropagationDelay, PropagationTimeout: solver.PropagationTimeout,
   Resolvers: append([]string(nil),solver.Resolvers...), OverrideDomain: solver.OverrideDomain,
   Logger: r.logger.Named("dns_manager"),
  }}
  // Provider clients may reset cleanup cancellation. A fresh callback-owned
  // admission below restores only this provider's exact immutable DAG.
  issuer.DNS01Solver = &runtimeACMEDNSSolver{inner:copy, owner:r}
 }
 concrete, err := NewACMEIssuerWithHTTPClient(cfg, issuer, r.httpClient)
 if err != nil { return err }
 cfg.Issuers = []certmagic.Issuer{concrete}
 // A named async provider exposes each successful domain immediately and
 // keeps its last certificate during an unrelated domain's failure. Seed only
 // unmanaged snapshots: ManageSync must still load, check ARI/OCSP and renew
 // every domain in this fresh, stopped cache rather than skipping it as already
 // managed. The public cache methods synchronize concurrent TLS readers.
 if !r.synchronous && r.cache != nil {
  seen := make(map[string]bool)
  for _,domain := range r.domains {
   for _,previous := range r.cache.AllMatchingCertificates(domain) {
    if seen[previous.Hash()] { continue }; seen[previous.Hash()] = true
    if _,err := cfg.CacheUnmanagedTLSCertificate(ctx,previous.Certificate,previous.Tags); err != nil { return err }
   }
  }
 }
 r.challenge.Store(cfg)
 defer r.challenge.CompareAndSwap(cfg,nil)
 var manageErr error
 if r.synchronous {
  manageErr = cfg.ManageSync(ctx,r.domains)
 } else {
  r.cache = cache
  r.config.Store(cfg)
  for _,domain := range r.domains {
   if err := ctx.Err(); err != nil { manageErr = errors.Join(manageErr,err); break }
   manageErr = errors.Join(manageErr,cfg.ManageSync(ctx,[]string{domain}))
  }
 }
 r.mu.Lock(); cleanupErr := r.closeErr; r.mu.Unlock()
 if cleanupErr != nil { return errors.Join(manageErr,NewRuntimeCleanupError(cleanupErr)) }
 if err := ctx.Err(); err != nil { return errors.Join(manageErr,err) }
 if manageErr != nil { return manageErr }
 r.cache = cache
 r.config.Store(cfg)
 return nil
}

func (r *RuntimeACME) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) { return r.GetCertificateWithContext(certificate.HelloContext(hello), hello) }
func (r *RuntimeACME) GetCertificateWithContext(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
 ctx, release, err := certificate.BeginRuntimeCallback(ctx, r.source, r.fence)
 if err != nil { return nil, err }
 defer release()
 cfg := r.config.Load()
 if hello != nil && len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == "acme-tls/1" { if challenge := r.challenge.Load(); challenge != nil { cfg = challenge } }
 if cfg == nil { return nil, errors.New("ACME certificate acquisition is not ready") }
 return cfg.GetCertificateWithContext(ctx, hello)
}

// The existing pinned issuer integration replaces this private field already.
// Keep the shape check centralized and build it against the actual final Config.
func NewACMEIssuerWithHTTPClient(cfg *certmagic.Config, template certmagic.ACMEIssuer, client *http.Client) (*certmagic.ACMEIssuer, error) {
 issuer := certmagic.NewACMEIssuer(cfg, template)
 if client == nil { return issuer, nil }
 field := reflect.ValueOf(issuer).Elem().FieldByName("httpClient")
 if !field.IsValid() || !field.CanAddr() || field.Type() != reflect.TypeOf(client) { return nil, errors.New("certmagic ACME issuer HTTP client field is unavailable") }
 reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(client))
 return issuer, nil
}

func (r *RuntimeACME) recordCleanup(err error) {
 if err == nil { return }
 r.mu.Lock(); r.closeErr = errors.Join(r.closeErr,fmt.Errorf("ACME external cleanup incomplete: %v",err)); r.mu.Unlock()
}

// HTTPClient is used only while constructing the matching DNS01 provider.
// It owns no transport: the referenced HTTP manager retains that resource.
func (r *RuntimeACME) HTTPClient() *http.Client { return r.httpClient }

func (r *RuntimeACME) RuntimeExternalEffects() bool { return r.synchronous }
