package box

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

// Use the actual Box constructor, initial persistent binding, graph owner,
// CacheFile child scope and temporary bbolt database. No packet, dial or TUN
// operation is needed to exercise the shutdown path observed in the App CI.
func runtimeFakeIPCleanupConstruction(t *testing.T, path string, hook func(*runtimeTestSocks) error) (*runtimeTestFixture, Options) {
	t.Helper()
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "example.org"), hook)
	fakeip.RegisterTransport(service.FromContext[adapter.DNSTransportRegistry](f.ctx).(*dns.TransportRegistry))
	server := runtimeFakeIPCandidate(t, "198.18.0.0/15").options.DNS.Servers[0]
	server.Tag = "fakeip"
	options.DNS.Servers = append(options.DNS.Servers, server)
	options.Experimental = &option.ExperimentalOptions{CacheFile: &option.CacheFileOptions{
		Enabled: true, Path: path, StoreFakeIP: true, StoreDNS: true,
	}}
	return f, options
}

func runtimeFakeIPCleanupBox(t *testing.T, f *runtimeTestFixture, options Options) *cachefile.CacheFile {
	t.Helper()
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.box = instance
	t.Cleanup(func() { _ = instance.CloseWithResult() })
	if instance.runtime == nil {
		t.Fatal("fixture did not select the actual runtime Box path")
	}
	physical, ok := service.FromContext[adapter.CacheFile](instance.runtime.ctx).(*cachefile.CacheFile)
	if !ok {
		t.Fatal("fixture did not retain the actual stable cache")
	}
	return physical
}

func runtimeFakeIPCleanupAllocate(t *testing.T, instance *Box) netip.Addr {
	t.Helper()
	store, err := instance.runtime.fakeIP.Borrow(netip.MustParsePrefix("198.18.0.0/15"), netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	address, err := store.Create("retained.example", false)
	if err != nil {
		t.Fatal(err)
	}
	return address
}

func runtimeFakeIPCleanupReopen(t *testing.T, path string) *cachefile.CacheFile {
	t.Helper()
	logger := log.NewNOPFactory().Logger()
	scope := adapter.NewScope(context.Background(), logger)
	cache := cachefile.New(cachefile.ContextWithFakeIPRuntimeOpen(context.Background(), nil), logger, option.CacheFileOptions{
		Path: path, StoreFakeIP: true,
	})
	if err := cache.Start(adapter.StartStateInitialize, scope); err != nil {
		_ = scope.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := scope.Close(); err != nil {
			t.Error(err)
		}
	})
	return cache
}

func runtimeFakeIPCleanupAssertSuccess(t *testing.T, instance *Box) {
	t.Helper()
	if err := instance.closeRuntimeResourcesContext(runtimeTestContext(t)); err != nil {
		t.Fatal(err)
	}
	if err := instance.CloseWithResult(); err != nil {
		t.Fatal(err)
	}
	snapshot := instance.RuntimeCleanupSnapshot()
	if !snapshot.Available || !snapshot.Done || snapshot.Failed || snapshot.Phase != 8 || snapshot.Resources[1].OwnerFailures != 0 {
		t.Fatalf("core cleanup was not confirmed: %+v", snapshot)
	}
}

func TestRuntimeFakeIPCleanupPersistsBeforePhysicalCacheClose(t *testing.T) {
	for _, allocate := range []bool{false, true} {
		name := "without-answers"
		if allocate {
			name = "with-allocation"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cache.db")
			f, options := runtimeFakeIPCleanupConstruction(t, path, nil)
			physical := runtimeFakeIPCleanupBox(t, f, options)
			f.start(t)
			want := netip.MustParseAddr("198.18.0.1")
			if allocate {
				want = runtimeFakeIPCleanupAllocate(t, f.box)
				before := physical.FakeIPMetadata()
				if before == nil || before.Inet4Current == want {
					t.Fatal("fixture did not distinguish reserved high-water mark from final cursor")
				}
			}
			runtimeFakeIPCleanupAssertSuccess(t, f.box)
			if err := physical.DB.View(func(*bbolt.Tx) error { return nil }); err == nil {
				t.Fatal("successful Box cleanup left the physical cache open")
			}
			if err := f.box.CloseWithResult(); err != nil {
				t.Fatal("repeated joining close changed the successful result", err)
			}
			if err := f.box.runtime.fakeIP.Close(); err != nil {
				t.Fatal("repeated allocator close attempted a post-close write", err)
			}
			reopened := runtimeFakeIPCleanupReopen(t, path)
			metadata := reopened.FakeIPMetadata()
			if metadata == nil || metadata.Inet4Current != want || metadata.Inet4Range != netip.MustParsePrefix("198.18.0.0/15") {
				t.Fatalf("final metadata did not survive actual database reopen: %+v, want cursor %s", metadata, want)
			}
			if allocate {
				if got, ok := reopened.FakeIPLoadDomain("retained.example", false); !ok || got != want {
					t.Fatalf("mapping was not flushed with metadata: %s %v", got, ok)
				}
			}
		})
	}
}

func TestRuntimeFakeIPCleanupNeverOpenedAndFailedStart(t *testing.T) {
	for _, mode := range []string{"never-started", "cache-open-fails", "graph-start-fails"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cache.db")
			if mode == "cache-open-fails" {
				path = filepath.Join(t.TempDir(), "missing-parent", "cache.db")
			}
			f, options := runtimeFakeIPCleanupConstruction(t, path, func(outbound *runtimeTestSocks) error {
				if mode == "graph-start-fails" && outbound.Tag() == "a" {
					outbound.startHook = func(stage adapter.StartStage) error {
						if stage == adapter.StartStateStarted {
							return errors.New("injected post-binding initial graph failure")
						}
						return nil
					}
				}
				return nil
			})
			physical := runtimeFakeIPCleanupBox(t, f, options)
			if mode != "never-started" {
				if err := f.box.Start(); err == nil {
					t.Fatal("injected startup failure reported success")
				}
			}
			runtimeFakeIPCleanupAssertSuccess(t, f.box)
			if mode == "graph-start-fails" {
				if physical.DB == nil {
					t.Fatal("failure fixture did not initialize the actual physical cache")
				}
				if err := physical.DB.View(func(*bbolt.Tx) error { return nil }); err == nil {
					t.Fatal("failed startup left the physical cache open")
				}
				if metadata := runtimeFakeIPCleanupReopen(t, path).FakeIPMetadata(); metadata != nil {
					t.Fatal("unpublished initial candidate wrote allocator metadata", metadata)
				}
			} else {
				if physical.DB != nil {
					t.Fatal("unopened fixture unexpectedly acquired a database")
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("cleanup created an unopened database", err)
				}
			}
		})
	}
}

func TestRuntimeFakeIPCleanupConstructorFailureStillDrains(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	f, options := runtimeFakeIPCleanupConstruction(t, path, func(outbound *runtimeTestSocks) error {
		if outbound.Tag() == "b" {
			return errors.New("injected constructor failure before stable start")
		}
		return nil
	})
	instance, err, report := NewWithConstructionReport(options)
	if instance != nil || err == nil || !report.Attempted || report.CleanupError != nil {
		t.Fatalf("constructor failure lost cleanup: %p %v %+v", instance, err, report)
	}
	for _, tag := range []string{"a", "b"} {
		actual := f.object(t, tag, 0)
		runtimeTestWait(t, actual.closed, "constructor cleanup")
		if _, count := actual.snapshot(); count != 1 {
			t.Fatalf("constructor cleanup repeated for %s: %d", tag, count)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("constructor cleanup opened the physical cache", err)
	}
}

func TestRuntimeFakeIPCleanupUnactivatedAndMemoryOnly(t *testing.T) {
	for _, mode := range []string{"unactivated", "memory-only"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cache.db")
			f, options := runtimeFakeIPCleanupConstruction(t, path, nil)
			if mode == "unactivated" {
				options.DNS.Servers = options.DNS.Servers[:len(options.DNS.Servers)-1]
			} else {
				options.Experimental = nil
			}
			instance, err := New(options)
			if err != nil {
				t.Fatal(err)
			}
			f.box = instance
			t.Cleanup(func() { _ = instance.CloseWithResult() })
			if instance.runtime == nil {
				t.Fatal("fixture did not select runtime Box")
			}
			f.start(t)
			if mode == "memory-only" {
				runtimeFakeIPCleanupAllocate(t, instance)
			}
			runtimeFakeIPCleanupAssertSuccess(t, instance)
			if mode == "unactivated" {
				if metadata := runtimeFakeIPCleanupReopen(t, path).FakeIPMetadata(); metadata != nil {
					t.Fatal("empty allocator wrote metadata", metadata)
				}
			} else if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("memory-only allocator created a database", err)
			}
		})
	}
}

func TestRuntimeFakeIPCleanupFailureStaysVisibleAndDrainsOtherCleanup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	f, options := runtimeFakeIPCleanupConstruction(t, path, nil)
	physical := runtimeFakeIPCleanupBox(t, f, options)
	f.start(t)
	runtimeFakeIPCleanupAllocate(t, f.box)
	// A real closed database, not an error-only mock, must still fail the final
	// durable write after the ordering fix. Do not filter this failure as benign.
	if err := physical.DB.Close(); err != nil {
		t.Fatal(err)
	}
	var cleanups atomic.Int32
	other := errors.New("injected other stable cleanup failure")
	f.box.runtime.stable.scope.Add(func() error { cleanups.Add(1); return other })
	err := f.box.closeRuntimeResourcesContext(runtimeTestContext(t))
	if err == nil || !errors.Is(err, errRuntimeCleanupIncomplete) || !errors.Is(err, other) || !strings.Contains(err.Error(), "Box fake-IP allocator") || !strings.Contains(err.Error(), "database not open") {
		t.Fatalf("real persistence/other cleanup failure was hidden: %v", err)
	}
	if cleanups.Load() != 1 {
		t.Fatal("allocator failure abandoned the remaining stable scope")
	}
	snapshot := f.box.RuntimeCleanupSnapshot()
	if !snapshot.Done || !snapshot.Failed || snapshot.Resources[1].OwnerFailures != 1 {
		t.Fatalf("failed cleanup was not retained: %+v", snapshot)
	}
	first := f.box.CloseWithResult()
	second := f.box.CloseWithResult()
	if first == nil || second == nil || first.Error() != second.Error() || cleanups.Load() != 1 {
		t.Fatal("repeated close lost the sticky failure or repeated cleanup", first, second)
	}
	// Box.Close is deliberately non-joining after the first invocation. Its nil
	// result must not erase the separately retained CloseWithResult failure.
	if err := f.box.Close(); err != nil {
		t.Fatal("later non-joining Close changed its documented contract", err)
	}
	if retained := f.box.CloseWithResult(); retained == nil || retained.Error() != first.Error() {
		t.Fatal("non-joining Close erased the retained failure", retained)
	}
}

type runtimeFakeIPCleanupPanicStorage struct{ adapter.CacheFile }

func (*runtimeFakeIPCleanupPanicStorage) StoreFakeIP() bool { return true }
func (*runtimeFakeIPCleanupPanicStorage) FakeIPMetadata() *adapter.FakeIPMetadata {
	return nil
}
func (*runtimeFakeIPCleanupPanicStorage) FakeIPReset() error { return nil }
func (*runtimeFakeIPCleanupPanicStorage) FakeIPSaveMetadata(*adapter.FakeIPMetadata) error {
	panic("injected allocator final-write panic")
}

func TestRuntimeFakeIPCleanupPanicStillDrainsStableScope(t *testing.T) {
	f, options := newRuntimeTestConstruction(t, runtimeTestConfig(1080, "example.org"), nil)
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.box = instance
	t.Cleanup(func() { _ = instance.CloseWithResult() })
	if instance.runtime == nil {
		t.Fatal("fixture did not select runtime Box")
	}
	f.start(t)
	if err := instance.runtime.fakeIP.Close(); err != nil {
		t.Fatal(err)
	}
	// Only this exceptional boundary uses an injected storage implementation.
	// The normal/order regressions above use the unchanged physical CacheFile.
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegister[adapter.CacheFile](ctx, &runtimeFakeIPCleanupPanicStorage{})
	manager, err := fakeip.NewManager(ctx, instance.logger, netip.MustParsePrefix("198.18.0.0/15"), netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	instance.runtime.fakeIP = manager
	var cleanups atomic.Int32
	instance.runtime.stable.scope.Add(func() error { cleanups.Add(1); return nil })
	err = instance.closeRuntimeResourcesContext(runtimeTestContext(t))
	if err == nil || !strings.Contains(err.Error(), "injected allocator final-write panic") || cleanups.Load() != 1 {
		t.Fatal("allocator panic hid failure or abandoned stable cleanup", err, cleanups.Load())
	}
	if snapshot := instance.RuntimeCleanupSnapshot(); !snapshot.Done || !snapshot.Failed || snapshot.Resources[1].OwnerFailures != 1 {
		t.Fatalf("allocator panic was not retained by the stable owner: %+v", snapshot)
	}
}

// closeRuntimeResourcesContext evaluates Done only at its final observation
// select. Signal entry to that actual wait point, not just goroutine startup.
type runtimeFakeIPCleanupWaitContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *runtimeFakeIPCleanupWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestRuntimeFakeIPCleanupWaitsForOtherOwnersAndConcurrentResourceObservers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	f, options := runtimeFakeIPCleanupConstruction(t, path, nil)
	physical := runtimeFakeIPCleanupBox(t, f, options)
	f.start(t)
	want := runtimeFakeIPCleanupAllocate(t, f.box)
	lease, _ := f.acquire(t)
	defer lease.Release()
	barrier := newRuntimeTestBarrier()
	t.Cleanup(barrier.open)
	actual := f.object(t, "a", 0)
	actual.access.Lock()
	actual.closeHook = func() error { barrier.block(); return nil }
	actual.access.Unlock()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.box.closeRuntimeResourcesContext(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled observer changed resource custody", err)
	}
	lease.Release()
	runtimeTestWait(t, barrier.entered, "dependent outbound cleanup")
	if err := physical.DB.View(func(*bbolt.Tx) error { return nil }); err != nil {
		t.Fatal("physical cache closed while another owner was still draining", err)
	}
	results := make(chan error, 2)
	observers := make([]*runtimeFakeIPCleanupWaitContext, 2)
	for index := range observers {
		observer := &runtimeFakeIPCleanupWaitContext{Context: runtimeTestContext(t), waiting: make(chan struct{})}
		observers[index] = observer
		go func() { results <- f.box.closeRuntimeResourcesContext(observer) }()
	}
	for _, observer := range observers {
		runtimeTestWait(t, observer.waiting, "shutdown observer entering its actual wait select")
	}
	select {
	case err := <-results:
		t.Fatal("joining observer claimed completion while another owner was blocked", err)
	default:
	}
	barrier.open()
	ctx := runtimeTestContext(t)
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("concurrent close observers did not join", ctx.Err())
		}
	}
	runtimeFakeIPCleanupAssertSuccess(t, f.box)
	if _, count := actual.snapshot(); count != 1 {
		t.Fatalf("dependent owner cleanup repeated: %d", count)
	}
	if metadata := runtimeFakeIPCleanupReopen(t, path).FakeIPMetadata(); metadata == nil || metadata.Inet4Current != want {
		t.Fatal("ordered close did not persist the exact cursor after other owners drained", metadata)
	}
}
