package clashmode

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
)

type testCacheFile struct {
	adapter.CacheFile
	mu     sync.Mutex
	mode   string
	loads  int
	stored []string
}

func (c *testCacheFile) LoadMode() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loads++
	return c.mode
}

func (c *testCacheFile) StoreMode(mode string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mode = mode
	c.stored = append(c.stored, mode)
	return nil
}

type testDNSRouter struct {
	adapter.DNSRouter
	clears atomic.Int32
}

func (r *testDNSRouter) ClearCache() {
	r.clears.Add(1)
}

func newTestManager(defaultMode, cachedMode string) (*Manager, *testCacheFile, *testDNSRouter) {
	cache := &testCacheFile{mode: cachedMode}
	dns := &testDNSRouter{}
	ctx := service.ContextWith[adapter.CacheFile](context.Background(), cache)
	ctx = service.ContextWith[adapter.DNSRouter](ctx, dns)
	m := NewManager(ctx, log.NewNOPFactory().NewLogger("test"), defaultMode, []string{"Rule", "Direct", "Global"})
	return m, cache, dns
}

func TestExplicitDefaultModeWinsOverCachedMode(t *testing.T) {
	m, cache, _ := newTestManager("Direct", "Rule")
	if got := m.Mode(); got != "Direct" {
		t.Fatalf("mode before start = %q, want Direct", got)
	}
	if err := m.Start(adapter.StartStateStart, adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())); err != nil {
		t.Fatal(err)
	}
	if got := m.Mode(); got != "Direct" {
		t.Fatalf("mode after start = %q, want Direct", got)
	}
	if cache.loads != 0 {
		t.Fatalf("explicit default mode loaded stale cache %d times", cache.loads)
	}
	if got := cache.mode; got != "Rule" {
		t.Fatalf("startup changed cached mode to %q", got)
	}
}

func TestUnspecifiedDefaultRestoresCachedMode(t *testing.T) {
	m, cache, _ := newTestManager("", "Direct")
	if err := m.Start(adapter.StartStateStart, adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())); err != nil {
		t.Fatal(err)
	}
	if got := m.Mode(); got != "Direct" {
		t.Fatalf("mode after start = %q, want Direct", got)
	}
	if cache.loads != 1 {
		t.Fatalf("cache loads = %d, want 1", cache.loads)
	}
}

func TestConcurrentModeReadAndSwitch(t *testing.T) {
	m, cache, dns := newTestManager("Rule", "")
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			for j := range 1000 {
				if (i+j)%2 == 0 {
					m.SetMode("Direct")
				} else {
					m.SetMode("Rule")
				}
			}
		}(i)
		go func() {
			defer wg.Done()
			for range 1000 {
				if mode := m.Mode(); mode != "Rule" && mode != "Direct" {
					t.Errorf("unexpected mode %q", mode)
					return
				}
			}
		}()
	}
	wg.Wait()
	m.SetMode("invalid")
	if got := m.Mode(); got != "Rule" && got != "Direct" {
		t.Fatalf("invalid mode was accepted: %q", got)
	}
	cache.mu.Lock()
	stored := cache.mode
	cache.mu.Unlock()
	if stored != m.Mode() {
		t.Fatalf("cached mode = %q, current mode = %q", stored, m.Mode())
	}
	if dns.clears.Load() == 0 {
		t.Fatal("mode switches did not clear DNS cache")
	}
}
