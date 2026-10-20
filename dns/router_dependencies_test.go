package dns

import (
	"context"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type dependenciesCacheFile struct {
	adapter.CacheFile              // Unrelated lifecycle/FakeIP methods panic if incorrectly used.
	dnsEnabled, rdrcEnabled        bool
	dnsChecks, rdrcChecks, setters int
	disableExpire                  bool
	optimisticTimeout              time.Duration
}

func (c *dependenciesCacheFile) StoreDNS() bool  { c.dnsChecks++; return c.dnsEnabled }
func (c *dependenciesCacheFile) StoreRDRC() bool { c.rdrcChecks++; return c.rdrcEnabled }

func (c *dependenciesCacheFile) SetDisableExpire(value bool) { c.setters++; c.disableExpire = value }

func (c *dependenciesCacheFile) SetOptimisticTimeout(value time.Duration) {
	c.setters++
	c.optimisticTimeout = value
}

func dependenciesStartRouter(t *testing.T, router *Router) {
	t.Helper()
	require.NoError(t, router.Initialize(nil))
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().NewLogger("test"))
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	require.NoError(t, router.Start(adapter.StartStateStart, scope))
}

func TestPrivateClientDependenciesRejectPersistence(t *testing.T) {
	deps, err := PrivateClientDependencies(nil)
	require.NoError(t, err)
	require.Nil(t, deps.DNSCache)
	require.Nil(t, deps.RDRC)
	for _, flags := range [][2]bool{{false, false}, {true, false}, {false, true}, {true, true}} {
		cache := &dependenciesCacheFile{dnsEnabled: flags[0], rdrcEnabled: flags[1]}
		deps, err := PrivateClientDependencies(cache)
		if flags[0] || flags[1] {
			require.Error(t, err)
			if flags[0] {
				require.ErrorContains(t, err, "experimental.cache_file.store_dns")
			}
			if flags[1] {
				require.ErrorContains(t, err, "experimental.cache_file.store_rdrc")
			}
		} else {
			require.NoError(t, err)
		}
		require.Nil(t, deps.DNSCache)
		require.Nil(t, deps.RDRC)
		require.Equal(t, 1, cache.dnsChecks)
		require.Equal(t, 1, cache.rdrcChecks)
		require.Zero(t, cache.setters) // No FakeIP or lifetime method may be called either.
	}
}

func TestRouterExplicitNilStoresIgnoreAmbientCache(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	ambient := &dependenciesCacheFile{dnsEnabled: true, rdrcEnabled: true}
	service.MustRegister[adapter.CacheFile](ctx, ambient)
	first, err := NewRouterWithClientDependencies(ctx, log.NewNOPFactory(), option.DNSOptions{}, RouterClientDependencies{})
	require.NoError(t, err)
	second, err := NewRouterWithClientDependencies(ctx, log.NewNOPFactory(), option.DNSOptions{}, RouterClientDependencies{})
	require.NoError(t, err)
	dependenciesStartRouter(t, first)
	dependenciesStartRouter(t, second)
	a, b := first.client.(*Client), second.client.(*Client)
	require.Nil(t, a.dnsCache)
	require.Nil(t, a.rdrc)
	require.NotNil(t, a.cache)
	require.NotSame(t, a.cache, b.cache)
	require.Zero(t, ambient.dnsChecks)
	require.Zero(t, ambient.rdrcChecks)
	require.Zero(t, ambient.setters)
	transport := policyReply("private-memory", 0, 0, "192.0.2.1")
	for _, client := range []*Client{a, b} {
		for range 2 {
			_, err := client.Exchange(context.Background(), transport, correctnessQuestion(mDNS.TypeA), adapter.DNSQueryOptions{}, nil)
			require.NoError(t, err)
		}
	}
	require.EqualValues(t, 2, transport.calls.Load())
	a.ClearCache()
	_, err = b.Exchange(context.Background(), transport, correctnessQuestion(mDNS.TypeA), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	require.EqualValues(t, 2, transport.calls.Load())
	_, err = a.Exchange(context.Background(), transport, correctnessQuestion(mDNS.TypeA), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	require.EqualValues(t, 3, transport.calls.Load())
	require.Zero(t, ambient.dnsChecks)
	require.Zero(t, ambient.rdrcChecks)
	require.Zero(t, ambient.setters)

	var disabled option.DNSOptions
	require.NoError(t, json.Unmarshal([]byte(`{"disable_cache":true}`), &disabled))
	third, err := NewRouterWithClientDependencies(ctx, log.NewNOPFactory(), disabled, RouterClientDependencies{})
	require.NoError(t, err)
	dependenciesStartRouter(t, third)
	require.Nil(t, third.client.(*Client).cache)
}

func TestRouterExplicitStoresRemainBoundAfterRegistryReplacement(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	firstAmbient := &dependenciesCacheFile{dnsEnabled: true, rdrcEnabled: true}
	service.MustRegister[adapter.CacheFile](ctx, firstAmbient)
	store := &correctnessCacheStore{}
	rdrc := &dependenciesRDRC{}
	deps := RouterClientDependencies{DNSCache: store, RDRC: rdrc}
	router, err := NewRouterWithClientDependencies(ctx, log.NewNOPFactory(), option.DNSOptions{}, deps)
	require.NoError(t, err)
	deps.DNSCache = &correctnessCacheStore{}
	deps.RDRC = &dependenciesRDRC{}
	secondAmbient := &dependenciesCacheFile{dnsEnabled: true, rdrcEnabled: true}
	service.MustRegister[adapter.CacheFile](ctx, secondAmbient)
	dependenciesStartRouter(t, router)
	client := router.client.(*Client)
	require.Same(t, store, client.dnsCache)
	require.Same(t, rdrc, client.rdrc)
	for _, cache := range []*dependenciesCacheFile{firstAmbient, secondAmbient} {
		require.Zero(t, cache.dnsChecks)
		require.Zero(t, cache.rdrcChecks)
		require.Zero(t, cache.setters)
	}
}

func TestRouterLegacyStorageRemainsLazy(t *testing.T) {
	for _, flags := range [][2]bool{{false, false}, {true, false}, {false, true}, {true, true}} {
		ctx := service.ContextWithDefaultRegistry(context.Background())
		var options option.DNSOptions
		require.NoError(t, json.Unmarshal([]byte(`{"optimistic":{"enabled":true}}`), &options))
		router, err := NewRouter(ctx, log.NewNOPFactory(), options)
		require.NoError(t, err)
		// Normal Box order registers CacheFile after constructing the DNS Router.
		cache := &dependenciesCacheFile{dnsEnabled: flags[0], rdrcEnabled: flags[1]}
		service.MustRegister[adapter.CacheFile](ctx, cache)
		require.Zero(t, cache.dnsChecks)
		require.Zero(t, cache.rdrcChecks)
		require.Zero(t, cache.setters)
		dependenciesStartRouter(t, router)
		client := router.client.(*Client)
		require.Equal(t, 1, cache.dnsChecks)
		require.Equal(t, 1, cache.rdrcChecks)
		if flags[1] {
			require.Same(t, cache, client.rdrc)
		} else {
			require.Nil(t, client.rdrc)
		}
		if flags[0] {
			require.Same(t, cache, client.dnsCache)
			require.Equal(t, 2, cache.setters)
			require.False(t, cache.disableExpire)
			require.Equal(t, 3*24*time.Hour, cache.optimisticTimeout)
		} else {
			require.Nil(t, client.dnsCache)
			require.NotNil(t, client.cache)
			require.Zero(t, cache.setters)
		}
	}
}

func TestRouterBoundStoresIsolateQueriesAndRejections(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	ambient := &dependenciesCacheFile{dnsEnabled: true, rdrcEnabled: true}
	service.MustRegister[adapter.CacheFile](ctx, ambient)
	stores := []*correctnessCacheStore{{}, {}}
	rejections := []*dependenciesRDRC{{}, {}}
	clients := make([]*Client, 2)
	for i := range clients {
		router, err := NewRouterWithClientDependencies(ctx, log.NewNOPFactory(), option.DNSOptions{}, RouterClientDependencies{DNSCache: stores[i], RDRC: rejections[i]})
		require.NoError(t, err)
		dependenciesStartRouter(t, router)
		clients[i] = router.client.(*Client)
	}
	transport := policyReply("same-tag", 0, 0, "192.0.2.1")
	for _, client := range clients {
		_, err := client.Exchange(context.Background(), transport, correctnessQuestion(mDNS.TypeA), adapter.DNSQueryOptions{}, nil)
		require.NoError(t, err)
		_, err = client.Exchange(context.Background(), transport, correctnessQuestion(mDNS.TypeA), adapter.DNSQueryOptions{}, nil)
		require.NoError(t, err)
	}
	require.EqualValues(t, 2, transport.calls.Load()) // Each client's second query hits its own cache.
	for _, store := range stores {
		require.Equal(t, 1, store.writeCount())
	}
	for owner := range clients {
		question := correctnessQuestion(mDNS.TypeA)
		question.Question[0].Name = fmt.Sprintf("rejected-%d.example.", owner)
		_, err := clients[owner].Exchange(context.Background(), transport, question, adapter.DNSQueryOptions{}, func(*mDNS.Msg) bool { return false })
		require.ErrorIs(t, err, ErrResponseRejected)
		calls := transport.calls.Load()
		_, err = clients[owner].Exchange(context.Background(), transport, question, adapter.DNSQueryOptions{}, func(*mDNS.Msg) bool { return true })
		require.ErrorIs(t, err, ErrResponseRejectedCached)
		require.Equal(t, calls, transport.calls.Load())
		other := 1 - owner
		_, err = clients[other].Exchange(context.Background(), transport, question, adapter.DNSQueryOptions{}, func(*mDNS.Msg) bool { return true })
		require.NoError(t, err)
		require.Equal(t, calls+1, transport.calls.Load())
		require.True(t, rejections[owner].LoadRDRC(transport.Tag(), question.Question[0].Name, mDNS.TypeA))
		require.False(t, rejections[other].LoadRDRC(transport.Tag(), question.Question[0].Name, mDNS.TypeA))
	}
	for _, rejection := range rejections {
		require.Equal(t, 1, rejection.writeCount())
	}
	calls := transport.calls.Load()
	clients[0].ClearCache()
	_, err := clients[1].Exchange(context.Background(), transport, correctnessQuestion(mDNS.TypeA), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	require.Equal(t, calls, transport.calls.Load())
	_, err = clients[0].Exchange(context.Background(), transport, correctnessQuestion(mDNS.TypeA), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	require.Equal(t, calls+1, transport.calls.Load())

	require.Zero(t, ambient.dnsChecks)
	require.Zero(t, ambient.rdrcChecks)
	require.Zero(t, ambient.setters)
}

func TestOldOptimisticRefreshCannotWriteCandidateStore(t *testing.T) {
	for _, rejected := range []bool{false, true} {
		t.Run(fmt.Sprint("rejected=", rejected), func(t *testing.T) { dependenciesRefreshIsolation(t, rejected) })
	}
}

func dependenciesRefreshIsolation(t *testing.T, rejected bool) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	var options option.DNSOptions
	require.NoError(t, json.Unmarshal([]byte(`{"optimistic":{"enabled":true}}`), &options))
	oldStore, nextStore := &correctnessCacheStore{}, &correctnessCacheStore{}
	oldRDRC, nextRDRC := &dependenciesRDRC{}, &dependenciesRDRC{}
	oldRouter, err := NewRouterWithClientDependencies(ctx, log.NewNOPFactory(), options, RouterClientDependencies{DNSCache: oldStore, RDRC: oldRDRC})
	require.NoError(t, err)
	dependenciesStartRouter(t, oldRouter)
	old := oldRouter.client.(*Client)
	question := correctnessQuestion(mDNS.TypeA)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	var refreshKey *dnsCacheKey
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		if refreshKey != nil {
			require.NoError(t, dependenciesWaitRefresh(old, *refreshKey))
		}
	})
	transport := &policyTestTransport{tag: "same-tag", exchange: func(context.Context, *mDNS.Msg) (*mDNS.Msg, error) {
		close(entered)
		<-release
		return FixedResponse(question.Id, question.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.2")}, 60), nil
	}}
	key := old.newCacheKey(transport, question.Question[0], question, adapter.DNSQueryOptions{})
	refreshKey = &key
	stale := FixedResponse(question.Id, question.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 60)
	packed, err := stale.Pack()
	require.NoError(t, err)
	require.NoError(t, oldStore.SaveDNSCache(key.persistentName(), key.Name, key.Qtype, packed, time.Now().Add(-time.Minute)))
	response, err := old.Exchange(context.Background(), transport, question, adapter.DNSQueryOptions{}, func(*mDNS.Msg) bool { return !rejected })
	require.NoError(t, err)
	require.NotNil(t, response)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh never entered transport")
	}
	// Rebinding ambient state cannot retarget an already admitted old refresh.
	service.MustRegister[adapter.CacheFile](ctx, &dependenciesCacheFile{dnsEnabled: true})
	nextRouter, err := NewRouterWithClientDependencies(ctx, log.NewNOPFactory(), options, RouterClientDependencies{DNSCache: nextStore, RDRC: nextRDRC})
	require.NoError(t, err)
	dependenciesStartRouter(t, nextRouter)
	releaseOnce.Do(func() { close(release) })
	// Check actual worker removal after save/log, not transport callback completion.
	require.NoError(t, dependenciesWaitRefresh(old, key))
	if rejected {
		require.Equal(t, 1, oldStore.writeCount())
		require.True(t, oldRDRC.LoadRDRC(transport.Tag(), key.Name, key.Qtype))
		require.Equal(t, 1, oldRDRC.writeCount())
	} else {
		require.Equal(t, 2, oldStore.writeCount())
		require.Zero(t, oldRDRC.writeCount())
	}
	require.False(t, nextRDRC.LoadRDRC(transport.Tag(), key.Name, key.Qtype))
	require.Zero(t, nextRDRC.writeCount())
	require.Zero(t, nextStore.writeCount())
	require.Same(t, nextStore, nextRouter.client.(*Client).dnsCache)
}

type dependenciesRDRC struct {
	mu      sync.Mutex
	entries map[string]bool
	writes  int
}

func (s *dependenciesRDRC) LoadRDRC(transport, name string, qtype uint16) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.entries[fmt.Sprint(transport, "|", name, "|", qtype)]
}

func (s *dependenciesRDRC) SaveRDRC(transport, name string, qtype uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entries == nil {
		s.entries = make(map[string]bool)
	}
	s.entries[fmt.Sprint(transport, "|", name, "|", qtype)] = true
	s.writes++
	return nil
}

func (s *dependenciesRDRC) SaveRDRCAsync(transport, name string, qtype uint16, _ logger.Logger) {
	_ = s.SaveRDRC(transport, name, qtype)
}
func (s *dependenciesRDRC) writeCount() int { s.mu.Lock(); defer s.mu.Unlock(); return s.writes }

// A watchdog bounds a failure, never establishes success. The terminal map
// deletion is the actual worker completion oracle; Gosched yields without sleeps.
func dependenciesWaitRefresh(client *Client, key dnsCacheKey) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		if _, running := client.backgroundRefresh.Load(key); !running {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			runtime.Gosched()
		}
	}
}

func TestRouterDependencyValidationFailuresLeaveStoresUntouched(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	ambient := &dependenciesCacheFile{dnsEnabled: true, rdrcEnabled: true}
	service.MustRegister[adapter.CacheFile](ctx, ambient)
	store := &correctnessCacheStore{}
	rdrc := &dependenciesRDRC{}
	deps := RouterClientDependencies{DNSCache: store, RDRC: rdrc}
	require.NoError(t, store.SaveDNSCache("live", "live.example.", mDNS.TypeA, []byte{1}, time.Now().Add(time.Hour)))
	require.NoError(t, rdrc.SaveRDRC("live", "live.example.", mDNS.TypeA))
	for _, config := range []string{`{"disable_cache":true,"optimistic":{"enabled":true}}`, `{"disable_expire":true,"optimistic":{"enabled":true}}`} {
		var options option.DNSOptions
		require.NoError(t, json.Unmarshal([]byte(config), &options))
		_, err := NewRouterWithClientDependencies(ctx, log.NewNOPFactory(), options, deps)
		require.Error(t, err)
	}
	router, err := NewRouterWithClientDependencies(ctx, log.NewNOPFactory(), option.DNSOptions{}, deps)
	require.NoError(t, err)
	empty := ""
	invalid := []option.DNSRule{{DefaultOptions: option.DefaultDNSRule{RawDefaultDNSRule: option.RawDefaultDNSRule{ResolverPolicy: &empty}}}}
	require.ErrorContains(t, router.Initialize(invalid), "empty resolver_policy")
	scope := adapter.NewScope(ctx, log.NewNOPFactory().NewLogger("test"))
	require.ErrorContains(t, router.Start(adapter.StartStateStart, scope), "empty resolver_policy")
	require.NoError(t, scope.Close())
	require.Equal(t, 1, store.writeCount())
	require.Equal(t, 1, rdrc.writeCount())
	_, _, loaded := store.LoadDNSCache("live", "live.example.", mDNS.TypeA)
	require.True(t, loaded)
	require.True(t, rdrc.LoadRDRC("live", "live.example.", mDNS.TypeA))
	require.Zero(t, ambient.dnsChecks)
	require.Zero(t, ambient.rdrcChecks)
	require.Zero(t, ambient.setters)
}

func TestRouterLegacyNonDefaultCacheOptions(t *testing.T) {
	for _, test := range []struct {
		config     string
		disable    bool
		optimistic time.Duration
	}{
		{`{"disable_expire":true}`, true, 0},
		{`{"optimistic":{"enabled":true,"timeout":"2h"}}`, false, 2 * time.Hour},
	} {
		ctx := service.ContextWithDefaultRegistry(context.Background())
		var options option.DNSOptions
		require.NoError(t, json.Unmarshal([]byte(test.config), &options))
		router, err := NewRouter(ctx, log.NewNOPFactory(), options)
		require.NoError(t, err)
		cache := &dependenciesCacheFile{dnsEnabled: true}
		service.MustRegister[adapter.CacheFile](ctx, cache)
		dependenciesStartRouter(t, router)
		require.Equal(t, 2, cache.setters)
		require.Equal(t, test.disable, cache.disableExpire)
		require.Equal(t, test.optimistic, cache.optimisticTimeout)
	}
}
