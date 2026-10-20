package local

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestResolvedIdleControlsCoverPrimaryFallbackAndLazyCohorts(t *testing.T) {
	resolver := new(DBusResolvedResolver)
	primary, fallback := newIdleTestTransport(), newIdleTestTransport()
	defer primary.pool.Close(); defer fallback.pool.Close()
	resolver.swapIdleServerSet(&resolvedServerSet{scopes: []*resolvedScope{{servers: []resolvedServer{{primaryTransport: primary, fallbackTransport: fallback}}}}})
	first, second := primary.acquire(t), fallback.acquire(t)
	resolver.SetKeepIdleConnections(false)
	resolver.CloseIdleConnections()
	if primary.closed != 0 || fallback.closed != 0 { t.Fatal("resolved idle effect closed an active query") }
	primary.pool.Release(first, true); fallback.pool.Release(second, true)
	if primary.closed != 1 || fallback.closed != 1 { t.Fatal("resolved policy missed a query pool") }
	lazy := newIdleTestTransport(); defer lazy.pool.Close()
	resolver.swapIdleServerSet(&resolvedServerSet{scopes: []*resolvedScope{{servers: []resolvedServer{{primaryTransport: adapter.DNSTransport(lazy)}}}}})
	last := lazy.acquire(t); lazy.pool.Release(last, true)
	if lazy.closed != 1 || primary.resets+fallback.resets+lazy.resets != 0 { t.Fatal("resolved replacement lost idle policy or reset a transport") }
}
