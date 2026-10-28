package systemconfig

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
)

func TestConfigurationRefreshWithoutInterfaceEvent(t *testing.T) {
	start := time.Now()
	initial := &Config{Servers: []M.Socksaddr{M.SocksaddrFrom(netip.MustParseAddr("192.168.10.1"), 53)}}
	changed := &Config{Servers: []M.Socksaddr{M.SocksaddrFrom(netip.MustParseAddr("223.5.5.5"), 53)}, Search: []string{"corp.example."}}
	s := &Source{updateCallback: new(list.Element[tun.DefaultInterfaceUpdateCallback])}
	reads := 0
	current := initial
	read := func() *Config { reads++; return current }
	if s.configuration(start, read) != initial {
		t.Fatal("initial configuration was not read")
	}
	current = changed
	if s.configuration(start.Add(configRefreshInterval-time.Nanosecond), read) != initial || reads != 1 {
		t.Fatal("cache did not bound reads")
	}
	if s.configuration(start.Add(configRefreshInterval), read) != changed || reads != 2 {
		t.Fatal("DNS-only change remained stale")
	}
	current = initial
	if s.configuration(start.Add(2*configRefreshInterval), read) != initial {
		t.Fatal("DNS restoration remained stale")
	}
}

func TestConfigurationInvalidationAndEqualReuse(t *testing.T) {
	for _, invalidate := range []string{"reset", "interface", "no-monitor", "expired"} {
		t.Run(invalidate, func(t *testing.T) {
			now := time.Now()
			initial := &Config{Search: []string{"corp.example."}}
			s := &Source{config: initial, lastChecked: now, updateCallback: new(list.Element[tun.DefaultInterfaceUpdateCallback])}
			switch invalidate {
			case "reset":
				s.Reset()
			case "interface":
				s.interfaceUpdated(nil, 0)
			case "no-monitor":
				s.updateCallback = nil
			case "expired":
				now = now.Add(configRefreshInterval)
			}
			reads := 0
			got := s.configuration(now, func() *Config { reads++; return &Config{Search: []string{"corp.example."}} })
			if reads != 1 || got != initial {
				t.Fatal("invalidation must reread and reuse an equal snapshot")
			}
		})
	}
}

func TestConfigurationConcurrentRefresh(t *testing.T) {
	now := time.Now()
	s := &Source{config: &Config{}, lastChecked: now.Add(-configRefreshInterval), updateCallback: new(list.Element[tun.DefaultInterfaceUpdateCallback])}
	changed := &Config{Search: []string{"new.example."}}
	reads := 0
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if s.configuration(now, func() *Config { reads++; return changed }) != changed {
				t.Error("inconsistent snapshot")
			}
		})
	}
	wg.Wait()
	if reads != 1 {
		t.Fatalf("concurrent reads = %d, want 1", reads)
	}
}
