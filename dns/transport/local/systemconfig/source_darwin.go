//go:build cgo

package systemconfig

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/lifecycle"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/dnsinfo"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

type Source struct {
	work             lifecycle.Work
	closeOnce        sync.Once
	interfaceMonitor tun.DefaultInterfaceMonitor
	updateCallback   *list.Element[tun.DefaultInterfaceUpdateCallback]
	access           sync.Mutex
	stale            bool
	interfaceIndex   int
	config           *Config
}

func NewSource(ctx context.Context) *Source {
	source := &Source{
		interfaceMonitor: service.FromContext[adapter.NetworkManager](ctx).InterfaceMonitor(),
	}
	// A DNS-only update no longer resets the network, so follow the monitor
	// directly, as on Windows.
	if source.interfaceMonitor != nil {
		source.updateCallback = source.interfaceMonitor.RegisterCallback(func(_ *control.Interface, _ int) { source.Reset() })
	}
	return source
}

func (s *Source) Configuration() *Config {
	done, ok := s.work.Reserve()
	if !ok {
		return &Config{}
	}
	defer done()
	interfaceIndex := s.defaultInterfaceIndex()
	s.access.Lock()
	defer s.access.Unlock()
	interfaceChanged := s.interfaceIndex != interfaceIndex
	s.interfaceIndex = interfaceIndex
	if s.config != nil && !s.stale && !interfaceChanged && s.interfaceMonitor != nil {
		return s.config
	}
	s.stale = false
	dnsConfiguration := dnsinfo.Copy()
	if dnsConfiguration == nil {
		if s.config == nil {
			s.config = newConfig(dnsinfo.Resolver{})
		}
		return s.config
	}
	config := newConfig(dnsConfiguration.Select(interfaceIndex))
	if s.config != nil && config.Equal(s.config) {
		return s.config
	}
	s.config = config
	return config
}

func (s *Source) Reset() {
	done, ok := s.work.Reserve()
	if !ok {
		return
	}
	defer done()
	s.access.Lock()
	s.stale = true
	s.access.Unlock()
}

func (s *Source) Close() error {
	s.closeOnce.Do(func() {
		s.work.Seal()
		if s.updateCallback != nil {
			s.interfaceMonitor.UnregisterCallback(s.updateCallback)
		}
		s.work.Wait()
	})
	return nil
}

func (s *Source) defaultInterfaceIndex() int {
	if s.interfaceMonitor == nil {
		return 0
	}
	defaultInterface := s.interfaceMonitor.DefaultInterface()
	if defaultInterface == nil {
		return 0
	}
	return defaultInterface.Index
}

func newConfig(resolver dnsinfo.Resolver) *Config {
	config := &Config{
		Ndots:    1,
		Timeout:  5 * time.Second,
		Attempts: 2,
	}
	if len(resolver.Servers) == 0 {
		config.Servers = defaultServers
		config.Search = defaultSearch()
		return config
	}
	config.Servers = common.Map(resolver.Servers, M.SocksaddrFromNetIP)
	for _, searchDomain := range resolver.Search {
		searchDomain = mDNS.Fqdn(searchDomain)
		if searchDomain == "." {
			continue
		}
		config.Search = append(config.Search, searchDomain)
	}
	if len(config.Search) == 0 {
		config.Search = defaultSearch()
	}
	if resolver.Timeout > 0 {
		config.Timeout = resolver.Timeout
	}
	return config
}
