package dns

import (
	"fmt"
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

type dependenciesRuntimeStores struct {
	adapter.DNSCacheStore
	adapter.RDRCStore
	physical                adapter.CacheFile
	dnsEnabled, rdrcEnabled bool
	dnsChecks, rdrcChecks   int
}

func (v *dependenciesRuntimeStores) RuntimeDNSPhysicalCache() adapter.CacheFile {
	return v.physical
}

func (v *dependenciesRuntimeStores) StoreDNS() bool {
	v.dnsChecks++
	return v.dnsEnabled
}

func (v *dependenciesRuntimeStores) StoreRDRC() bool {
	v.rdrcChecks++
	return v.rdrcEnabled
}

func TestPrivateClientDependenciesRetainedViewSettings(t *testing.T) {
	flags := [][2]bool{{false, false}, {true, false}, {false, true}, {true, true}}
	for _, physicalFlags := range flags {
		for _, viewFlags := range flags {
			t.Run(fmt.Sprint(physicalFlags, "/", viewFlags), func(t *testing.T) {
				physical := &dependenciesCacheFile{dnsEnabled: physicalFlags[0], rdrcEnabled: physicalFlags[1]}
				view := &dependenciesRuntimeStores{physical: physical, dnsEnabled: viewFlags[0], rdrcEnabled: viewFlags[1]}
				deps, err := PrivateClientDependencies(physical, view)
				if physicalFlags != viewFlags {
					require.ErrorContains(t, err, "settings differ")
					require.Nil(t, deps.DNSCache)
					require.Nil(t, deps.RDRC)
				} else {
					require.NoError(t, err)
					if physicalFlags[0] {
						require.Same(t, view, deps.DNSCache)
					} else {
						require.Nil(t, deps.DNSCache)
					}
					if physicalFlags[1] {
						require.Same(t, view, deps.RDRC)
					} else {
						require.Nil(t, deps.RDRC)
					}
				}
				require.Equal(t, 1, physical.dnsChecks)
				require.Equal(t, 1, physical.rdrcChecks)
				require.Equal(t, 1, view.dnsChecks)
				require.Equal(t, 1, view.rdrcChecks)
				require.Zero(t, physical.setters)
			})
		}
	}
}

func TestPrivateClientDependenciesRejectForeignAndMultipleViews(t *testing.T) {
	physical := &dependenciesCacheFile{dnsEnabled: true, rdrcEnabled: true}
	foreign := &dependenciesCacheFile{dnsEnabled: true, rdrcEnabled: true}
	view := &dependenciesRuntimeStores{physical: foreign, dnsEnabled: true, rdrcEnabled: true}
	for _, cache := range []adapter.CacheFile{nil, physical} {
		deps, err := PrivateClientDependencies(cache, view)
		require.ErrorContains(t, err, "different physical cache")
		require.Nil(t, deps.DNSCache)
		require.Nil(t, deps.RDRC)
	}
	deps, err := PrivateClientDependencies(physical, view, view)
	require.ErrorContains(t, err, "multiple private DNS store views")
	require.Nil(t, deps.DNSCache)
	require.Nil(t, deps.RDRC)
	for _, cache := range []*dependenciesCacheFile{physical, foreign} {
		require.Zero(t, cache.dnsChecks)
		require.Zero(t, cache.rdrcChecks)
		require.Zero(t, cache.setters)
	}
	require.Zero(t, view.dnsChecks)
	require.Zero(t, view.rdrcChecks)
}

func TestPrivateClientDependenciesNilViewStillRejectsPersistence(t *testing.T) {
	deps, err := PrivateClientDependencies(nil, nil)
	require.NoError(t, err)
	require.Nil(t, deps.DNSCache)
	require.Nil(t, deps.RDRC)
	for _, flags := range [][2]bool{{false, false}, {true, false}, {false, true}, {true, true}} {
		physical := &dependenciesCacheFile{dnsEnabled: flags[0], rdrcEnabled: flags[1]}
		deps, err := PrivateClientDependencies(physical, nil)
		if flags[0] || flags[1] {
			require.ErrorContains(t, err, "retained private logical view")
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
		require.Equal(t, 1, physical.dnsChecks)
		require.Equal(t, 1, physical.rdrcChecks)
		require.Zero(t, physical.setters)
	}
}
