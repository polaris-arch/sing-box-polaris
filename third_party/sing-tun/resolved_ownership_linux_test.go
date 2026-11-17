package tun

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestExternalResolvedOwnershipPreservesHijack(t *testing.T) {
	options := Options{AutoRoute: true, DNSMode: DNSModeHijack}
	if !options.ManageLinuxResolved() {
		t.Fatal("legacy resolver ownership changed")
	}
	options.LinuxResolvedExternal = true
	if options.ManageLinuxResolved() {
		t.Fatal("core retained external resolver ownership")
	}
	if options.DNSModeOrDefault() != DNSModeHijack || !options.AutoRoute {
		t.Fatal("external resolver ownership disabled packet hijack or routing")
	}
}

func TestResolvedOwnershipExclusions(t *testing.T) {
	for _, options := range []Options{
		{DNSMode: DNSModeDisabled},
		{DNSMode: DNSModeHijack, NetNs: "other"},
		{DNSMode: DNSModeHijack, EXP_ExternalConfiguration: true},
		{DNSMode: DNSModeHijack, LinuxResolvedExternal: true},
	} {
		if options.ManageLinuxResolved() {
			t.Fatalf("unexpected core resolver ownership: %+v", options)
		}
	}
}

func TestNativeResolverMethodsHonorExternalOwner(t *testing.T) {
	for _, external := range []bool{false, true} {
		t.Run(fmt.Sprint(external), func(t *testing.T) {
			directory := t.TempDir()
			trace := filepath.Join(directory, "calls")
			if err := os.WriteFile(filepath.Join(directory, "resolvectl"), []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$RESOLVED_TEST_TRACE\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", directory)
			t.Setenv("RESOLVED_TEST_TRACE", trace)
			native := &NativeTun{options: Options{
				Name: "test-tun", DNSMode: DNSModeHijack, LinuxResolvedExternal: external,
				DNSAddress: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
				Inet4Address: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")},
			}}
			if err := native.setSearchDomainForSystemdResolved(); err != nil {
				t.Fatal(err)
			}
			if err := native.unsetSearchDomainForSystemdResolved(); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(trace)
			if external {
				if !os.IsNotExist(err) {
					t.Fatalf("external owner invoked resolvectl: %q err=%v", data, err)
				}
			} else if err != nil || string(data) != "dns test-tun 192.0.2.1\ndomain test-tun ~.\ndefault-route test-tun true\nrevert test-tun\n" {
				t.Fatalf("legacy command path changed: %q err=%v", data, err)
			}
		})
	}
}
