package tun

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

type dnsEvent struct {
	operation string
	family    uint16
	addresses []netip.Prefix
	servers   []netip.Addr
	domains   []string
}

func dualDNSOptions() Options {
	return Options{
		Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
		Inet6Address: []netip.Prefix{netip.MustParsePrefix("fdfe::1/126")},
	}
}

func recordDNSOperations(events *[]dnsEvent, failOperation string, failFamily uint16, failure error) windowsAddressDNSOperations {
	return windowsAddressDNSOperations{
		setAddresses: func(family uint16, addresses []netip.Prefix) error {
			*events = append(*events, dnsEvent{operation: "address", family: family, addresses: addresses})
			if failOperation == "address" && family == failFamily {
				return failure
			}
			return nil
		},
		resolveDNS: func(options *Options, family uint16) ([]netip.Addr, error) {
			*events = append(*events, dnsEvent{operation: "resolve", family: family})
			if failOperation == "resolve" && family == failFamily {
				return nil, failure
			}
			return resolveWindowsDNSAddress(options, family)
		},
		setDNS: func(family uint16, servers []netip.Addr, domains []string) error {
			*events = append(*events, dnsEvent{operation: "dns", family: family, servers: servers, domains: domains})
			if failOperation == "dns" && family == failFamily {
				return failure
			}
			return nil
		},
	}
}

func TestWindowsDNSAutoRouteModes(t *testing.T) {
	for _, autoRoute := range []bool{false, true} {
		for _, mode := range []string{"", DNSModeDisabled, DNSModeNative, DNSModeHijack} {
			for _, explicit := range []bool{false, true} {
				t.Run(fmt.Sprintf("auto=%v/mode=%s/explicit=%v", autoRoute, mode, explicit), func(t *testing.T) {
					options := dualDNSOptions()
					options.AutoRoute = autoRoute
					options.DNSMode = mode
					if explicit {
						options.DNSAddress = []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700::1111")}
					}
					var got []dnsEvent
					if err := configureWindowsAddressesAndDNS(&options, recordDNSOperations(&got, "", 0, nil)); err != nil {
						t.Fatal(err)
					}
					var want []dnsEvent
					for _, family := range []uint16{windowsDNSIPv4, windowsDNSIPv6} {
						addresses := options.Inet4Address
						if family == windowsDNSIPv6 {
							addresses = options.Inet6Address
						}
						want = append(want, dnsEvent{operation: "address", family: family, addresses: addresses})
						var servers []netip.Addr
						if autoRoute && mode != DNSModeDisabled {
							want = append(want, dnsEvent{operation: "resolve", family: family})
							address := "172.19.0.2"
							if family == windowsDNSIPv6 {
								address = "fdfe::2"
							}
							if explicit {
								address = "1.1.1.1"
								if family == windowsDNSIPv6 {
									address = "2606:4700::1111"
								}
							}
							servers = []netip.Addr{netip.MustParseAddr(address)}
						}
						want = append(want, dnsEvent{operation: "dns", family: family, servers: servers})
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("actual operations %#v; want %#v", got, want)
					}
				})
			}
		}
	}
}

func TestWindowsDNSExternalAndMissingFamilies(t *testing.T) {
	for _, families := range []int{0, 4, 6, 46} {
		for _, external := range []bool{false, true} {
			t.Run(fmt.Sprintf("families=%d/external=%v", families, external), func(t *testing.T) {
				options := dualDNSOptions()
				options.AutoRoute = true
				options.EXP_ExternalConfiguration = external
				if families == 0 || families == 6 {
					options.Inet4Address = nil
				}
				if families == 0 || families == 4 {
					options.Inet6Address = nil
				}
				var events []dnsEvent
				if err := configureWindowsAddressesAndDNS(&options, recordDNSOperations(&events, "", 0, nil)); err != nil {
					t.Fatal(err)
				}
				count := 0
				if !external {
					if families == 4 || families == 6 {
						count = 3
					}
					if families == 46 {
						count = 6
					}
				}
				if len(events) != count {
					t.Fatalf("events %#v, want %d", events, count)
				}
				for _, event := range events {
					if families == 4 && event.family != windowsDNSIPv4 || families == 6 && event.family != windowsDNSIPv6 {
						t.Fatalf("absent family called: %#v", event)
					}
				}
			})
		}
	}
}

func TestWindowsDNSFailureOrder(t *testing.T) {
	failure := errors.New("injected failure")
	for _, family := range []uint16{windowsDNSIPv4, windowsDNSIPv6} {
		for index, operation := range []string{"address", "resolve", "dns"} {
			t.Run(fmt.Sprintf("family=%d/%s", family, operation), func(t *testing.T) {
				options := dualDNSOptions()
				options.AutoRoute = true
				var events []dnsEvent
				err := configureWindowsAddressesAndDNS(&options, recordDNSOperations(&events, operation, family, failure))
				if !errors.Is(err, failure) {
					t.Fatalf("error chain %v", err)
				}
				expected := index + 1
				if family == windowsDNSIPv6 {
					expected += 3
				}
				if len(events) != expected {
					t.Fatalf("did not stop after failure: %#v", events)
				}
				if operation == "resolve" {
					if err != failure {
						t.Fatalf("resolver error wrapped: %v", err)
					}
				} else {
					name := "ipv4"
					if family == windowsDNSIPv6 {
						name = "ipv6"
					}
					if !strings.Contains(err.Error(), "set "+name+" "+operation) {
						t.Fatalf("error context %v", err)
					}
				}
			})
		}
	}
}

func TestWindowsDNSRealResolverFailureStopsIPv6(t *testing.T) {
	options := dualDNSOptions()
	options.AutoRoute = true
	options.Inet4Address = []netip.Prefix{netip.MustParsePrefix("172.19.0.1/32")}
	options.Inet6Address = []netip.Prefix{netip.MustParsePrefix("fdfe::1/128")}
	var events []dnsEvent
	err := configureWindowsAddressesAndDNS(&options, recordDNSOperations(&events, "", 0, nil))
	if err == nil || !strings.Contains(err.Error(), "no IPv4 server configured") {
		t.Fatalf("real resolver error %v", err)
	}
	if len(events) != 2 || events[0].operation != "address" || events[1].operation != "resolve" || events[1].family != windowsDNSIPv4 {
		t.Fatalf("real IPv4 failure did not stop chain: %#v", events)
	}
	options.AutoRoute = false
	options.DNSMode = DNSModeHijack
	events = nil
	if err := configureWindowsAddressesAndDNS(&options, recordDNSOperations(&events, "", 0, nil)); err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 {
		t.Fatalf("false must address/clear both families: %#v", events)
	}
	for _, event := range events {
		if event.operation == "resolve" || event.servers != nil || event.domains != nil {
			t.Fatalf("unexpected resolution/servers: %#v", event)
		}
	}
}

func TestWindowsDNSRealResolverEmptyFamilyList(t *testing.T) {
	for _, family := range []uint16{windowsDNSIPv4, windowsDNSIPv6} {
		options := dualDNSOptions()
		options.AutoRoute = true
		options.DNSMode = DNSModeNative
		if family == windowsDNSIPv4 {
			options.DNSAddress = []netip.Addr{netip.MustParseAddr("2606:4700::1111")}
		} else {
			options.DNSAddress = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
		}
		var events []dnsEvent
		if err := configureWindowsAddressesAndDNS(&options, recordDNSOperations(&events, "", 0, nil)); err != nil {
			t.Fatal(err)
		}
		if len(events) != 6 {
			t.Fatalf("both families must run: %#v", events)
		}
		for _, event := range events {
			if event.operation == "dns" && (event.domains != nil || event.family == family && len(event.servers) != 0) {
				t.Fatalf("actual filtered DNS argument: %#v", event)
			}
		}
	}
}
