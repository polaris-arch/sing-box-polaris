package tun

import (
	"errors"
	"reflect"
	"testing"
)

func TestNativeTunCleanupNetworkPrecedesSlowDNS(t *testing.T) {
	var calls []string
	networkFailure := errors.New("rule cleanup failed")
	dnsFailure := errors.New("resolver timeout")
	deviceFailure := errors.New("device close failed")
	err := closeNativeTunResources(func() error {
		calls = append(calls, "rules/routes")
		return networkFailure
	}, func() error {
		if !reflect.DeepEqual(calls, []string{"rules/routes"}) {
			t.Fatal("DNS ran before independent rule cleanup")
		}
		calls = append(calls, "dns")
		return dnsFailure
	}, func() error {
		calls = append(calls, "device")
		return deviceFailure
	})
	if !reflect.DeepEqual(calls, []string{"rules/routes", "dns", "device"}) {
		t.Fatalf("cleanup order: %v", calls)
	}
	for _, failure := range []error{networkFailure, dnsFailure, deviceFailure} {
		if !errors.Is(err, failure) {
			t.Fatalf("cleanup error lost: %v", failure)
		}
	}
}
