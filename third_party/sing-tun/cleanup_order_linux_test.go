package tun

import (
	"errors"
	"os"
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

func TestConstructionFailureClosesFileOwner(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "tun-owner")
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("configure failed")
	if err := failNativeTunConstruction(failure, file); !errors.Is(err, failure) {
		t.Fatalf("lost configure error: %v", err)
	}
	if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("file owner still considers descriptor open: %v", err)
	}
}
