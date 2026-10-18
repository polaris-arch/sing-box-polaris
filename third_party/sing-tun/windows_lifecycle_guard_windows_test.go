package tun

import (
	"golang.org/x/sys/windows"
	"testing"
)

func TestWindowsDNSFamilyConstants(t *testing.T) {
	if windowsDNSIPv4 != windows.AF_INET || windowsDNSIPv6 != windows.AF_INET6 {
		t.Fatal("family constants differ from Windows API")
	}
}

func TestWindowsLifecycleEarlyGuards(t *testing.T) {
	external := NativeTun{options: Options{EXP_ExternalConfiguration: true, AutoRoute: true}}
	if err := external.configure(); err != nil {
		t.Fatal(err)
	}
	if err := external.Start(); err != nil {
		t.Fatal(err)
	}
	noAutoRoute := NativeTun{options: Options{AutoRoute: false}}
	if err := noAutoRoute.Start(); err != nil {
		t.Fatal(err)
	}
}
