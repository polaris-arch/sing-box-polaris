package box

import (
	"context"
	"strings"
	"testing"
)

func TestRuntimeDomainSOCKSReplacesCapturedDNSClosure(t *testing.T) {
	base := strings.Replace(string(runtimeTestConfig(1080, "example.org")), `"server":"192.0.2.1"`, `"server":"proxy.example"`, 1)
	f := newRuntimeTestFixture(t, []byte(base), nil)
	f.start(t)
	_, before := f.acquire(t)
	next := strings.Replace(base, `"server":"192.0.2.53"`, `"server":"192.0.2.54"`, 1)
	_, request := f.plan(t, []byte(next))
	operation, err := f.box.applyRuntimeConfig(context.Background(), "actor-a", request)
	if err != nil || operation.Active.Revision != 2 {
		t.Fatalf("domain candidate: %+v %v", operation, err)
	}
	_, after := f.acquire(t)
	if before.componentIDs["outbound:a"] == after.componentIDs["outbound:a"] {
		t.Fatal("domain dialer retained old DNS router capture")
	}
	if before.componentIDs["outbound:b"] != after.componentIDs["outbound:b"] {
		t.Fatal("numeric independent proxy rebuilt")
	}
}

func TestRuntimeDomainDNSTransportCapturesBootstrapAndRouter(t *testing.T) {
	base := strings.Replace(string(runtimeTestConfig(1080, "example.org")), `[{"type":"udp","tag":"resolver","server":"192.0.2.53"}]`, `[{"type":"udp","tag":"bootstrap","server":"192.0.2.53"},{"type":"tcp","tag":"resolver","server":"dns.example","domain_resolver":"bootstrap"}]`, 1)
	f := newRuntimeTestFixture(t, []byte(base), nil)
	f.start(t)
	_, view := f.acquire(t)
	resolver := runtimeTestResource(t, f, view.componentIDs["dns-transport:resolver"])
	dns := runtimeTestResource(t, f, view.componentIDs["dns-router"])
	if resolver != dns {
		t.Fatal("actual DNS router/transport capture cycle was not condensed")
	}
	bootstrap := runtimeTestResource(t, f, view.componentIDs["dns-transport:bootstrap"])
	if bootstrap == resolver {
		t.Fatal("independent bootstrap artificially folded into cycle")
	}
}
