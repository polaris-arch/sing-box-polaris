package daemon

import (
	"context"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	boxCertificate "github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	boxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func runtimeTLSFixture(t *testing.T) *Instance {
	t.Helper()
	outbounds := outbound.NewRegistry()
	direct.RegisterOutbound(outbounds)
	transports := dns.NewTransportRegistry()
	transport.RegisterUDP(transports)
	ctx := box.Context(context.Background(), inbound.NewRegistry(), outbounds, endpoint.NewRegistry(), transports, boxService.NewRegistry(), boxCertificate.NewRegistry())
	ctx = pause.WithDefaultManager(ctx)
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, &runtimeURLTestPlatform{})
	var options option.Options
	if err := json.UnmarshalContext(ctx, []byte(`{"log":{"disabled":true},"dns":{"servers":[{"type":"udp","tag":"resolver","server":"192.0.2.53"}],"final":"resolver"},"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`), &options); err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := instance.CloseWithResult(); err != nil {
			t.Error(err)
		}
	})
	return &Instance{instance: instance, ctx: ctx}
}

func TestRuntimeTLSCapabilitiesUseSameDocumentAndActiveIncarnation(t *testing.T) {
	first, second := runtimeTLSFixture(t), runtimeTLSFixture(t)
	service := &StartedService{instance: first}
	ctx := ContextWithRuntimeActor(context.Background(), "authenticated-tls-reader")
	expected, err := boxtls.FingerprintCapabilitiesJSON()
	if err != nil {
		t.Fatal(err)
	}
	before, err := service.GetRuntimeCapabilities(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if before.TlsFingerprintCapabilitiesJson != expected || before.Active.Incarnation == "" {
		t.Fatal("authenticated running binary document/identity differs")
	}
	initial := before.Active.Incarnation
	before.TlsFingerprintCapabilitiesJson = "client-mutated"
	service.serviceAccess.Lock()
	service.instance = second
	service.serviceAccess.Unlock()
	after, err := service.GetRuntimeCapabilities(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if after.TlsFingerprintCapabilitiesJson != expected || after.Active.Incarnation == "" || after.Active.Incarnation == initial || before.Active.Incarnation != initial {
		t.Fatal("document leaked a stale instance or mutable response")
	}
	encoded, err := proto.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}
	var decoded RuntimeCapabilities
	if err = proto.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.TlsFingerprintCapabilitiesJson != expected || decoded.Active.Incarnation != after.Active.Incarnation {
		t.Fatal("tag 10 wire document/active binding differs")
	}
}
